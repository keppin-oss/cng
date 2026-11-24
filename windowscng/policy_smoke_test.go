//go:build windows && cng_smoke

package windowscng

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// Native smoke tests of the policy cycle. They are gated behind the cng_smoke
// build tag, create real persisted machine keys and need a privileged caller
// (SYSTEM or an elevated Administrator) on a test machine. They are never run
// by `go test ./...` without the tag.
//
// Every scenario uses its own fresh key name,
// Keppin.OSS.Test.CNG.Policy.<scenario>.<16 random hex digits>, and deletes
// only that exact name, and only if this test created it. Nothing is deleted
// by prefix or by enumeration. A scenario deletes its key with the public
// Delete, against the policy and SubjectPublicKeyInfo it recorded; the
// cleanup of a scenario that stopped earlier, or whose key Delete must refuse
// (an exportable key), deletes the exact name through the internal native
// path instead.

// smokeRequiredEnv, when set to 1, turns every unmet precondition of a smoke
// test into a failure: with it set, no smoke test can skip.
const smokeRequiredEnv = "KEPPIN_CNG_SMOKE_REQUIRED"

// smokeUnmet reports an unmet precondition: it skips the test, or fails it when
// KEPPIN_CNG_SMOKE_REQUIRED=1. It is the only place of the smoke tests that
// can skip.
func smokeUnmet(t *testing.T, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	if os.Getenv(smokeRequiredEnv) == "1" {
		t.Fatalf("%s=1 and a precondition is not met: %s", smokeRequiredEnv, msg)
	}
	t.Skipf("skipping cng smoke test: %s — NOT EXECUTED (set %s=1 to fail instead of skipping)", msg, smokeRequiredEnv)
}

// smokeKey is the key of one scenario and the bookkeeping for its cleanup.
type smokeKey struct {
	t    *testing.T
	name string
	// probe opens the name with the policy of the scenario; it is used for the
	// precondition and to confirm that a deleted key is absent.
	probe func(name string) (Signer, error)
	// created is set before the first creation call, because a failed create
	// can still leave a key behind; it is cleared again only when that call
	// failed and nothing proves the key exists (exists).
	created, exists, deleted bool
	signers                  []Signer
	// policy is the policy the key currently holds, and spki the
	// SubjectPublicKeyInfo recorded at its creation: the inputs of Delete.
	policy KeyPolicy
	spki   []byte
}

// newSmokeKey checks the preconditions, before anything is created, and
// registers the cleanup.
func newSmokeKey(t *testing.T, scenario string, probe func(name string) (Signer, error)) *smokeKey {
	t.Helper()
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		t.Fatalf("random key name: %v", err)
	}
	k := &smokeKey{
		t:     t,
		name:  fmt.Sprintf("Keppin.OSS.Test.CNG.Policy.%s.%016x", scenario, binary.BigEndian.Uint64(r[:])),
		probe: probe,
	}
	privileged, err := nativeKeyStore{}.callerPrivileged()
	if err != nil {
		smokeUnmet(t, "privilege check failed: %v", err)
	}
	if !privileged {
		smokeUnmet(t, "the caller is not privileged (SYSTEM or an elevated Administrator)")
	}
	s, err := probe(k.name)
	if s != nil {
		_ = s.Close()
		t.Fatalf("precondition: key %q already opens", k.name)
	}
	if !errors.Is(err, ErrKeyNotFound) {
		smokeUnmet(t, "opening the new name %q = %v, want ErrKeyNotFound", k.name, err)
	}
	t.Cleanup(k.cleanup)
	return k
}

// cleanup closes the signers first, then deletes the exact name if this test
// created it and did not delete it. A failure fails the test and names the key
// to inspect by hand.
func (k *smokeKey) cleanup() {
	for _, s := range k.signers {
		_ = s.Close()
	}
	if !k.created || k.deleted {
		return
	}
	if err := smokeDeleteExact(k.name); err != nil {
		k.t.Errorf("cleanup: delete %q = %v: inspect and remove this exact key by hand", k.name, err)
	}
}

// smokeDeleteExact deletes the exact test key name through the internal
// native path, without the checks of Delete: it opens the name and deletes
// through that same handle. It is used only for keys this test created.
func smokeDeleteExact(name string) error {
	sk, err := nativeKeyStore{}.open(name)
	if err != nil {
		return err
	}
	return sk.deleteAndRelease()
}

// smokeSPKI returns the DER SubjectPublicKeyInfo of s, the form Delete expects.
func smokeSPKI(t *testing.T, step string, s Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		t.Fatalf("%s: MarshalPKIXPublicKey = %v", step, err)
	}
	return der
}

// track registers a signer so that cleanup closes it. Close is idempotent.
func (k *smokeKey) track(s Signer) Signer {
	if s != nil {
		k.signers = append(k.signers, s)
	}
	return s
}

// afterCreate records the outcome of a creation call.
func (k *smokeKey) afterCreate(err error) {
	if err == nil {
		k.exists = true
		return
	}
	// A failed create has cleaned up after itself, except when the rollback
	// failed: then the key may persist.
	if !k.exists && !errors.Is(err, ErrCleanupFailed) {
		k.created = false
	}
}

// create creates the key with policy and records the policy and the
// SubjectPublicKeyInfo of the new key.
func (k *smokeKey) create(policy KeyPolicy) Signer {
	k.t.Helper()
	k.created = true
	s, err := Create(k.name, policy)
	k.afterCreate(err)
	if err != nil {
		k.t.Fatalf("Create(%v) = %v", policy, err)
	}
	k.policy, k.spki = policy, smokeSPKI(k.t, "Create", s)
	return k.track(s)
}

// apply runs Apply, which must succeed, and records the new policy.
func (k *smokeKey) apply(step string, policy KeyPolicy) {
	k.t.Helper()
	k.mustNil(step, Apply(k.name, policy))
	k.policy = policy
}

// openOK opens with open, which must succeed.
func (k *smokeKey) openOK(step string, open func() (Signer, error)) Signer {
	k.t.Helper()
	s, err := open()
	k.track(s)
	if err != nil {
		k.t.Fatalf("%s = %v, want success", step, err)
	}
	return s
}

// openIs requires open to fail with an error wrapping want and return no signer.
func (k *smokeKey) openIs(step string, want error, open func() (Signer, error)) {
	k.t.Helper()
	s, err := open()
	k.track(s)
	if s != nil {
		k.t.Fatalf("%s returned a signer, want none (error %v)", step, err)
	}
	if !errors.Is(err, want) {
		k.t.Fatalf("%s = %v, want %v", step, err, want)
	}
}

// openFailsNotAbsent requires open to fail, with no signer, with an error that
// is not ErrKeyNotFound: the key exists but is refused.
func (k *smokeKey) openFailsNotAbsent(step string, open func() (Signer, error)) {
	k.t.Helper()
	s, err := open()
	k.track(s)
	if s != nil {
		k.t.Fatalf("%s returned a signer, want none", step)
	}
	if err == nil {
		k.t.Fatalf("%s succeeded, want an error", step)
	}
	if errors.Is(err, ErrKeyNotFound) {
		k.t.Fatalf("%s = %v, want an error that is not ErrKeyNotFound", step, err)
	}
}

func (k *smokeKey) withPolicy(p Policy) func() (Signer, error) {
	return func() (Signer, error) { return Open(k.name, p) }
}

func (k *smokeKey) forService(p ServicePolicy) func() (Signer, error) {
	return func() (Signer, error) { return Open(k.name, p) }
}

// release closes a signer and requires Close to succeed.
func (k *smokeKey) release(step string, s Signer) {
	k.t.Helper()
	if err := s.Close(); err != nil {
		k.t.Fatalf("%s: Close = %v", step, err)
	}
}

// deleteAndConfirm deletes the exact name with the public Delete, against the
// recorded policy and SubjectPublicKeyInfo, and confirms that open reports it
// absent.
func (k *smokeKey) deleteAndConfirm(open func() (Signer, error)) {
	k.t.Helper()
	if err := Delete(k.name, k.policy, k.spki); err != nil {
		k.t.Fatalf("Delete(%v) = %v", k.policy, err)
	}
	k.deleted = true
	k.openIs("open after Delete", ErrKeyNotFound, open)
}

func (k *smokeKey) mustNil(step string, err error) {
	k.t.Helper()
	if err != nil {
		k.t.Fatalf("%s = %v, want nil", step, err)
	}
}

func (k *smokeKey) mustBe(step string, want, err error) {
	k.t.Helper()
	if !errors.Is(err, want) {
		k.t.Fatalf("%s = %v, want %v", step, err, want)
	}
}

// smokePublic returns the ECDSA public key of s.
func smokePublic(t *testing.T, step string, s Signer) *ecdsa.PublicKey {
	t.Helper()
	pub, ok := s.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("%s: Public() = %T, want *ecdsa.PublicKey", step, s.Public())
	}
	return pub
}

// smokeSignVerify signs a SHA-256 digest and verifies it with the public key.
func smokeSignVerify(t *testing.T, step string, s Signer) *ecdsa.PublicKey {
	t.Helper()
	pub := smokePublic(t, step, s)
	digest := sha256.Sum256([]byte("keppin-oss-cng-policy-smoke"))
	sig, err := s.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatalf("%s: Sign = %v", step, err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatalf("%s: the signature did not verify", step)
	}
	return pub
}

// smokeSamePublic fails unless s has the public key want.
func smokeSamePublic(t *testing.T, step string, s Signer, want *ecdsa.PublicKey) {
	t.Helper()
	if !smokePublic(t, step, s).Equal(want) {
		t.Fatalf("%s: the public key differs from the one of the key created by this test", step)
	}
}

// smokeDACL returns the persisted security descriptor of the exact key name,
// read without any validation, through a short-lived handle.
func smokeDACL(t *testing.T, name string) []byte {
	t.Helper()
	sk, err := nativeKeyStore{}.open(name)
	if err != nil {
		t.Fatalf("open %q to read its DACL: %v", name, err)
	}
	defer sk.close()
	sd, err := sk.securityDescriptor()
	if err != nil {
		t.Fatalf("read the DACL of %q: %v", name, err)
	}
	return sd
}

func smokeSameDACL(t *testing.T, step string, before, after []byte) {
	t.Helper()
	if !bytes.Equal(before, after) {
		t.Fatalf("%s: the persisted DACL changed", step)
	}
}

func policyProbe(p Policy) func(string) (Signer, error) {
	return func(name string) (Signer, error) { return Open(name, p) }
}

func serviceProbe(p ServicePolicy) func(string) (Signer, error) {
	return func(name string) (Signer, error) { return Open(name, p) }
}

func smokeServicePolicy(t *testing.T, service string) ServicePolicy {
	t.Helper()
	p, err := NewServicePolicy(service)
	if err != nil {
		t.Fatalf("NewServicePolicy(%q) = %v", service, err)
	}
	return p
}

// TestSmokePolicyGeneric is scenario A: the generic policies.
func TestSmokePolicyGeneric(t *testing.T) {
	k := newSmokeKey(t, "A", policyProbe(PolicyServiceSigner))

	// 0. an Open of the absent name never creates it.
	k.openIs("A0 Open(PolicyServiceSigner) on the absent name", ErrKeyNotFound, k.withPolicy(PolicyServiceSigner))
	k.openIs("A0 Open again: still absent", ErrKeyNotFound, k.withPolicy(PolicyServiceSigner))

	// 1. create, sign, verify.
	s := k.create(PolicyServiceSigner)
	pub := smokeSignVerify(t, "A1", s)
	k.release("A1", s)

	// 2. open with the same policy.
	s = k.openOK("A2 Open(PolicyServiceSigner)", k.withPolicy(PolicyServiceSigner))
	k.release("A2", s)

	// 3. the other policy does not match yet.
	k.openIs("A3 Open(PolicyPrivilegedOnly)", ErrPolicyMismatch, k.withPolicy(PolicyPrivilegedOnly))

	// 4. a Create on the existing name fails with ErrKeyExists and leaves the
	// key untouched.
	before := smokeDACL(t, k.name)
	created, err := Create(k.name, PolicyServiceSigner)
	k.track(created)
	if created != nil || !errors.Is(err, ErrKeyExists) {
		t.Fatalf("A4 Create on the existing name = (%v, %v), want no signer and ErrKeyExists", created, err)
	}
	smokeSameDACL(t, "A4", before, smokeDACL(t, k.name))
	s = k.openOK("A4 Open(PolicyServiceSigner) after the refused create", k.withPolicy(PolicyServiceSigner))
	smokeSamePublic(t, "A4", s, pub)
	k.release("A4", s)

	// 5. tighten, and again (idempotent).
	k.apply("A5 Apply(PolicyPrivilegedOnly)", PolicyPrivilegedOnly)
	k.apply("A5 Apply(PolicyPrivilegedOnly) again", PolicyPrivilegedOnly)

	// 6. the tightened key opens, with the same public key.
	s = k.openOK("A6 Open(PolicyPrivilegedOnly)", k.withPolicy(PolicyPrivilegedOnly))
	smokeSamePublic(t, "A6", s, pub)
	k.release("A6", s)

	// 7. the old policy no longer matches.
	k.openIs("A7 Open(PolicyServiceSigner)", ErrPolicyMismatch, k.withPolicy(PolicyServiceSigner))

	// 8. widening is refused, and the DACL is unchanged.
	before = smokeDACL(t, k.name)
	k.mustBe("A8 Apply(PolicyServiceSigner)", ErrPolicyMismatch, Apply(k.name, PolicyServiceSigner))
	smokeSameDACL(t, "A8", before, smokeDACL(t, k.name))
	s = k.openOK("A8 Open(PolicyPrivilegedOnly) after the refused widening", k.withPolicy(PolicyPrivilegedOnly))
	k.release("A8", s)

	// 9. a Delete with another SubjectPublicKeyInfo, or with a policy the key
	// does not hold, deletes nothing.
	other, err := ecdsa.GenerateKey(pub.Curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSPKI, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k.mustBe("A9 Delete with another SPKI", ErrDeleteVerificationFailed, Delete(k.name, PolicyPrivilegedOnly, otherSPKI))
	err = Delete(k.name, PolicyServiceSigner, k.spki)
	k.mustBe("A9 Delete with another policy", ErrDeleteVerificationFailed, err)
	k.mustBe("A9 Delete with another policy", ErrPolicyMismatch, err)
	s = k.openOK("A9 Open(PolicyPrivilegedOnly) after the refused deletes", k.withPolicy(PolicyPrivilegedOnly))
	smokeSamePublic(t, "A9", s, pub)
	k.release("A9", s)

	// 10. delete.
	k.deleteAndConfirm(k.withPolicy(PolicyPrivilegedOnly))
}

// TestSmokePolicyServiceSID is scenario B: a per-service SID. The service does
// not need to exist.
func TestSmokePolicyServiceSID(t *testing.T) {
	svc := smokeServicePolicy(t, "KeppinSmokeSvc")
	k := newSmokeKey(t, "B", serviceProbe(svc))

	// 1. create, sign, verify.
	s := k.create(svc)
	smokeSignVerify(t, "B1", s)
	k.release("B1", s)

	// 2. open for the service; the generic policy does not match.
	s = k.openOK("B2 Open(service)", k.forService(svc))
	k.release("B2", s)
	k.openIs("B2 Open(PolicyServiceSigner)", ErrPolicyMismatch, k.withPolicy(PolicyServiceSigner))

	// 3. tighten; the service form no longer matches.
	k.apply("B3 Apply(PolicyPrivilegedOnly)", PolicyPrivilegedOnly)
	k.openIs("B3 Open(service)", ErrPolicyMismatch, k.forService(svc))

	// 4. delete.
	k.deleteAndConfirm(k.withPolicy(PolicyPrivilegedOnly))
}

// TestSmokePolicyMigration is scenario C: from the generic LOCAL SERVICE key to
// a service SID.
func TestSmokePolicyMigration(t *testing.T) {
	svc := smokeServicePolicy(t, "KeppinSmokeSvc")
	other := smokeServicePolicy(t, "KeppinSmokeOtherSvc")
	k := newSmokeKey(t, "C", policyProbe(PolicyServiceSigner))

	// 1. create with the generic policy.
	s := k.create(PolicyServiceSigner)
	k.release("C1", s)

	// 2. migrate to the service.
	k.apply("C2 Apply(service)", svc)
	s = k.openOK("C2 Open(service)", k.forService(svc))
	k.release("C2", s)

	// 3. another service's policy is not a transition from this state.
	k.mustBe("C3 Apply(other service)", ErrPolicyMismatch, Apply(k.name, other))

	// 4. delete.
	k.deleteAndConfirm(k.forService(svc))
}

// exportableCreateOps is the production create path with a single change:
// Export Policy is set to NCRYPT_ALLOW_EXPORT_FLAG instead of 0, so that the
// key it creates is exportable.
type exportableCreateOps struct{ nativeCreateKeyOps }

func (exportableCreateOps) setExportPolicyNone(keyHandle uintptr) uint32 {
	allow := uint32(ncryptAllowExportFlag)
	return ncryptStatus(procNCryptSetProperty.Call(
		keyHandle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Export Policy"))),
		uintptr(unsafe.Pointer(&allow)),
		unsafe.Sizeof(allow),
		uintptr(ncryptSilentFlag),
	))
}

// smokeCreateWith runs the internal create path of the package with ops on the
// exact key name, with the DACL of PolicyServiceSigner. On success the caller
// owns the returned key handle; the provider handle is always released.
func smokeCreateWith(ops createKeyNative, name string) (uintptr, error) {
	provider, err := openProvider()
	if err != nil {
		return 0, err
	}
	defer procNCryptFreeObject.Call(provider)
	nameUTF16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	return createPersistedKeyWith(ops, provider, nameUTF16, keySecuritySDDL)
}

// TestSmokePolicyExportableRejected is scenario D: a key that is exportable
// must be refused by every path. Without it, a run with only non-exportable
// keys would not notice that the check was removed.
func TestSmokePolicyExportableRejected(t *testing.T) {
	k := newSmokeKey(t, "D", policyProbe(PolicyServiceSigner))

	// 1. create an exportable key and release its handle.
	k.created = true
	h, err := smokeCreateWith(exportableCreateOps{}, k.name)
	k.afterCreate(err)
	if err != nil {
		t.Fatalf("D1 create of the exportable key = %v", err)
	}
	if h == 0 {
		t.Fatalf("D1 create returned a zero handle without an error")
	}
	procNCryptFreeObject.Call(h)

	// 2. Open refuses it: it exists, so not ErrKeyNotFound.
	k.openFailsNotAbsent("D2 Open(PolicyServiceSigner)", k.withPolicy(PolicyServiceSigner))

	// 3. Apply refuses it and does not touch the DACL.
	before := smokeDACL(t, k.name)
	if err := Apply(k.name, PolicyPrivilegedOnly); err == nil {
		t.Fatalf("D3 Apply(PolicyPrivilegedOnly) = nil, want an error")
	}
	smokeSameDACL(t, "D3", before, smokeDACL(t, k.name))

	// 4. Delete refuses it too, whatever SubjectPublicKeyInfo is passed: the
	// export policy is checked first.
	sk, err := nativeKeyStore{}.open(k.name)
	if err != nil {
		t.Fatalf("D4 open %q to read its public key: %v", k.name, err)
	}
	pub, err := sk.publicKey()
	sk.close()
	if err != nil {
		t.Fatalf("D4 public key of %q: %v", k.name, err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	k.mustBe("D4 Delete of the exportable key", ErrDeleteVerificationFailed, Delete(k.name, PolicyServiceSigner, spki))
	smokeSameDACL(t, "D4", before, smokeDACL(t, k.name))

	// 5. delete the exact name through the internal path.
	if err := smokeDeleteExact(k.name); err != nil {
		t.Fatalf("D5 delete = %v", err)
	}
	k.deleted = true
	k.openIs("D5 open after the delete", ErrKeyNotFound, k.withPolicy(PolicyServiceSigner))
}

// TestSmokePolicyCreateExistingName is scenario E: what the Microsoft Software
// KSP does when a create hits a name that already exists. The status and the
// step of the refusal are observed and logged, not fixed; the test fails only
// if the create succeeds or the original key changes or disappears.
func TestSmokePolicyCreateExistingName(t *testing.T) {
	k := newSmokeKey(t, "E", policyProbe(PolicyServiceSigner))

	// 1. create the original key and keep its public key.
	s := k.create(PolicyServiceSigner)
	pub := smokePublic(t, "E1", s)
	k.release("E1", s)

	// 2. run the internal create on the same name, recording every step.
	ops := &recordingCreateOps{
		createKeyNative: nativeCreateKeyOps{},
		freeStatus:      func(h uintptr) uint32 { return ncryptStatus(procNCryptFreeObject.Call(h)) },
	}
	h, err := smokeCreateWith(ops, k.name)

	// 3. observe.
	for i, st := range ops.steps {
		t.Logf("E3 step %d: %s -> %s", i+1, st.Op, st.Status)
	}
	t.Logf("E3 create on the existing name: handle=%#x error=%v finalize=%s delete=%s",
		h, err, smokeStatus(ops.reached("finalize"), ops.finalizeHR), smokeStatus(ops.reached("delete"), ops.deleteHR))
	for _, step := range []string{"create", "finalize", "delete"} {
		if ops.reached(step) {
			t.Logf("E3 the sequence reached %q", step)
		}
	}

	// 5. a create that succeeds is a failure: delete only what it returned.
	if err == nil || h != 0 {
		if h != 0 {
			if d := ops.createKeyNative.deleteKey(h); d != 0 {
				ops.createKeyNative.free(h)
				t.Errorf("E5 the key created on the existing name could not be deleted through its handle: status %#x; inspect %q by hand", d, k.name)
			}
		}
		t.Fatalf("E3/E5 create on an existing name = (handle %#x, error %v), want a failure and handle 0; the handle returned, if any, was deleted", h, err)
	}

	// 4. the original key is untouched.
	s = k.openOK("E4 Open(PolicyServiceSigner)", k.withPolicy(PolicyServiceSigner))
	smokeSamePublic(t, "E4", s, pub)
	k.release("E4", s)

	// 6. delete.
	k.deleteAndConfirm(k.withPolicy(PolicyServiceSigner))
}

// smokeStatus formats a recorded 32-bit status, or "not reached".
func smokeStatus(reached bool, hr uint32) string {
	if !reached {
		return "not reached"
	}
	return hex32(hr)
}
