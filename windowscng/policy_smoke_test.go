//go:build windows && cng_smoke

package windowscng

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
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
// by prefix or by enumeration.

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
// created it. A failure fails the test and names the key to inspect by hand.
func (k *smokeKey) cleanup() {
	for _, s := range k.signers {
		_ = s.Close()
	}
	if !k.created || k.deleted {
		return
	}
	if err := Delete(k.name); err != nil {
		k.t.Errorf("cleanup: Delete(%q) = %v: inspect and remove this exact key by hand", k.name, err)
	}
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

func (k *smokeKey) loadOrCreate(policy Policy) Signer {
	k.t.Helper()
	k.created = true
	s, err := LoadOrCreateWithPolicy(k.name, policy)
	k.afterCreate(err)
	if err != nil {
		k.t.Fatalf("LoadOrCreateWithPolicy(%v) = %v", policy, err)
	}
	return k.track(s)
}

func (k *smokeKey) loadOrCreateForService(policy ServicePolicy) Signer {
	k.t.Helper()
	k.created = true
	s, err := LoadOrCreateForService(k.name, policy)
	k.afterCreate(err)
	if err != nil {
		k.t.Fatalf("LoadOrCreateForService(%v) = %v", policy, err)
	}
	return k.track(s)
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
	return func() (Signer, error) { return OpenWithPolicy(k.name, p) }
}

func (k *smokeKey) forService(p ServicePolicy) func() (Signer, error) {
	return func() (Signer, error) { return OpenForService(k.name, p) }
}

// release closes a signer and requires Close to succeed.
func (k *smokeKey) release(step string, s Signer) {
	k.t.Helper()
	if err := s.Close(); err != nil {
		k.t.Fatalf("%s: Close = %v", step, err)
	}
}

// deleteAndConfirm deletes the exact name and confirms that open reports it absent.
func (k *smokeKey) deleteAndConfirm(open func() (Signer, error)) {
	k.t.Helper()
	if err := Delete(k.name); err != nil {
		k.t.Fatalf("Delete = %v", err)
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
	return func(name string) (Signer, error) { return OpenWithPolicy(name, p) }
}

func serviceProbe(p ServicePolicy) func(string) (Signer, error) {
	return func(name string) (Signer, error) { return OpenForService(name, p) }
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

	// 1. create, sign, verify.
	s := k.loadOrCreate(PolicyServiceSigner)
	pub := smokeSignVerify(t, "A1", s)
	k.release("A1", s)

	// 2. open with the same policy.
	s = k.openOK("A2 OpenWithPolicy(PolicyServiceSigner)", k.withPolicy(PolicyServiceSigner))
	k.release("A2", s)

	// 3. the other policy does not match yet.
	k.openIs("A3 OpenWithPolicy(PolicyPrivilegedOnly)", ErrPolicyMismatch, k.withPolicy(PolicyPrivilegedOnly))

	// 4. tighten, and again (idempotent).
	k.mustNil("A4 ApplyPolicy(PolicyPrivilegedOnly)", ApplyPolicy(k.name, PolicyPrivilegedOnly))
	k.mustNil("A4 ApplyPolicy(PolicyPrivilegedOnly) again", ApplyPolicy(k.name, PolicyPrivilegedOnly))

	// 5. the tightened key opens, with the same public key.
	s = k.openOK("A5 OpenWithPolicy(PolicyPrivilegedOnly)", k.withPolicy(PolicyPrivilegedOnly))
	smokeSamePublic(t, "A5", s, pub)
	k.release("A5", s)

	// 6. the old policy no longer matches.
	k.openIs("A6 OpenWithPolicy(PolicyServiceSigner)", ErrPolicyMismatch, k.withPolicy(PolicyServiceSigner))

	// 7. widening is refused, and the DACL is unchanged.
	before := smokeDACL(t, k.name)
	k.mustBe("A7 ApplyPolicy(PolicyServiceSigner)", ErrPolicyMismatch, ApplyPolicy(k.name, PolicyServiceSigner))
	smokeSameDACL(t, "A7", before, smokeDACL(t, k.name))
	s = k.openOK("A7 OpenWithPolicy(PolicyPrivilegedOnly) after the refused widening", k.withPolicy(PolicyPrivilegedOnly))
	k.release("A7", s)

	// 8. the legacy Open needs the LOCAL SERVICE entry and refuses the key, which exists.
	k.openFailsNotAbsent("A8 Open", func() (Signer, error) { return Open(k.name) })

	// 9. delete.
	k.deleteAndConfirm(k.withPolicy(PolicyPrivilegedOnly))
}

// TestSmokePolicyServiceSID is scenario B: a per-service SID. The service does
// not need to exist.
func TestSmokePolicyServiceSID(t *testing.T) {
	svc := smokeServicePolicy(t, "KeppinSmokeSvc")
	k := newSmokeKey(t, "B", serviceProbe(svc))

	// 1. create, sign, verify.
	s := k.loadOrCreateForService(svc)
	smokeSignVerify(t, "B1", s)
	k.release("B1", s)

	// 2. open for the service; the generic policy does not match.
	s = k.openOK("B2 OpenForService", k.forService(svc))
	k.release("B2", s)
	k.openIs("B2 OpenWithPolicy(PolicyServiceSigner)", ErrPolicyMismatch, k.withPolicy(PolicyServiceSigner))

	// 3. tighten; the service form no longer matches.
	k.mustNil("B3 ApplyPolicy(PolicyPrivilegedOnly)", ApplyPolicy(k.name, PolicyPrivilegedOnly))
	k.openIs("B3 OpenForService", ErrPolicyMismatch, k.forService(svc))

	// 4. delete.
	k.deleteAndConfirm(k.forService(svc))
}

// TestSmokePolicyMigration is scenario C: from the generic LOCAL SERVICE key to
// a service SID.
func TestSmokePolicyMigration(t *testing.T) {
	svc := smokeServicePolicy(t, "KeppinSmokeSvc")
	other := smokeServicePolicy(t, "KeppinSmokeOtherSvc")
	k := newSmokeKey(t, "C", policyProbe(PolicyServiceSigner))

	// 1. create with the generic policy.
	s := k.loadOrCreate(PolicyServiceSigner)
	k.release("C1", s)

	// 2. migrate to the service.
	k.mustNil("C2 ApplyServicePolicy", ApplyServicePolicy(k.name, svc))
	s = k.openOK("C2 OpenForService", k.forService(svc))
	k.release("C2", s)

	// 3. another service's policy is not a transition from this state.
	k.mustBe("C3 ApplyServicePolicy(other service)", ErrPolicyMismatch, ApplyServicePolicy(k.name, other))

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
// exact key name, with the DACL of the legacy profile. On success the caller
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

	// 2. OpenWithPolicy refuses it: it exists, so not ErrKeyNotFound.
	k.openFailsNotAbsent("D2 OpenWithPolicy(PolicyServiceSigner)", k.withPolicy(PolicyServiceSigner))

	// 3. the legacy Open refuses it too.
	k.openFailsNotAbsent("D3 Open", func() (Signer, error) { return Open(k.name) })

	// 4. ApplyPolicy refuses it and does not touch the DACL.
	before := smokeDACL(t, k.name)
	if err := ApplyPolicy(k.name, PolicyPrivilegedOnly); err == nil {
		t.Fatalf("D4 ApplyPolicy(PolicyPrivilegedOnly) = nil, want an error")
	}
	smokeSameDACL(t, "D4", before, smokeDACL(t, k.name))

	// 5. delete.
	k.deleteAndConfirm(k.withPolicy(PolicyServiceSigner))
}

// TestSmokePolicyCreateExistingName is scenario E: what the Microsoft Software
// KSP does when a create hits a name that already exists. The status and the
// step of the refusal are observed and logged, not fixed; the test fails only
// if the create succeeds or the original key changes or disappears.
func TestSmokePolicyCreateExistingName(t *testing.T) {
	k := newSmokeKey(t, "E", policyProbe(PolicyServiceSigner))

	// 1. create the original key and keep its public key.
	s := k.loadOrCreate(PolicyServiceSigner)
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
	s = k.openOK("E4 OpenWithPolicy(PolicyServiceSigner)", k.withPolicy(PolicyServiceSigner))
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
