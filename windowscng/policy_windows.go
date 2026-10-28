//go:build windows

package windowscng

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var procCheckTokenMembership = advapi32.NewProc("CheckTokenMembership")

// OpenWithPolicy opens the existing persisted machine-scoped key named name
// without creating it, and returns a signer only if the key is non-exportable,
// is ECDSA P-256, and its persisted DACL is exactly in the state required by
// policy (see classifyDescriptor for the exact forms).
//
// For PolicyPrivilegedOnly the caller must be privileged (SYSTEM or an elevated
// Administrators member); otherwise ErrPrivilegeRequired is returned before
// any key is opened. PolicyServiceSigner does not require a privileged caller,
// so a LOCAL SERVICE runtime can use it.
//
// It returns an error wrapping ErrKeyNotFound when the native open reports
// NTE_NOT_FOUND or NTE_BAD_KEYSET, that is the key was not found or is not
// accessible to the caller, and ErrPolicyMismatch when the key exists
// but its DACL is not exactly the required form. OpenWithPolicy never modifies
// the key. It is stricter than Open and may reject keys that Open accepts.
func OpenWithPolicy(name string, policy Policy) (Signer, error) {
	return openWithPolicy(nativeKeyStore{}, name, policy)
}

// LoadOrCreateWithPolicy opens the existing key named name and validates it
// like OpenWithPolicy, or creates it with the DACL of policy if, and only if,
// the native open reports that the key does not exist.
//
// Unlike LoadOrCreate, any other open failure (for example access denied) is
// returned without attempting creation. Creation additionally requires a
// privileged caller: if the open reports "not found" to a non-privileged
// caller, ErrPrivilegeRequired is returned, because for such a caller the
// absence of the key cannot be distinguished from a lack of access.
//
// An existing key in a different policy state is never converted; the result
// is ErrPolicyMismatch. Use ApplyPolicy for an explicit, tighten-only change.
func LoadOrCreateWithPolicy(name string, policy Policy) (Signer, error) {
	return loadOrCreateWithPolicy(nativeKeyStore{}, name, policy)
}

// ApplyPolicy brings the existing persisted key named name to policy by
// rewriting its DACL in place, without recreating, rotating or deleting it.
//
// It requires a privileged caller and only performs these transitions:
//
//   - the key is already exactly in the policy state: no write, nil (idempotent);
//   - the key is exactly in the PolicyServiceSigner state and policy is
//     PolicyPrivilegedOnly: the DACL is replaced with the privileged-only DACL.
//
// Any other state, including an unrecognized DACL or a request that would widen
// access, returns ErrPolicyMismatch without modifying the key. The key must
// also be non-exportable ECDSA P-256. A missing key returns ErrKeyNotFound;
// ApplyPolicy never creates a key.
//
// After writing, the DACL is read back both from the open handle and from a
// freshly opened handle. If either read-back does not match, an error is
// returned and the key is NOT rolled back (rolling back would widen access);
// its persisted DACL must then be inspected manually.
func ApplyPolicy(name string, policy Policy) error {
	return applyPolicy(nativeKeyStore{}, name, policy)
}

// errPostWriteVerification marks a DACL write whose read-back did not confirm
// the requested state.
var errPostWriteVerification = errors.New("windowscng: post-write DACL verification failed; persisted state is unverified and was not rolled back")

// keyStore is the seam between the policy engine and native CNG. The native
// implementation is nativeKeyStore; unit tests substitute a fake.
type keyStore interface {
	// callerPrivileged reports whether the calling thread's token is SYSTEM or
	// an enabled member of the built-in Administrators group.
	callerPrivileged() (bool, error)
	// open opens the exact existing machine-scoped key without creating it.
	// The error wraps ErrKeyNotFound only for NTE_NOT_FOUND/NTE_BAD_KEYSET.
	open(name string) (storedKey, error)
	// create creates a new non-exportable machine-scoped ECDSA P-256 key with
	// the DACL in sddl, never overwriting an existing key.
	create(name, sddl string) (storedKey, error)
}

// storedKey is an open persisted key. Exactly one of close, deleteCreated or a
// successful signer call must end its lifetime.
type storedKey interface {
	verifyNonExportable() error
	publicKey() (*ecdsa.PublicKey, error)
	securityDescriptor() ([]byte, error)
	setSecurityDescriptor(sddl string) error
	// signer transfers ownership of the handles to the returned Signer.
	signer() (Signer, error)
	// deleteCreated deletes a key created by this call and releases handles.
	// It returns the delete error; the handles are released either way.
	deleteCreated() error
	close()
}

// policySDDL returns the SDDL this package requests for policy.
func policySDDL(p Policy) string {
	if p == PolicyPrivilegedOnly {
		return privilegedOnlySDDL
	}
	return keySecuritySDDL
}

// OpenForService opens the existing persisted machine-scoped key named name
// without creating it, and returns a signer only if the key is non-exportable,
// is ECDSA P-256, and its persisted DACL is exactly the ServicePolicy form for
// policy's service SID.
//
// It does not require a privileged caller, so the service itself can use it.
// For a caller the DACL does not grant, the Microsoft Software KSP has been
// observed to report the key as not found (NTE_BAD_KEYSET) rather than access
// denied: an error wrapping ErrKeyNotFound therefore does not prove that the
// key is absent. OpenForService never modifies the key.
func OpenForService(name string, policy ServicePolicy) (Signer, error) {
	return openForService(nativeKeyStore{}, name, policy)
}

// LoadOrCreateForService is LoadOrCreateWithPolicy for a ServicePolicy: it
// opens and validates the existing key like OpenForService, or creates it with
// the ServicePolicy DACL if, and only if, a privileged caller's open reports
// that the key does not exist. An existing key in another state is never
// converted; the result is ErrPolicyMismatch. Use ApplyServicePolicy for the
// explicit migration of a PolicyServiceSigner key.
func LoadOrCreateForService(name string, policy ServicePolicy) (Signer, error) {
	return loadOrCreateForService(nativeKeyStore{}, name, policy)
}

// ApplyServicePolicy brings the existing persisted key named name to policy by
// rewriting its DACL in place, without recreating, rotating or deleting it. It
// requires a privileged caller and only performs these transitions:
//
//   - the key is already exactly in policy's state: no write, nil (idempotent);
//   - the key is exactly in the PolicyServiceSigner state: the LOCAL SERVICE
//     ACE is replaced by policy's service SID ACE (migration of a baseline key
//     from "any LOCAL SERVICE service" to "this service").
//
// Any other state, including privileged-only (that would widen access) or a
// service-sid DACL for a different service, returns ErrPolicyMismatch without
// modifying the key. Post-write verification is as for ApplyPolicy.
func ApplyServicePolicy(name string, policy ServicePolicy) error {
	return applyServicePolicy(nativeKeyStore{}, name, policy)
}

// policySpec is the engine's form of a Policy or a ServicePolicy.
type policySpec struct {
	label      string
	state      daclState
	serviceSID string // set only for daclServiceSID
	sddl       string
	// privilegedOpen requires a privileged caller even to open the key.
	privilegedOpen bool
}

func (p Policy) spec() policySpec {
	return policySpec{label: p.String(), state: p.state(), sddl: policySDDL(p), privilegedOpen: p == PolicyPrivilegedOnly}
}

func (p ServicePolicy) spec() policySpec {
	return policySpec{label: p.String(), state: daclServiceSID, serviceSID: p.sid, sddl: p.sddl()}
}

// describeState names a classified DACL state for error messages.
func describeState(st daclState, sid string) string {
	if st == daclServiceSID {
		return st.String() + "(" + sid + ")"
	}
	return st.String()
}

// transitionAllowed reports whether the DACL of a key in state current may be
// rewritten to want. Only narrowing transitions are permitted, plus the
// replacement of the generic LOCAL SERVICE grant by a single service SID.
func transitionAllowed(current daclState, want policySpec) bool {
	switch want.state {
	case daclPrivilegedOnly:
		return current == daclServiceSigner || current == daclServiceSID
	case daclServiceSID:
		return current == daclServiceSigner
	default:
		return false
	}
}

// requirePrivilege fails closed: an error from the privilege check is treated
// as "not privileged".
func requirePrivilege(ks keyStore) error {
	ok, err := ks.callerPrivileged()
	if err != nil {
		return fmt.Errorf("%w: privilege check failed: %v", ErrPrivilegeRequired, err)
	}
	if !ok {
		return ErrPrivilegeRequired
	}
	return nil
}

// checkKeyPolicy validates key profile and DACL state without modifying the key.
func checkKeyPolicy(k storedKey, s policySpec) error {
	if err := k.verifyNonExportable(); err != nil {
		return err
	}
	if _, err := k.publicKey(); err != nil {
		return fmt.Errorf("%w: key is not a valid ECDSA P-256 key: %v", ErrPolicyMismatch, err)
	}
	return checkDACLState(k, s)
}

func checkDACLState(k storedKey, want policySpec) error {
	sd, err := k.securityDescriptor()
	if err != nil {
		return fmt.Errorf("read persisted DACL (descriptor unavailable): %w", err)
	}
	got, sid, err := classifyDescriptorSID(sd)
	if err != nil {
		return descriptorMismatch(sd, err.Error())
	}
	if got != want.state || sid != want.serviceSID {
		return descriptorMismatch(sd, fmt.Sprintf("persisted DACL is %s, want %s", describeState(got, sid), describeState(want.state, want.serviceSID)))
	}
	return nil
}

// descriptorMismatch preserves the ENTIRE buffer used by the classifier,
// including header/control and every ACE, even when the first ACE is rejected.
// Formatting occurs before the caller closes/deletes a newly created key;
// there is no second read, no callback, and no change to rollback semantics.
// Scope is explicitly DACL_SECURITY_INFORMATION: owner/group/SACL are not
// requested. This is public security metadata, never private key material.
func descriptorMismatch(sd []byte, reason string) error {
	return fmt.Errorf("%w: %s; security_information=DACL_SECURITY_INFORMATION; persisted_sd_dacl_hex=%x", ErrPolicyMismatch, reason, sd)
}

func signerWithPolicy(k storedKey, name string, s policySpec) (Signer, error) {
	if err := checkKeyPolicy(k, s); err != nil {
		k.close()
		return nil, fmt.Errorf("key %q (%s): %w", name, s.label, err)
	}
	signer, err := k.signer()
	if err != nil {
		k.close()
		return nil, err
	}
	return signer, nil
}

func openWithPolicy(ks keyStore, name string, p Policy) (Signer, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	return openSpec(ks, name, p.spec())
}

func openForService(ks keyStore, name string, p ServicePolicy) (Signer, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	return openSpec(ks, name, p.spec())
}

func openSpec(ks keyStore, name string, s policySpec) (Signer, error) {
	if s.privilegedOpen {
		if err := requirePrivilege(ks); err != nil {
			return nil, err
		}
	}
	k, err := ks.open(name)
	if err != nil {
		return nil, err
	}
	return signerWithPolicy(k, name, s)
}

func loadOrCreateWithPolicy(ks keyStore, name string, p Policy) (Signer, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	return loadOrCreateSpec(ks, name, p.spec())
}

func loadOrCreateForService(ks keyStore, name string, p ServicePolicy) (Signer, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	return loadOrCreateSpec(ks, name, p.spec())
}

func loadOrCreateSpec(ks keyStore, name string, s policySpec) (Signer, error) {
	privileged, privErr := ks.callerPrivileged()
	if privErr != nil {
		privileged = false
	}
	if s.privilegedOpen && !privileged {
		if privErr != nil {
			return nil, fmt.Errorf("%w: privilege check failed: %v", ErrPrivilegeRequired, privErr)
		}
		return nil, ErrPrivilegeRequired
	}

	k, err := ks.open(name)
	if err == nil {
		return signerWithPolicy(k, name, s)
	}
	if !errors.Is(err, ErrKeyNotFound) {
		// Never interpret access denied or any other failure as "absent".
		return nil, err
	}
	if !privileged {
		return nil, fmt.Errorf("key %q: open reported not found, but absence cannot be established for a non-privileged caller and creation requires a privileged caller: %w", name, ErrPrivilegeRequired)
	}

	k, err = ks.create(name, s.sddl)
	if err != nil {
		return nil, fmt.Errorf("create key %q (%s): %w", name, s.label, err)
	}
	if err := checkKeyPolicy(k, s); err != nil {
		// The key was created by this call and does not hold the requested
		// policy (for example because of provider canonicalization): remove it
		// rather than leave a key in an unverified state. A DACL mismatch error
		// already contains the full descriptor buffer captured before deletion.
		// The delete outcome is reported: on failure the error also wraps
		// ErrCleanupFailed and the unverified key may persist.
		return nil, fmt.Errorf("created key %q failed %s verification: %w", name, s.label, cleanupCreatedKey(err, k.deleteCreated))
	}
	signer, err := k.signer()
	if err != nil {
		k.close()
		return nil, err
	}
	return signer, nil
}

func applyPolicy(ks keyStore, name string, p Policy) error {
	if err := p.validate(); err != nil {
		return err
	}
	return applySpec(ks, name, p.spec())
}

func applyServicePolicy(ks keyStore, name string, p ServicePolicy) error {
	if err := p.validate(); err != nil {
		return err
	}
	return applySpec(ks, name, p.spec())
}

func applySpec(ks keyStore, name string, want policySpec) error {
	if err := requirePrivilege(ks); err != nil {
		return err
	}

	k, err := ks.open(name)
	if err != nil {
		return err
	}
	defer k.close()

	if err := k.verifyNonExportable(); err != nil {
		return fmt.Errorf("key %q: %w", name, err)
	}
	if _, err := k.publicKey(); err != nil {
		return fmt.Errorf("key %q: %w: key is not a valid ECDSA P-256 key: %v", name, ErrPolicyMismatch, err)
	}
	sd, err := k.securityDescriptor()
	if err != nil {
		return fmt.Errorf("key %q: %w", name, err)
	}
	current, currentSID, err := classifyDescriptorSID(sd)
	if err != nil {
		return fmt.Errorf("key %q: current DACL: %w", name, descriptorMismatch(sd, err.Error()))
	}

	if current == want.state && currentSID == want.serviceSID {
		return nil
	}
	if !transitionAllowed(current, want) {
		return fmt.Errorf("key %q: %w: refusing transition %s -> %s", name, ErrPolicyMismatch,
			describeState(current, currentSID), describeState(want.state, want.serviceSID))
	}

	if err := k.setSecurityDescriptor(want.sddl); err != nil {
		return fmt.Errorf("key %q: %w", name, err)
	}

	// Read back from the same handle, then from a fresh handle so that the
	// persisted state, not only the handle's view, is confirmed.
	if err := checkDACLState(k, want); err != nil {
		return fmt.Errorf("key %q: %w: read-back on open handle: %v", name, errPostWriteVerification, err)
	}
	fresh, err := ks.open(name)
	if err != nil {
		return fmt.Errorf("key %q: %w: reopen: %v", name, errPostWriteVerification, err)
	}
	defer fresh.close()
	if err := checkDACLState(fresh, want); err != nil {
		return fmt.Errorf("key %q: %w: read-back on fresh handle: %v", name, errPostWriteVerification, err)
	}
	return nil
}

// nativeKeyStore implements keyStore with Microsoft Software KSP calls.
type nativeKeyStore struct{}

func (nativeKeyStore) callerPrivileged() (bool, error) {
	for _, sid := range []string{sidSYSTEM, sidAdministrators} {
		member, err := checkTokenMembership(sid)
		if err != nil {
			return false, err
		}
		if member {
			return true, nil
		}
	}
	return false, nil
}

// checkTokenMembership reports whether sid is enabled in the calling thread's
// effective token (impersonation token if impersonating, else the primary
// token). Under UAC the Administrators SID of a filtered token is deny-only
// and therefore reported as not a member.
func checkTokenMembership(sidString string) (bool, error) {
	if err := loadNativeAPIs(); err != nil {
		return false, err
	}
	sid, err := convertStringSid(sidString)
	if err != nil {
		return false, err
	}
	defer procLocalFree.Call(uintptr(sid))
	var member int32
	r, _, callErr := procCheckTokenMembership.Call(0, uintptr(sid), uintptr(unsafe.Pointer(&member)))
	if r == 0 {
		return false, fmt.Errorf("CheckTokenMembership(%s): %v", sidString, callErr)
	}
	return member != 0, nil
}

func (nativeKeyStore) open(name string) (storedKey, error) {
	provider, err := openProvider()
	if err != nil {
		return nil, err
	}
	nameUTF16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		procNCryptFreeObject.Call(provider)
		return nil, fmt.Errorf("convert key name: %w", err)
	}
	var keyHandle uintptr
	r, _, _ := procNCryptOpenKey.Call(
		provider,
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(unsafe.Pointer(nameUTF16)),
		0,
		uintptr(openKeyFlags),
	)
	if r != 0 {
		procNCryptFreeObject.Call(provider)
		if IsKeyNotFound(r) {
			return nil, fmt.Errorf("key %q: NCryptOpenKey hr=0x%x: %w", name, r, ErrKeyNotFound)
		}
		return nil, fmt.Errorf("NCryptOpenKey %q: hr=0x%x", name, r)
	}
	return &nativeKey{provider: provider, key: keyHandle, name: name}, nil
}

func (nativeKeyStore) create(name, sddl string) (storedKey, error) {
	provider, err := openProvider()
	if err != nil {
		return nil, err
	}
	nameUTF16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		procNCryptFreeObject.Call(provider)
		return nil, fmt.Errorf("convert key name: %w", err)
	}
	keyHandle, err := createPersistedKey(provider, nameUTF16, sddl)
	if err != nil {
		procNCryptFreeObject.Call(provider)
		return nil, err
	}
	return &nativeKey{provider: provider, key: keyHandle, name: name}, nil
}

// nativeKey implements storedKey over open NCrypt provider and key handles.
type nativeKey struct {
	provider uintptr
	key      uintptr
	name     string
}

func (k *nativeKey) verifyNonExportable() error { return verifyExportPolicy(k.key) }

func (k *nativeKey) publicKey() (*ecdsa.PublicKey, error) { return exportPublicKey(k.key) }

func (k *nativeKey) securityDescriptor() ([]byte, error) { return getSecurityDescriptor(k.key) }

func (k *nativeKey) setSecurityDescriptor(sddl string) error {
	sd, err := buildSecurityDescriptor(sddl)
	if err != nil {
		return fmt.Errorf("build security descriptor: %w", err)
	}
	return setSecurityDescriptor(k.key, sd)
}

func (k *nativeKey) signer() (Signer, error) {
	s, err := newCNGSigner(k.provider, k.key, k.name)
	if err != nil {
		return nil, err
	}
	k.provider, k.key = 0, 0
	return s, nil
}

func (k *nativeKey) deleteCreated() error {
	var err error
	if k.key != 0 {
		err = deletePersistedKey(k.key)
		k.key = 0
	}
	k.close()
	return err
}

func (k *nativeKey) close() {
	if k.key != 0 {
		procNCryptFreeObject.Call(k.key)
		k.key = 0
	}
	if k.provider != 0 {
		procNCryptFreeObject.Call(k.provider)
		k.provider = 0
	}
}
