//go:build windows

package windowscng

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"syscall"
	"unsafe"
)

// CNG flags and properties.
const (
	ncryptMachineKeyFlag   = 0x00000020
	ncryptSilentFlag       = 0x00000040
	ncryptAllowSigningFlag = 0x00000002

	// NCRYPT_EXPORT_POLICY_PROPERTY values.
	ncryptAllowExportFlag             = 0x00000001
	ncryptAllowPlaintextExportFlag    = 0x00000002
	ncryptAllowArchivingFlag          = 0x00000004
	ncryptAllowPlaintextArchivingFlag = 0x00000008

	// BCRYPT ECC public blob magic.
	ecdsaPublicBlobMagic    = 0x31534345 // "ECS1"
	ecdsaP256CoordinateSize = 32

	// bcryptECCPublicBlob is BCRYPT_ECCPUBLIC_BLOB per Windows SDK.
	bcryptECCPublicBlob = "ECCPUBLICBLOB"
)

// daclSecurityInformation requests only the DACL portion of a security descriptor.
const daclSecurityInformation = 0x00000004

// SDDL security descriptor for machine-scoped CNG keys.
//
// Principals:
//
//	SY (SYSTEM):           GA  (GENERIC_ALL) — administrative/system access
//	BA (Administrators):   GA  (GENERIC_ALL) — administrative/repair access
//	LS (LOCAL SERVICE):    GRGX (GENERIC_READ | GENERIC_EXECUTE) — requested service access
//
// The Microsoft Software KSP may canonicalize the persisted generic mask. In
// manual Windows proof, the LOCAL SERVICE ACE persisted as GENERIC_READ only.
// Provisioning requests this restrictive DACL policy. Validation checks the
// required principals and rejects specific disallowed principals, but it does
// not establish an exclusive allow-list or fully evaluate owner, inheritance,
// every additional ACE, or Windows effective access. LOCAL SERVICE is a shared
// Windows service identity; this policy does not by itself isolate one LOCAL
// SERVICE process from another.
//
// The SDDL string requests no allow ACE for ordinary interactive users (no WD,
// AU, IU, BU ACE).
const keySecuritySDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;LS)"

// privilegedOnlySDDL is the protected DACL requested for PolicyPrivilegedOnly
// keys (for example a local CA key): SYSTEM and Administrators only, with no
// LOCAL SERVICE or any other allow ACE.
const privilegedOnlySDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

// The generic access masks and well-known SID strings used for structural ACL
// verification are declared in acl_constants.go so the platform-neutral
// descriptor classifier in sd.go can share them.

// aceHeader mirrors the ACE_HEADER from Windows SDK.
type aceHeader struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
}

// accessAllowedAce mirrors ACCESS_ALLOWED_ACE from Windows SDK.
type accessAllowedAce struct {
	Header aceHeader
	Mask   uint32
	// SidStart follows in memory.
}

// aclSizeInfo mirrors ACL_SIZE_INFORMATION from Windows SDK.
type aclSizeInfo struct {
	AceCount      uint32
	AclBytesInUse uint32
	AclBytesFree  uint32
}

var (
	// ncrypt.dll and advapi32.dll are bound from the system directory only;
	// see dll_windows.go.
	ncrypt                        = newSystemDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procNCryptCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procNCryptGetProperty         = ncrypt.NewProc("NCryptGetProperty")
	procNCryptFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procNCryptExportKey           = ncrypt.NewProc("NCryptExportKey")
	procNCryptSignHash            = ncrypt.NewProc("NCryptSignHash")
	procNCryptFreeObject          = ncrypt.NewProc("NCryptFreeObject")
	procNCryptDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")

	advapi32                                                 = newSystemDLL("advapi32.dll")
	procConvertStringSecurityDescriptorToSecurityDescriptorW = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSecurityDescriptorDacl                            = advapi32.NewProc("GetSecurityDescriptorDacl")
	procGetAclInformation                                    = advapi32.NewProc("GetAclInformation")
	procGetAce                                               = advapi32.NewProc("GetAce")
	procEqualSid                                             = advapi32.NewProc("EqualSid")
	procConvertStringSidToSidW                               = advapi32.NewProc("ConvertStringSidToSidW")
	procLocalFree                                            = kernel32.NewProc("LocalFree")
)

// msSoftwareKSP is the only KSP this package operates against.
const msSoftwareKSP = "Microsoft Software Key Storage Provider"

// ecdsaP256Algorithm is the NCrypt algorithm identifier used to create the
// ECDSA P-256 signing key.
const ecdsaP256Algorithm = "ECDSA_P256"

// deleteKeyOpenFlags are the NCryptOpenKey flags used when opening a key for
// deletion: machine scope with silent operation. No create fallback is used.
const deleteKeyOpenFlags = ncryptMachineKeyFlag | ncryptSilentFlag

// openKeyFlags are the NCryptOpenKey flags used when opening an existing key.
const openKeyFlags = ncryptMachineKeyFlag | ncryptSilentFlag

// Open opens the existing persisted machine-scoped key named name without
// creating a replacement. It returns an error wrapping ErrKeyNotFound when the
// native open reports the key as not found or not accessible (see
// ErrKeyNotFound), and another error for other open failures or when the key
// fails security validation. Successful Open means the key passed the
// validation implemented by this module; it is not a certification of the
// key's complete Windows effective-access policy.
func Open(name string) (Signer, error) {
	return openKey(name)
}

// LoadOrCreate first attempts to open the existing persisted machine-scoped key
// named name. After a successful native open, it returns a signer only if key
// validation and public-key loading also succeed. The key must be non-exportable,
// machine-scoped ECDSA P-256 in the Microsoft Software Key Storage Provider.
// If the native open operation fails, it attempts creation
// without first classifying every possible open failure as "not found". Callers
// that need to distinguish an absent key from an inaccessible or otherwise
// failing key should not treat LoadOrCreate as proof that the key was absent. If
// the subsequent creation attempt also fails, the returned error can describe
// that creation failure rather than the original open failure.
func LoadOrCreate(name string) (Signer, error) {
	return loadOrCreateKey(name)
}

// Delete removes exactly the persisted machine-scoped CNG key named name. It
// never creates a key and never performs wildcard/prefix enumeration or
// deletion. It returns an error wrapping ErrKeyNotFound when the native open
// reports the key as not found or not accessible, and deletes nothing. That
// means "nothing deleted by this call"; for no caller does it prove that the
// key was removed or is absent.
func Delete(name string) error {
	return deleteKey(name)
}

// deleteCNGKeyHandle enforces NCryptDeleteKey handle-ownership semantics using
// injected delete/free operations. It is a seam that isolates the ownership
// contract from the concrete NCrypt syscalls so it can be unit-tested.
//
// Contract:
//   - on success, the key handle is consumed by the delete call; free must NOT
//     be called again;
//   - on failure, the caller still owns the key handle and free IS called;
//   - a zero handle is a no-op.
func deleteCNGKeyHandle(keyHandle uintptr, deleteKey func(uintptr) error, freeKey func(uintptr)) error {
	if keyHandle == 0 {
		return nil
	}
	if err := deleteKey(keyHandle); err != nil {
		freeKey(keyHandle)
		return err
	}
	return nil
}

func openProvider() (uintptr, error) {
	if err := loadNativeAPIs(); err != nil {
		return 0, err
	}
	var provider uintptr
	r := ncryptStatus(procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&provider)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(msSoftwareKSP))),
		0,
	))
	if r != 0 {
		return 0, ncryptStatusError("NCryptOpenStorageProvider", r)
	}
	return provider, nil
}

// ncryptStatus returns the 32-bit SECURITY_STATUS of an NCrypt call from the
// results of Proc.Call, used as ncryptStatus(proc.Call(...)). Only the low 32
// bits of the return register are defined for a SECURITY_STATUS, so every
// status check and message must use this value, never the raw uintptr. The
// last error is discarded: NCrypt functions do not set it. The Go pointers
// stay converted inside the Call argument list, as the go:uintptrescapes
// contract of systemProc.Call requires.
func ncryptStatus(r, _ uintptr, _ error) uint32 {
	return uint32(r)
}

// ncryptStatusAndCallErr is ncryptStatus for a seam that also hands the
// Proc.Call last error to its caller.
func ncryptStatusAndCallErr(r, _ uintptr, err error) (uint32, error) {
	return uint32(r), err
}

// win32BOOL reports whether the Win32 BOOL returned by a call is TRUE, used as
// win32BOOL(proc.Call(...)). BOOL is a 32-bit int: only the low 32 bits of the
// return register are defined, zero is FALSE and any other value is TRUE.
func win32BOOL(r, _ uintptr, _ error) bool {
	return uint32(r) != 0
}

// win32BOOLAndCallErr is win32BOOL for a caller that also reports the
// Proc.Call last error, which a Win32 function returning FALSE sets.
func win32BOOLAndCallErr(r, _ uintptr, err error) (bool, error) {
	return uint32(r) != 0, err
}

// buildSecurityDescriptor converts an SDDL string into a self-relative
// security descriptor.
func buildSecurityDescriptor(sddlString string) ([]byte, error) {
	sddl, err := syscall.UTF16PtrFromString(sddlString)
	if err != nil {
		return nil, fmt.Errorf("convert SDDL: %w", err)
	}
	var sdPtr unsafe.Pointer
	var sdSize uint32
	ok, err := win32BOOLAndCallErr(procConvertStringSecurityDescriptorToSecurityDescriptorW.Call(
		uintptr(unsafe.Pointer(sddl)),
		1,
		uintptr(unsafe.Pointer(&sdPtr)),
		uintptr(unsafe.Pointer(&sdSize)),
	))
	if !ok {
		return nil, withCauses(fmt.Sprintf("ConvertStringSecurityDescriptorToSecurityDescriptorW: %v", err), win32Cause(err))
	}
	defer procLocalFree.Call(uintptr(sdPtr))
	out := make([]byte, sdSize)
	copy(out, unsafe.Slice((*byte)(sdPtr), sdSize))
	return out, nil
}

func convertStringSid(sidString string) (unsafe.Pointer, error) {
	sidU16, err := syscall.UTF16PtrFromString(sidString)
	if err != nil {
		return nil, fmt.Errorf("UTF16 encode SID %s: %w", sidString, err)
	}
	var sidPtr unsafe.Pointer
	ok, err := win32BOOLAndCallErr(procConvertStringSidToSidW.Call(
		uintptr(unsafe.Pointer(sidU16)),
		uintptr(unsafe.Pointer(&sidPtr)),
	))
	if !ok {
		return nil, withCauses(fmt.Sprintf("ConvertStringSidToSidW(%s): %v", sidString, err), win32Cause(err))
	}
	return sidPtr, nil
}

func aceSid(ace *accessAllowedAce) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(ace)) + unsafe.Offsetof(ace.Mask) + unsafe.Sizeof(ace.Mask))
}

// verifyDACL checks the required principals and rejects specific disallowed
// principals in the persisted DACL. It does not establish an exclusive
// allow-list or fully evaluate owner, inheritance, every additional ACE, or
// Windows effective access. It does not infer LOCAL SERVICE signing capability
// from a particular serialized generic execute bit.
func verifyDACL(keyHandle uintptr) error {
	buf, err := getSecurityDescriptor(keyHandle)
	if err != nil {
		return err
	}

	var daclPresent int32
	var daclDefaulted int32
	var daclPtr unsafe.Pointer
	// The last error is read only on failure, from the same Proc.Call.
	ok, callErr := win32BOOLAndCallErr(procGetSecurityDescriptorDacl.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&daclPresent)),
		uintptr(unsafe.Pointer(&daclPtr)),
		uintptr(unsafe.Pointer(&daclDefaulted)),
	))
	if !ok {
		return withCauses("GetSecurityDescriptorDacl failed", win32Cause(callErr))
	}
	if daclPresent == 0 || daclPtr == nil {
		return fmt.Errorf("persisted DACL is NULL — key has no access control")
	}

	var aclInfo aclSizeInfo
	ok, callErr = win32BOOLAndCallErr(procGetAclInformation.Call(
		uintptr(daclPtr),
		uintptr(unsafe.Pointer(&aclInfo)),
		uintptr(unsafe.Sizeof(aclInfo)),
		uintptr(aclSizeInfoClass),
	))
	if !ok {
		return withCauses("GetAclInformation failed", win32Cause(callErr))
	}
	if aclInfo.AceCount == 0 {
		return fmt.Errorf("persisted DACL has zero ACEs — key is inaccessible")
	}

	allocSid := func(sidStr string) (unsafe.Pointer, error) {
		return convertStringSid(sidStr)
	}
	freeSid := func(p unsafe.Pointer) {
		if p != nil {
			procLocalFree.Call(uintptr(p))
		}
	}

	sidSYSTEMp, err := allocSid(sidSYSTEM)
	if err != nil {
		return err
	}
	defer freeSid(sidSYSTEMp)
	sidAdminp, err := allocSid(sidAdministrators)
	if err != nil {
		return err
	}
	defer freeSid(sidAdminp)
	sidLSp, err := allocSid(sidLocalService)
	if err != nil {
		return err
	}
	defer freeSid(sidLSp)
	sidWDp, err := allocSid(sidEveryone)
	if err != nil {
		return err
	}
	defer freeSid(sidWDp)
	sidAUp, err := allocSid(sidAuthUsers)
	if err != nil {
		return err
	}
	defer freeSid(sidAUp)
	sidBUp, err := allocSid(sidBuiltinUsers)
	if err != nil {
		return err
	}
	defer freeSid(sidBUp)
	sidIUp, err := allocSid(sidInteractive)
	if err != nil {
		return err
	}
	defer freeSid(sidIUp)
	sidSUp, err := allocSid(sidService)
	if err != nil {
		return err
	}
	defer freeSid(sidSUp)
	sidANp, err := allocSid(sidAnonymous)
	if err != nil {
		return err
	}
	defer freeSid(sidANp)

	var foundSys, foundAdm, foundLS bool
	for i := uint32(0); i < aclInfo.AceCount; i++ {
		var acePtr unsafe.Pointer
		ok, callErr := win32BOOLAndCallErr(procGetAce.Call(
			uintptr(daclPtr),
			uintptr(i),
			uintptr(unsafe.Pointer(&acePtr)),
		))
		if !ok {
			return withCauses(fmt.Sprintf("GetAce(%d) failed", i), win32Cause(callErr))
		}

		ace := (*accessAllowedAce)(acePtr)
		if ace.Header.AceType != aceTypeAccessAllowed {
			continue
		}

		sid := aceSid(ace)
		generic := ace.Mask & genericRights

		if matchSid(sid, sidWDp) {
			return fmt.Errorf("persisted DACL contains forbidden allow ACE for Everyone")
		}
		if matchSid(sid, sidAUp) {
			return fmt.Errorf("persisted DACL contains forbidden allow ACE for Authenticated Users")
		}
		if matchSid(sid, sidBUp) {
			return fmt.Errorf("persisted DACL contains forbidden allow ACE for Built-in Users")
		}
		if matchSid(sid, sidIUp) {
			return fmt.Errorf("persisted DACL contains forbidden allow ACE for Interactive Users")
		}
		if matchSid(sid, sidSUp) {
			return fmt.Errorf("persisted DACL contains forbidden allow ACE for Service")
		}
		if matchSid(sid, sidANp) {
			return fmt.Errorf("persisted DACL contains forbidden allow ACE for Anonymous")
		}

		if matchSid(sid, sidSYSTEMp) {
			if foundSys {
				return fmt.Errorf("duplicate allow ACE for SYSTEM")
			}
			foundSys = true
			if generic&genericAll == 0 {
				return fmt.Errorf("SYSTEM ACE generic mask 0x%08X lacks GENERIC_ALL bit (0x%08X)", generic, genericAll)
			}
		}

		if matchSid(sid, sidAdminp) {
			if foundAdm {
				return fmt.Errorf("duplicate allow ACE for Administrators")
			}
			foundAdm = true
			if generic&genericAll == 0 {
				return fmt.Errorf("Administrators ACE generic mask 0x%08X lacks GENERIC_ALL bit (0x%08X)", generic, genericAll)
			}
		}

		if matchSid(sid, sidLSp) {
			if foundLS {
				return fmt.Errorf("duplicate allow ACE for LOCAL SERVICE")
			}
			foundLS = true
			// The Software KSP canonicalized the requested GR|GX ACE to GR in
			// the real Windows proof. Require GENERIC_READ and reject
			// GENERIC_WRITE and GENERIC_ALL. Other access-mask bits are not
			// checked here; effective open or signing access is not established.
			if generic&genericRead == 0 {
				return fmt.Errorf("LOCAL SERVICE ACE generic mask 0x%08X lacks GENERIC_READ", generic)
			}
			if generic&genericWrite != 0 || generic&genericAll != 0 {
				return fmt.Errorf("LOCAL SERVICE ACE generic mask 0x%08X grants administrative/write access", generic)
			}
		}
	}

	if !foundSys {
		return fmt.Errorf("persisted DACL missing expected allow ACE for SYSTEM")
	}
	if !foundAdm {
		return fmt.Errorf("persisted DACL missing expected allow ACE for Administrators")
	}
	if !foundLS {
		return fmt.Errorf("persisted DACL missing expected allow ACE for LOCAL SERVICE")
	}
	return nil
}

// getSecurityDescriptor reads the DACL portion of the persisted key's security
// descriptor as a self-relative SECURITY_DESCRIPTOR.
func getSecurityDescriptor(keyHandle uintptr) ([]byte, error) {
	var propLen uint32
	r := ncryptStatus(procNCryptGetProperty.Call(
		keyHandle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Security Descr"))),
		0, 0,
		uintptr(unsafe.Pointer(&propLen)),
		uintptr(daclSecurityInformation),
	))
	if r != 0 {
		return nil, withCauses(fmt.Sprintf("cannot read persisted security descriptor: hr=0x%x", r), &NCryptError{Op: "NCryptGetProperty", Code: r})
	}
	if propLen == 0 {
		return nil, fmt.Errorf("cannot read persisted security descriptor: reported size 0")
	}

	buf := make([]byte, propLen)
	r = ncryptStatus(procNCryptGetProperty.Call(
		keyHandle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Security Descr"))),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(propLen),
		uintptr(unsafe.Pointer(&propLen)),
		uintptr(daclSecurityInformation),
	))
	if r != 0 {
		return nil, ncryptStatusError("NCryptGetProperty(Security Descr)", r)
	}
	// Compare as uint64: int(propLen) would turn negative on 32-bit Windows
	// for sizes >= 0x80000000 and let the slice below panic.
	if uint64(propLen) > uint64(len(buf)) {
		return nil, fmt.Errorf("NCryptGetProperty(Security Descr): reported size %d exceeds buffer %d", propLen, len(buf))
	}
	return buf[:propLen], nil
}

// setSecurityDescriptor writes the DACL portion of sd to the persisted key.
func setSecurityDescriptor(keyHandle uintptr, sd []byte) error {
	r := ncryptStatus(procNCryptSetProperty.Call(
		keyHandle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Security Descr"))),
		uintptr(unsafe.Pointer(&sd[0])),
		uintptr(len(sd)),
		uintptr(daclSecurityInformation),
	))
	if r != 0 {
		return ncryptStatusError("set security descriptor", r)
	}
	return nil
}

func matchSid(s1, s2 unsafe.Pointer) bool {
	return win32BOOL(procEqualSid.Call(uintptr(s1), uintptr(s2)))
}

func verifyExportPolicy(keyHandle uintptr) error {
	var actualPolicy uint32
	var outLen uint32
	r := ncryptStatus(procNCryptGetProperty.Call(
		keyHandle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Export Policy"))),
		uintptr(unsafe.Pointer(&actualPolicy)),
		uintptr(unsafe.Sizeof(actualPolicy)),
		uintptr(unsafe.Pointer(&outLen)),
		uintptr(ncryptSilentFlag),
	))
	if r != 0 {
		return withCauses(fmt.Sprintf("cannot verify export policy: hr=0x%x", r), &NCryptError{Op: "NCryptGetProperty", Code: r})
	}
	forbidden := uint32(ncryptAllowExportFlag | ncryptAllowPlaintextExportFlag | ncryptAllowArchivingFlag | ncryptAllowPlaintextArchivingFlag)
	if actualPolicy&forbidden != 0 {
		return fmt.Errorf("export policy permits forbidden export/archiving (actual=0x%x)", actualPolicy)
	}
	return nil
}

func validatePersistedKey(keyHandle uintptr) error {
	if err := verifyExportPolicy(keyHandle); err != nil {
		return err
	}
	if err := verifyDACL(keyHandle); err != nil {
		return fmt.Errorf("persisted DACL verification failed: %w", err)
	}
	return nil
}

// deleteKeyHandle deletes an opened CNG key handle, enforcing NCryptDeleteKey
// handle-ownership semantics.
func deleteKeyHandle(keyHandle uintptr) error {
	return deleteCNGKeyHandle(keyHandle,
		func(h uintptr) error {
			r := ncryptStatus(procNCryptDeleteKey.Call(h, 0))
			if r != 0 {
				return ncryptStatusError("NCryptDeleteKey", r)
			}
			return nil
		},
		func(h uintptr) { procNCryptFreeObject.Call(h) },
	)
}

// deletePersistedKey deletes a key and obeys NCryptDeleteKey handle ownership:
// on success NCryptDeleteKey frees the key handle; on failure the caller still
// owns the handle and must free it explicitly. The delete error is returned,
// never discarded.
func deletePersistedKey(keyHandle uintptr) error {
	return deleteKeyHandle(keyHandle)
}

// cleanupCreatedKey deletes a key created by the current call after a later
// step failed with cause, and reports the cleanup outcome together with cause.
// A failed delete is joined as ErrCleanupFailed; nothing is retried, and no
// pre-existing key is ever deleted, overwritten or regenerated by this path.
func cleanupCreatedKey(cause error, deleteCreated func() error) error {
	if err := deleteCreated(); err != nil {
		return errors.Join(cause, fmt.Errorf("%w: %w", ErrCleanupFailed, err))
	}
	return fmt.Errorf("%w (the key created by this call was deleted)", cause)
}

// openKeyStatusError reports a failed NCryptOpenKey of the key name with the
// existing texts: "key <name>: NCryptOpenKey hr=0x..: <ErrKeyNotFound>" when
// IsKeyNotFound(r), else "NCryptOpenKey <name><label>: hr=0x..". The status
// is reachable as an NCryptError with Op "NCryptOpenKey", and the first form
// also wraps ErrKeyNotFound.
func openKeyStatusError(name string, r uint32, label string) error {
	status := &NCryptError{Op: "NCryptOpenKey", Code: r}
	if IsKeyNotFound(uintptr(r)) {
		return withCauses(fmt.Sprintf("key %q: NCryptOpenKey hr=0x%x: %v", name, r, ErrKeyNotFound), status, ErrKeyNotFound)
	}
	return withCauses(fmt.Sprintf("NCryptOpenKey %q%s: hr=0x%x", name, label, r), status)
}

// deleteKey deletes exactly one persisted CNG key by its exact name. It never
// creates a key and never performs wildcard/prefix deletion.
//
// NCryptDeleteKey handle ownership is preserved: on success the key handle has
// been freed by NCryptDeleteKey and must not be freed again; on failure the
// caller still owns the handle and frees it explicitly. The provider handle is
// always released.
func deleteKey(name string) error {
	provider, err := openProvider()
	if err != nil {
		return err
	}
	defer procNCryptFreeObject.Call(provider)

	nameUTF16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("convert key name: %w", err)
	}

	var keyHandle uintptr
	r := ncryptStatus(procNCryptOpenKey.Call(
		provider,
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(unsafe.Pointer(nameUTF16)),
		0,
		uintptr(deleteKeyOpenFlags),
	))
	if r != 0 {
		return openKeyStatusError(name, r, " (for delete)")
	}

	if err := deleteKeyHandle(keyHandle); err != nil {
		return fmt.Errorf("delete key %q: %w", name, err)
	}
	return nil
}

// legacyKeyOps is the set of native operations performed by Open and
// LoadOrCreate. Production code uses nativeLegacyKeyOps; unit tests inject a
// simulated backend so that the handle-ownership and cleanup control flow can
// be verified without touching any real persisted CNG key.
type legacyKeyOps interface {
	// openProvider opens the Microsoft Software KSP. The caller owns the
	// returned provider handle.
	openProvider() (uintptr, error)
	// openKey runs NCryptOpenKey for the exact name and returns the key
	// handle and the native 32-bit status (0 on success).
	openKey(provider uintptr, nameUTF16 *uint16) (keyHandle uintptr, hr uint32)
	// createKey creates and finalizes a new key without overwrite (see
	// createPersistedKey). On failure it has already released or deleted what
	// it created and returns a zero handle.
	createKey(provider uintptr, nameUTF16 *uint16) (uintptr, error)
	// validate checks the export policy and persisted DACL of a key handle.
	validate(keyHandle uintptr) error
	// newSigner exports the public key and builds a signer that owns provider
	// and keyHandle. On failure ownership of both handles stays with the caller.
	newSigner(provider, keyHandle uintptr, name string) (Signer, error)
	// deleteCreated deletes the key identified by keyHandle, with the handle
	// contract of deletePersistedKey: success consumes the handle, failure
	// frees it once. It never looks the key up by name.
	deleteCreated(keyHandle uintptr) error
	// free runs NCryptFreeObject on a provider or key handle.
	free(h uintptr)
}

// nativeLegacyKeyOps calls ncrypt.dll.
type nativeLegacyKeyOps struct{}

func (nativeLegacyKeyOps) openProvider() (uintptr, error) { return openProvider() }

func (nativeLegacyKeyOps) openKey(provider uintptr, nameUTF16 *uint16) (uintptr, uint32) {
	var keyHandle uintptr
	r := ncryptStatus(procNCryptOpenKey.Call(
		provider,
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(unsafe.Pointer(nameUTF16)),
		0,
		uintptr(openKeyFlags),
	))
	return keyHandle, r
}

func (nativeLegacyKeyOps) createKey(provider uintptr, nameUTF16 *uint16) (uintptr, error) {
	return createPersistedKey(provider, nameUTF16, keySecuritySDDL)
}

func (nativeLegacyKeyOps) validate(keyHandle uintptr) error {
	return validatePersistedKey(keyHandle)
}

func (nativeLegacyKeyOps) newSigner(provider, keyHandle uintptr, name string) (Signer, error) {
	s, err := newCNGSigner(provider, keyHandle, name)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (nativeLegacyKeyOps) deleteCreated(keyHandle uintptr) error {
	return deletePersistedKey(keyHandle)
}

func (nativeLegacyKeyOps) free(h uintptr) { procNCryptFreeObject.Call(h) }

// openKey opens an existing persisted key and never creates it.
// On successful return, the cngSigner owns both the provider and key handles.
func openKey(name string) (Signer, error) {
	return openKeyWith(nativeLegacyKeyOps{}, name)
}

func openKeyWith(ops legacyKeyOps, name string) (Signer, error) {
	provider, err := ops.openProvider()
	if err != nil {
		return nil, err
	}

	nameUTF16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		ops.free(provider)
		return nil, fmt.Errorf("convert key name: %w", err)
	}

	keyHandle, r := ops.openKey(provider, nameUTF16)
	if r != 0 {
		ops.free(provider)
		return nil, openKeyStatusError(name, r, "")
	}

	// Existing keys are security-sensitive state. Revalidate every time before
	// exposing a signer; proximity/name knowledge is not trust.
	if err := ops.validate(keyHandle); err != nil {
		ops.free(keyHandle)
		ops.free(provider)
		return nil, fmt.Errorf("existing key %s failed security validation: %w", name, err)
	}

	signer, err := ops.newSigner(provider, keyHandle, name)
	if err != nil {
		ops.free(keyHandle)
		ops.free(provider)
		return nil, err
	}
	return signer, nil
}

// loadOrCreateKey opens an existing persisted key or creates a new one.
// On successful return, the cngSigner owns both the provider and key handles.
func loadOrCreateKey(name string) (Signer, error) {
	return loadOrCreateKeyWith(nativeLegacyKeyOps{}, name)
}

func loadOrCreateKeyWith(ops legacyKeyOps, name string) (Signer, error) {
	provider, err := ops.openProvider()
	if err != nil {
		return nil, err
	}

	nameUTF16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		ops.free(provider)
		return nil, fmt.Errorf("convert key name: %w", err)
	}

	keyHandle, r := ops.openKey(provider, nameUTF16)
	if r == 0 {
		// Existing keys are security-sensitive state. Revalidate every time
		// before exposing a signer; proximity/name knowledge is not trust.
		// A key opened here was not created by this call: it is never deleted.
		if err := ops.validate(keyHandle); err != nil {
			ops.free(keyHandle)
			ops.free(provider)
			return nil, fmt.Errorf("existing key %s failed security validation: %w", name, err)
		}
		signer, err := ops.newSigner(provider, keyHandle, name)
		if err != nil {
			ops.free(keyHandle)
			ops.free(provider)
			return nil, err
		}
		return signer, nil
	}

	// createKey never overwrites: a successful return proves that this call
	// created the key behind keyHandle. On failure it has already handled its
	// own cleanup, and nothing else may be deleted here.
	keyHandle, err = ops.createKey(provider, nameUTF16)
	if err != nil {
		ops.free(provider)
		return nil, err
	}

	if err := ops.validate(keyHandle); err != nil {
		err = cleanupCreatedKey(err, func() error { return ops.deleteCreated(keyHandle) })
		ops.free(provider)
		return nil, fmt.Errorf("created key %q failed security validation: %w", name, err)
	}

	signer, err := ops.newSigner(provider, keyHandle, name)
	if err != nil {
		// The key was created by this call and the signer did not take the
		// handles: delete it through the same handle, never by name. The
		// delete consumes keyHandle on success and frees it on failure, so it
		// must not be freed again here; only the provider remains to release.
		err = cleanupCreatedKey(err, func() error { return ops.deleteCreated(keyHandle) })
		ops.free(provider)
		return nil, err
	}
	return signer, nil
}

// createKeyNative is the set of native operations performed by
// createPersistedKey. Production code uses nativeCreateKeyOps; unit tests
// inject a simulated backend so that the status handling, the rollback after a
// failed NCryptFinalizeKey and the key handle ownership can be verified
// without touching any real persisted CNG key. No operation looks a key up by
// name: the rollback only ever acts on the handle returned by the create.
type createKeyNative interface {
	// createPersisted runs NCryptCreatePersistedKey for an ECDSA P-256
	// machine key named nameUTF16, without NCRYPT_OVERWRITE_KEY_FLAG, and
	// returns the new key handle and the native 32-bit status.
	createPersisted(provider uintptr, nameUTF16 *uint16) (keyHandle uintptr, hr uint32)
	// setExportPolicyNone sets the "Export Policy" property to 0.
	setExportPolicyNone(keyHandle uintptr) (hr uint32)
	// setSecurityDescriptor builds the descriptor from sddl and writes it to
	// the not yet finalized key.
	setSecurityDescriptor(keyHandle uintptr, sddl string) error
	// finalize runs NCryptFinalizeKey.
	finalize(keyHandle uintptr) (hr uint32)
	// deleteKey runs NCryptDeleteKey. Success consumes the handle; on failure
	// the caller still owns it.
	deleteKey(keyHandle uintptr) (hr uint32)
	// free runs NCryptFreeObject on a key handle.
	free(keyHandle uintptr)
	// callerPrivileged reports whether the calling thread's token is SYSTEM
	// or an enabled member of the built-in Administrators group (see
	// nativeKeyStore.callerPrivileged). It is asked only by
	// cleanupAfterFinalizeFailure.
	callerPrivileged() (bool, error)
}

// nativeCreateKeyOps calls ncrypt.dll and advapi32.dll.
type nativeCreateKeyOps struct{}

func (nativeCreateKeyOps) createPersisted(provider uintptr, nameUTF16 *uint16) (uintptr, uint32) {
	var keyHandle uintptr
	r := ncryptStatus(procNCryptCreatePersistedKey.Call(
		provider,
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(ecdsaP256Algorithm))),
		uintptr(unsafe.Pointer(nameUTF16)),
		0,
		uintptr(ncryptMachineKeyFlag),
	))
	return keyHandle, r
}

func (nativeCreateKeyOps) setExportPolicyNone(keyHandle uintptr) uint32 {
	zero := uint32(0)
	return ncryptStatus(procNCryptSetProperty.Call(
		keyHandle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Export Policy"))),
		uintptr(unsafe.Pointer(&zero)),
		unsafe.Sizeof(zero),
		uintptr(ncryptSilentFlag),
	))
}

func (nativeCreateKeyOps) setSecurityDescriptor(keyHandle uintptr, sddl string) error {
	sd, err := buildSecurityDescriptor(sddl)
	if err != nil {
		return fmt.Errorf("build security descriptor: %w", err)
	}
	if err := setSecurityDescriptor(keyHandle, sd); err != nil {
		return fmt.Errorf("before finalize: %w", err)
	}
	return nil
}

func (nativeCreateKeyOps) finalize(keyHandle uintptr) uint32 {
	return ncryptStatus(procNCryptFinalizeKey.Call(keyHandle, 0))
}

func (nativeCreateKeyOps) deleteKey(keyHandle uintptr) uint32 {
	return ncryptStatus(procNCryptDeleteKey.Call(keyHandle, 0))
}

func (nativeCreateKeyOps) free(keyHandle uintptr) { procNCryptFreeObject.Call(keyHandle) }

func (nativeCreateKeyOps) callerPrivileged() (bool, error) {
	return nativeKeyStore{}.callerPrivileged()
}

// createPersistedKey creates a new non-exportable, machine-scoped ECDSA P-256
// key named nameUTF16, sets the DACL in sddl and only then finalizes it. It
// never sets NCRYPT_OVERWRITE_KEY_FLAG, so an existing key of the same name is
// not replaced. On failure it releases or deletes the key it created and
// returns a zero handle; see cleanupAfterFinalizeFailure for when a failed
// rollback wraps ErrCleanupFailed. The provider handle always remains owned by
// the caller. On success the caller owns the returned key handle.
func createPersistedKey(provider uintptr, nameUTF16 *uint16, sddl string) (uintptr, error) {
	return createPersistedKeyWith(nativeCreateKeyOps{}, provider, nameUTF16, sddl)
}

func createPersistedKeyWith(ops createKeyNative, provider uintptr, nameUTF16 *uint16, sddl string) (uintptr, error) {
	keyHandle, r := ops.createPersisted(provider, nameUTF16)
	if r != 0 {
		// Nothing was created by this call; a key of the same name that
		// already exists is reported here and is never touched.
		return 0, ncryptStatusError("NCryptCreatePersistedKey", r)
	}

	if r := ops.setExportPolicyNone(keyHandle); r != 0 {
		// Not finalized, therefore not persisted: releasing the handle is the
		// whole cleanup.
		ops.free(keyHandle)
		return 0, ncryptStatusError("set export policy", r)
	}

	// The DACL is set before NCryptFinalizeKey, so the key is persisted with it
	// and never carries the provider's default security descriptor; see
	// "Provisioning window" in docs/README.md. A failure up to and including
	// this write leaves nothing persisted: releasing the handle is the whole
	// cleanup. The callers validate the persisted DACL before returning a
	// signer, so a provider that did not apply it fails closed and the key is
	// deleted.
	if err := ops.setSecurityDescriptor(keyHandle, sddl); err != nil {
		ops.free(keyHandle)
		return 0, err
	}

	if r := ops.finalize(keyHandle); r != 0 {
		return 0, cleanupAfterFinalizeFailure(r, func() uint32 {
			// Same handle contract as deletePersistedKey: success consumes
			// the handle, failure leaves it to be freed exactly once.
			d := ops.deleteKey(keyHandle)
			if d != 0 {
				ops.free(keyHandle)
			}
			return d
		}, ops.callerPrivileged)
	}
	return keyHandle, nil
}

// finalizeFailureLeftNothingPersisted reports whether the pair of native
// statuses observed on one handle shows that a key created by
// createPersistedKey was never persisted, so that the failed rollback delete
// is not a cleanup failure. It is deliberately narrow and holds only on the
// path of createPersistedKey: Microsoft Software KSP, a handle created by the
// same call without NCRYPT_OVERWRITE_KEY_FLAG, NCryptFinalizeKey denied with
// NTE_PERM and NCryptDeleteKey on that same, never finalized handle reporting
// NTE_BAD_KEYSET. NTE_BAD_KEYSET is not treated as absence anywhere else: on
// an opened or finalized key it can also mean "not accessible" (see
// ErrKeyNotFound). Every other combination is reported as ErrCleanupFailed.
// cleanupAfterFinalizeFailure further requires a non-privileged caller.
func finalizeFailureLeftNothingPersisted(finalizeStatus, deleteStatus uint32) bool {
	return finalizeStatus == NTEPerm && deleteStatus == NTEBadKeyset
}

// cleanupAfterFinalizeFailure rolls back a key whose NCryptFinalizeKey failed
// with finalizeStatus. deleteCreated deletes the key through the handle
// returned by the create, never by name, and returns the native
// NCryptDeleteKey status. The finalize failure is always the reported cause:
//   - delete succeeded: the cause, noting that the key was deleted;
//   - the statuses match finalizeFailureLeftNothingPersisted and
//     callerPrivileged reports a non-privileged caller: the cause, noting that
//     the key was not persisted (it is not claimed to be deleted) and the
//     delete status, without ErrCleanupFailed;
//   - any other delete failure: the cause joined with ErrCleanupFailed and
//     the delete status, because the key may persist.
//
// The non-privileged condition is the case verified natively: an
// Administrator with a UAC-filtered token. For a privileged caller, NTE_PERM
// from the finalize has another, unobserved reason, and a privilege check
// that fails counts as privileged: both stay ErrCleanupFailed (fail closed).
// callerPrivileged is asked only when the statuses match.
//
// Nothing is retried. The paths after a successful finalize keep using
// cleanupCreatedKey, which reports every failed delete as ErrCleanupFailed.
func cleanupAfterFinalizeFailure(finalizeStatus uint32, deleteCreated func() uint32, callerPrivileged func() (bool, error)) error {
	cause := ncryptStatusError("NCryptFinalizeKey", finalizeStatus)
	deleteStatus := deleteCreated()
	if deleteStatus != 0 && finalizeFailureLeftNothingPersisted(finalizeStatus, deleteStatus) {
		if privileged, err := callerPrivileged(); err == nil && !privileged {
			return fmt.Errorf("%w (the key created by this call was not persisted; %w on its unfinalized handle)", cause, ncryptStatusError("NCryptDeleteKey", deleteStatus))
		}
	}
	return cleanupCreatedKey(cause, func() error {
		if deleteStatus != 0 {
			return ncryptStatusError("NCryptDeleteKey", deleteStatus)
		}
		return nil
	})
}

// errSignerClosed is returned by Sign on a closed signer: always once Close
// has returned, and for a Sign that the signer's lock orders after Close.
var errSignerClosed = errors.New("signer is closed")

// signerNative is the set of native operations a cngSigner performs on its
// handles. Production code uses nativeSignerOps; tests inject a simulated
// backend to drive Sign/Close interleavings deterministically.
type signerNative interface {
	// signHashSize runs NCryptSignHash without an output buffer to obtain
	// the signature size.
	signHashSize(key uintptr, digest []byte, size *uint32) (hr uint32, callErr error)
	// signHash runs NCryptSignHash into sig. sig is never empty.
	signHash(key uintptr, digest, sig []byte, size *uint32) (hr uint32, callErr error)
	// freeObject runs NCryptFreeObject on a provider or key handle.
	freeObject(h uintptr) (hr uint32)
}

// nativeSignerOps calls ncrypt.dll. Each Go pointer is converted to uintptr
// inside the Call argument list, as the go:uintptrescapes contract of
// systemProc.Call requires.
type nativeSignerOps struct{}

func (nativeSignerOps) signHashSize(key uintptr, digest []byte, size *uint32) (uint32, error) {
	return ncryptStatusAndCallErr(procNCryptSignHash.Call(
		key, 0,
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		0, 0,
		uintptr(unsafe.Pointer(size)),
		uintptr(ncryptSilentFlag),
	))
}

func (nativeSignerOps) signHash(key uintptr, digest, sig []byte, size *uint32) (uint32, error) {
	return ncryptStatusAndCallErr(procNCryptSignHash.Call(
		key, 0,
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(len(sig)),
		uintptr(unsafe.Pointer(size)),
		uintptr(ncryptSilentFlag),
	))
}

func (nativeSignerOps) freeObject(h uintptr) uint32 {
	return ncryptStatus(procNCryptFreeObject.Call(h))
}

// cngSigner implements Signer backed by a CNG persisted key.
//
// Concurrency (D3): mu guards the handles and the closed flag. Sign holds a
// read lock for its whole use of the key handle (state check and both
// NCryptSignHash calls), so concurrent Sign calls proceed in parallel. Close
// takes the write lock: it waits for every Sign already holding the read lock,
// and while it waits sync.RWMutex admits no new readers. It then marks the
// signer closed and makes at most one free attempt per handle. The lock orders
// overlapping calls: a Sign that acquires it before Close runs normally, a
// Sign that acquires it after Close fails with errSignerClosed without calling
// CNG, and every Sign fails that way once Close has returned.
type cngSigner struct {
	mu        sync.RWMutex
	closed    bool
	provider  uintptr
	key       uintptr
	name      string
	publicKey crypto.PublicKey
	native    signerNative // nil means nativeSignerOps
}

func newCNGSigner(provider, key uintptr, name string) (*cngSigner, error) {
	pub, err := exportPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("export public key for %s: %w", name, err)
	}
	return &cngSigner{provider: provider, key: key, name: name, publicKey: pub}, nil
}

func (s *cngSigner) ops() signerNative {
	if s.native != nil {
		return s.native
	}
	return nativeSignerOps{}
}

// Public returns the public key exported when the signer was built. It needs
// no handle and stays valid after Close.
func (s *cngSigner) Public() crypto.PublicKey { return s.publicKey }

// Sign signs digest with the CNG key. It is safe to call concurrently with
// other Sign calls and with Close on the same signer; see cngSigner for how
// overlapping calls are ordered.
func (s *cngSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed || s.key == 0 {
		return nil, errSignerClosed
	}
	if len(digest) == 0 {
		return nil, fmt.Errorf("digest is empty")
	}
	native := s.ops()

	var sigSize uint32
	// The second result of the native seam is the Proc.Call last error, which
	// NCryptSignHash does not set; only the returned status is reported.
	if r, _ := native.signHashSize(s.key, digest, &sigSize); r != 0 {
		return nil, ncryptStatusError("NCryptSignHash (query size)", r)
	}
	if sigSize == 0 {
		return nil, fmt.Errorf("NCryptSignHash (query size): reported size 0")
	}

	sigBuf := make([]byte, sigSize)
	if r, _ := native.signHash(s.key, digest, sigBuf, &sigSize); r != 0 {
		return nil, ncryptStatusError("NCryptSignHash", r)
	}
	// Compare as uint64: int(sigSize) would turn negative on 32-bit Windows
	// for sizes >= 0x80000000 and let the slice below panic.
	if uint64(sigSize) > uint64(len(sigBuf)) {
		return nil, fmt.Errorf("NCryptSignHash: reported size %d exceeds buffer %d", sigSize, len(sigBuf))
	}
	return p1363ToASN1(sigBuf[:sigSize])
}

// Close waits for Sign calls holding the lock, then attempts to release the
// key and provider handles. Each handle gets at most one free attempt, even if
// freeing fails: a handle is never retried, because a failed NCryptFreeObject
// leaves its state unknown. The first Close reports free failures; later calls
// return nil and make no further attempt.
func (s *cngSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	native := s.ops()

	var errs []error
	if s.key != 0 {
		if r := native.freeObject(s.key); r != 0 {
			errs = append(errs, withCauses(fmt.Sprintf("NCryptFreeObject (key %s): hr=0x%x", s.name, r), &NCryptError{Op: "NCryptFreeObject", Code: r}))
		}
		s.key = 0
	}
	if s.provider != 0 {
		if r := native.freeObject(s.provider); r != 0 {
			errs = append(errs, withCauses(fmt.Sprintf("NCryptFreeObject (provider): hr=0x%x", r), &NCryptError{Op: "NCryptFreeObject", Code: r}))
		}
		s.provider = 0
	}
	return errors.Join(errs...)
}

// ncryptExportFunc runs one NCryptExportKey of the ECC public blob of key and
// returns its SECURITY_STATUS (0 on success). With out == nil it is the size
// query (no output buffer, capacity 0); otherwise it fills out, whose length is
// the capacity. result receives the size reported by the call: the required
// size for the query, the number of bytes written for the fill.
type ncryptExportFunc func(key uintptr, out []byte, result *uint32) uint32

// nativeExportECCPublicBlob is the production ncryptExportFunc. Each Go
// pointer is converted to uintptr inside the Call argument list, as the
// go:uintptrescapes contract of systemProc.Call requires.
func nativeExportECCPublicBlob(key uintptr, out []byte, result *uint32) uint32 {
	if out == nil {
		return ncryptStatus(procNCryptExportKey.Call(
			key, 0,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(bcryptECCPublicBlob))),
			0, 0, 0,
			uintptr(unsafe.Pointer(result)), 0,
		))
	}
	return ncryptStatus(procNCryptExportKey.Call(
		key, 0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(bcryptECCPublicBlob))),
		0,
		uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)),
		uintptr(unsafe.Pointer(result)), 0,
	))
}

func exportPublicKey(key uintptr) (*ecdsa.PublicKey, error) {
	return exportPublicKeyWith(key, nativeExportECCPublicBlob)
}

// exportPublicKeyWith queries the size of the ECC public blob, fills a buffer
// of that capacity and parses only the bytes the fill reports as written.
// A nonzero status always wins and keeps its phase and code. A zero size from
// a successful query, and a fill that reports zero bytes or more bytes than
// the capacity, are returned as errors before the buffer is used. It never
// retries and never releases or deletes the key.
func exportPublicKeyWith(key uintptr, export ncryptExportFunc) (*ecdsa.PublicKey, error) {
	var queried uint32
	if r := export(key, nil, &queried); r != 0 {
		return nil, ncryptStatusError("NCryptExportKey (query size)", r)
	}
	if queried == 0 {
		return nil, fmt.Errorf("NCryptExportKey (query size): reported size 0")
	}

	blob := make([]byte, queried)
	var written uint32
	if r := export(key, blob, &written); r != 0 {
		return nil, ncryptStatusError("NCryptExportKey", r)
	}
	if written == 0 {
		return nil, fmt.Errorf("NCryptExportKey: reported 0 bytes written")
	}
	// Compare as uint64 before any conversion or slicing, so that the check
	// cannot overflow on 32-bit Windows.
	if uint64(written) > uint64(len(blob)) {
		return nil, fmt.Errorf("NCryptExportKey: reported %d bytes written, exceeds buffer %d", written, len(blob))
	}
	return parseECCPublicBlob(blob[:written])
}

func parseECCPublicBlob(blob []byte) (*ecdsa.PublicKey, error) {
	if len(blob) < 8 {
		return nil, fmt.Errorf("ECCPublicBlob too short")
	}
	magic := binary.LittleEndian.Uint32(blob[0:4])
	if magic != ecdsaPublicBlobMagic {
		return nil, fmt.Errorf("ECCPublicBlob magic = 0x%X, expected 0x%X", magic, ecdsaPublicBlobMagic)
	}
	cbKey := binary.LittleEndian.Uint32(blob[4:8])
	if cbKey != ecdsaP256CoordinateSize {
		return nil, fmt.Errorf("ECCPublicBlob cbKey = %d, expected %d", cbKey, ecdsaP256CoordinateSize)
	}
	if len(blob) < int(8+2*cbKey) {
		return nil, fmt.Errorf("ECCPublicBlob truncated")
	}

	X := new(big.Int).SetBytes(blob[8 : 8+cbKey])
	Y := new(big.Int).SetBytes(blob[8+cbKey : 8+2*cbKey])
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: X, Y: Y}
	if !pub.Curve.IsOnCurve(X, Y) {
		return nil, fmt.Errorf("ECCPublicBlob point is not on P-256 curve")
	}
	return pub, nil
}

func p1363ToASN1(sig []byte) ([]byte, error) {
	if len(sig) != 2*ecdsaP256CoordinateSize {
		return nil, fmt.Errorf("P1363 signature length = %d, expected %d", len(sig), 2*ecdsaP256CoordinateSize)
	}
	r := new(big.Int).SetBytes(sig[:ecdsaP256CoordinateSize])
	s := new(big.Int).SetBytes(sig[ecdsaP256CoordinateSize:])
	result, err := marshalECDSASig(r, s)
	if err != nil {
		return nil, fmt.Errorf("marshal ASN.1: %w", err)
	}
	return result, nil
}

func marshalECDSASig(r, s *big.Int) ([]byte, error) {
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	if len(rBytes) == 0 || len(sBytes) == 0 {
		return nil, fmt.Errorf("invalid zero ECDSA signature component")
	}
	if rBytes[0]&0x80 != 0 {
		rBytes = append([]byte{0x00}, rBytes...)
	}
	if sBytes[0]&0x80 != 0 {
		sBytes = append([]byte{0x00}, sBytes...)
	}

	totalLen := 2 + len(rBytes) + 2 + len(sBytes)
	var seqHeader []byte
	if totalLen < 128 {
		seqHeader = []byte{0x30, byte(totalLen)}
	} else {
		seqHeader = []byte{0x30, 0x81, byte(totalLen)}
	}

	out := make([]byte, 0, len(seqHeader)+totalLen)
	out = append(out, seqHeader...)
	out = append(out, 0x02, byte(len(rBytes)))
	out = append(out, rBytes...)
	out = append(out, 0x02, byte(len(sBytes)))
	out = append(out, sBytes...)
	return out, nil
}
