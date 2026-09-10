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
	"syscall"
	"unsafe"
)

// CNG flags and properties.
const (
	ncryptMachineKeyFlag   = 0x00000020
	ncryptSilentFlag       = 0x00000040
	ncryptAllowSigningFlag = 0x00000001

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
// Static DACL verification therefore proves the principal boundary and rejects
// administrative/write access; actual signing capability is proved behaviorally
// by running NCryptOpenKey + NCryptSignHash as LOCAL SERVICE.
//
// No access for ordinary interactive users (no WD, AU, IU, BU ACE).
const keySecuritySDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;LS)"

// Generic access rights masks — used for structural ACL verification.
const (
	genericAll     = 0x10000000                                               // GENERIC_ALL
	genericRead    = 0x80000000                                               // GENERIC_READ
	genericWrite   = 0x40000000                                               // GENERIC_WRITE
	genericExecute = 0x20000000                                               // GENERIC_EXECUTE
	genericRights  = genericAll | genericRead | genericWrite | genericExecute // extraction mask

	aceTypeAccessAllowed = 0 // ACCESS_ALLOWED_ACE_TYPE
	aclSizeInfoClass     = 2 // AclSizeInformation
)

// Well-known SID strings used as expected / forbidden principals during DACL walk.
const (
	sidSYSTEM         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
	sidLocalService   = "S-1-5-19"
	sidEveryone       = "S-1-1-0"
	sidAuthUsers      = "S-1-5-11"
	sidBuiltinUsers   = "S-1-5-32-545"
	sidInteractive    = "S-1-5-4"
	sidService        = "S-1-5-6"
	sidAnonymous      = "S-1-5-7"
)

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
	ncrypt                        = syscall.NewLazyDLL("ncrypt.dll")
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

	advapi32                                                 = syscall.NewLazyDLL("advapi32.dll")
	procConvertStringSecurityDescriptorToSecurityDescriptorW = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSecurityDescriptorDacl                            = advapi32.NewProc("GetSecurityDescriptorDacl")
	procGetAclInformation                                    = advapi32.NewProc("GetAclInformation")
	procGetAce                                               = advapi32.NewProc("GetAce")
	procEqualSid                                             = advapi32.NewProc("EqualSid")
	procConvertStringSidToSidW                               = advapi32.NewProc("ConvertStringSidToSidW")
	procLocalFree                                            = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")
)

// msSoftwareKSP is the only KSP this package operates against.
const msSoftwareKSP = "Microsoft Software Key Storage Provider"

// ecdsaP256Algorithm is the NCrypt algorithm identifier used to create the
// ECDSA P-256 signing key.
const ecdsaP256Algorithm = "ECDSA_P256"

// NTSTATUS/HRESULT values used to classify "key does not exist".
const (
	// nteNotFound is NTE_NOT_FOUND (0x8009000D): object was not found.
	nteNotFound = 0x8009000D
	// nteBadKeyset is NTE_BAD_KEYSET (0x80090016): the keyset does not exist.
	nteBadKeyset = 0x80090016
)

// deleteKeyOpenFlags are the NCryptOpenKey flags used when opening a key for
// deletion: machine scope with silent operation. No create fallback is used.
const deleteKeyOpenFlags = ncryptMachineKeyFlag | ncryptSilentFlag

// openKeyFlags are the NCryptOpenKey flags used when opening an existing key.
const openKeyFlags = ncryptMachineKeyFlag | ncryptSilentFlag

// ErrKeyNotFound indicates that the exact persisted CNG key does not exist. It
// is a sentinel so callers can treat an already-absent key as idempotent
// success during cleanup/reset.
var ErrKeyNotFound = errors.New("windowscng: persisted CNG key not found")

// IsKeyNotFound reports whether an NCrypt HRESULT indicates the exact persisted
// key does not exist (as opposed to an access or other failure). It classifies
// both NTE_NOT_FOUND and NTE_BAD_KEYSET.
func IsKeyNotFound(r uintptr) bool {
	hr := uint32(r)
	return hr == nteNotFound || hr == nteBadKeyset
}

// Open opens the existing persisted machine-scoped key named name without
// creating a replacement. It returns ErrKeyNotFound when the key does not exist
// and an error when the key exists but is inaccessible or fails security
// validation.
func Open(name string) (Signer, error) {
	return openKey(name)
}

// LoadOrCreate opens the existing persisted machine-scoped key named name, or
// creates it as a non-exportable, machine-scoped ECDSA P-256 signing key in the
// Microsoft Software Key Storage Provider if it does not yet exist.
//
// It never silently replaces an existing incompatible or inaccessible key.
func LoadOrCreate(name string) (Signer, error) {
	return loadOrCreateKey(name)
}

// Delete removes exactly the persisted machine-scoped CNG key named name. It
// never creates a key and never performs wildcard/prefix enumeration or
// deletion. It returns ErrKeyNotFound when the key is already absent, allowing
// idempotent cleanup.
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
	var provider uintptr
	r, _, err := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&provider)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(msSoftwareKSP))),
		0,
	)
	if r != 0 {
		return 0, fmt.Errorf("NCryptOpenStorageProvider: hr=0x%x %v", r, err)
	}
	return provider, nil
}

func buildSDDL() ([]byte, error) {
	sddl, err := syscall.UTF16PtrFromString(keySecuritySDDL)
	if err != nil {
		return nil, fmt.Errorf("convert SDDL: %w", err)
	}
	var sdPtr unsafe.Pointer
	var sdSize uint32
	r, _, err := procConvertStringSecurityDescriptorToSecurityDescriptorW.Call(
		uintptr(unsafe.Pointer(sddl)),
		1,
		uintptr(unsafe.Pointer(&sdPtr)),
		uintptr(unsafe.Pointer(&sdSize)),
	)
	if r == 0 {
		return nil, fmt.Errorf("ConvertStringSecurityDescriptorToSecurityDescriptorW: %v", err)
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
	r, _, err := procConvertStringSidToSidW.Call(
		uintptr(unsafe.Pointer(sidU16)),
		uintptr(unsafe.Pointer(&sidPtr)),
	)
	if r == 0 {
		return nil, fmt.Errorf("ConvertStringSidToSidW(%s): %v", sidString, err)
	}
	return sidPtr, nil
}

func aceSid(ace *accessAllowedAce) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(ace)) + unsafe.Offsetof(ace.Mask) + unsafe.Sizeof(ace.Mask))
}

// verifyDACL proves the persisted principal boundary structurally. It does not
// infer LOCAL SERVICE signing capability from a particular serialized generic
// execute bit; that capability is verified by the LocalService behavioral test.
func verifyDACL(keyHandle uintptr) error {
	var propLen uint32
	r, _, _ := procNCryptGetProperty.Call(
		keyHandle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Security Descr"))),
		0, 0,
		uintptr(unsafe.Pointer(&propLen)),
		uintptr(daclSecurityInformation),
	)
	if r != 0 || propLen == 0 {
		return fmt.Errorf("cannot read persisted security descriptor: hr=0x%x", r)
	}

	buf := make([]byte, propLen)
	r, _, _ = procNCryptGetProperty.Call(
		keyHandle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Security Descr"))),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(propLen),
		uintptr(unsafe.Pointer(&propLen)),
		uintptr(daclSecurityInformation),
	)
	if r != 0 {
		return fmt.Errorf("NCryptGetProperty(Security Descr): hr=0x%x", r)
	}

	var daclPresent int32
	var daclDefaulted int32
	var daclPtr unsafe.Pointer
	ret, _, _ := procGetSecurityDescriptorDacl.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&daclPresent)),
		uintptr(unsafe.Pointer(&daclPtr)),
		uintptr(unsafe.Pointer(&daclDefaulted)),
	)
	if ret == 0 {
		return fmt.Errorf("GetSecurityDescriptorDacl failed")
	}
	if daclPresent == 0 || daclPtr == nil {
		return fmt.Errorf("persisted DACL is NULL — key has no access control")
	}

	var aclInfo aclSizeInfo
	ret, _, _ = procGetAclInformation.Call(
		uintptr(daclPtr),
		uintptr(unsafe.Pointer(&aclInfo)),
		uintptr(unsafe.Sizeof(aclInfo)),
		uintptr(aclSizeInfoClass),
	)
	if ret == 0 {
		return fmt.Errorf("GetAclInformation failed")
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
		ret, _, _ := procGetAce.Call(
			uintptr(daclPtr),
			uintptr(i),
			uintptr(unsafe.Pointer(&acePtr)),
		)
		if ret == 0 {
			return fmt.Errorf("GetAce(%d) failed", i)
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
			// the real Windows proof. Require read/open capability, and reject
			// administrative/write capability. Signing is proved behaviorally.
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

func matchSid(s1, s2 unsafe.Pointer) bool {
	r, _, _ := procEqualSid.Call(uintptr(s1), uintptr(s2))
	return r != 0
}

func verifyExportPolicy(keyHandle uintptr) error {
	var actualPolicy uint32
	var outLen uint32
	r, _, _ := procNCryptGetProperty.Call(
		keyHandle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Export Policy"))),
		uintptr(unsafe.Pointer(&actualPolicy)),
		uintptr(unsafe.Sizeof(actualPolicy)),
		uintptr(unsafe.Pointer(&outLen)),
		uintptr(ncryptSilentFlag),
	)
	if r != 0 {
		return fmt.Errorf("cannot verify export policy: hr=0x%x", r)
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
			r, _, _ := procNCryptDeleteKey.Call(h, 0)
			if r != 0 {
				return fmt.Errorf("NCryptDeleteKey: hr=0x%x", r)
			}
			return nil
		},
		func(h uintptr) { procNCryptFreeObject.Call(h) },
	)
}

// deletePersistedKey deletes a key and obeys NCryptDeleteKey handle ownership:
// on success NCryptDeleteKey frees the key handle; on failure the caller still
// owns the handle and must free it explicitly.
func deletePersistedKey(keyHandle uintptr) {
	_ = deleteKeyHandle(keyHandle)
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
	r, _, _ := procNCryptOpenKey.Call(
		provider,
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(unsafe.Pointer(nameUTF16)),
		0,
		uintptr(deleteKeyOpenFlags),
	)
	if r != 0 {
		if IsKeyNotFound(r) {
			return fmt.Errorf("key %q: %w", name, ErrKeyNotFound)
		}
		return fmt.Errorf("NCryptOpenKey %q (for delete): hr=0x%x", name, r)
	}

	if err := deleteKeyHandle(keyHandle); err != nil {
		return fmt.Errorf("delete key %q: %w", name, err)
	}
	return nil
}

// openKey opens an existing persisted key and never creates it.
// On successful return, the cngSigner owns both the provider and key handles.
func openKey(name string) (Signer, error) {
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
			return nil, fmt.Errorf("key %q: %w", name, ErrKeyNotFound)
		}
		return nil, fmt.Errorf("NCryptOpenKey %q: hr=0x%x", name, r)
	}

	// Existing keys are security-sensitive state. Revalidate every time before
	// exposing a signer; proximity/name knowledge is not trust.
	if err := validatePersistedKey(keyHandle); err != nil {
		procNCryptFreeObject.Call(keyHandle)
		procNCryptFreeObject.Call(provider)
		return nil, fmt.Errorf("existing key %s failed security validation: %w", name, err)
	}

	signer, err := newCNGSigner(provider, keyHandle, name)
	if err != nil {
		procNCryptFreeObject.Call(keyHandle)
		procNCryptFreeObject.Call(provider)
		return nil, err
	}
	return signer, nil
}

// loadOrCreateKey opens an existing persisted key or creates a new one.
// On successful return, the cngSigner owns both the provider and key handles.
func loadOrCreateKey(name string) (Signer, error) {
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
	if r == 0 {
		// Existing keys are security-sensitive state. Revalidate every time
		// before exposing a signer; proximity/name knowledge is not trust.
		if err := validatePersistedKey(keyHandle); err != nil {
			procNCryptFreeObject.Call(keyHandle)
			procNCryptFreeObject.Call(provider)
			return nil, fmt.Errorf("existing key %s failed security validation: %w", name, err)
		}
		signer, err := newCNGSigner(provider, keyHandle, name)
		if err != nil {
			procNCryptFreeObject.Call(keyHandle)
			procNCryptFreeObject.Call(provider)
			return nil, err
		}
		return signer, nil
	}

	r, _, err = procNCryptCreatePersistedKey.Call(
		provider,
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(ecdsaP256Algorithm))),
		uintptr(unsafe.Pointer(nameUTF16)),
		0,
		uintptr(ncryptMachineKeyFlag),
	)
	if r != 0 {
		procNCryptFreeObject.Call(provider)
		return nil, fmt.Errorf("NCryptCreatePersistedKey: hr=0x%x %v", r, err)
	}

	zero := uint32(0)
	r, _, err = procNCryptSetProperty.Call(
		keyHandle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Export Policy"))),
		uintptr(unsafe.Pointer(&zero)),
		unsafe.Sizeof(zero),
		uintptr(ncryptSilentFlag),
	)
	if r != 0 {
		procNCryptFreeObject.Call(keyHandle)
		procNCryptFreeObject.Call(provider)
		return nil, fmt.Errorf("set export policy: hr=0x%x %v", r, err)
	}

	r, _, err = procNCryptFinalizeKey.Call(keyHandle, 0)
	if r != 0 {
		deletePersistedKey(keyHandle)
		procNCryptFreeObject.Call(provider)
		return nil, fmt.Errorf("NCryptFinalizeKey: hr=0x%x %v", r, err)
	}

	sd, err := buildSDDL()
	if err != nil {
		deletePersistedKey(keyHandle)
		procNCryptFreeObject.Call(provider)
		return nil, fmt.Errorf("build security descriptor: %w", err)
	}
	r, _, err = procNCryptSetProperty.Call(
		keyHandle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Security Descr"))),
		uintptr(unsafe.Pointer(&sd[0])),
		uintptr(len(sd)),
		uintptr(daclSecurityInformation),
	)
	if r != 0 {
		deletePersistedKey(keyHandle)
		procNCryptFreeObject.Call(provider)
		return nil, fmt.Errorf("set security descriptor: hr=0x%x %v", r, err)
	}

	if err := validatePersistedKey(keyHandle); err != nil {
		deletePersistedKey(keyHandle)
		procNCryptFreeObject.Call(provider)
		return nil, err
	}

	signer, err := newCNGSigner(provider, keyHandle, name)
	if err != nil {
		procNCryptFreeObject.Call(keyHandle)
		procNCryptFreeObject.Call(provider)
		return nil, err
	}
	return signer, nil
}

// cngSigner implements Signer backed by a CNG persisted key.
type cngSigner struct {
	provider  uintptr
	key       uintptr
	name      string
	publicKey crypto.PublicKey
}

func newCNGSigner(provider, key uintptr, name string) (*cngSigner, error) {
	pub, err := exportPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("export public key for %s: %w", name, err)
	}
	return &cngSigner{provider: provider, key: key, name: name, publicKey: pub}, nil
}

func (s *cngSigner) Public() crypto.PublicKey { return s.publicKey }

func (s *cngSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if s.key == 0 {
		return nil, fmt.Errorf("signer is closed")
	}
	if len(digest) == 0 {
		return nil, fmt.Errorf("digest is empty")
	}

	var sigSize uint32
	r, _, err := procNCryptSignHash.Call(
		s.key, 0,
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		0, 0,
		uintptr(unsafe.Pointer(&sigSize)),
		uintptr(ncryptSilentFlag),
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash (query size): hr=0x%x %v", r, err)
	}

	sigBuf := make([]byte, sigSize)
	r, _, err = procNCryptSignHash.Call(
		s.key, 0,
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sigBuf[0])), uintptr(sigSize),
		uintptr(unsafe.Pointer(&sigSize)),
		uintptr(ncryptSilentFlag),
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash: hr=0x%x %v", r, err)
	}
	return p1363ToASN1(sigBuf)
}

func (s *cngSigner) Close() error {
	if s.key != 0 {
		procNCryptFreeObject.Call(s.key)
		s.key = 0
	}
	if s.provider != 0 {
		procNCryptFreeObject.Call(s.provider)
		s.provider = 0
	}
	return nil
}

func exportPublicKey(key uintptr) (*ecdsa.PublicKey, error) {
	var blobSize uint32
	r, _, _ := procNCryptExportKey.Call(
		key, 0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(bcryptECCPublicBlob))),
		0, 0, 0,
		uintptr(unsafe.Pointer(&blobSize)), 0,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey (query size): hr=0x%x", r)
	}

	blob := make([]byte, blobSize)
	r, _, _ = procNCryptExportKey.Call(
		key, 0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(bcryptECCPublicBlob))),
		0,
		uintptr(unsafe.Pointer(&blob[0])), uintptr(blobSize),
		uintptr(unsafe.Pointer(&blobSize)), 0,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey: hr=0x%x", r)
	}
	return parseECCPublicBlob(blob)
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
