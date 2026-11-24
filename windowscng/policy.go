package windowscng

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// KeyPolicy is the access policy of a persisted machine-scoped key, the
// policy argument of Open, Create, Delete and Apply. Its only valid values are
// a Policy (PolicyServiceSigner or PolicyPrivilegedOnly) and a ServicePolicy
// built by NewServicePolicy, passed by value.
//
// The unexported method keeps other packages from declaring their own
// policies, but a type that embeds Policy or ServicePolicy would still satisfy
// the interface. Every function therefore accepts only the concrete values
// Policy and ServicePolicy and rejects anything else (nil, a pointer, even a
// typed nil one, or any other dynamic type) with an input error, before any
// native call and without panicking. The zero values Policy(0) and
// ServicePolicy{} are not valid policies.
type KeyPolicy interface {
	isKeyPolicy()
}

func (Policy) isKeyPolicy()        {}
func (ServicePolicy) isKeyPolicy() {}

// Policy selects one of the two fixed access-control policies of a persisted
// machine-scoped key. It is a KeyPolicy; ServicePolicy is the other one.
//
// The zero value is not a valid policy; callers must choose one explicitly.
type Policy int

const (
	// PolicyServiceSigner is a protected DACL granting SYSTEM and
	// Administrators GENERIC_ALL and LOCAL SERVICE
	// GENERIC_READ|GENERIC_EXECUTE, so that a LOCAL SERVICE runtime can open
	// the key and sign. It is the DACL that every release before v0.5.0
	// requested for the keys created by the removed LoadOrCreate.
	//
	//	D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;LS)
	PolicyServiceSigner Policy = iota + 1

	// PolicyPrivilegedOnly is a protected DACL granting only SYSTEM and
	// Administrators GENERIC_ALL, with no LOCAL SERVICE or other allow ACE. It
	// is intended for keys, such as a local CA key, that only privileged
	// provisioning code may use.
	//
	//	D:P(A;;GA;;;SY)(A;;GA;;;BA)
	PolicyPrivilegedOnly
)

// String returns a stable, human-readable policy name.
func (p Policy) String() string {
	switch p {
	case PolicyServiceSigner:
		return "service-signer"
	case PolicyPrivilegedOnly:
		return "privileged-only"
	default:
		return fmt.Sprintf("Policy(%d)", int(p))
	}
}

// ErrPolicyMismatch indicates that a persisted key's DACL is not exactly in the
// state required by the requested KeyPolicy, that its public key is not a
// valid ECDSA P-256 key, or that a requested policy change is not a permitted
// transition. A failure to read the DACL or the export policy is reported as
// its own error, not as ErrPolicyMismatch.
//
// No pre-existing key was modified: Open never writes, Apply returns it only
// before writing (a failure after the write is ErrPostWriteVerification), and
// Delete returns it together with ErrDeleteVerificationFailed without
// deleting anything. Create also returns it when the key it just created does
// not hold the policy: that key is then deleted through the same handle, or,
// if the delete fails, the error also wraps ErrCleanupFailed and the new key
// may persist.
var ErrPolicyMismatch = errors.New("windowscng: persisted key does not match the requested policy")

// ErrPrivilegeRequired indicates that the operation requires the calling
// thread's token to be SYSTEM or an enabled (elevated) member of the built-in
// Administrators group, and the caller is not, or that this could not be
// established. No key was opened, created or modified on that basis.
var ErrPrivilegeRequired = errors.New("windowscng: operation requires a privileged (SYSTEM or elevated Administrators) caller")

// ErrKeyExists indicates that Create found a persisted key with the requested
// name: NCryptCreatePersistedKey, called without NCRYPT_OVERWRITE_KEY_FLAG,
// reported NTE_EXISTS. The existing key was not opened, adopted, modified or
// deleted, and no signer is returned. The native status stays reachable as an
// *NCryptError with Code NTEExists. Only the status of that create call
// produces it, never the same status from a later step, and no other function
// returns it. It covers only a key already persisted under the name: it does
// not reserve the name against a concurrent creator.
var ErrKeyExists = errors.New("windowscng: a persisted CNG key with this name already exists")

// ErrDeleteVerificationFailed indicates that Delete opened the key but did not
// delete it, because a check on that open handle did not pass or could not be
// completed: the key is exportable, is not a valid ECDSA P-256 key, its DACL
// is not exactly the requested KeyPolicy form, or its public key differs from
// the expected SubjectPublicKeyInfo. Nothing was deleted or modified.
// ErrPolicyMismatch is also wrapped when the cause is a policy mismatch, and
// native causes stay reachable with errors.As.
var ErrDeleteVerificationFailed = errors.New("windowscng: key verification failed before delete; nothing was deleted")

// validate rejects the zero value and any undefined Policy.
func (p Policy) validate() error {
	switch p {
	case PolicyServiceSigner, PolicyPrivilegedOnly:
		return nil
	default:
		return fmt.Errorf("windowscng: invalid policy %v", p)
	}
}

// state maps a valid Policy to the DACL state that satisfies it.
func (p Policy) state() daclState {
	switch p {
	case PolicyServiceSigner:
		return daclServiceSigner
	case PolicyPrivilegedOnly:
		return daclPrivilegedOnly
	default:
		return daclUnknown
	}
}

// ServicePolicy is the per-key access policy for a signing key that exactly
// one Windows service may use: a protected DACL granting SYSTEM and
// Administrators GENERIC_ALL and the service's own per-service SID
// (NT SERVICE\<name>, S-1-5-80-...) GENERIC_READ|GENERIC_EXECUTE. Unlike
// PolicyServiceSigner it grants nothing to LOCAL SERVICE as a whole, so other
// services running as LOCAL SERVICE get no access through the DACL.
//
//	D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;S-1-5-80-...)
//
// The service must run with its service SID enabled in its token
// (SERVICE_SID_TYPE_UNRESTRICTED or SERVICE_SID_TYPE_RESTRICTED); with
// SERVICE_SID_TYPE_NONE the SID is absent and the key cannot be used. The zero
// value is not valid; use NewServicePolicy.
type ServicePolicy struct {
	name string
	sid  string
}

// NewServicePolicy returns the ServicePolicy for the Windows service named
// serviceName. The service SID is derived from the name with the documented
// Windows algorithm (see ServiceSID); the service does not need to exist yet.
func NewServicePolicy(serviceName string) (ServicePolicy, error) {
	sid, err := ServiceSID(serviceName)
	if err != nil {
		return ServicePolicy{}, err
	}
	return ServicePolicy{name: serviceName, sid: sid}, nil
}

// ServiceName returns the service name the policy was built for.
func (p ServicePolicy) ServiceName() string { return p.name }

// SID returns the per-service SID the policy grants.
func (p ServicePolicy) SID() string { return p.sid }

// String returns a stable, human-readable policy name.
func (p ServicePolicy) String() string {
	return "service-sid(" + p.name + "=" + p.sid + ")"
}

// validate rejects the zero value and any value not built by NewServicePolicy.
func (p ServicePolicy) validate() error {
	if want, err := ServiceSID(p.name); err != nil || want != p.sid {
		return fmt.Errorf("windowscng: invalid service policy %v", p)
	}
	return nil
}

// sddl returns the protected DACL requested for p.
func (p ServicePolicy) sddl() string {
	return "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;" + p.sid + ")"
}

// maxServiceNameLen is the SCM limit on service name length.
const maxServiceNameLen = 256

// ServiceSID returns the per-service SID (S-1-5-80-x-x-x-x-x) that Windows
// assigns to the service named serviceName: the SHA-1 digest of the
// upper-cased UTF-16LE name, read as five little-endian 32-bit
// sub-authorities. The computation is local and does not require the service
// to exist.
//
// To keep the upper-casing unambiguous, only names of 1 to 256 characters from
// [A-Za-z0-9_.-] are accepted; anything else is an error.
func ServiceSID(serviceName string) (string, error) {
	if serviceName == "" || len(serviceName) > maxServiceNameLen {
		return "", fmt.Errorf("windowscng: service name length %d out of range 1..%d", len(serviceName), maxServiceNameLen)
	}
	b := make([]byte, 0, 2*len(serviceName))
	for i := 0; i < len(serviceName); i++ {
		c := serviceName[i]
		switch {
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '.', c == '-':
		default:
			return "", fmt.Errorf("windowscng: service name %q contains unsupported character %q", serviceName, serviceName[i])
		}
		b = append(b, c, 0)
	}
	sum := sha1.Sum(b)
	var sb strings.Builder
	sb.WriteString("S-1-5-80")
	for i := 0; i < 5; i++ {
		sb.WriteByte('-')
		sb.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(sum[4*i:])), 10))
	}
	return sb.String(), nil
}
