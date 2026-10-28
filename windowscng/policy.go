package windowscng

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Policy selects the access-control policy of a persisted machine-scoped key
// for the policy-aware functions OpenWithPolicy, LoadOrCreateWithPolicy and
// ApplyPolicy. The legacy Open, LoadOrCreate and Delete functions are not
// affected by Policy and keep their existing behavior.
//
// The zero value is not a valid policy; callers must choose one explicitly.
type Policy int

const (
	// PolicyServiceSigner is the policy provisioned by LoadOrCreate: a
	// protected DACL granting SYSTEM and Administrators GENERIC_ALL and LOCAL
	// SERVICE GENERIC_READ|GENERIC_EXECUTE, so that a LOCAL SERVICE runtime can
	// open the key and sign.
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
// state required by the requested Policy, or that a requested policy change is
// not a permitted transition. The key was not modified.
var ErrPolicyMismatch = errors.New("windowscng: persisted key does not match the requested policy")

// ErrPrivilegeRequired indicates that the operation requires the calling
// thread's token to be SYSTEM or an enabled (elevated) member of the built-in
// Administrators group, and the caller is not, or that this could not be
// established. No key was opened, created or modified on that basis.
var ErrPrivilegeRequired = errors.New("windowscng: operation requires a privileged (SYSTEM or elevated Administrators) caller")

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
