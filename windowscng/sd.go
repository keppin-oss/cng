package windowscng

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// This file implements a strict, platform-neutral parser and classifier for the
// self-relative SECURITY_DESCRIPTOR returned by NCryptGetProperty("Security
// Descr", DACL_SECURITY_INFORMATION). It is pure Go so that the per-key policy
// decision can be unit-tested without touching a persisted CNG key.
//
// The classifier is an exact-match allow-list: a descriptor is recognized only
// if its DACL is byte-for-byte one of the forms this package provisions (modulo
// ACE order and the explicitly allow-listed KSP mask representations). Anything
// else, including forms that might be "safe enough", is reported as unknown so
// that callers fail closed.

// Security descriptor control bits (SECURITY_DESCRIPTOR_CONTROL).
const (
	seDACLPresent   = 0x0004 // SE_DACL_PRESENT
	seDACLProtected = 0x1000 // SE_DACL_PROTECTED
	seSelfRelative  = 0x8000 // SE_SELF_RELATIVE
)

// ACL revisions accepted for the DACL.
const (
	aclRevision   = 2 // ACL_REVISION
	aclRevisionDS = 4 // ACL_REVISION_DS
)

const (
	sdHeaderSize  = 20 // self-relative SECURITY_DESCRIPTOR header
	aclHeaderSize = 8  // ACL header
	aceFixedSize  = 8  // ACE_HEADER + ACCESS_MASK
	sidRevision   = 1  // SID_REVISION
	sidMaxSubAuth = 15 // SID_MAX_SUB_AUTHORITIES
)

// Exact persisted access masks recognized by the classifier.
const (
	// maskAdministrative is the GENERIC_ALL requested for SYSTEM/Administrators.
	maskAdministrative = genericAll
	// maskAdministrativeKSP is the exact representation the Microsoft Software
	// KSP was observed to persist for SYSTEM and Administrators in native
	// testing. It retains GA and adds GR|GW|0x001F01FF, rights already covered
	// by full control. Allow this same exact representation for the two
	// administrative principals only.
	// Do not replace this allow-list with a GA-bit or generic-mapping test.
	maskAdministrativeKSP = 0xD01F01FF
	// maskLocalServiceRequested is the GENERIC_READ|GENERIC_EXECUTE mask this
	// package requests for LOCAL SERVICE.
	maskLocalServiceRequested = genericRead | genericExecute
	// maskLocalServiceCanonical is the GENERIC_READ-only form observed after
	// Microsoft Software KSP canonicalization in a manual Windows proof.
	maskLocalServiceCanonical = genericRead
	// maskLocalServiceKSP is the exact LOCAL SERVICE form observed in native
	// testing on a key persisted by the Microsoft Software KSP: GR plus
	// FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, without write, DELETE,
	// WRITE_DAC or WRITE_OWNER.
	// Keep the other two forms; do not generalize to other masks/principals.
	maskLocalServiceKSP = 0x801200A9
	// maskServiceRequested is the GENERIC_READ|GENERIC_EXECUTE mask this
	// package requests for the service SID of a ServicePolicy.
	maskServiceRequested = genericRead | genericExecute
	// maskServiceKSP is the exact service-SID form observed in native testing
	// in a DACL persisted by the Microsoft Software KSP: GR |
	// FILE_GENERIC_READ | FILE_GENERIC_EXECUTE. No write, DELETE, WRITE_DAC or
	// WRITE_OWNER rights.
	// Allow only this value or the requested mask, only for a service SID.
	// LOCAL SERVICE's GR-only form remains invalid for a service SID.
	maskServiceKSP = 0x801200A9
)

// errDescriptorUnrecognized marks a descriptor that does not match any known
// policy state. It is always wrapped with a specific reason.
var errDescriptorUnrecognized = errors.New("unrecognized security descriptor")

// daclState is the result of classifying a persisted DACL.
type daclState int

const (
	daclUnknown daclState = iota
	daclServiceSigner
	daclPrivilegedOnly
	daclServiceSID
)

func (s daclState) String() string {
	switch s {
	case daclServiceSigner:
		return "service-signer"
	case daclPrivilegedOnly:
		return "privileged-only"
	case daclServiceSID:
		return "service-sid"
	default:
		return "unknown"
	}
}

// parsedACE is one access-allowed ACE from a parsed DACL.
type parsedACE struct {
	aceType  byte
	aceFlags byte
	mask     uint32
	sid      string
}

func unrecognized(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errDescriptorUnrecognized, fmt.Sprintf(format, args...))
}

// parseSelfRelativeDACL parses a self-relative security descriptor and returns
// the ACEs of its DACL. It requires a present, non-NULL, protected DACL and
// rejects any malformed or out-of-bounds structure.
func parseSelfRelativeDACL(sd []byte) ([]parsedACE, error) {
	if len(sd) < sdHeaderSize {
		return nil, unrecognized("descriptor length %d is shorter than the %d-byte header", len(sd), sdHeaderSize)
	}
	if sd[0] != 1 {
		return nil, unrecognized("descriptor revision %d, want 1", sd[0])
	}
	control := binary.LittleEndian.Uint16(sd[2:4])
	if control&seSelfRelative == 0 {
		return nil, unrecognized("descriptor is not self-relative (control 0x%04X)", control)
	}
	if control&seDACLPresent == 0 {
		return nil, unrecognized("descriptor has no DACL (control 0x%04X)", control)
	}
	if control&seDACLProtected == 0 {
		return nil, unrecognized("DACL is not protected against inheritance (control 0x%04X)", control)
	}
	daclOffset := binary.LittleEndian.Uint32(sd[16:20])
	if daclOffset == 0 {
		return nil, unrecognized("DACL is NULL")
	}
	if daclOffset < sdHeaderSize || uint64(daclOffset)+aclHeaderSize > uint64(len(sd)) {
		return nil, unrecognized("DACL offset %d out of bounds (descriptor length %d)", daclOffset, len(sd))
	}

	acl := sd[daclOffset:]
	if rev := acl[0]; rev != aclRevision && rev != aclRevisionDS {
		return nil, unrecognized("ACL revision %d not supported", rev)
	}
	aclSize := int(binary.LittleEndian.Uint16(acl[2:4]))
	aceCount := int(binary.LittleEndian.Uint16(acl[4:6]))
	if aclSize < aclHeaderSize || aclSize > len(acl) {
		return nil, unrecognized("ACL size %d out of bounds (%d bytes available)", aclSize, len(acl))
	}
	acl = acl[:aclSize]

	aces := make([]parsedACE, 0, aceCount)
	off := aclHeaderSize
	for i := 0; i < aceCount; i++ {
		if off+aceFixedSize > len(acl) {
			return nil, unrecognized("ACE %d header exceeds ACL size", i)
		}
		aceType := acl[off]
		aceFlags := acl[off+1]
		aceSize := int(binary.LittleEndian.Uint16(acl[off+2 : off+4]))
		if aceSize < aceFixedSize || aceSize%4 != 0 || off+aceSize > len(acl) {
			return nil, unrecognized("ACE %d size %d invalid", i, aceSize)
		}
		if aceType != aceTypeAccessAllowed {
			return nil, unrecognized("ACE %d has type %d; only ACCESS_ALLOWED_ACE is permitted", i, aceType)
		}
		mask := binary.LittleEndian.Uint32(acl[off+4 : off+8])
		sid, sidLen, err := parseSID(acl[off+aceFixedSize : off+aceSize])
		if err != nil {
			return nil, unrecognized("ACE %d: %v", i, err)
		}
		if aceFixedSize+sidLen != aceSize {
			return nil, unrecognized("ACE %d size %d does not match SID length %d", i, aceSize, sidLen)
		}
		aces = append(aces, parsedACE{aceType: aceType, aceFlags: aceFlags, mask: mask, sid: sid})
		off += aceSize
	}
	return aces, nil
}

// parseSID decodes a binary SID at the start of b into its string form and
// returns the number of bytes it occupies.
func parseSID(b []byte) (string, int, error) {
	if len(b) < 8 {
		return "", 0, fmt.Errorf("SID truncated")
	}
	if b[0] != sidRevision {
		return "", 0, fmt.Errorf("SID revision %d, want %d", b[0], sidRevision)
	}
	n := int(b[1])
	if n > sidMaxSubAuth {
		return "", 0, fmt.Errorf("SID has %d sub-authorities, max %d", n, sidMaxSubAuth)
	}
	size := 8 + 4*n
	if len(b) < size {
		return "", 0, fmt.Errorf("SID truncated")
	}
	var authority uint64
	for _, v := range b[2:8] {
		authority = authority<<8 | uint64(v)
	}
	var sb strings.Builder
	sb.WriteString("S-1-")
	sb.WriteString(strconv.FormatUint(authority, 10))
	for i := 0; i < n; i++ {
		sb.WriteByte('-')
		sb.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b[8+4*i:])), 10))
	}
	return sb.String(), size, nil
}

// classifyDescriptor reports which known per-key policy state a persisted
// self-relative descriptor is in. It returns daclUnknown and a non-nil error
// describing the first deviation for anything that is not an exact match.
// See classifyDescriptorSID for the recognized forms.
func classifyDescriptor(sd []byte) (daclState, error) {
	st, _, err := classifyDescriptorSID(sd)
	return st, err
}

// classifyDescriptorSID is classifyDescriptor that also returns, for the
// service-sid state, the service SID the DACL grants.
//
// Recognized states (ACE order is not significant; every ACE must be an
// explicit ACCESS_ALLOWED_ACE with no flags, and the DACL must be protected):
//
//	privileged-only: SYSTEM GA, Administrators GA
//	service-signer:  SYSTEM GA, Administrators GA, LOCAL SERVICE exactly
//	                 0x80000000, 0xA0000000 or 0x801200A9
//	service-sid:     SYSTEM GA, Administrators GA, one service SID
//	                 (S-1-5-80-x-x-x-x-x) exactly 0xA0000000 or 0x801200A9
//
// For SYSTEM/Administrators, GA means exactly 0x10000000 or the allow-listed
// KSP representation 0xD01F01FF, not any mask containing the GA bit.
//
// A DACL granting both LOCAL SERVICE and a service SID, or more than one
// service SID, is unknown. The classification is static: it does not evaluate
// the owner (which has implicit READ_CONTROL/WRITE_DAC), the SACL, privileges
// such as SeTakeOwnershipPrivilege, or Windows effective access.
func classifyDescriptorSID(sd []byte) (daclState, string, error) {
	aces, err := parseSelfRelativeDACL(sd)
	if err != nil {
		return daclUnknown, "", err
	}
	seen := make(map[string]bool, len(aces))
	serviceSID := ""
	for i, ace := range aces {
		if ace.aceFlags != 0 {
			return daclUnknown, "", unrecognized("ACE %d for %s has flags 0x%02X; only explicit, non-inheritable ACEs are permitted", i, ace.sid, ace.aceFlags)
		}
		if seen[ace.sid] {
			return daclUnknown, "", unrecognized("duplicate ACE for %s", ace.sid)
		}
		seen[ace.sid] = true
		switch {
		case ace.sid == sidSYSTEM || ace.sid == sidAdministrators:
			if ace.mask != maskAdministrative && ace.mask != maskAdministrativeKSP {
				return daclUnknown, "", unrecognized("ACE for %s has mask 0x%08X, want exactly 0x%08X or 0x%08X", ace.sid, ace.mask, uint32(maskAdministrative), uint32(maskAdministrativeKSP))
			}
		case ace.sid == sidLocalService:
			if ace.mask != maskLocalServiceRequested && ace.mask != maskLocalServiceCanonical && ace.mask != maskLocalServiceKSP {
				return daclUnknown, "", unrecognized("ACE for LOCAL SERVICE has mask 0x%08X, want exactly 0x%08X, 0x%08X or 0x%08X", ace.mask, uint32(maskLocalServiceCanonical), uint32(maskLocalServiceRequested), uint32(maskLocalServiceKSP))
			}
		case isServiceSID(ace.sid):
			if serviceSID != "" {
				return daclUnknown, "", unrecognized("more than one service SID ACE (%s, %s)", serviceSID, ace.sid)
			}
			if ace.mask != maskServiceRequested && ace.mask != maskServiceKSP {
				return daclUnknown, "", unrecognized("ACE for service SID %s has mask 0x%08X, want exactly 0x%08X or 0x%08X", ace.sid, ace.mask, uint32(maskServiceRequested), uint32(maskServiceKSP))
			}
			serviceSID = ace.sid
		default:
			return daclUnknown, "", unrecognized("unexpected allow ACE for %s", ace.sid)
		}
	}
	if !seen[sidSYSTEM] || !seen[sidAdministrators] {
		return daclUnknown, "", unrecognized("DACL lacks the required SYSTEM and Administrators ACEs")
	}
	if seen[sidLocalService] && serviceSID != "" {
		return daclUnknown, "", unrecognized("DACL grants both LOCAL SERVICE and service SID %s", serviceSID)
	}
	switch len(aces) {
	case 2:
		return daclPrivilegedOnly, "", nil
	case 3:
		if seen[sidLocalService] {
			return daclServiceSigner, "", nil
		}
		if serviceSID != "" {
			return daclServiceSID, serviceSID, nil
		}
	}
	return daclUnknown, "", unrecognized("DACL with %d ACEs matches no known policy", len(aces))
}

// isServiceSID reports whether s is a per-service SID: S-1-5-80 followed by
// exactly five decimal 32-bit sub-authorities, the form Windows derives from
// a service name. It excludes S-1-5-80-0 (NT SERVICE\ALL SERVICES).
func isServiceSID(s string) bool {
	const prefix = "S-1-5-80-"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	parts := strings.Split(s[len(prefix):], "-")
	if len(parts) != 5 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 10 || (len(p) > 1 && p[0] == '0') {
			return false
		}
		if _, err := strconv.ParseUint(p, 10, 32); err != nil {
			return false
		}
	}
	return true
}
