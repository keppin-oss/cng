package windowscng

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// testACE describes one ACE for the synthetic descriptor builder.
type testACE struct {
	aceType byte
	flags   byte
	mask    uint32
	sid     string
}

func allow(mask uint32, sid string) testACE {
	return testACE{aceType: aceTypeAccessAllowed, mask: mask, sid: sid}
}

// encodeSID encodes a string SID ("S-1-5-32-544") in binary form.
func encodeSID(t *testing.T, s string) []byte {
	t.Helper()
	parts := strings.Split(s, "-")
	if len(parts) < 3 || parts[0] != "S" || parts[1] != "1" {
		t.Fatalf("bad SID %q", s)
	}
	auth, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		t.Fatalf("bad SID authority %q: %v", s, err)
	}
	subs := parts[3:]
	b := make([]byte, 8+4*len(subs))
	b[0] = 1
	b[1] = byte(len(subs))
	for i := 0; i < 6; i++ {
		b[2+i] = byte(auth >> (8 * (5 - i)))
	}
	for i, sub := range subs {
		v, err := strconv.ParseUint(sub, 10, 32)
		if err != nil {
			t.Fatalf("bad SID sub-authority %q: %v", s, err)
		}
		binary.LittleEndian.PutUint32(b[8+4*i:], uint32(v))
	}
	return b
}

// buildDescriptor builds a self-relative security descriptor containing only
// a DACL with the given ACEs.
func buildDescriptor(t *testing.T, control uint16, aces ...testACE) []byte {
	t.Helper()
	var body []byte
	for _, a := range aces {
		sid := encodeSID(t, a.sid)
		ace := make([]byte, aceFixedSize, aceFixedSize+len(sid))
		ace[0] = a.aceType
		ace[1] = a.flags
		binary.LittleEndian.PutUint16(ace[2:4], uint16(aceFixedSize+len(sid)))
		binary.LittleEndian.PutUint32(ace[4:8], a.mask)
		body = append(body, append(ace, sid...)...)
	}
	acl := make([]byte, aclHeaderSize)
	acl[0] = aclRevision
	binary.LittleEndian.PutUint16(acl[2:4], uint16(aclHeaderSize+len(body)))
	binary.LittleEndian.PutUint16(acl[4:6], uint16(len(aces)))
	acl = append(acl, body...)

	sd := make([]byte, sdHeaderSize)
	sd[0] = 1
	binary.LittleEndian.PutUint16(sd[2:4], control)
	binary.LittleEndian.PutUint32(sd[16:20], sdHeaderSize)
	return append(sd, acl...)
}

const protectedControl = seSelfRelative | seDACLPresent | seDACLProtected

func privilegedOnlyDescriptor(t *testing.T) []byte {
	return buildDescriptor(t, protectedControl,
		allow(genericAll, sidSYSTEM),
		allow(genericAll, sidAdministrators))
}

func serviceSignerDescriptor(t *testing.T, lsMask uint32) []byte {
	return buildDescriptor(t, protectedControl,
		allow(genericAll, sidSYSTEM),
		allow(genericAll, sidAdministrators),
		allow(lsMask, sidLocalService))
}

func TestParseSIDRoundTrip(t *testing.T) {
	for _, s := range []string{sidSYSTEM, sidAdministrators, sidLocalService, sidEveryone, "S-1-5-21-1004336348-1177238915-682003330-512"} {
		got, n, err := parseSID(encodeSID(t, s))
		if err != nil {
			t.Fatalf("parseSID(%s): %v", s, err)
		}
		if got != s || n != len(encodeSID(t, s)) {
			t.Fatalf("parseSID(%s) = %q, %d", s, got, n)
		}
	}
}

func TestClassifyRecognizedStates(t *testing.T) {
	tests := []struct {
		name string
		sd   []byte
		want daclState
	}{
		{"privileged-only", privilegedOnlyDescriptor(t), daclPrivilegedOnly},
		{"service-signer requested GR|GX", serviceSignerDescriptor(t, genericRead|genericExecute), daclServiceSigner},
		{"service-signer canonical GR", serviceSignerDescriptor(t, genericRead), daclServiceSigner},
		{"privileged-only reversed order", buildDescriptor(t, protectedControl,
			allow(genericAll, sidAdministrators), allow(genericAll, sidSYSTEM)), daclPrivilegedOnly},
		{"service-signer LS first", buildDescriptor(t, protectedControl,
			allow(genericRead, sidLocalService), allow(genericAll, sidSYSTEM), allow(genericAll, sidAdministrators)), daclServiceSigner},
		{"ACL_REVISION_DS accepted", func() []byte {
			sd := privilegedOnlyDescriptor(t)
			sd[sdHeaderSize] = aclRevisionDS
			return sd
		}(), daclPrivilegedOnly},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifyDescriptor(tt.sd)
			if err != nil {
				t.Fatalf("classifyDescriptor: %v", err)
			}
			if got != tt.want {
				t.Fatalf("classifyDescriptor = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestClassifyRejectsUnknownForms(t *testing.T) {
	sy := allow(genericAll, sidSYSTEM)
	ba := allow(genericAll, sidAdministrators)
	ls := allow(genericRead, sidLocalService)

	truncate := func(b []byte, n int) []byte { return b[:len(b)-n] }
	setU16 := func(b []byte, off int, v uint16) []byte { binary.LittleEndian.PutUint16(b[off:], v); return b }
	setU32 := func(b []byte, off int, v uint32) []byte { binary.LittleEndian.PutUint32(b[off:], v); return b }

	tests := []struct {
		name string
		sd   []byte
	}{
		{"empty", nil},
		{"short header", make([]byte, sdHeaderSize-1)},
		{"bad SD revision", func() []byte { b := privilegedOnlyDescriptor(t); b[0] = 2; return b }()},
		{"not self-relative", buildDescriptor(t, seDACLPresent|seDACLProtected, sy, ba)},
		{"DACL not present", buildDescriptor(t, seSelfRelative|seDACLProtected, sy, ba)},
		{"DACL not protected", buildDescriptor(t, seSelfRelative|seDACLPresent, sy, ba)},
		{"NULL DACL offset", setU32(privilegedOnlyDescriptor(t), 16, 0)},
		{"DACL offset out of bounds", setU32(privilegedOnlyDescriptor(t), 16, 4096)},
		{"DACL offset inside header", setU32(privilegedOnlyDescriptor(t), 16, 4)},
		{"bad ACL revision", func() []byte { b := privilegedOnlyDescriptor(t); b[sdHeaderSize] = 3; return b }()},
		{"ACL size beyond buffer", setU16(privilegedOnlyDescriptor(t), sdHeaderSize+2, 0xFFF0)},
		{"ACE count beyond ACL", setU16(privilegedOnlyDescriptor(t), sdHeaderSize+4, 3)},
		{"truncated ACE", truncate(privilegedOnlyDescriptor(t), 4)},
		{"ACE size not aligned", setU16(privilegedOnlyDescriptor(t), sdHeaderSize+aclHeaderSize+2, 21)},
		{"zero ACEs", buildDescriptor(t, protectedControl)},
		{"only SYSTEM", buildDescriptor(t, protectedControl, sy)},
		{"only Administrators", buildDescriptor(t, protectedControl, ba)},
		{"LS without Administrators", buildDescriptor(t, protectedControl, sy, ls)},
		{"duplicate SYSTEM", buildDescriptor(t, protectedControl, sy, sy, ba)},
		{"duplicate LS", buildDescriptor(t, protectedControl, sy, ba, ls, ls)},
		{"extra Everyone", buildDescriptor(t, protectedControl, sy, ba, allow(genericRead, sidEveryone))},
		{"extra Users", buildDescriptor(t, protectedControl, sy, ba, allow(genericRead, sidBuiltinUsers))},
		{"extra domain SID", buildDescriptor(t, protectedControl, sy, ba, allow(genericAll, "S-1-5-21-1-2-3-500"))},
		{"deny ACE", buildDescriptor(t, protectedControl, sy, ba, testACE{aceType: 1, mask: genericAll, sid: sidLocalService})},
		{"inherited ACE flag", buildDescriptor(t, protectedControl, sy, testACE{flags: 0x10, mask: genericAll, sid: sidAdministrators})},
		{"inheritable ACE flag", buildDescriptor(t, protectedControl, testACE{flags: 0x03, mask: genericAll, sid: sidSYSTEM}, ba)},
		{"SYSTEM mask canonicalized", buildDescriptor(t, protectedControl, allow(0x001F0003, sidSYSTEM), ba)},
		{"Administrators GA plus extra bit", buildDescriptor(t, protectedControl, sy, allow(genericAll|genericRead, sidAdministrators))},
		{"Administrators read-only", buildDescriptor(t, protectedControl, sy, allow(genericRead, sidAdministrators))},
		{"LS write", buildDescriptor(t, protectedControl, sy, ba, allow(genericRead|genericWrite, sidLocalService))},
		{"LS GA", buildDescriptor(t, protectedControl, sy, ba, allow(genericAll, sidLocalService))},
		{"LS execute only", buildDescriptor(t, protectedControl, sy, ba, allow(genericExecute, sidLocalService))},
		{"LS specific rights", buildDescriptor(t, protectedControl, sy, ba, allow(genericRead|0x1, sidLocalService))},
		{"bad SID revision", func() []byte {
			b := privilegedOnlyDescriptor(t)
			b[sdHeaderSize+aclHeaderSize+aceFixedSize] = 2
			return b
		}()},
		{"SID too many sub-authorities", func() []byte {
			b := privilegedOnlyDescriptor(t)
			b[sdHeaderSize+aclHeaderSize+aceFixedSize+1] = 16
			return b
		}()},
		{"ACE size larger than SID", func() []byte {
			b := buildDescriptor(t, protectedControl, sy, ba)
			// Grow the first ACE by 4 bytes of padding and fix up sizes.
			first := sdHeaderSize + aclHeaderSize
			size := int(binary.LittleEndian.Uint16(b[first+2:]))
			grown := append(append(append([]byte{}, b[:first+size]...), 0, 0, 0, 0), b[first+size:]...)
			binary.LittleEndian.PutUint16(grown[first+2:], uint16(size+4))
			aclSize := binary.LittleEndian.Uint16(grown[sdHeaderSize+2:])
			binary.LittleEndian.PutUint16(grown[sdHeaderSize+2:], aclSize+4)
			return grown
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifyDescriptor(tt.sd)
			if err == nil {
				t.Fatalf("classifyDescriptor accepted descriptor as %s", got)
			}
			if got != daclUnknown {
				t.Fatalf("classifyDescriptor = %s with error %v, want unknown", got, err)
			}
			if !errors.Is(err, errDescriptorUnrecognized) {
				t.Fatalf("error %v does not wrap errDescriptorUnrecognized", err)
			}
		})
	}
}

func TestPolicyValidateAndState(t *testing.T) {
	if err := PolicyServiceSigner.validate(); err != nil {
		t.Fatal(err)
	}
	if err := PolicyPrivilegedOnly.validate(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []Policy{0, -1, 3, 100} {
		if err := p.validate(); err == nil {
			t.Errorf("Policy(%d).validate() accepted an undefined policy", int(p))
		}
		if p.state() != daclUnknown {
			t.Errorf("Policy(%d).state() = %s, want unknown", int(p), p.state())
		}
	}
	if PolicyServiceSigner.state() != daclServiceSigner || PolicyPrivilegedOnly.state() != daclPrivilegedOnly {
		t.Fatal("policy to DACL state mapping changed")
	}
	if PolicyServiceSigner.String() != "service-signer" || PolicyPrivilegedOnly.String() != "privileged-only" {
		t.Fatal("policy names changed")
	}
}

func TestPolicyErrorsAreDistinct(t *testing.T) {
	if ErrPolicyMismatch == nil || ErrPrivilegeRequired == nil {
		t.Fatal("policy sentinels must be non-nil")
	}
	if errors.Is(ErrPolicyMismatch, ErrPrivilegeRequired) || errors.Is(ErrPrivilegeRequired, ErrPolicyMismatch) {
		t.Fatal("policy sentinels must be distinct")
	}
}
