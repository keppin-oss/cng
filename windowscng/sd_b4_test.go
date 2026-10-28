package windowscng

import (
	"encoding/hex"
	"testing"
)

// Exact 92-byte DACL metadata of a LOCAL SERVICE key as persisted by the
// Microsoft Software KSP in native testing. No test opens a key.
const p2B3MigrationSDHex = "0100049000000000000000000000000014000000020048000300000000001400ff011fd001010000000000051200000000001800ff011fd00102000000000005200000002002000000001400a9001280010100000000000513000000"

func observedMigrationDescriptor(t *testing.T) []byte {
	t.Helper()
	sd, err := hex.DecodeString(p2B3MigrationSDHex)
	if err != nil || len(sd) != 92 {
		t.Fatalf("Migration fixture: len=%d err=%v", len(sd), err)
	}
	return sd
}

func TestB4ObservedMigrationDescriptor(t *testing.T) {
	st, sid, err := classifyDescriptorSID(observedMigrationDescriptor(t))
	if err != nil || st != daclServiceSigner || sid != "" {
		t.Fatalf("Migration: %s %s %v", st, sid, err)
	}
	for _, sy := range []uint32{0x10000000, 0xD01F01FF} {
		for _, ba := range []uint32{0x10000000, 0xD01F01FF} {
			for _, ls := range []uint32{0x80000000, 0xA0000000, 0x801200A9} {
				sd := buildDescriptor(t, protectedControl, allow(sy, sidSYSTEM), allow(ba, sidAdministrators), allow(ls, sidLocalService))
				st, sid, err := classifyDescriptorSID(sd)
				if err != nil || st != daclServiceSigner || sid != "" {
					t.Fatalf("LS=%08X: %s %s %v", ls, st, sid, err)
				}
			}
		}
	}
}

func TestB4LocalServiceMaskConfinement(t *testing.T) {
	base := []testACE{allow(0xD01F01FF, sidSYSTEM), allow(0xD01F01FF, sidAdministrators), allow(0x801200A9, sidLocalService)}
	reject := func(control uint16, aces []testACE) {
		t.Helper()
		if st, _, err := classifyDescriptorSID(buildDescriptor(t, control, aces...)); err == nil || st != daclUnknown {
			t.Fatalf("accepted %+v control=%04X", aces, control)
		}
	}
	for _, mask := range []uint32{0x80000000, 0xA0000000, 0x801200A9} {
		for bit := uint(0); bit < 32; bit++ {
			m := mask ^ (uint32(1) << bit)
			if m == 0x80000000 || m == 0xA0000000 || m == 0x801200A9 {
				continue
			}
			aces := append([]testACE(nil), base...)
			aces[2].mask = m
			reject(protectedControl, aces)
		}
	}
	for idx := 0; idx < 2; idx++ {
		aces := append([]testACE(nil), base...)
		aces[idx].mask = 0x801200A9
		reject(protectedControl, aces)
	}
	for _, sid := range []string{sidEveryone, sidBuiltinUsers, "S-1-5-80-0", "S-1-5-20"} {
		aces := append([]testACE(nil), base...)
		aces[2].sid = sid
		reject(protectedControl, aces)
	}
	for idx := 0; idx < 3; idx++ {
		for bit := uint(0); bit < 8; bit++ {
			aces := append([]testACE(nil), base...)
			aces[idx].flags = byte(1 << bit)
			reject(protectedControl, aces)
		}
	}
	for _, typ := range []byte{1, 5, 6} {
		aces := append([]testACE(nil), base...)
		aces[2].aceType = typ
		reject(protectedControl, aces)
	}
	for _, extra := range []testACE{base[2], allow(0x801200A9, "S-1-5-80-1-2-3-4-5"), allow(0x80000000, sidEveryone)} {
		reject(protectedControl, append(append([]testACE(nil), base...), extra))
	}
	reject(seSelfRelative|seDACLPresent, base)
}
