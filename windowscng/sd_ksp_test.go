package windowscng

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// Synthetic combinations of allowed masks, not new native executions.
func TestKSPAdministrativeMaskAllowList(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	for _, sy := range []uint32{0x10000000, 0xD01F01FF} {
		for _, ba := range []uint32{0x10000000, 0xD01F01FF} {
			for _, state := range []daclState{daclPrivilegedOnly, daclServiceSigner, daclServiceSID} {
				aces := []testACE{allow(sy, sidSYSTEM), allow(ba, sidAdministrators)}
				wantSID := ""
				switch state {
				case daclServiceSigner:
					aces = append(aces, allow(0xA0000000, sidLocalService))
				case daclServiceSID:
					wantSID = p.SID()
					aces = append(aces, allow(0xA0000000, wantSID))
				}
				got, gotSID, err := classifyDescriptorSID(buildDescriptor(t, protectedControl, aces...))
				if err != nil || got != state || gotSID != wantSID {
					t.Fatalf("SY=%08X BA=%08X state=%s: got %s %s %v", sy, ba, state, got, gotSID, err)
				}
			}
		}
	}
}

// Exact 112-byte DACL-scoped SD of a per-service key as persisted by the
// Microsoft Software KSP in native testing. This is ACL metadata, not private
// key data.
const p2B2ObservedSDHex = "010004900000000000000000000000001400000002005c000300000000001400ff011fd001010000000000051200000000001800ff011fd00102000000000005200000002002000000002800a90012800106000000000005500000000956e7e65492e1ea1832aa083f4bfb72dee47ab8"
const p2B2ObservedService = "KeppinCngP2_R20261026T231912Z-0064f235_A"

func observedP2B2Descriptor(t *testing.T) []byte {
	t.Helper()
	sd, err := hex.DecodeString(p2B2ObservedSDHex)
	if err != nil || len(sd) != 112 {
		t.Fatalf("observed SD fixture: %v, len=%d", err, len(sd))
	}
	return sd
}

func TestB3ObservedServiceDescriptor(t *testing.T) {
	p := mustServicePolicy(t, p2B2ObservedService)
	st, sid, err := classifyDescriptorSID(observedP2B2Descriptor(t))
	if err != nil || st != daclServiceSID || sid != p.SID() {
		t.Fatalf("observed descriptor: %s %s %v", st, sid, err)
	}
	// The requested and observed forms remain accepted with either allowed
	// administrative representation. No mask is normalized by generic bits.
	for _, sy := range []uint32{0x10000000, 0xD01F01FF} {
		for _, ba := range []uint32{0x10000000, 0xD01F01FF} {
			for _, svc := range []uint32{0xA0000000, 0x801200A9} {
				sd := buildDescriptor(t, protectedControl, allow(sy, sidSYSTEM), allow(ba, sidAdministrators), allow(svc, p.SID()))
				st, sid, err := classifyDescriptorSID(sd)
				if err != nil || st != daclServiceSID || sid != p.SID() {
					t.Fatalf("service mask %08X: %v", svc, err)
				}
			}
		}
	}
}

func TestB3ServiceMaskConfinement(t *testing.T) {
	p := mustServicePolicy(t, p2B2ObservedService)
	base := []testACE{allow(0xD01F01FF, sidSYSTEM), allow(0xD01F01FF, sidAdministrators), allow(0x801200A9, p.SID())}
	reject := func(aces []testACE) {
		t.Helper()
		if st, _, err := classifyDescriptorSID(buildDescriptor(t, protectedControl, aces...)); err == nil || st != daclUnknown {
			t.Fatalf("accepted %+v", aces)
		}
	}
	for _, mask := range []uint32{0xA0000000, 0x801200A9} {
		for bit := uint(0); bit < 32; bit++ {
			aces := append([]testACE(nil), base...)
			aces[2].mask = mask ^ (uint32(1) << bit)
			reject(aces)
		}
	}
	// No reuse for SYSTEM, Administrators or unrelated principals. The
	// classifier separately permits this exact mask for LOCAL SERVICE as
	// service-signer, not service-sid.
	for idx := 0; idx < 2; idx++ {
		aces := append([]testACE(nil), base...)
		aces[idx].mask = 0x801200A9
		reject(aces)
	}
	for _, sid := range []string{sidEveryone, sidBuiltinUsers, "S-1-5-80-0"} {
		aces := append([]testACE(nil), base...)
		aces[2].sid = sid
		reject(aces)
	}
	for idx := 0; idx < 3; idx++ {
		for bit := uint(0); bit < 8; bit++ {
			aces := append([]testACE(nil), base...)
			aces[idx].flags = byte(1 << bit)
			reject(aces)
		}
	}
	for _, typ := range []byte{1, 5, 6} {
		aces := append([]testACE(nil), base...)
		aces[2].aceType = typ
		reject(aces)
	}
	for _, extra := range []testACE{base[2], allow(0x80000000, sidLocalService), allow(0x801200A9, "S-1-5-80-1-2-3-4-5")} {
		reject(append(append([]testACE(nil), base...), extra))
	}
}

func TestKSPMasksRejectNearMissesAndServiceWrites(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	reject := func(aces []testACE) {
		t.Helper()
		if st, _, err := classifyDescriptorSID(buildDescriptor(t, protectedControl, aces...)); err == nil || st != daclUnknown {
			t.Fatalf("accepted unexpected ACEs: %+v", aces)
		}
	}
	// Each bit addition/removal around either allowed admin value is forbidden;
	// in particular GA present is not enough and mapped-only rights are not GA.
	for _, principal := range []string{sidSYSTEM, sidAdministrators} {
		for _, base := range []uint32{0x10000000, 0xD01F01FF} {
			for bit := uint(0); bit < 32; bit++ {
				aces := []testACE{allow(0xD01F01FF, sidSYSTEM), allow(0xD01F01FF, sidAdministrators), allow(0xA0000000, p.SID())}
				idx := 0
				if principal == sidAdministrators {
					idx = 1
				}
				aces[idx].mask = base ^ (uint32(1) << bit)
				reject(aces)
			}
		}
	}
	for _, mask := range []uint32{0, 0x80000000, 0xD01F01FF, 0x10000000, 0x40000000, 0xF0000000, 0xA0040000, 0xA0080000, 0xA0010000, 0xA0000002, 0x80120089, 0xA0120089} {
		t.Run(fmt.Sprintf("service-%08X", mask), func(t *testing.T) {
			reject([]testACE{allow(0xD01F01FF, sidSYSTEM), allow(0xD01F01FF, sidAdministrators), allow(mask, p.SID())})
		})
	}
	for idx := 0; idx < 3; idx++ {
		for bit := uint(0); bit < 8; bit++ {
			aces := []testACE{allow(0xD01F01FF, sidSYSTEM), allow(0xD01F01FF, sidAdministrators), allow(0xA0000000, p.SID())}
			aces[idx].flags = byte(1 << bit)
			reject(aces)
		}
	}
	base := []testACE{allow(0xD01F01FF, sidSYSTEM), allow(0xD01F01FF, sidAdministrators), allow(0xA0000000, p.SID())}
	for _, extra := range []testACE{allow(0x80000000, sidEveryone), allow(0xA0000000, sidLocalService), base[0], base[2], {aceType: 1, mask: 0x80000000, sid: sidEveryone}} {
		reject(append(append([]testACE{}, base...), extra))
	}
}
