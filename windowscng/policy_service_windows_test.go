//go:build windows

package windowscng

import (
	"errors"
	"fmt"
	"testing"
)

// Engine tests of the ServicePolicy API against the in-memory fake keyStore.
// They never open, create, modify or delete a real persisted CNG key.

func TestServicePolicyAPIsRejectInvalidPolicy(t *testing.T) {
	for _, p := range []ServicePolicy{{}, {name: testServiceName}, {name: testServiceName, sid: "S-1-5-80-1-2-3-4-5"}} {
		s := newFakeStore(t)
		s.privileged = true
		if _, err := openForService(s, testKey, p); err == nil {
			t.Errorf("openForService accepted %+v", p)
		}
		if _, err := loadOrCreateForService(s, testKey, p); err == nil {
			t.Errorf("loadOrCreateForService accepted %+v", p)
		}
		if err := applyServicePolicy(s, testKey, p); err == nil {
			t.Errorf("applyServicePolicy accepted %+v", p)
		}
		if s.opens != 0 || s.privilegeChecks != 0 {
			t.Errorf("invalid policy %+v reached the key store", p)
		}
		assertNoMutation(t, s)
	}
}

func TestOpenForService(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	other := mustServicePolicy(t, "Example.Policy.Other")

	t.Run("matching service SID opens without privilege", func(t *testing.T) {
		for _, mask := range []uint32{genericRead | genericExecute, 0x801200A9} {
			s := newFakeStore(t)
			s.persisted[testKey] = serviceSIDDescriptor(t, p.SID(), mask)
			signer, err := openForService(s, testKey, p)
			if err != nil {
				t.Fatalf("mask 0x%08X: %v", mask, err)
			}
			_ = signer.Close()
			if s.privilegeChecks != 0 {
				t.Fatal("open for service must not require a privileged caller")
			}
			assertNoMutation(t, s)
			assertHandlesReleased(t, s)
		}
	})
	mismatches := map[string]func(*testing.T) []byte{
		"other service SID":     func(t *testing.T) []byte { return serviceSIDDescriptor(t, other.SID(), genericRead|genericExecute) },
		"generic LOCAL SERVICE": func(t *testing.T) []byte { return serviceSignerDescriptor(t, genericRead) },
		"privileged-only":       privilegedOnlyDescriptor,
		"unknown": func(t *testing.T) []byte {
			return buildDescriptor(t, protectedControl, allow(genericAll, sidSYSTEM), allow(genericAll, sidAdministrators), allow(genericRead, sidEveryone))
		},
	}
	for name, sd := range mismatches {
		t.Run("rejects "+name, func(t *testing.T) {
			s := newFakeStore(t)
			s.persisted[testKey] = sd(t)
			if _, err := openForService(s, testKey, p); !errors.Is(err, ErrPolicyMismatch) {
				t.Fatalf("err = %v, want ErrPolicyMismatch", err)
			}
			assertNoMutation(t, s)
			assertHandlesReleased(t, s)
		})
	}
	t.Run("missing key reports ErrKeyNotFound and creates nothing", func(t *testing.T) {
		s := newFakeStore(t)
		if _, err := openForService(s, testKey, p); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("err = %v, want ErrKeyNotFound", err)
		}
		assertNoMutation(t, s)
	})
	t.Run("exportable or malformed key is rejected", func(t *testing.T) {
		s := newFakeStore(t)
		s.persisted[testKey] = serviceSIDDescriptor(t, p.SID(), genericRead|genericExecute)
		s.exportErr = errors.New("exportable")
		if _, err := openForService(s, testKey, p); err == nil {
			t.Fatal("exportable key accepted")
		}
		assertHandlesReleased(t, s)
	})
}

func TestLoadOrCreateForService(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)

	t.Run("privileged caller creates with the service SDDL", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		signer, err := loadOrCreateForService(s, testKey, p)
		if err != nil {
			t.Fatal(err)
		}
		_ = signer.Close()
		if len(s.creates) != 1 || s.creates[0] != p.sddl() {
			t.Fatalf("creates = %v, want [%s]", s.creates, p.sddl())
		}
		st, sid, err := classifyDescriptorSID(s.persisted[testKey])
		if err != nil || st != daclServiceSID || sid != p.SID() {
			t.Fatalf("persisted %s %q %v", st, sid, err)
		}
		assertHandlesReleased(t, s)
	})
	t.Run("existing matching key is reused without writes", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSIDDescriptor(t, p.SID(), genericRead|genericExecute)
		signer, err := loadOrCreateForService(s, testKey, p)
		if err != nil {
			t.Fatal(err)
		}
		_ = signer.Close()
		assertNoMutation(t, s)
		assertHandlesReleased(t, s)
	})
	t.Run("non-privileged not-found never creates", func(t *testing.T) {
		s := newFakeStore(t)
		if _, err := loadOrCreateForService(s, testKey, p); !errors.Is(err, ErrPrivilegeRequired) {
			t.Fatalf("err = %v, want ErrPrivilegeRequired", err)
		}
		assertNoMutation(t, s)
	})
	t.Run("privilege check error fails closed", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.privErr = errors.New("token query failed")
		if _, err := loadOrCreateForService(s, testKey, p); !errors.Is(err, ErrPrivilegeRequired) {
			t.Fatalf("err = %v, want ErrPrivilegeRequired", err)
		}
		assertNoMutation(t, s)
	})
	t.Run("generic LOCAL SERVICE key is not converted", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		if _, err := loadOrCreateForService(s, testKey, p); !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want ErrPolicyMismatch", err)
		}
		assertNoMutation(t, s)
		assertHandlesReleased(t, s)
	})
	t.Run("open failure other than not-found is never treated as absent", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.openErr = errors.New("NCryptOpenKey: hr=0x80090010")
		if _, err := loadOrCreateForService(s, testKey, p); err == nil {
			t.Fatal("open failure accepted")
		}
		assertNoMutation(t, s)
	})
	t.Run("create failure surfaces and deletes nothing", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.createErr = errors.New("NTE_EXISTS")
		if _, err := loadOrCreateForService(s, testKey, p); err == nil {
			t.Fatal("create failure accepted")
		}
		if len(s.deleted) != 0 {
			t.Fatal("deleted after create failure")
		}
	})
	t.Run("created key in the wrong state is deleted", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.writeResult = serviceSignerDescriptor(t, genericRead)
		if _, err := loadOrCreateForService(s, testKey, p); !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want ErrPolicyMismatch", err)
		}
		if len(s.deleted) != 1 {
			t.Fatalf("deleted = %v, want the created key", s.deleted)
		}
		assertHandlesReleased(t, s)
	})
	t.Run("unobserved GENERIC_READ service ACE is rejected after create", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.writeResult = serviceSIDDescriptor(t, p.SID(), genericRead)
		if _, err := loadOrCreateForService(s, testKey, p); !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want ErrPolicyMismatch", err)
		}
		if len(s.deleted) != 1 {
			t.Fatal("unverified new key not deleted")
		}
		assertHandlesReleased(t, s)
	})
}

func TestApplyServicePolicy(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	other := mustServicePolicy(t, "Example.Policy.Other")

	t.Run("requires privilege before open", func(t *testing.T) {
		s := newFakeStore(t)
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		if err := applyServicePolicy(s, testKey, p); !errors.Is(err, ErrPrivilegeRequired) {
			t.Fatalf("err = %v, want ErrPrivilegeRequired", err)
		}
		if s.opens != 0 {
			t.Fatal("key opened for a non-privileged caller")
		}
		assertNoMutation(t, s)
	})
	for _, lsMask := range []uint32{genericRead, genericRead | genericExecute, 0x801200A9} {
		t.Run(fmt.Sprintf("migrates generic LOCAL SERVICE (0x%08X) to the service SID", lsMask), func(t *testing.T) {
			s := newFakeStore(t)
			s.privileged = true
			s.persisted[testKey] = serviceSignerDescriptor(t, lsMask)
			if err := applyServicePolicy(s, testKey, p); err != nil {
				t.Fatal(err)
			}
			if len(s.writes) != 1 || s.writes[0] != p.sddl() {
				t.Fatalf("writes = %v, want exactly [%s]", s.writes, p.sddl())
			}
			st, sid, err := classifyDescriptorSID(s.persisted[testKey])
			if err != nil || st != daclServiceSID || sid != p.SID() {
				t.Fatalf("persisted %s %q %v", st, sid, err)
			}
			if s.opens != 2 || len(s.creates) != 0 || len(s.deleted) != 0 {
				t.Fatalf("opens=%d creates=%v deleted=%v", s.opens, s.creates, s.deleted)
			}
			assertHandlesReleased(t, s)
		})
	}
	t.Run("idempotent on the same service SID", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSIDDescriptor(t, p.SID(), genericRead|genericExecute)
		if err := applyServicePolicy(s, testKey, p); err != nil {
			t.Fatal(err)
		}
		assertNoMutation(t, s)
		assertHandlesReleased(t, s)
	})
	refusals := map[string]func(*testing.T) []byte{
		"other service SID":          func(t *testing.T) []byte { return serviceSIDDescriptor(t, other.SID(), genericRead|genericExecute) },
		"privileged-only (widening)": privilegedOnlyDescriptor,
		"unknown DACL": func(t *testing.T) []byte {
			return buildDescriptor(t, protectedControl, allow(genericAll, sidSYSTEM), allow(genericAll, sidAdministrators), allow(genericRead, sidBuiltinUsers))
		},
	}
	for name, sd := range refusals {
		t.Run("refuses "+name, func(t *testing.T) {
			s := newFakeStore(t)
			s.privileged = true
			s.persisted[testKey] = sd(t)
			if err := applyServicePolicy(s, testKey, p); !errors.Is(err, ErrPolicyMismatch) {
				t.Fatalf("err = %v, want ErrPolicyMismatch", err)
			}
			assertNoMutation(t, s)
			assertHandlesReleased(t, s)
		})
	}
	t.Run("post-write mismatch is reported and not rolled back", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		s.writeResult = serviceSIDDescriptor(t, other.SID(), genericRead|genericExecute)
		err := applyServicePolicy(s, testKey, p)
		if !errors.Is(err, errPostWriteVerification) {
			t.Fatalf("err = %v, want errPostWriteVerification", err)
		}
		if len(s.writes) != 1 {
			t.Fatalf("writes = %v, want exactly one (no rollback)", s.writes)
		}
		assertHandlesReleased(t, s)
	})
	t.Run("stale fresh-handle read-back is reported", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		s.reopenResult = serviceSignerDescriptor(t, genericRead)
		if err := applyServicePolicy(s, testKey, p); !errors.Is(err, errPostWriteVerification) {
			t.Fatalf("err = %v, want errPostWriteVerification", err)
		}
		assertHandlesReleased(t, s)
	})
}

// TestApplyPolicyTightensServiceSIDKey: a service-sid key can be tightened to
// privileged-only (the CA-key form), never widened back by ApplyPolicy.
func TestApplyPolicyTightensServiceSIDKey(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	s := newFakeStore(t)
	s.privileged = true
	s.persisted[testKey] = serviceSIDDescriptor(t, p.SID(), genericRead|genericExecute)
	if err := applyPolicy(s, testKey, PolicyPrivilegedOnly); err != nil {
		t.Fatal(err)
	}
	if len(s.writes) != 1 || s.writes[0] != privilegedOnlySDDL {
		t.Fatalf("writes = %v", s.writes)
	}
	s = newFakeStore(t)
	s.privileged = true
	s.persisted[testKey] = serviceSIDDescriptor(t, p.SID(), genericRead|genericExecute)
	if err := applyPolicy(s, testKey, PolicyServiceSigner); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("service-sid -> generic LOCAL SERVICE: err = %v, want ErrPolicyMismatch", err)
	}
	assertNoMutation(t, s)
}

// TestOpenWithPolicyRejectsServiceSIDKey: the generic policies do not accept a
// key provisioned for one service.
func TestOpenWithPolicyRejectsServiceSIDKey(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	s := newFakeStore(t)
	s.privileged = true
	s.persisted[testKey] = serviceSIDDescriptor(t, p.SID(), genericRead|genericExecute)
	for _, pol := range []Policy{PolicyServiceSigner, PolicyPrivilegedOnly} {
		if _, err := openWithPolicy(s, testKey, pol); !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("%s: err = %v, want ErrPolicyMismatch", pol, err)
		}
	}
	assertNoMutation(t, s)
	assertHandlesReleased(t, s)
}

// TestServiceSDDLMatchesWindowsEncoding converts the requested service SDDL
// with the native SDDL parser (no key involved) and classifies the result.
func TestServiceSDDLMatchesWindowsEncoding(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	sd, err := buildSecurityDescriptor(p.sddl())
	if err != nil {
		t.Fatalf("buildSecurityDescriptor(%s): %v", p.sddl(), err)
	}
	st, sid, err := classifyDescriptorSID(sd)
	if err != nil || st != daclServiceSID || sid != p.SID() {
		t.Fatalf("classifyDescriptorSID = %s %q %v", st, sid, err)
	}
	aces, err := parseSelfRelativeDACL(sd)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range aces {
		if a.sid == sidLocalService || a.sid == "S-1-5-80-0" {
			t.Fatalf("service DACL grants %s", a.sid)
		}
	}
}
