//go:build windows

package windowscng

import (
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func requireDescriptorDiagnostic(t *testing.T, err error, sd []byte) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "security_information=DACL_SECURITY_INFORMATION; persisted_sd_dacl_hex="+hex.EncodeToString(sd)) {
		t.Fatalf("missing full descriptor diagnostic: %v", err)
	}
}

func TestCreatedKeyDiagnosticBeforeRollback(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	for name, sd := range map[string][]byte{
		"observed service mask plus WRITE_DAC":      serviceSIDDescriptor(t, p.SID(), 0x801600A9),
		"unknown service mask":                      buildDescriptor(t, protectedControl, allow(0xD01F01FF, sidSYSTEM), allow(0xD01F01FF, sidAdministrators), allow(0x80120089, p.SID())),
		"first ACE invalid still includes last ACE": buildDescriptor(t, protectedControl, allow(0x10000001, sidSYSTEM), allow(0xD01F01FF, sidAdministrators), allow(0x80120089, p.SID())),
		"wrong recognized policy":                   serviceSignerDescriptor(t, genericRead),
		"malformed descriptor":                      {1, 0, 4, 0x90, 0xAB, 0xCD},
	} {
		t.Run(name, func(t *testing.T) {
			s := newFakeStore(t)
			s.privileged, s.writeResult = true, append([]byte(nil), sd...)
			_, err := createWith(s, testKey, p)
			if !errors.Is(err, ErrPolicyMismatch) {
				t.Fatalf("sentinel lost: %v", err)
			}
			requireDescriptorDiagnostic(t, err, sd)
			if !reflect.DeepEqual(s.events, []string{"read-descriptor", "delete-created"}) || s.sdReads != 1 {
				t.Fatalf("read/rollback order changed: %v", s.events)
			}
			if len(s.deleted) != 1 || len(s.persisted) != 0 || len(s.writes) != 0 {
				t.Fatal("new-key rollback changed")
			}
			clear(s.writeResult)
			requireDescriptorDiagnostic(t, err, sd) // evidence survives handle/buffer lifetime
			assertHandlesReleased(t, s)
		})
	}
}

func TestB3ServicePolicyEngine(t *testing.T) {
	p := mustServicePolicy(t, p2B2ObservedService)
	observed := observedP2B2Descriptor(t)
	s := newFakeStore(t)
	s.privileged = true
	s.writeResult = observed
	signer, err := createWith(s, testKey, p)
	if err != nil {
		t.Fatal(err)
	}
	signer.Close()
	if len(s.deleted) != 0 || len(s.creates) != 1 {
		t.Fatal("accepted creation rolled back")
	}
	assertHandlesReleased(t, s)
	// Existing matching keys: open and idempotent apply must not change them.
	s = newFakeStore(t)
	s.privileged = true
	s.persisted[testKey] = observed
	signer, err = openWith(s, testKey, p)
	if err != nil {
		t.Fatal(err)
	}
	signer.Close()
	if err := applyWith(s, testKey, p); err != nil {
		t.Fatal(err)
	}
	other := mustServicePolicy(t, "Example.Other.Service")
	if _, err := openWith(s, testKey, other); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("other SID accepted: %v", err)
	}
	if err := applyWith(s, testKey, other); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("service retarget accepted: %v", err)
	}
	assertNoMutation(t, s)
	assertHandlesReleased(t, s)
	// This is a simulated migration read-back, not a native migration result.
	s = newFakeStore(t)
	s.privileged = true
	s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
	s.writeResult = observed
	if err := applyWith(s, testKey, p); err != nil {
		t.Fatal(err)
	}
	if s.opens != 2 || len(s.writes) != 1 || len(s.deleted) != 0 || len(s.creates) != 0 {
		t.Fatal("migration lifecycle changed")
	}
	assertHandlesReleased(t, s)
	// A write-enabled near miss still fails after write, preserving the SD and
	// the existing no-rollback rule for an already persisted key.
	s = newFakeStore(t)
	s.privileged = true
	s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
	s.writeResult = serviceSIDDescriptor(t, p.SID(), 0x801600A9)
	err = applyWith(s, testKey, p)
	if !errors.Is(err, ErrPostWriteVerification) {
		t.Fatalf("unsafe migration accepted: %v", err)
	}
	requireDescriptorDiagnostic(t, err, s.writeResult)
	if len(s.writes) != 1 || len(s.deleted) != 0 || len(s.creates) != 0 {
		t.Fatal("unsafe migration rollback changed")
	}
	assertHandlesReleased(t, s)
}

func TestDescriptorReadFailureStillRollsBackNewKey(t *testing.T) {
	s := newFakeStore(t)
	s.privileged = true
	s.sdErr = errors.New("synthetic descriptor read failure")
	_, err := createWith(s, testKey, mustServicePolicy(t, testServiceName))
	if !errors.Is(err, s.sdErr) || !strings.Contains(err.Error(), "descriptor unavailable") || strings.Contains(err.Error(), "persisted_sd_dacl_hex=") {
		t.Fatalf("read failure must not fabricate evidence: %v", err)
	}
	if len(s.deleted) != 1 || s.sdReads != 1 {
		t.Fatal("read failure changed rollback")
	}
	assertHandlesReleased(t, s)
}

func TestDescriptorDiagnosticDoesNotMutateExistingKey(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	sd := serviceSIDDescriptor(t, p.SID(), 0x80000000) // unobserved service form
	for _, action := range []string{"open", "apply"} {
		t.Run(action, func(t *testing.T) {
			s := newFakeStore(t)
			s.privileged = true
			s.persisted[testKey] = append([]byte(nil), sd...)
			var err error
			switch action {
			case "open":
				_, err = openWith(s, testKey, p)
			case "apply":
				err = applyWith(s, testKey, p)
			}
			if !errors.Is(err, ErrPolicyMismatch) {
				t.Fatalf("sentinel lost: %v", err)
			}
			requireDescriptorDiagnostic(t, err, sd)
			assertNoMutation(t, s)
			if !reflect.DeepEqual(s.persisted[testKey], sd) {
				t.Fatal("existing key changed")
			}
			assertHandlesReleased(t, s)
		})
	}
}

func TestPostWriteDiagnosticNoRollback(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	bad := serviceSIDDescriptor(t, p.SID(), 0x80120089)
	for _, fresh := range []bool{false, true} {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		if fresh {
			s.reopenResult = bad
		} else {
			s.writeResult = bad
		}
		err := applyWith(s, testKey, p)
		if !errors.Is(err, ErrPostWriteVerification) {
			t.Fatalf("post-write sentinel lost: %v", err)
		}
		requireDescriptorDiagnostic(t, err, bad)
		if len(s.writes) != 1 || len(s.creates) != 0 || len(s.deleted) != 0 {
			t.Fatal("post-write rollback semantics changed")
		}
		assertHandlesReleased(t, s)
	}
}

func TestKSPAdministrativePolicyEngine(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	canonical := buildDescriptor(t, protectedControl, allow(0xD01F01FF, sidSYSTEM), allow(0xD01F01FF, sidAdministrators), allow(0xA0000000, p.SID()))
	s := newFakeStore(t)
	s.privileged, s.writeResult = true, canonical
	signer, err := createWith(s, testKey, p)
	if err != nil {
		t.Fatal(err)
	}
	signer.Close()
	if len(s.deleted) != 0 {
		t.Fatal("allowed representation rolled back")
	}
	assertHandlesReleased(t, s)
	s = newFakeStore(t)
	s.privileged, s.writeResult = true, canonical
	s.persisted[testKey] = buildDescriptor(t, protectedControl, allow(0xD01F01FF, sidSYSTEM), allow(0xD01F01FF, sidAdministrators), allow(genericRead, sidLocalService))
	if err := applyWith(s, testKey, p); err != nil {
		t.Fatal(err)
	}
	if err := applyWith(s, testKey, p); err != nil {
		t.Fatal(err)
	}
	if len(s.writes) != 1 || len(s.deleted) != 0 || len(s.creates) != 0 {
		t.Fatal("migration/idempotency changed")
	}
	assertHandlesReleased(t, s)
}
