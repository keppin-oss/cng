//go:build windows

package windowscng

import (
	"errors"
	"testing"
)

func TestB4ObservedServiceSignerEngine(t *testing.T) {
	observed := observedMigrationDescriptor(t)
	s := newFakeStore(t)
	s.privileged = true
	s.writeResult = observed
	signer, err := createWith(s, testKey, PolicyServiceSigner)
	if err != nil {
		t.Fatal(err)
	}
	signer.Close()
	if len(s.creates) != 1 || len(s.deleted) != 0 {
		t.Fatal("accepted creation rolled back")
	}
	assertHandlesReleased(t, s)
	s = newFakeStore(t)
	s.privileged = true
	s.persisted[testKey] = observed
	signer, err = openWith(s, testKey, PolicyServiceSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyWith(s, testKey, PolicyServiceSigner); err != nil {
		t.Fatal(err)
	}
	p := mustServicePolicy(t, testServiceName)
	if _, err := openWith(s, testKey, p); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("LS treated as service-SID: %v", err)
	}
	assertNoMutation(t, s)
	assertHandlesReleased(t, s)
	// Simulated migration of the observed service-signer state; no claim of native
	// Apply verification. It must still read back a fresh handle.
	s = newFakeStore(t)
	s.privileged = true
	s.persisted[testKey] = observed
	s.writeResult = serviceSIDDescriptor(t, p.SID(), 0x801200A9)
	if err := applyWith(s, testKey, p); err != nil {
		t.Fatal(err)
	}
	if s.opens != 2 || len(s.writes) != 1 || len(s.creates) != 0 || len(s.deleted) != 0 {
		t.Fatal("migration lifecycle changed")
	}
	if err := applyWith(s, testKey, p); err != nil {
		t.Fatal(err)
	}
	if len(s.writes) != 1 {
		t.Fatal("migration not idempotent")
	}
	assertHandlesReleased(t, s)
}

func TestB4ServiceSignerFailureProtection(t *testing.T) {
	bad := serviceSignerDescriptor(t, 0x801600A9) // observed mask plus WRITE_DAC
	s := newFakeStore(t)
	s.privileged = true
	s.writeResult = bad
	_, err := createWith(s, testKey, PolicyServiceSigner)
	if !errors.Is(err, ErrPolicyMismatch) || len(s.deleted) != 1 {
		t.Fatalf("unsafe new key: %v", err)
	}
	requireDescriptorDiagnostic(t, err, bad)
	assertHandlesReleased(t, s)
	s = newFakeStore(t)
	s.privileged = true
	s.persisted[testKey] = bad
	_, err = openWith(s, testKey, PolicyServiceSigner)
	if !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("unsafe existing key accepted: %v", err)
	}
	requireDescriptorDiagnostic(t, err, bad)
	assertNoMutation(t, s)
	assertHandlesReleased(t, s)
	// A failed write on an existing service-signer key never deletes or rolls back it.
	s = newFakeStore(t)
	s.privileged = true
	s.persisted[testKey] = observedMigrationDescriptor(t)
	s.writeResult = bad
	err = applyWith(s, testKey, mustServicePolicy(t, testServiceName))
	if !errors.Is(err, ErrPostWriteVerification) || len(s.writes) != 1 || len(s.deleted) != 0 || len(s.creates) != 0 {
		t.Fatalf("post-write behavior changed: %v", err)
	}
	requireDescriptorDiagnostic(t, err, bad)
	assertHandlesReleased(t, s)
}
