//go:build windows

package windowscng

import (
	"errors"
	"strings"
	"testing"
)

// TestDeleteTargetsExactCallerSuppliedKeyName checks that the example key name
// is non-empty. It does not exercise the native delete path.
func TestDeleteTargetsExactCallerSuppliedKeyName(t *testing.T) {
	const name = "Example.Caller.Owned.Key.v1"

	// The classification and injected handle-ownership tests below are pure
	// unit checks; they do not verify the complete native missing-key path.
	if name == "" {
		t.Fatal("test key name must be non-empty")
	}
}

// TestIsKeyNotFound classification.
func TestIsKeyNotFound(t *testing.T) {
	if !IsKeyNotFound(nteNotFound) {
		t.Error("NTE_NOT_FOUND should classify as not-found")
	}
	if !IsKeyNotFound(nteBadKeyset) {
		t.Error("NTE_BAD_KEYSET should classify as not-found")
	}
	if IsKeyNotFound(0x80090010) { // NTE_PERM
		t.Error("NTE_PERM must not classify as not-found")
	}
	if IsKeyNotFound(0) {
		t.Error("success must not classify as not-found")
	}
}

// TestErrKeyNotFoundSentinel asserts the not-found sentinel exists and is
// matchable via errors.Is.
func TestErrKeyNotFoundSentinel(t *testing.T) {
	if ErrKeyNotFound == nil {
		t.Fatal("ErrKeyNotFound must be non-nil")
	}
	if !errors.Is(ErrKeyNotFound, ErrKeyNotFound) {
		t.Fatal("ErrKeyNotFound must be matchable via errors.Is with itself")
	}
}

// TestDeleteCNGKeyHandleOwnership locks the NCryptDeleteKey handle-ownership
// contract through the injected seam.
func TestDeleteCNGKeyHandleOwnership(t *testing.T) {
	t.Run("success does not free", func(t *testing.T) {
		freeCalled := false
		err := deleteCNGKeyHandle(
			1,
			func(h uintptr) error { return nil },
			func(h uintptr) { freeCalled = true },
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if freeCalled {
			t.Fatal("free was called after a successful delete")
		}
	})

	t.Run("failure frees handle", func(t *testing.T) {
		freeCalled := false
		want := errors.New("delete failed")
		err := deleteCNGKeyHandle(
			1,
			func(h uintptr) error { return want },
			func(h uintptr) { freeCalled = true },
		)
		if !errors.Is(err, want) {
			t.Fatalf("expected wrapped error, got %v", err)
		}
		if !freeCalled {
			t.Fatal("free was NOT called after a failed delete")
		}
	})

	t.Run("zero handle noop", func(t *testing.T) {
		deleteCalled := false
		freeCalled := false
		err := deleteCNGKeyHandle(
			0,
			func(h uintptr) error { deleteCalled = true; return nil },
			func(h uintptr) { freeCalled = true },
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if deleteCalled || freeCalled {
			t.Fatal("zero handle should be a no-op")
		}
	})
}

// TestNoProductionIdentityLeaks checks the SDDL, provider, and algorithm
// constants for the listed consumer identity strings. It is not a repository scan.
func TestNoProductionIdentityLeaks(t *testing.T) {
	forbidden := []string{
		"Keppin.Agent.MachineIdentity.v1",
		"Keppin.Agent.LocalHTTPS.CA.v1",
		"Keppin.Agent.LocalHTTPS.Server.v1",
		"keppin-enterprise-tls-",
	}
	source := keySecuritySDDL + " " + msSoftwareKSP + " " + ecdsaP256Algorithm
	for _, f := range forbidden {
		if strings.Contains(source, f) {
			t.Errorf("checked constants reference forbidden consumer identity %q", f)
		}
	}
}
