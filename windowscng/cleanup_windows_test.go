//go:build windows

package windowscng

import (
	"errors"
	"strings"
	"testing"
)

// These tests exercise cleanup reporting against the in-memory fake keyStore
// and injected delete functions. They never touch a real CNG key.

func TestCleanupCreatedKeyReportsOutcome(t *testing.T) {
	cause := errors.New("NCryptFinalizeKey: hr=0x80090009")
	t.Run("delete succeeds", func(t *testing.T) {
		err := cleanupCreatedKey(cause, func() error { return nil })
		if !errors.Is(err, cause) || errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v, want cause without ErrCleanupFailed", err)
		}
		if !strings.Contains(err.Error(), "was deleted") {
			t.Fatalf("err = %v, want the delete reported", err)
		}
	})
	t.Run("delete fails", func(t *testing.T) {
		calls := 0
		deleteErr := errors.New("NCryptDeleteKey: hr=0x80090010")
		err := cleanupCreatedKey(cause, func() error { calls++; return deleteErr })
		if !errors.Is(err, cause) || !errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v, want cause and ErrCleanupFailed", err)
		}
		if !strings.Contains(err.Error(), "hr=0x80090010") || !strings.Contains(err.Error(), "hr=0x80090009") {
			t.Fatalf("err = %v, want both HRESULTs", err)
		}
		if strings.Contains(err.Error(), "was deleted") {
			t.Fatalf("err = %v claims deletion", err)
		}
		if calls != 1 {
			t.Fatalf("delete called %d times, want exactly once (no retry)", calls)
		}
	})
}

func TestCreatedKeyCleanupFailureIsReported(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	s := newFakeStore(t)
	s.privileged = true
	sd := serviceSignerDescriptor(t, genericRead) // wrong policy for p
	s.writeResult = append([]byte(nil), sd...)
	s.deleteErr = errors.New("NCryptDeleteKey: hr=0x80090010")

	_, err := loadOrCreateForService(s, testKey, p)
	if !errors.Is(err, ErrPolicyMismatch) || !errors.Is(err, ErrCleanupFailed) {
		t.Fatalf("err = %v, want ErrPolicyMismatch and ErrCleanupFailed", err)
	}
	requireDescriptorDiagnostic(t, err, sd)
	if strings.Contains(err.Error(), "was deleted") {
		t.Fatalf("err = %v claims deletion", err)
	}
	if len(s.deleted) != 1 || len(s.creates) != 1 || len(s.writes) != 0 {
		t.Fatalf("deleted=%v creates=%v writes=%v, want one delete attempt and no retry", s.deleted, s.creates, s.writes)
	}
	if _, ok := s.persisted[testKey]; !ok {
		t.Fatal("fake should keep the key whose delete failed")
	}
	assertHandlesReleased(t, s)
}

func TestCreatedKeyCleanupSuccessIsReported(t *testing.T) {
	s := newFakeStore(t)
	s.privileged = true
	s.writeResult = privilegedOnlyDescriptor(t) // wrong policy for service-signer
	_, err := loadOrCreateWithPolicy(s, testKey, PolicyServiceSigner)
	if !errors.Is(err, ErrPolicyMismatch) || errors.Is(err, ErrCleanupFailed) {
		t.Fatalf("err = %v, want ErrPolicyMismatch only", err)
	}
	if !strings.Contains(err.Error(), "was deleted") {
		t.Fatalf("err = %v, want the delete reported", err)
	}
	if _, ok := s.persisted[testKey]; ok || len(s.deleted) != 1 {
		t.Fatal("created key not deleted")
	}
	assertHandlesReleased(t, s)
}
