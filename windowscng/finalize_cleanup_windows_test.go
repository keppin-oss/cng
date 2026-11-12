//go:build windows

package windowscng

import (
	"errors"
	"strings"
	"testing"
)

// These tests drive createPersistedKeyWith against a simulated createKeyNative
// backend. They never call ncrypt.dll and never touch a real CNG key.

const (
	fakeCreateProviderHandle = uintptr(0x1000)
	fakeCreatedKeyHandle     = uintptr(0x2000)
	nteExists                = 0x8009000F // NTE_EXISTS
	nteBadFlags              = 0x80090009 // NTE_BAD_FLAGS
)

// fakeCreateOps records every native operation and the life of the single key
// handle a create can produce. Its interface has no open-by-name operation, so
// a rollback through it can only act on the handle returned by the create.
type fakeCreateOps struct {
	t *testing.T

	createStatus   uint32
	exportStatus   uint32
	sdErr          error
	finalizeStatus uint32
	deleteStatus   uint32
	privileged     bool  // what callerPrivileged reports
	privErr        error // returned by callerPrivileged
	privChecks     int   // callerPrivileged calls

	calls     []string
	live      bool // the key handle is open
	consumed  int  // successful deletes (handle consumed)
	frees     int  // NCryptFreeObject on the key handle
	finalized bool
}

func (f *fakeCreateOps) record(op string) { f.calls = append(f.calls, op) }

func (f *fakeCreateOps) requireLiveKey(op string, h uintptr) {
	f.t.Helper()
	if h != fakeCreatedKeyHandle || !f.live {
		f.t.Fatalf("%s on handle 0x%x (live=%v): use of an unknown or released handle", op, h, f.live)
	}
}

func (f *fakeCreateOps) createPersisted(provider uintptr, nameUTF16 *uint16) (uintptr, uint32) {
	f.record("create")
	if provider != fakeCreateProviderHandle || nameUTF16 == nil {
		f.t.Fatalf("create(provider=0x%x, name=%v)", provider, nameUTF16)
	}
	if f.createStatus != 0 {
		return 0, f.createStatus
	}
	f.live = true
	return fakeCreatedKeyHandle, 0
}

func (f *fakeCreateOps) setExportPolicyNone(h uintptr) uint32 {
	f.record("export")
	f.requireLiveKey("export", h)
	return f.exportStatus
}

func (f *fakeCreateOps) setSecurityDescriptor(h uintptr, sddl string) error {
	f.record("sd")
	f.requireLiveKey("sd", h)
	if sddl == "" {
		f.t.Fatal("empty SDDL")
	}
	return f.sdErr
}

func (f *fakeCreateOps) finalize(h uintptr) uint32 {
	f.record("finalize")
	f.requireLiveKey("finalize", h)
	if f.finalizeStatus == 0 {
		f.finalized = true
	}
	return f.finalizeStatus
}

func (f *fakeCreateOps) deleteKey(h uintptr) uint32 {
	f.record("delete")
	f.requireLiveKey("delete", h)
	if f.deleteStatus == 0 {
		f.live = false
		f.consumed++
	}
	return f.deleteStatus
}

func (f *fakeCreateOps) free(h uintptr) {
	f.record("free")
	f.requireLiveKey("free", h)
	f.live = false
	f.frees++
}

func (f *fakeCreateOps) callerPrivileged() (bool, error) {
	f.privChecks++
	return f.privileged, f.privErr
}

func (f *fakeCreateOps) run() (uintptr, error) {
	name := []uint16{'k', 0}
	return createPersistedKeyWith(f, fakeCreateProviderHandle, &name[0], keySecuritySDDL)
}

// requireReleasedOnce checks that the key handle is no longer open and that it
// was released exactly once, either consumed by a successful delete or freed.
func (f *fakeCreateOps) requireReleasedOnce() {
	f.t.Helper()
	if f.live || f.consumed+f.frees != 1 {
		f.t.Fatalf("live=%v consumed=%d frees=%d calls=%v, want the handle released exactly once", f.live, f.consumed, f.frees, f.calls)
	}
}

func (f *fakeCreateOps) requireCalls(want ...string) {
	f.t.Helper()
	if strings.Join(f.calls, ",") != strings.Join(want, ",") {
		f.t.Fatalf("calls = %v, want %v", f.calls, want)
	}
}

func TestCreatePersistedKeyFinalizeFailureRollback(t *testing.T) {
	t.Run("finalize fails, delete succeeds", func(t *testing.T) {
		f := &fakeCreateOps{t: t, finalizeStatus: NTEPerm}
		h, err := f.run()
		if h != 0 || err == nil || errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("h=0x%x err=%v, want zero handle and the cause without ErrCleanupFailed", h, err)
		}
		if !strings.Contains(err.Error(), "NCryptFinalizeKey: hr=0x80090010") || !strings.Contains(err.Error(), "was deleted") {
			t.Fatalf("err = %v, want the finalize cause and the deletion reported", err)
		}
		f.requireCalls("create", "export", "sd", "finalize", "delete")
		if f.consumed != 1 || f.frees != 0 {
			t.Fatalf("consumed=%d frees=%d, want the delete to consume the handle", f.consumed, f.frees)
		}
		f.requireReleasedOnce()
	})

	t.Run("NTE_PERM finalize, NTE_BAD_KEYSET delete: not persisted", func(t *testing.T) {
		f := &fakeCreateOps{t: t, finalizeStatus: NTEPerm, deleteStatus: NTEBadKeyset}
		h, err := f.run()
		if h != 0 || err == nil || errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("h=0x%x err=%v, want zero handle and no ErrCleanupFailed", h, err)
		}
		msg := err.Error()
		if !strings.Contains(msg, "NCryptFinalizeKey: hr=0x80090010") {
			t.Fatalf("err = %v, want the finalize denial preserved", err)
		}
		if !strings.Contains(msg, "not persisted") || !strings.Contains(msg, "NCryptDeleteKey: hr=0x80090016") {
			t.Fatalf("err = %v, want the not-persisted outcome with the delete status", err)
		}
		if strings.Contains(msg, "was deleted") {
			t.Fatalf("err = %v falsely claims deletion", err)
		}
		f.requireCalls("create", "export", "sd", "finalize", "delete", "free")
		f.requireReleasedOnce()
	})

	for _, tc := range []struct {
		name               string
		finalize, deleteHR uint32
	}{
		{"NTE_PERM finalize, delete denied", NTEPerm, NTEPerm},
		{"NTE_PERM finalize, delete NTE_NOT_FOUND", NTEPerm, NTENotFound},
		{"other finalize status, delete NTE_BAD_KEYSET", nteBadFlags, NTEBadKeyset},
		{"other finalize status, delete denied", nteBadFlags, NTEPerm},
	} {
		t.Run(tc.name+": ErrCleanupFailed", func(t *testing.T) {
			f := &fakeCreateOps{t: t, finalizeStatus: tc.finalize, deleteStatus: tc.deleteHR}
			h, err := f.run()
			if h != 0 || !errors.Is(err, ErrCleanupFailed) {
				t.Fatalf("h=0x%x err=%v, want ErrCleanupFailed", h, err)
			}
			msg := err.Error()
			if !strings.Contains(msg, "NCryptFinalizeKey: hr=0x") || !strings.Contains(msg, "NCryptDeleteKey: hr=0x") {
				t.Fatalf("err = %v, want both statuses", err)
			}
			if strings.Contains(msg, "was deleted") || strings.Contains(msg, "not persisted") {
				t.Fatalf("err = %v, want no claim about the key's absence", err)
			}
			f.requireCalls("create", "export", "sd", "finalize", "delete", "free")
			f.requireReleasedOnce()
			if f.privChecks != 0 {
				t.Fatalf("privilege checked %d times for statuses that never qualify", f.privChecks)
			}
		})
	}
}

// The not-persisted outcome holds only for the case verified natively, a
// non-privileged caller. A privileged caller, or a privilege check that fails,
// keeps ErrCleanupFailed (review #29, finding 2).
func TestFinalizeRuleRequiresNonPrivilegedCaller(t *testing.T) {
	for _, tc := range []struct {
		name       string
		privileged bool
		privErr    error
		notPersist bool
	}{
		{"non-privileged caller: not persisted", false, nil, true},
		{"privileged caller: ErrCleanupFailed", true, nil, false},
		{"privilege check fails: ErrCleanupFailed", false, errors.New("CheckTokenMembership failed"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeCreateOps{t: t, finalizeStatus: NTEPerm, deleteStatus: NTEBadKeyset, privileged: tc.privileged, privErr: tc.privErr}
			h, err := f.run()
			if h != 0 || err == nil {
				t.Fatalf("h=0x%x err=%v", h, err)
			}
			msg := err.Error()
			if tc.notPersist {
				if errors.Is(err, ErrCleanupFailed) || !strings.Contains(msg, "not persisted") {
					t.Fatalf("err = %v, want the not-persisted outcome", err)
				}
			} else {
				if !errors.Is(err, ErrCleanupFailed) || strings.Contains(msg, "not persisted") || strings.Contains(msg, "was deleted") {
					t.Fatalf("err = %v, want ErrCleanupFailed and no claim about the key", err)
				}
				if !strings.Contains(msg, "NCryptFinalizeKey: hr=0x80090010") || !strings.Contains(msg, "NCryptDeleteKey: hr=0x80090016") {
					t.Fatalf("err = %v, want both statuses", err)
				}
			}
			if f.privChecks != 1 {
				t.Fatalf("privilege checked %d times, want once", f.privChecks)
			}
			f.requireCalls("create", "export", "sd", "finalize", "delete", "free")
			f.requireReleasedOnce()
		})
	}
	t.Run("successful delete: no privilege check", func(t *testing.T) {
		f := &fakeCreateOps{t: t, finalizeStatus: NTEPerm, privileged: true}
		if _, err := f.run(); err == nil || errors.Is(err, ErrCleanupFailed) || !strings.Contains(err.Error(), "was deleted") {
			t.Fatalf("err = %v", err)
		}
		if f.privChecks != 0 {
			t.Fatalf("privilege checked %d times, want none", f.privChecks)
		}
	})
}

func TestCreatePersistedKeyEarlyFailures(t *testing.T) {
	t.Run("existing key: nothing deleted or freed", func(t *testing.T) {
		f := &fakeCreateOps{t: t, createStatus: nteExists}
		h, err := f.run()
		if h != 0 || err == nil || errors.Is(err, ErrCleanupFailed) || !strings.Contains(err.Error(), "NCryptCreatePersistedKey: hr=0x8009000f") {
			t.Fatalf("h=0x%x err=%v, want the create failure only", h, err)
		}
		f.requireCalls("create")
	})
	t.Run("export policy fails: handle freed, no delete", func(t *testing.T) {
		f := &fakeCreateOps{t: t, exportStatus: NTEPerm}
		h, err := f.run()
		if h != 0 || err == nil || errors.Is(err, ErrCleanupFailed) || !strings.Contains(err.Error(), "set export policy: hr=0x80090010") {
			t.Fatalf("h=0x%x err=%v", h, err)
		}
		f.requireCalls("create", "export", "free")
		f.requireReleasedOnce()
	})
	t.Run("DACL write fails: handle freed, no delete", func(t *testing.T) {
		sdErr := errors.New("before finalize: NCryptSetProperty: hr=0x80090010")
		f := &fakeCreateOps{t: t, sdErr: sdErr}
		h, err := f.run()
		if h != 0 || !errors.Is(err, sdErr) || errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("h=0x%x err=%v", h, err)
		}
		f.requireCalls("create", "export", "sd", "free")
		f.requireReleasedOnce()
	})
	t.Run("success: caller owns the open handle", func(t *testing.T) {
		f := &fakeCreateOps{t: t}
		h, err := f.run()
		if err != nil || h != fakeCreatedKeyHandle || !f.live || !f.finalized {
			t.Fatalf("h=0x%x err=%v live=%v", h, err, f.live)
		}
		f.requireCalls("create", "export", "sd", "finalize")
	})
}

// After a successful finalize the key is persisted, so NTE_BAD_KEYSET from the
// rollback delete may mean "not accessible": it must still be reported as
// ErrCleanupFailed on every path that runs after finalize.
func TestCleanupAfterFinalizeSuccessKeepsBadKeysetAsFailure(t *testing.T) {
	badKeyset := ncryptStatusError("NCryptDeleteKey", NTEBadKeyset)

	t.Run("cleanupCreatedKey", func(t *testing.T) {
		cause := errors.New("persisted DACL verification failed")
		err := cleanupCreatedKey(cause, func() error { return badKeyset })
		if !errors.Is(err, cause) || !errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v, want the cause and ErrCleanupFailed", err)
		}
	})
	t.Run("legacy LoadOrCreate validation failure", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.allowCreate = true
		o.validateErr = errors.New("persisted DACL verification failed")
		o.deleteErr = badKeyset
		_, err := loadOrCreateKeyWith(o, legacyTestKey)
		if !errors.Is(err, ErrCleanupFailed) || len(o.deletedHandles) != 1 {
			t.Fatalf("err = %v deletes=%d, want ErrCleanupFailed and one delete", err, len(o.deletedHandles))
		}
		o.requireReleased()
	})
	t.Run("policy LoadOrCreate verification failure", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.writeResult = privilegedOnlyDescriptor(t) // wrong policy for service-signer
		s.deleteErr = badKeyset
		_, err := loadOrCreateWithPolicy(s, testKey, PolicyServiceSigner)
		if !errors.Is(err, ErrPolicyMismatch) || !errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v, want ErrPolicyMismatch and ErrCleanupFailed", err)
		}
		assertHandlesReleased(t, s)
	})
}

func TestFinalizeFailureLeftNothingPersistedIsNarrow(t *testing.T) {
	statuses := []uint32{0, NTEPerm, NTEBadKeyset, NTENotFound, nteBadFlags, nteExists, 0x80070005}
	for _, f := range statuses {
		for _, d := range statuses {
			want := f == NTEPerm && d == NTEBadKeyset
			if got := finalizeFailureLeftNothingPersisted(f, d); got != want {
				t.Errorf("finalizeFailureLeftNothingPersisted(0x%x, 0x%x) = %v, want %v", f, d, got, want)
			}
		}
	}
}
