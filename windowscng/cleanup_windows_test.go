//go:build windows

package windowscng

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"
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

// ---------------------------------------------------------------------------
// R2: legacy Open / LoadOrCreate against a simulated legacyKeyOps backend.
//
// fakeLegacyOps models provider and key handles as opaque integers bound to
// key objects with an identity, independent of the name under which they are
// currently visible. It never calls ncrypt.dll: openKeyWith and
// loadOrCreateKeyWith reach the backend only through the ops they are given,
// and every operation that a test does not expect fails the test.
// ---------------------------------------------------------------------------

type fakeLegacyObject struct {
	id      int
	name    string
	present bool // persisted in the simulated store
}

type fakeLegacyHandle struct {
	provider bool
	obj      *fakeLegacyObject // nil for provider handles
	live     bool
	bySigner bool // ownership transferred to a signer
}

type fakeLegacyOps struct {
	t *testing.T

	byName  map[string]*fakeLegacyObject // current name binding
	handles map[uintptr]*fakeLegacyHandle
	next    uintptr
	nextObj int

	allowCreate  bool
	openHR       uintptr // forced NCryptOpenKey result, 0 = look up by name
	createErr    error
	beforeCreate func(o *fakeLegacyOps)
	afterCreate  func(o *fakeLegacyOps)
	validateErr  error
	signerErr    error
	deleteErr    error

	opens, creates, validates, signerCalls, frees int
	deletedHandles                                []uintptr
	created                                       *fakeLegacyObject
	createdHandle                                 uintptr
}

func newFakeLegacyOps(t *testing.T) *fakeLegacyOps {
	return &fakeLegacyOps{t: t, byName: map[string]*fakeLegacyObject{}, handles: map[uintptr]*fakeLegacyHandle{}, next: 0x1000}
}

// persist adds a key object visible under name, as if created elsewhere.
func (o *fakeLegacyOps) persist(name string) *fakeLegacyObject {
	o.nextObj++
	obj := &fakeLegacyObject{id: o.nextObj, name: name, present: true}
	o.byName[name] = obj
	return obj
}

func (o *fakeLegacyOps) newHandle(h *fakeLegacyHandle) uintptr {
	o.next += 0x10
	h.live = true
	o.handles[o.next] = h
	return o.next
}

func (o *fakeLegacyOps) mustLive(h uintptr, what string) *fakeLegacyHandle {
	o.t.Helper()
	hd := o.handles[h]
	if hd == nil || !hd.live {
		o.t.Fatalf("%s on handle 0x%x that is not live (use after free/consume)", what, h)
	}
	if hd.bySigner {
		o.t.Fatalf("%s on handle 0x%x owned by a signer", what, h)
	}
	return hd
}

func utf16PtrToString(p *uint16) string {
	var s []uint16
	for ptr := unsafe.Pointer(p); *(*uint16)(ptr) != 0; ptr = unsafe.Add(ptr, 2) {
		s = append(s, *(*uint16)(ptr))
	}
	return string(utf16.Decode(s))
}

func (o *fakeLegacyOps) openProvider() (uintptr, error) {
	return o.newHandle(&fakeLegacyHandle{provider: true}), nil
}

func (o *fakeLegacyOps) openKey(provider uintptr, nameUTF16 *uint16) (uintptr, uintptr) {
	o.mustLive(provider, "openKey")
	o.opens++
	if o.openHR != 0 {
		return 0, o.openHR
	}
	obj := o.byName[utf16PtrToString(nameUTF16)]
	if obj == nil || !obj.present {
		return 0, nteNotFound
	}
	return o.newHandle(&fakeLegacyHandle{obj: obj}), 0
}

func (o *fakeLegacyOps) createKey(provider uintptr, nameUTF16 *uint16) (uintptr, error) {
	o.mustLive(provider, "createKey")
	o.creates++
	if !o.allowCreate {
		o.t.Fatal("unexpected createKey")
	}
	if o.beforeCreate != nil {
		o.beforeCreate(o)
	}
	if o.createErr != nil {
		return 0, o.createErr
	}
	name := utf16PtrToString(nameUTF16)
	if obj := o.byName[name]; obj != nil && obj.present {
		// No overwrite flag: an existing key of the same name is never replaced.
		return 0, errors.New("NCryptCreatePersistedKey: hr=0x8009000f")
	}
	obj := o.persist(name)
	o.created = obj
	o.createdHandle = o.newHandle(&fakeLegacyHandle{obj: obj})
	if o.afterCreate != nil {
		o.afterCreate(o)
	}
	return o.createdHandle, nil
}

func (o *fakeLegacyOps) validate(keyHandle uintptr) error {
	o.mustLive(keyHandle, "validate")
	o.validates++
	return o.validateErr
}

func (o *fakeLegacyOps) newSigner(provider, keyHandle uintptr, name string) (Signer, error) {
	o.mustLive(provider, "newSigner")
	o.mustLive(keyHandle, "newSigner")
	o.signerCalls++
	if o.signerErr != nil {
		// Like newCNGSigner: export fails before the signer takes the handles.
		return nil, fmt.Errorf("export public key for %s: %w", name, o.signerErr)
	}
	o.handles[provider].bySigner = true
	o.handles[keyHandle].bySigner = true
	return &fakeLegacySigner{ops: o, provider: provider, key: keyHandle}, nil
}

// deleteCreated reuses the production handle contract (deleteCNGKeyHandle)
// with a simulated NCryptDeleteKey that removes exactly the object behind the
// handle, whatever name is currently bound.
func (o *fakeLegacyOps) deleteCreated(keyHandle uintptr) error {
	o.mustLive(keyHandle, "deleteCreated")
	o.deletedHandles = append(o.deletedHandles, keyHandle)
	return deleteCNGKeyHandle(keyHandle,
		func(h uintptr) error {
			if o.deleteErr != nil {
				return o.deleteErr
			}
			hd := o.handles[h]
			hd.obj.present = false
			if o.byName[hd.obj.name] == hd.obj {
				delete(o.byName, hd.obj.name)
			}
			hd.live = false // consumed by a successful delete
			return nil
		},
		o.free,
	)
}

func (o *fakeLegacyOps) free(h uintptr) {
	o.t.Helper()
	o.mustLive(h, "free")
	o.frees++
	o.handles[h].live = false
}

func (o *fakeLegacyOps) requireReleased() {
	o.t.Helper()
	n := 0
	for _, hd := range o.handles {
		if hd.live && !hd.bySigner {
			n++
		}
	}
	if n != 0 {
		o.t.Fatalf("%d handle(s) leaked", n)
	}
}

type fakeLegacySigner struct {
	ops           *fakeLegacyOps
	provider, key uintptr
}

func (s *fakeLegacySigner) Public() crypto.PublicKey {
	return &ecdsa.PublicKey{Curve: elliptic.P256()}
}

func (s *fakeLegacySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("fake signer")
}

func (s *fakeLegacySigner) Close() error {
	for _, h := range []uintptr{s.key, s.provider} {
		hd := s.ops.handles[h]
		if !hd.live || !hd.bySigner {
			s.ops.t.Fatalf("signer releasing handle 0x%x it does not own", h)
		}
		hd.live = false
	}
	return nil
}

const legacyTestKey = "Example.Legacy.Key.v1"

var errLegacyExport = errors.New("NCryptExportKey: hr=0x80090009")

// requireNCryptNotLoaded is a runtime isolation guard: if ncrypt.dll has not
// been loaded by this test process when the test starts, it must still not be
// loaded when the test ends, which proves the test made no NCrypt call. When
// another test already loaded it, the guard is inconclusive and says so.
func requireNCryptNotLoaded(t *testing.T) {
	t.Helper()
	if ncrypt.dll != nil {
		t.Log("isolation guard inconclusive: ncrypt.dll was already loaded by an earlier test")
		return
	}
	t.Cleanup(func() {
		if ncrypt.dll != nil {
			t.Fatal("ncrypt.dll was loaded during a synthetic test")
		}
		t.Log("isolation guard: ncrypt.dll was never loaded")
	})
}

func TestLegacyLoadOrCreateR2(t *testing.T) {
	requireNCryptNotLoaded(t)
	t.Run("new key, export fails, delete succeeds", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.allowCreate = true
		o.signerErr = errLegacyExport
		signer, err := loadOrCreateKeyWith(o, legacyTestKey)
		if signer != nil {
			t.Fatal("signer returned on failure")
		}
		if !errors.Is(err, errLegacyExport) || errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v, want the export cause without ErrCleanupFailed", err)
		}
		if !strings.Contains(err.Error(), "was deleted") {
			t.Fatalf("err = %v, want the delete reported", err)
		}
		if len(o.deletedHandles) != 1 || o.deletedHandles[0] != o.createdHandle {
			t.Fatalf("deleted handles = %v, want exactly the created handle 0x%x", o.deletedHandles, o.createdHandle)
		}
		if o.created.present || o.byName[legacyTestKey] != nil {
			t.Fatal("created key still persisted")
		}
		if o.frees != 1 {
			t.Fatalf("frees = %d, want 1 (provider only; the delete consumed the key handle)", o.frees)
		}
		o.requireReleased()
	})
	t.Run("new key, export fails, delete fails", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.allowCreate = true
		o.signerErr = errLegacyExport
		o.deleteErr = errors.New("NCryptDeleteKey: hr=0x80090010")
		_, err := loadOrCreateKeyWith(o, legacyTestKey)
		if !errors.Is(err, errLegacyExport) || !errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v, want the export cause and ErrCleanupFailed", err)
		}
		if !strings.Contains(err.Error(), "hr=0x80090010") || strings.Contains(err.Error(), "was deleted") {
			t.Fatalf("err = %v, want the delete failure reported and no deletion claimed", err)
		}
		if len(o.deletedHandles) != 1 {
			t.Fatalf("deletes = %d, want exactly one attempt (no retry)", len(o.deletedHandles))
		}
		if !o.created.present {
			t.Fatal("fake should keep the key whose delete failed")
		}
		if o.frees != 2 {
			t.Fatalf("frees = %d, want 2 (key once after the failed delete, provider once)", o.frees)
		}
		o.requireReleased()
	})
	t.Run("pre-existing key, export fails: no delete", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		existing := o.persist(legacyTestKey)
		o.signerErr = errLegacyExport
		_, err := loadOrCreateKeyWith(o, legacyTestKey)
		if !errors.Is(err, errLegacyExport) || errors.Is(err, ErrCleanupFailed) || strings.Contains(err.Error(), "was deleted") {
			t.Fatalf("err = %v, want only the export cause", err)
		}
		if o.creates != 0 || len(o.deletedHandles) != 0 || !existing.present {
			t.Fatalf("creates=%d deletes=%d present=%v, want the existing key untouched", o.creates, len(o.deletedHandles), existing.present)
		}
		if o.frees != 2 {
			t.Fatalf("frees = %d, want 2 (key and provider)", o.frees)
		}
		o.requireReleased()
	})
	t.Run("pre-existing key, validation fails: no delete", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		existing := o.persist(legacyTestKey)
		o.validateErr = errors.New("export policy permits export")
		if _, err := loadOrCreateKeyWith(o, legacyTestKey); err == nil || errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v", err)
		}
		if o.creates != 0 || len(o.deletedHandles) != 0 || !existing.present || o.signerCalls != 0 {
			t.Fatal("existing key must not be created, deleted or exposed")
		}
		o.requireReleased()
	})
	t.Run("open fails, concurrent create collides: no delete", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.allowCreate = true
		var concurrent *fakeLegacyObject
		o.beforeCreate = func(o *fakeLegacyOps) { concurrent = o.persist(legacyTestKey) }
		_, err := loadOrCreateKeyWith(o, legacyTestKey)
		if err == nil || errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v, want the create collision", err)
		}
		if len(o.deletedHandles) != 0 || !concurrent.present || o.byName[legacyTestKey] != concurrent {
			t.Fatal("the concurrently created key must be preserved")
		}
		if o.validates != 0 || o.signerCalls != 0 || o.frees != 1 {
			t.Fatalf("validates=%d signerCalls=%d frees=%d, want 0/0/1", o.validates, o.signerCalls, o.frees)
		}
		o.requireReleased()
	})
	t.Run("create/finalize failure: no further delete", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.allowCreate = true
		// createPersistedKey has already reported its own finalize rollback.
		o.createErr = cleanupCreatedKey(errors.New("NCryptFinalizeKey: hr=0x80090009"), func() error { return errors.New("NCryptDeleteKey: hr=0x80090010") })
		_, err := loadOrCreateKeyWith(o, legacyTestKey)
		if !errors.Is(err, ErrCleanupFailed) || !strings.Contains(err.Error(), "NCryptFinalizeKey") {
			t.Fatalf("err = %v, want the finalize error passed through", err)
		}
		if len(o.deletedHandles) != 0 || o.validates != 0 || o.signerCalls != 0 {
			t.Fatal("no further delete, validation or signer after a failed create")
		}
		o.requireReleased()
	})
	t.Run("created key failing validation is deleted", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.allowCreate = true
		cause := errors.New("persisted DACL verification failed")
		o.validateErr = cause
		_, err := loadOrCreateKeyWith(o, legacyTestKey)
		if !errors.Is(err, cause) || errors.Is(err, ErrCleanupFailed) || !strings.Contains(err.Error(), "was deleted") {
			t.Fatalf("err = %v, want the validation cause and the deletion reported", err)
		}
		if len(o.deletedHandles) != 1 || o.deletedHandles[0] != o.createdHandle || o.created.present || o.signerCalls != 0 {
			t.Fatal("created key not rolled back through its handle")
		}
		o.requireReleased()
	})
	t.Run("created key failing validation, delete fails", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.allowCreate = true
		o.validateErr = errors.New("persisted DACL verification failed")
		o.deleteErr = errors.New("NCryptDeleteKey: hr=0x80090010")
		_, err := loadOrCreateKeyWith(o, legacyTestKey)
		if !errors.Is(err, ErrCleanupFailed) || len(o.deletedHandles) != 1 {
			t.Fatalf("err = %v deletes=%d, want ErrCleanupFailed and one delete", err, len(o.deletedHandles))
		}
		o.requireReleased()
	})
	t.Run("rollback uses the original handle, not the name", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.allowCreate = true
		o.signerErr = errLegacyExport
		var replacement *fakeLegacyObject
		// After the create, another object becomes visible under the same
		// name (simulated replacement).
		o.afterCreate = func(o *fakeLegacyOps) {
			replacement = &fakeLegacyObject{id: 999, name: legacyTestKey, present: true}
			o.byName[legacyTestKey] = replacement
		}
		if _, err := loadOrCreateKeyWith(o, legacyTestKey); !errors.Is(err, errLegacyExport) {
			t.Fatalf("err = %v", err)
		}
		if o.created.present {
			t.Fatal("the object created by the call was not deleted")
		}
		if !replacement.present || o.byName[legacyTestKey] != replacement {
			t.Fatal("the object now bound to the name was deleted")
		}
		if o.opens != 1 {
			t.Fatalf("opens = %d, want 1: rollback must not reopen by name", o.opens)
		}
		o.requireReleased()
	})
	t.Run("success transfers handle ownership to the signer", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.allowCreate = true
		signer, err := loadOrCreateKeyWith(o, legacyTestKey)
		if err != nil || signer == nil {
			t.Fatalf("loadOrCreateKeyWith: %v", err)
		}
		if len(o.deletedHandles) != 0 || o.frees != 0 || !o.created.present {
			t.Fatalf("deletes=%d frees=%d, want no rollback and no release on success", len(o.deletedHandles), o.frees)
		}
		if fs := signer.(*fakeLegacySigner); fs.key != o.createdHandle {
			t.Fatal("signer does not own the created key handle")
		}
		o.requireReleased()
		if err := signer.Close(); err != nil {
			t.Fatal(err)
		}
		if !o.created.present {
			t.Fatal("Close must not delete the key")
		}
	})
	t.Run("success on pre-existing key", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		existing := o.persist(legacyTestKey)
		signer, err := loadOrCreateKeyWith(o, legacyTestKey)
		if err != nil || signer == nil || o.creates != 0 || len(o.deletedHandles) != 0 || !existing.present {
			t.Fatalf("err = %v creates=%d deletes=%d", err, o.creates, len(o.deletedHandles))
		}
		o.requireReleased()
		_ = signer.Close()
	})
}

func TestLegacyOpenNeverCreatesOrDeletes(t *testing.T) {
	requireNCryptNotLoaded(t)
	t.Run("not found", func(t *testing.T) {
		o := newFakeLegacyOps(t) // allowCreate is false: any create fails the test
		_, err := openKeyWith(o, legacyTestKey)
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("err = %v, want ErrKeyNotFound", err)
		}
		if o.creates != 0 || len(o.deletedHandles) != 0 || o.frees != 1 {
			t.Fatalf("creates=%d deletes=%d frees=%d", o.creates, len(o.deletedHandles), o.frees)
		}
		o.requireReleased()
	})
	t.Run("other open failure", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.openHR = 0x80090010 // NTE_PERM
		_, err := openKeyWith(o, legacyTestKey)
		if err == nil || errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("err = %v, want a non-not-found open error", err)
		}
		if o.creates != 0 || len(o.deletedHandles) != 0 {
			t.Fatal("Open must not create or delete")
		}
		o.requireReleased()
	})
	t.Run("export fails", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		existing := o.persist(legacyTestKey)
		o.signerErr = errLegacyExport
		_, err := openKeyWith(o, legacyTestKey)
		if !errors.Is(err, errLegacyExport) || errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v, want only the export cause", err)
		}
		if o.creates != 0 || len(o.deletedHandles) != 0 || !existing.present || o.frees != 2 {
			t.Fatalf("creates=%d deletes=%d frees=%d", o.creates, len(o.deletedHandles), o.frees)
		}
		o.requireReleased()
	})
	t.Run("success", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.persist(legacyTestKey)
		signer, err := openKeyWith(o, legacyTestKey)
		if err != nil || signer == nil || o.frees != 0 {
			t.Fatalf("err = %v frees=%d", err, o.frees)
		}
		o.requireReleased()
		_ = signer.Close()
	})
}

// TestLegacyZeroSizeExportComposition feeds the error that exportPublicKeyWith
// really returns for a zero-size query into the legacy newSigner seam, where
// newCNGSigner would surface it, and checks that the R2 ownership rules apply.
func TestLegacyZeroSizeExportComposition(t *testing.T) {
	requireNCryptNotLoaded(t)
	zeroErr := zeroSizeExportError(t)
	t.Run("new key, delete succeeds", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.allowCreate = true
		o.signerErr = zeroErr
		signer, err := loadOrCreateKeyWith(o, legacyTestKey)
		if signer != nil || !errors.Is(err, zeroErr) || errors.Is(err, ErrCleanupFailed) || !strings.Contains(err.Error(), "was deleted") {
			t.Fatalf("signer=%v err = %v, want the zero-size cause and the deletion reported", signer, err)
		}
		if len(o.deletedHandles) != 1 || o.deletedHandles[0] != o.createdHandle || o.created.present || o.frees != 1 {
			t.Fatalf("deletes=%v frees=%d, want one delete on the created handle and the provider freed once", o.deletedHandles, o.frees)
		}
		o.requireReleased()
	})
	t.Run("new key, delete fails", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.allowCreate = true
		o.signerErr = zeroErr
		o.deleteErr = errors.New("NCryptDeleteKey: hr=0x80090010")
		_, err := loadOrCreateKeyWith(o, legacyTestKey)
		if !errors.Is(err, zeroErr) || !errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v, want the zero-size cause and ErrCleanupFailed", err)
		}
		if len(o.deletedHandles) != 1 || !o.created.present || o.frees != 2 {
			t.Fatalf("deletes=%d frees=%d, want one delete, key freed once after it, provider once", len(o.deletedHandles), o.frees)
		}
		o.requireReleased()
	})
	t.Run("pre-existing key: no delete", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		existing := o.persist(legacyTestKey)
		o.signerErr = zeroErr
		_, err := loadOrCreateKeyWith(o, legacyTestKey)
		if !errors.Is(err, zeroErr) || errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v", err)
		}
		if o.creates != 0 || len(o.deletedHandles) != 0 || !existing.present || o.frees != 2 {
			t.Fatalf("creates=%d deletes=%d frees=%d", o.creates, len(o.deletedHandles), o.frees)
		}
		o.requireReleased()
	})
	t.Run("Open: no create or delete", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		existing := o.persist(legacyTestKey)
		o.signerErr = zeroErr
		_, err := openKeyWith(o, legacyTestKey)
		if !errors.Is(err, zeroErr) || errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v", err)
		}
		if o.creates != 0 || len(o.deletedHandles) != 0 || !existing.present || o.frees != 2 {
			t.Fatalf("creates=%d deletes=%d frees=%d", o.creates, len(o.deletedHandles), o.frees)
		}
		o.requireReleased()
	})
	t.Run("identity: replacement under the same name survives", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.allowCreate = true
		o.signerErr = zeroErr
		var replacement *fakeLegacyObject
		o.afterCreate = func(o *fakeLegacyOps) {
			replacement = &fakeLegacyObject{id: 999, name: legacyTestKey, present: true}
			o.byName[legacyTestKey] = replacement
		}
		if _, err := loadOrCreateKeyWith(o, legacyTestKey); !errors.Is(err, zeroErr) {
			t.Fatalf("err = %v", err)
		}
		if o.created.present || !replacement.present || o.byName[legacyTestKey] != replacement || o.opens != 1 {
			t.Fatal("rollback must delete the created object through its handle only")
		}
		o.requireReleased()
	})
	t.Run("collision: concurrent key preserved", func(t *testing.T) {
		o := newFakeLegacyOps(t)
		o.allowCreate = true
		o.signerErr = zeroErr // never reached: create fails first
		var concurrent *fakeLegacyObject
		o.beforeCreate = func(o *fakeLegacyOps) { concurrent = o.persist(legacyTestKey) }
		if _, err := loadOrCreateKeyWith(o, legacyTestKey); err == nil {
			t.Fatal("want the create collision")
		}
		if len(o.deletedHandles) != 0 || !concurrent.present || o.signerCalls != 0 {
			t.Fatal("collision must not delete or build a signer")
		}
		o.requireReleased()
	})
}
