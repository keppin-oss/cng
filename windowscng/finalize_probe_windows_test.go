//go:build windows && cng_finalize_probe

package windowscng

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// TestFinalizeFailureProbe is the native check behind
// finalizeFailureLeftNothingPersisted (issue #17). It is gated behind the
// cng_finalize_probe build tag and is never run by `go test ./...`.
//
// It runs in three separate processes, selected by KEPPIN_FINALIZE_PROBE_PHASE:
//
//  1. observe (elevated Administrator or SYSTEM): the unique temporary name in
//     KEPPIN_FINALIZE_PROBE_NAME must be absent, both by enumeration of the
//     machine keys of the Microsoft Software KSP and by NCryptOpenKey on the
//     exact name. As a positive control of the observation, the phase creates
//     the temporary key "<name>.Control" through LoadOrCreate, requires both
//     methods to find it, then deletes it and requires both methods to stop
//     finding it. It refuses to run if that control key already exists.
//  2. run (Administrator with a UAC-filtered token): the production create
//     path (create -> export policy -> DACL -> finalize) runs with the native
//     statuses of finalize and of the rollback delete logged.
//  3. observe again, elevated: the name must still be absent.
//
// Only the absence seen by an elevated caller counts: with the filtered token
// NTE_BAD_KEYSET cannot distinguish an absent key from an inaccessible one.
func TestFinalizeFailureProbe(t *testing.T) {
	name := os.Getenv("KEPPIN_FINALIZE_PROBE_NAME")
	if len(name) < len("Keppin.OSS.Test.") || name[:len("Keppin.OSS.Test.")] != "Keppin.OSS.Test." {
		t.Fatal("KEPPIN_FINALIZE_PROBE_NAME must be a unique temporary name starting with Keppin.OSS.Test.")
	}
	privileged, err := nativeKeyStore{}.callerPrivileged()
	if err != nil {
		t.Fatalf("privilege check: %v", err)
	}
	t.Logf("name=%q privileged=%v", name, privileged)

	switch phase := os.Getenv("KEPPIN_FINALIZE_PROBE_PHASE"); phase {
	case "observe":
		if !privileged {
			t.Fatal("observe must run elevated: a filtered token cannot distinguish absent from inaccessible")
		}
		control := probeCreateControlKey(t, name+".Control")
		enumerated := probeEnumMachineKeys(t)
		ctrlEnum, ctrlOpen := enumerated[control], probeOpenStatus(t, control)
		t.Logf("control %q: enumerated=%v NCryptOpenKey hr=0x%x", control, ctrlEnum, ctrlOpen)
		if !ctrlEnum || ctrlOpen != 0 {
			t.Fatal("positive control not observed by both methods: the observation is not valid")
		}
		nameEnum, nameOpen := enumerated[name], probeOpenStatus(t, name)
		t.Logf("probe %q: enumerated=%v NCryptOpenKey hr=0x%x (%d machine keys enumerated)", name, nameEnum, nameOpen, len(enumerated))
		if nameEnum || !IsKeyNotFound(uintptr(nameOpen)) {
			t.Fatalf("RESULT: %q is PRESENT or not provably absent", name)
		}
		t.Logf("RESULT: %q is ABSENT (enumeration and exact open)", name)

	case "run":
		if privileged {
			t.Fatal("run must use a UAC-filtered token, not an elevated one")
		}
		if hr := probeOpenStatus(t, name); hr == 0 {
			t.Fatalf("%q already exists: refusing to run", name)
		}
		provider, err := openProvider()
		if err != nil {
			t.Fatal(err)
		}
		defer procNCryptFreeObject.Call(provider)
		nameUTF16, err := syscall.UTF16PtrFromString(name)
		if err != nil {
			t.Fatal(err)
		}
		rec := &recordingCreateOps{createKeyNative: nativeCreateKeyOps{}}
		h, err := createPersistedKeyWith(rec, provider, nameUTF16, keySecuritySDDL)
		t.Logf("create hr=0x%x export hr=0x%x finalize hr=0x%x delete hr=0x%x frees=%d", rec.createHR, rec.exportHR, rec.finalizeHR, rec.deleteHR, rec.frees)
		t.Logf("error: %v", err)
		t.Logf("errors.Is(err, ErrCleanupFailed) = %v", errors.Is(err, ErrCleanupFailed))
		if err == nil {
			// Not the case under test: the key exists. Delete it through the
			// same handle so that the probe leaves nothing behind.
			t.Errorf("finalize succeeded with a filtered token; delete: %v", deletePersistedKey(h))
		}

	default:
		t.Fatal("KEPPIN_FINALIZE_PROBE_PHASE must be observe or run")
	}
}

// recordingCreateOps logs the native statuses of a production create.
type recordingCreateOps struct {
	createKeyNative
	createHR, exportHR, finalizeHR, deleteHR uint32
	frees                                    int
}

func (r *recordingCreateOps) createPersisted(p uintptr, n *uint16) (uintptr, uint32) {
	h, hr := r.createKeyNative.createPersisted(p, n)
	r.createHR = hr
	return h, hr
}

func (r *recordingCreateOps) setExportPolicyNone(h uintptr) uint32 {
	r.exportHR = r.createKeyNative.setExportPolicyNone(h)
	return r.exportHR
}

func (r *recordingCreateOps) finalize(h uintptr) uint32 {
	r.finalizeHR = r.createKeyNative.finalize(h)
	return r.finalizeHR
}

func (r *recordingCreateOps) deleteKey(h uintptr) uint32 {
	r.deleteHR = r.createKeyNative.deleteKey(h)
	return r.deleteHR
}

func (r *recordingCreateOps) free(h uintptr) {
	r.frees++
	r.createKeyNative.free(h)
}

var (
	procNCryptEnumKeys   = ncrypt.NewProc("NCryptEnumKeys")
	procNCryptFreeBuffer = ncrypt.NewProc("NCryptFreeBuffer")
)

const nteNoMoreItems = 0x8009002A

// ncryptKeyName mirrors NCryptKeyName.
type ncryptKeyName struct {
	name          *uint16
	algID         *uint16
	legacyKeySpec uint32
	flags         uint32
}

// probeEnumMachineKeys returns the names of all machine keys of the Microsoft
// Software KSP visible to the caller.
func probeEnumMachineKeys(t *testing.T) map[string]bool {
	t.Helper()
	provider, err := openProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer procNCryptFreeObject.Call(provider)
	out := map[string]bool{}
	var state uintptr
	defer func() {
		if state != 0 {
			procNCryptFreeBuffer.Call(state)
		}
	}()
	for {
		var kn *ncryptKeyName
		hr := ncryptStatus(procNCryptEnumKeys.Call(
			provider, 0,
			uintptr(unsafe.Pointer(&kn)),
			uintptr(unsafe.Pointer(&state)),
			uintptr(ncryptMachineKeyFlag|ncryptSilentFlag),
		))
		if hr == nteNoMoreItems {
			return out
		}
		if hr != 0 {
			t.Fatalf("NCryptEnumKeys: hr=0x%x", hr)
		}
		out[syscall.UTF16ToString(unsafe.Slice(kn.name, probeUTF16Len(kn.name)))] = true
		procNCryptFreeBuffer.Call(uintptr(unsafe.Pointer(kn)))
	}
}

func probeUTF16Len(p *uint16) int {
	n := 0
	for ptr := unsafe.Pointer(p); *(*uint16)(ptr) != 0; n++ {
		ptr = unsafe.Add(ptr, 2)
	}
	return n
}

// probeCreateControlKey creates the temporary control key, which must not
// already exist, and registers its deletion, checked by enumeration and exact
// open, for the end of the test. Elevated callers only.
func probeCreateControlKey(t *testing.T, control string) string {
	t.Helper()
	if hr := probeOpenStatus(t, control); !IsKeyNotFound(uintptr(hr)) {
		t.Fatalf("control key %q already exists or cannot be checked (NCryptOpenKey hr=0x%x): refusing to touch it", control, hr)
	}
	s, err := LoadOrCreate(control)
	if err != nil {
		t.Fatalf("create control key %q: %v", control, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close control signer: %v", err)
	}
	t.Logf("control key %q created", control)
	t.Cleanup(func() {
		if err := Delete(control); err != nil {
			t.Errorf("delete control key %q: %v", control, err)
			return
		}
		enumerated := probeEnumMachineKeys(t)
		hr := probeOpenStatus(t, control)
		t.Logf("control key %q deleted: enumerated=%v NCryptOpenKey hr=0x%x", control, enumerated[control], hr)
		if enumerated[control] || !IsKeyNotFound(uintptr(hr)) {
			t.Errorf("control key %q still observed after delete", control)
		}
	})
	return control
}

// probeOpenStatus runs NCryptOpenKey on the exact name and releases the handle.
func probeOpenStatus(t *testing.T, name string) uint32 {
	t.Helper()
	provider, err := openProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer procNCryptFreeObject.Call(provider)
	nameUTF16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	var key uintptr
	hr := ncryptStatus(procNCryptOpenKey.Call(provider, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(nameUTF16)), 0, uintptr(openKeyFlags)))
	if hr == 0 {
		procNCryptFreeObject.Call(key)
	}
	return hr
}
