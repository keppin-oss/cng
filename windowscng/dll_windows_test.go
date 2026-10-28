//go:build windows

package windowscng

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"testing"
	"unsafe"
)

// These tests exercise only DLL loading, module-path checks and the
// systemProc.Call pointer contract through advapi32 conversion functions. They
// never call an NCrypt function and never open, create, modify or delete a CNG
// key.

func TestNativeDLLsAreSystemDLLs(t *testing.T) {
	want := map[string]bool{"ncrypt.dll": true, "advapi32.dll": true}
	if len(nativeDLLs) != len(want) {
		t.Fatalf("nativeDLLs has %d entries, want %d", len(nativeDLLs), len(want))
	}
	for _, d := range nativeDLLs {
		if !want[d.name] {
			t.Errorf("unexpected native DLL %q", d.name)
		}
		if len(d.procs) == 0 {
			t.Errorf("%s has no procedures", d.name)
		}
	}
}

// TestLoadNativeAPIsFromSystemDirectory binds every procedure and checks that
// each module, including the kernel32.dll bootstrap, is the file in the system
// directory. Loading ncrypt.dll here performs no CNG operation.
func TestLoadNativeAPIsFromSystemDirectory(t *testing.T) {
	if err := loadNativeAPIs(); err != nil {
		t.Fatalf("loadNativeAPIs: %v", err)
	}
	dir, err := systemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	modules := map[string]syscall.Handle{"kernel32.dll": syscall.Handle(kernel32.Handle())}
	for _, d := range nativeDLLs {
		modules[d.name] = d.dll.Handle
	}
	for name, h := range modules {
		path, err := moduleFileName(h)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := checkModulePath(path, name, dir); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		t.Logf("%s -> %s", name, path)
	}
}

// TestSystemDLLIgnoresApplicationDirectory plants a file in the application
// directory of the test binary, which the default DLL search order searches
// first. The file is not a valid image, so nothing can execute. The default
// search finds it (ERROR_BAD_EXE_FORMAT); the system-only loader does not
// (ERROR_MOD_NOT_FOUND, since no such DLL exists in the system directory).
func TestSystemDLLIgnoresApplicationDirectory(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const probe = "keppin-cng-loader-probe.dll"
	planted := filepath.Join(filepath.Dir(exe), probe)
	if err := os.WriteFile(planted, []byte("not a PE image"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(planted) })

	if _, err := syscall.LoadLibrary(probe); !errors.Is(err, syscall.Errno(193)) {
		t.Fatalf("control: default search LoadLibrary(%s) = %v, want ERROR_BAD_EXE_FORMAT (planted file found)", probe, err)
	}
	if _, err := loadSystemDLL(probe); !errors.Is(err, syscall.Errno(126)) {
		t.Fatalf("loadSystemDLL(%s) = %v, want ERROR_MOD_NOT_FOUND", probe, err)
	}
}

func TestLoadSystemDLLRejectsPaths(t *testing.T) {
	for _, name := range []string{"", `C:\Windows\System32\ncrypt.dll`, `.\ncrypt.dll`, "sub/ncrypt.dll", "C:ncrypt.dll"} {
		if _, err := loadSystemDLL(name); err == nil || !strings.Contains(err.Error(), "not a DLL base name") {
			t.Errorf("loadSystemDLL(%q) = %v, want base-name rejection", name, err)
		}
	}
}

func TestCheckModulePath(t *testing.T) {
	const dir = `C:\Windows\system32`
	for _, tc := range []struct {
		path string
		ok   bool
	}{
		{`C:\Windows\system32\ncrypt.dll`, true},
		{`C:\WINDOWS\SYSTEM32\NCRYPT.DLL`, true},
		{`C:\Windows\system32\sub\ncrypt.dll`, false},
		{`C:\Windows\ncrypt.dll`, false},
		{`C:\app\ncrypt.dll`, false},
		{`C:\Windows\system32\ncryptx.dll`, false},
		{`C:\Windows\system32\..\ncrypt.dll`, false},
		{`D:\Windows\system32\ncrypt.dll`, false},
		{`C:\Windows\SysWOW64\ncrypt.dll`, false},
	} {
		err := checkModulePath(tc.path, "ncrypt.dll", dir)
		if (err == nil) != tc.ok {
			t.Errorf("checkModulePath(%q) = %v, want ok=%v", tc.path, err, tc.ok)
		}
		if err != nil && !errors.Is(err, errUntrustedModule) {
			t.Errorf("checkModulePath(%q) error does not wrap errUntrustedModule: %v", tc.path, err)
		}
	}
	if err := checkModulePath(`C:\Windows\system32\ncrypt.dll`, "ncrypt.dll", ""); err == nil {
		t.Error("empty system directory accepted")
	}
}

// convertSIDWrapper and convertSIDDirect convert the SID string s with
// ConvertStringSidToSidW into a local Go variable whose address is passed only
// as a uintptr argument: through systemProc.Call, and directly through
// syscall.Proc.Call. The calls must stay direct method calls: escape analysis
// applies go:uintptrescapes only to a statically known callee.
func convertSIDWrapper(s *uint16) uintptr {
	var out uintptr
	procConvertStringSidToSidW.Call(uintptr(unsafe.Pointer(s)), uintptr(unsafe.Pointer(&out)))
	return out
}

func convertSIDDirect(s *uint16) uintptr {
	var out uintptr
	procConvertStringSidToSidW.proc.Call(uintptr(unsafe.Pointer(s)), uintptr(unsafe.Pointer(&out)))
	return out
}

// TestSystemProcCallKeepsPointerContract checks that systemProc.Call keeps the
// go:uintptrescapes contract of syscall.Proc.Call: a Go pointer converted to
// uintptr in the call is moved to the heap exactly as it is for a direct
// syscall.Proc.Call. Without the directive on the wrapper the local output
// variable stays on the stack and the wrapper path allocates one object less.
func TestSystemProcCallKeepsPointerContract(t *testing.T) {
	if err := loadNativeAPIs(); err != nil {
		t.Fatalf("loadNativeAPIs: %v", err)
	}
	s, err := syscall.UTF16PtrFromString(sidSYSTEM)
	if err != nil {
		t.Fatal(err)
	}
	allocs := func(convert func(*uint16) uintptr) float64 {
		return testing.AllocsPerRun(100, func() {
			if p := convert(s); p != 0 {
				procLocalFree.Call(p)
			}
		})
	}
	wrapper := allocs(convertSIDWrapper)
	direct := allocs(convertSIDDirect)
	if wrapper != direct {
		t.Fatalf("systemProc.Call allocs = %v, syscall.Proc.Call allocs = %v: the wrapper does not move uintptr-converted pointers to the heap (missing go:uintptrescapes?)", wrapper, direct)
	}
}

// TestSystemProcCallUnderGCPressure runs output-pointer calls through the
// wrapper from many goroutines while forcing garbage collection and stack
// growth, and checks every result. It is a regression smoke test, not a proof:
// a lifetime defect is not guaranteed to manifest in a given run.
func TestSystemProcCallUnderGCPressure(t *testing.T) {
	if err := loadNativeAPIs(); err != nil {
		t.Fatalf("loadNativeAPIs: %v", err)
	}
	defer debug.SetGCPercent(debug.SetGCPercent(1))
	want, err := buildSecurityDescriptor(privilegedOnlySDDL)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
			}
		}
	}()
	defer close(stop)

	// grow recurses with a padded frame so the goroutine stack is grown and
	// copied between native calls.
	var grow func(depth int) ([]byte, error)
	grow = func(depth int) ([]byte, error) {
		var pad [256]byte
		if depth > 0 {
			sd, err := grow(depth - 1)
			return append(sd, pad[:0]...), err
		}
		sid, err := convertStringSid(sidSYSTEM)
		if err != nil {
			return nil, err
		}
		procLocalFree.Call(uintptr(sid))
		return buildSecurityDescriptor(privilegedOnlySDDL)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				got, err := grow((g + i) % 64)
				if err != nil {
					t.Errorf("goroutine %d iteration %d: %v", g, i, err)
					return
				}
				if !bytes.Equal(got, want) {
					t.Errorf("goroutine %d iteration %d: security descriptor differs", g, i)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
