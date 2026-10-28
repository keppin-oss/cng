//go:build windows

package windowscng

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// Native DLL binding.
//
// ncrypt.dll and advapi32.dll are loaded only from the Windows system
// directory: LoadLibraryExW with LOAD_LIBRARY_SEARCH_SYSTEM32, which also
// restricts the search for their dependencies, and never a fallback to the
// default search order (application directory, current directory, PATH). After
// loading, the module's file path is checked against the system directory and
// the binding fails closed on any mismatch, for example when a module with the
// same base name was already loaded into the process from elsewhere.
//
// This does not depend on the toolchain's internal list of system DLLs
// (syscall.LoadDLL restricts the search only for DLLs that Go itself imports,
// and ncrypt.dll is not one of them).
//
// kernel32.dll is the bootstrap: it is a KnownDLL that Windows maps into every
// process before any Go code runs, so it is not resolved through the DLL search
// path (the Go runtime and syscall package also bind it from the system
// directory). Its module path is verified like the others.

// loadLibrarySearchSystem32 is LOAD_LIBRARY_SEARCH_SYSTEM32.
const loadLibrarySearchSystem32 = 0x00000800

// errorInsufficientBuffer is ERROR_INSUFFICIENT_BUFFER.
const errorInsufficientBuffer = syscall.Errno(122)

// errUntrustedModule reports a native module that is not loaded from the
// Windows system directory.
var errUntrustedModule = errors.New("windowscng: native module is not loaded from the Windows system directory")

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procLoadLibraryExW      = kernel32.NewProc("LoadLibraryExW")
	procFreeLibrary         = kernel32.NewProc("FreeLibrary")
	procGetModuleFileNameW  = kernel32.NewProc("GetModuleFileNameW")
	procGetSystemDirectoryW = kernel32.NewProc("GetSystemDirectoryW")
)

// systemDLL is a DLL bound lazily, and only, from the Windows system directory.
type systemDLL struct {
	name  string
	once  sync.Once
	dll   *syscall.DLL
	err   error
	procs []*systemProc
}

// systemProc is a procedure of a systemDLL. Its Call has the signature of
// syscall.LazyProc.Call.
type systemProc struct {
	dll  *systemDLL
	name string
	once sync.Once
	proc *syscall.Proc
	err  error
}

// nativeDLLs are the DLLs this package binds through systemDLL.
var nativeDLLs []*systemDLL

func newSystemDLL(name string) *systemDLL {
	d := &systemDLL{name: name}
	nativeDLLs = append(nativeDLLs, d)
	return d
}

// NewProc returns the named procedure of d. Nothing is loaded until first use.
func (d *systemDLL) NewProc(name string) *systemProc {
	p := &systemProc{dll: d, name: name}
	d.procs = append(d.procs, p)
	return p
}

// load loads d from the system directory once and verifies its module path.
func (d *systemDLL) load() error {
	d.once.Do(func() { d.dll, d.err = loadSystemDLL(d.name) })
	return d.err
}

func (p *systemProc) find() error {
	p.once.Do(func() {
		if err := p.dll.load(); err != nil {
			p.err = err
			return
		}
		p.proc, p.err = p.dll.dll.FindProc(p.name)
	})
	return p.err
}

// Call calls the procedure. Like syscall.LazyProc.Call it panics if the
// procedure cannot be bound; loadNativeAPIs runs before the first native call
// of every entry point, so that failure is returned as an error instead.
//
// The go:uintptrescapes directive keeps the pointer-lifetime contract of
// syscall.Proc.Call and syscall.LazyProc.Call: the compiler applies it only
// to the immediate callee, so every Go pointer converted to uintptr in a call
// to this method is moved to the heap and kept alive until the call returns.
// Removing it lets those pointers stay on a stack that can move while native
// code uses them.
//
//go:uintptrescapes
func (p *systemProc) Call(a ...uintptr) (uintptr, uintptr, error) {
	if err := p.find(); err != nil {
		panic(err)
	}
	return p.proc.Call(a...)
}

// loadNativeAPIs binds every native procedure used by this package, failing
// closed if a DLL is not loaded from the system directory or a procedure is
// missing. It is idempotent and safe for concurrent use.
func loadNativeAPIs() error {
	if err := verifyModule(syscall.Handle(kernel32.Handle()), "kernel32.dll"); err != nil {
		return err
	}
	for _, d := range nativeDLLs {
		for _, p := range d.procs {
			if err := p.find(); err != nil {
				return fmt.Errorf("windowscng: bind %s!%s: %w", d.name, p.name, err)
			}
		}
	}
	return nil
}

// loadSystemDLL loads the DLL with base name name from the Windows system
// directory only, and verifies that the loaded module's file is in that
// directory.
func loadSystemDLL(name string) (*syscall.DLL, error) {
	if name == "" || strings.ContainsAny(name, `\/:`) {
		return nil, fmt.Errorf("windowscng: %q is not a DLL base name", name)
	}
	if err := procLoadLibraryExW.Find(); err != nil {
		return nil, err
	}
	namep, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, _, callErr := procLoadLibraryExW.Call(uintptr(unsafe.Pointer(namep)), 0, loadLibrarySearchSystem32)
	if h == 0 {
		return nil, &syscall.DLLError{Err: callErr, ObjName: name, Msg: fmt.Sprintf("windowscng: load %s from the system directory: %v", name, callErr)}
	}
	if err := verifyModule(syscall.Handle(h), name); err != nil {
		procFreeLibrary.Call(h)
		return nil, err
	}
	return &syscall.DLL{Name: name, Handle: syscall.Handle(h)}, nil
}

// verifyModule checks that the module h, loaded for base name name, is the file
// name in a Windows system directory.
func verifyModule(h syscall.Handle, name string) error {
	path, err := moduleFileName(h)
	if err != nil {
		return fmt.Errorf("windowscng: module path of %s: %w", name, err)
	}
	dir, err := systemDirectory()
	if err != nil {
		return err
	}
	return checkModulePath(path, name, dir)
}

// checkModulePath reports whether path is the file name directly inside dir.
// Windows paths compare case-insensitively. Under WOW64 a 32-bit process also
// reports its system modules with the system32 path (verified with
// GOARCH=386), so no SysWOW64 exception is needed.
func checkModulePath(path, name, dir string) error {
	if dir == "" || !strings.EqualFold(filepath.Base(path), name) ||
		!strings.EqualFold(filepath.Clean(filepath.Dir(path)), filepath.Clean(dir)) {
		return fmt.Errorf("%w: %s resolved to %q, want the file in %q", errUntrustedModule, name, path, dir)
	}
	return nil
}

// systemDirectory returns the Windows system directory (GetSystemDirectoryW).
func systemDirectory() (string, error) {
	buf := make([]uint16, syscall.MAX_PATH)
	for {
		n, _, err := procGetSystemDirectoryW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n == 0 {
			return "", fmt.Errorf("windowscng: GetSystemDirectoryW: %w", err)
		}
		if int(n) < len(buf) {
			return syscall.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, n)
	}
}

// moduleFileName returns the full path of the file the module h was loaded from.
func moduleFileName(h syscall.Handle) (string, error) {
	buf := make([]uint16, syscall.MAX_PATH)
	for {
		n, _, err := procGetModuleFileNameW.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n == 0 {
			return "", err
		}
		if int(n) < len(buf) {
			return syscall.UTF16ToString(buf[:n]), nil
		}
		if len(buf) >= 32768 {
			return "", errorInsufficientBuffer
		}
		buf = make([]uint16, 2*len(buf))
	}
}
