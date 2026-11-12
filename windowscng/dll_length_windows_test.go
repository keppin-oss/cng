//go:build windows

package windowscng

import (
	"errors"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"
	"unsafe"
)

// These tests drive the GetSystemDirectoryW and GetModuleFileNameW loops with
// a simulated lengthCall that returns raw uintptr registers, so that the
// normalization to 32 bits and the buffer handling are checked without native
// calls.

// highBits returns a register value with bits set above the low 32 bits, or 0
// on a 32-bit architecture, where they do not exist. The shift is computed at
// run time so that the test also compiles for 386.
func highBits() uintptr {
	shift := uint(32)
	return uintptr(0xDEADBEEF) << shift
}

func is64bit() bool { return unsafe.Sizeof(uintptr(0)) == 8 }

// fakeLengthCall replays a script of returns. Each step can copy text into the
// buffer. It records the capacity of every call.
type fakeLengthCall struct {
	t     *testing.T
	steps []lengthStep
	caps  []int
}

type lengthStep struct {
	write string // copied into the buffer, truncated to its capacity
	raw   uintptr
	err   error
}

func (f *fakeLengthCall) call(buf []uint16) (uintptr, error) {
	f.caps = append(f.caps, len(buf))
	if len(f.caps) > len(f.steps) {
		f.t.Fatalf("unexpected call %d with capacity %d (caps %v)", len(f.caps), len(buf), f.caps)
	}
	s := f.steps[len(f.caps)-1]
	copy(buf, utf16.Encode([]rune(s.write)))
	return s.raw, s.err
}

// requireGrowth checks that every retry used a strictly larger buffer and
// that no buffer exceeded maxPathChars.
func (f *fakeLengthCall) requireGrowth() {
	f.t.Helper()
	for i, c := range f.caps {
		if c > maxPathChars {
			f.t.Fatalf("capacity %d above the limit (caps %v)", c, f.caps)
		}
		if i > 0 && c <= f.caps[i-1] {
			f.t.Fatalf("retry without growth (caps %v)", f.caps)
		}
	}
}

const sysDir = `C:\Windows\system32`

// staleErr is a last error left by an earlier call: Proc.Call returns it
// even when the call succeeds.
var staleErr = syscall.Errno(87)

func TestSystemDirectoryLengths(t *testing.T) {
	n := uintptr(len(sysDir))
	accessDenied := syscall.Errno(5)
	for _, tc := range []struct {
		name    string
		only64  bool
		steps   []lengthStep
		want    string
		wantErr string
		caps    []int
	}{
		{"valid length", false, []lengthStep{{sysDir, n, staleErr}}, sysDir, "", []int{260}},
		{"dirty upper bits, valid low part", true, []lengthStep{{sysDir, highBits() | n, staleErr}}, sysDir, "", []int{260}},
		{"dirty upper bits, zero low part", true, []lengthStep{{"", highBits(), accessDenied}}, "", "windowscng: GetSystemDirectoryW: " + accessDenied.Error(), []int{260}},
		{"zero with native error", false, []lengthStep{{"", 0, accessDenied}}, "", "windowscng: GetSystemDirectoryW: " + accessDenied.Error(), []int{260}},
		{"length at the margin", false, []lengthStep{{strings.Repeat("a", 259), 259, nil}}, strings.Repeat("a", 259), "", []int{260}},
		{"required size above buffer, then success", false, []lengthStep{{"", 301, nil}, {strings.Repeat("b", 300), 300, nil}}, strings.Repeat("b", 300), "", []int{260, 301}},
		{"length equal to capacity", false, []lengthStep{{"", 260, nil}}, "", "windowscng: GetSystemDirectoryW: returned length 260 equal to the buffer size, which the API never reports", []int{260}},
		{"required size equal to capacity after growth", false, []lengthStep{{"", 400, nil}, {"", 400, nil}}, "", "returned length 400 equal to the buffer size", []int{260, 400}},
		{"required size above the limit", false, []lengthStep{{"", maxPathChars + 1, nil}}, "", "windowscng: GetSystemDirectoryW: required size 32769 exceeds the limit of 32768 characters", []int{260}},
		{"0x80000000", false, []lengthStep{{"", 0x80000000, nil}}, "", "required size 2147483648 exceeds the limit", []int{260}},
		{"0xffffffff", false, []lengthStep{{"", 0xFFFFFFFF, nil}}, "", "required size 4294967295 exceeds the limit", []int{260}},
		{"0xffffffff with dirty upper bits", true, []lengthStep{{"", highBits() | 0xFFFFFFFF, nil}}, "", "required size 4294967295 exceeds the limit", []int{260}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.only64 && !is64bit() {
				t.Skip("no upper register bits on a 32-bit architecture")
			}
			f := &fakeLengthCall{t: t, steps: tc.steps}
			got, err := systemDirectoryWith(f.call)
			checkLengthResult(t, got, err, tc.want, tc.wantErr)
			if !equalInts(f.caps, tc.caps) {
				t.Fatalf("caps = %v, want %v", f.caps, tc.caps)
			}
			f.requireGrowth()
		})
	}
	t.Run("zero keeps the native cause", func(t *testing.T) {
		f := &fakeLengthCall{t: t, steps: []lengthStep{{"", 0, accessDenied}}}
		_, err := systemDirectoryWith(f.call)
		if !errors.Is(err, accessDenied) {
			t.Fatalf("err = %v, want ERROR_ACCESS_DENIED reachable", err)
		}
	})
}

func TestModuleFileNameLengths(t *testing.T) {
	path := sysDir + `\ncrypt.dll`
	n := uintptr(len(path))
	modNotFound := syscall.Errno(126)
	long := strings.Repeat("p", 600)
	for _, tc := range []struct {
		name    string
		only64  bool
		steps   []lengthStep
		want    string
		wantErr string
		caps    []int
	}{
		{"valid length", false, []lengthStep{{path, n, staleErr}}, path, "", []int{260}},
		{"dirty upper bits, valid low part", true, []lengthStep{{path, highBits() | n, staleErr}}, path, "", []int{260}},
		{"dirty upper bits, zero low part", true, []lengthStep{{"", highBits(), modNotFound}}, "", modNotFound.Error(), []int{260}},
		{"zero with native error", false, []lengthStep{{"", 0, modNotFound}}, "", modNotFound.Error(), []int{260}},
		{"length at the margin", false, []lengthStep{{strings.Repeat("a", 259), 259, nil}}, strings.Repeat("a", 259), "", []int{260}},
		{"truncated, grows and retries", false, []lengthStep{{long, 260, errorInsufficientBuffer}, {long, 520, errorInsufficientBuffer}, {long, 600, nil}}, long, "", []int{260, 520, 1040}},
		{"length above capacity", false, []lengthStep{{"", 261, nil}}, "", "GetModuleFileNameW: returned length 261 exceeds the buffer size 260", []int{260}},
		{"0x80000000", false, []lengthStep{{"", 0x80000000, nil}}, "", "GetModuleFileNameW: returned length 2147483648 exceeds the buffer size 260", []int{260}},
		{"0xffffffff", false, []lengthStep{{"", 0xFFFFFFFF, nil}}, "", "returned length 4294967295 exceeds", []int{260}},
		{"0xffffffff with dirty upper bits", true, []lengthStep{{"", highBits() | 0xFFFFFFFF, nil}}, "", "returned length 4294967295 exceeds", []int{260}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.only64 && !is64bit() {
				t.Skip("no upper register bits on a 32-bit architecture")
			}
			f := &fakeLengthCall{t: t, steps: tc.steps}
			got, err := moduleFileNameWith(f.call)
			checkLengthResult(t, got, err, tc.want, tc.wantErr)
			if !equalInts(f.caps, tc.caps) {
				t.Fatalf("caps = %v, want %v", f.caps, tc.caps)
			}
			f.requireGrowth()
		})
	}
	t.Run("limit reached while truncated", func(t *testing.T) {
		var steps []lengthStep
		for _, c := range []uintptr{260, 520, 1040, 2080, 4160, 8320, 16640, 32768} {
			steps = append(steps, lengthStep{raw: c, err: errorInsufficientBuffer})
		}
		f := &fakeLengthCall{t: t, steps: steps}
		_, err := moduleFileNameWith(f.call)
		if err != errorInsufficientBuffer {
			t.Fatalf("err = %v, want ERROR_INSUFFICIENT_BUFFER", err)
		}
		if last := f.caps[len(f.caps)-1]; last != maxPathChars || len(f.caps) != 8 {
			t.Fatalf("caps = %v, want growth capped at %d", f.caps, maxPathChars)
		}
		f.requireGrowth()
	})
	t.Run("zero keeps the native cause unchanged", func(t *testing.T) {
		f := &fakeLengthCall{t: t, steps: []lengthStep{{"", 0, modNotFound}}}
		_, err := moduleFileNameWith(f.call)
		if err != modNotFound {
			t.Fatalf("err = %#v, want the last error itself", err)
		}
	})
}

func checkLengthResult(t *testing.T, got string, err error, want, wantErr string) {
	t.Helper()
	if wantErr == "" {
		if err != nil || got != want {
			t.Fatalf("got %q, %v; want %q", got, err, want)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), wantErr) || got != "" {
		t.Fatalf("got %q, %v; want error containing %q", got, err, wantErr)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
