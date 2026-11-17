//go:build windows

package windowscng

import (
	"syscall"
	"testing"
	"unsafe"
)

// NCrypt functions return their status and do not set the thread's last
// error. These tests prove that a failed NCrypt status is reported as
// "op: hr=0x<status>" only, without the Proc.Call last error that came with
// it. No test here opens, creates or deletes a CNG key.

func TestNCryptStatusErrorFormat(t *testing.T) {
	cases := []struct {
		op   string
		r    uint32
		want string
	}{
		{"NCryptFinalizeKey", 0x80090010, "NCryptFinalizeKey: hr=0x80090010"},
		{"NCryptSignHash", 0x8009000b, "NCryptSignHash: hr=0x8009000b"},
		// Lowercase hex without padding, as consumers and existing tests expect.
		{"set export policy", 0x1, "set export policy: hr=0x1"},
	}
	for _, tc := range cases {
		if got := ncryptStatusError(tc.op, tc.r).Error(); got != tc.want {
			t.Errorf("ncryptStatusError(%q, 0x%x) = %q, want %q", tc.op, tc.r, got, tc.want)
		}
	}
}

// TestNCryptStatusIgnoresUpperBits proves that a status is taken from the low
// 32 bits of the return register only: dirty upper bits over a zero status
// are a success, and over a nonzero status they do not reach the message.
func TestNCryptStatusIgnoresUpperBits(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) < 8 {
		t.Skip("uintptr has no upper 32 bits on this architecture")
	}
	errno := syscall.Errno(5)
	cases := []struct {
		name  string
		raw   uint64
		want  uint32
		isErr bool
	}{
		{"dirty upper bits over success", 0xdead0000_00000000, 0, false},
		{"all upper bits set over success", 0xffffffff_00000000, 0, false},
		{"dirty upper bits over NTE_PERM", 0xdead0000_80090010, 0x80090010, true},
		{"sign-extended NTE_PERM", 0xffffffff_80090010, 0x80090010, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ncryptStatus(uintptr(tc.raw), 0, errno)
			if got != tc.want || (got != 0) != tc.isErr {
				t.Fatalf("ncryptStatus(0x%x) = 0x%x, want 0x%x", tc.raw, got, tc.want)
			}
			if !tc.isErr {
				return
			}
			msg := ncryptStatusError("NCryptOpenKey", got).Error()
			if want := "NCryptOpenKey: hr=0x80090010"; msg != want {
				t.Fatalf("message %q, want %q", msg, want)
			}
		})
	}
}

// TestWin32BOOLIgnoresUpperBits proves that a Win32 BOOL is read from the low
// 32 bits only: zero is FALSE and any nonzero low half is TRUE, not just 1.
func TestWin32BOOLIgnoresUpperBits(t *testing.T) {
	cases := []struct {
		name string
		raw  uint64
		want bool
	}{
		{"zero", 0, false},
		{"one", 1, true},
		{"TRUE other than 1", 2, true},
		{"all low bits set", 0xffffffff, true},
		{"only upper bits set", 0xdead0000_00000000, false},
		{"all upper bits set, low zero", 0xffffffff_00000000, false},
		{"upper bits set, low TRUE", 0xdead0000_00000001, true},
		{"upper bits set, low TRUE other than 1", 0xdead0000_80000000, true},
	}
	wide := unsafe.Sizeof(uintptr(0)) >= 8
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.raw>>32 != 0 && !wide {
				t.Skip("uintptr has no upper 32 bits on this architecture")
			}
			errno := syscall.Errno(5)
			if got := win32BOOL(uintptr(tc.raw), 0, errno); got != tc.want {
				t.Fatalf("win32BOOL(0x%x) = %v, want %v", tc.raw, got, tc.want)
			}
			got, callErr := win32BOOLAndCallErr(uintptr(tc.raw), 0, errno)
			if got != tc.want || callErr != errno {
				t.Fatalf("win32BOOLAndCallErr(0x%x) = %v, %v", tc.raw, got, callErr)
			}
		})
	}
}
