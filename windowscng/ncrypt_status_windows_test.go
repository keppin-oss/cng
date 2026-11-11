//go:build windows

package windowscng

import (
	"strings"
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
			status, callErr := ncryptStatusAndCallErr(uintptr(tc.raw), 0, errno)
			if status != tc.want || callErr != errno {
				t.Fatalf("ncryptStatusAndCallErr(0x%x) = 0x%x, %v", tc.raw, status, callErr)
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

// TestSignNativeStatusOmitsCallError drives both NCryptSignHash failure paths
// of Sign through the simulated backend, returning a real syscall.Errno as
// Proc.Call would. The message must be exactly the status, with no trace of
// the Errno text (localized by Windows) or of its number.
func TestSignNativeStatusOmitsCallError(t *testing.T) {
	fx := newSignFixture(t)
	errnos := []syscall.Errno{
		0, // ERROR_SUCCESS: "The operation completed successfully."
		5, // ERROR_ACCESS_DENIED: a stale, unrelated last error
	}
	paths := []struct {
		name  string
		setup func(f *fakeSignerNative, errno syscall.Errno)
		want  string
	}{
		{"size query", func(f *fakeSignerNative, errno syscall.Errno) {
			f.sizeHR, f.sizeCallErr = 0x80090010, errno
		}, "NCryptSignHash (query size): hr=0x80090010"},
		{"sign", func(f *fakeSignerNative, errno syscall.Errno) {
			f.signHR, f.signCallErr = 0x80090010, errno
		}, "NCryptSignHash: hr=0x80090010"},
	}
	for _, p := range paths {
		for _, errno := range errnos {
			t.Run(p.name+"/"+errnoName(errno), func(t *testing.T) {
				f := newFakeSignerNative(fx.p1363)
				p.setup(f, errno)
				s := newTestSigner(f, fx.pub)
				defer s.Close()
				_, err := s.Sign(nil, fx.digest, nil)
				if err == nil {
					t.Fatal("Sign succeeded, want the native status error")
				}
				if got := err.Error(); got != p.want {
					t.Fatalf("err = %q, want exactly %q", got, p.want)
				}
				if text := errno.Error(); strings.Contains(err.Error(), text) {
					t.Fatalf("err %q contains the last-error text %q", err, text)
				}
			})
		}
	}
}

func errnoName(e syscall.Errno) string {
	switch e {
	case 0:
		return "ERROR_SUCCESS"
	case 5:
		return "ERROR_ACCESS_DENIED"
	}
	return "errno"
}
