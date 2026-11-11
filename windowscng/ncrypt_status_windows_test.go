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
		r    uintptr
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

func TestNCryptStatusErrorIgnoresUpperBits(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) < 8 {
		t.Skip("uintptr has no upper 32 bits on this architecture")
	}
	dirty := uint64(0xdead0000_80090010)
	got := ncryptStatusError("NCryptCreatePersistedKey", uintptr(dirty)).Error()
	if want := "NCryptCreatePersistedKey: hr=0x80090010"; got != want {
		t.Fatalf("got %q, want %q", got, want)
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
