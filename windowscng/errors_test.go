package windowscng

import (
	"errors"
	"syscall"
	"testing"
)

// These tests run on every platform: the error contract is not Windows-only.

func TestNCryptErrorText(t *testing.T) {
	for _, tc := range []struct {
		op   string
		code uint32
		want string
	}{
		{"NCryptFinalizeKey", NTEPerm, "NCryptFinalizeKey: hr=0x80090010"},
		{"NCryptSignHash (query size)", 0x8009000F, "NCryptSignHash (query size): hr=0x8009000f"},
		{"set export policy", 0x1, "set export policy: hr=0x1"},
	} {
		err := ncryptStatusError(tc.op, tc.code)
		if err.Error() != tc.want {
			t.Errorf("text = %q, want %q", err.Error(), tc.want)
		}
		var ne *NCryptError
		if !errors.As(err, &ne) || ne.Op != tc.op || ne.Code != tc.code {
			t.Errorf("errors.As = %+v, want Op %q Code 0x%x", ne, tc.op, tc.code)
		}
		if errors.Is(err, syscall.Errno(tc.code)) {
			t.Errorf("an NCrypt status must not match a syscall.Errno")
		}
	}
}

func TestPublicStatusCodes(t *testing.T) {
	if NTENotFound != 0x8009000D || NTEPerm != 0x80090010 || NTEBadKeyset != 0x80090016 {
		t.Fatal("public NTE codes changed")
	}
	if !IsKeyNotFound(uintptr(NTENotFound)) || !IsKeyNotFound(uintptr(NTEBadKeyset)) || IsKeyNotFound(uintptr(NTEPerm)) {
		t.Fatal("IsKeyNotFound classification changed")
	}
}

func TestSentinelTexts(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{ErrKeyNotFound, "windowscng: persisted CNG key not found or not accessible"},
		{ErrCleanupFailed, "windowscng: deleting the key created by the failed call also failed; the key may persist"},
		{ErrPostWriteVerification, "windowscng: post-write DACL verification failed; persisted state is unverified and was not rolled back"},
	} {
		if tc.err.Error() != tc.want {
			t.Errorf("text = %q, want %q", tc.err.Error(), tc.want)
		}
	}
}

func TestWithCausesKeepsTextAndCauses(t *testing.T) {
	status := &NCryptError{Op: "NCryptOpenKey", Code: NTEBadKeyset}
	err := withCauses("exact text", nil, status, ErrKeyNotFound, nil)
	if err.Error() != "exact text" {
		t.Fatalf("text = %q", err.Error())
	}
	var ne *NCryptError
	if !errors.As(err, &ne) || ne != status || !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("causes not reachable: %v", err)
	}
	if n := len(err.(*contextualError).causes); n != 2 {
		t.Fatalf("%d causes kept, want the 2 non-nil ones", n)
	}
	if err := withCauses("no cause"); errors.Unwrap(err) != nil || len(err.(*contextualError).Unwrap()) != 0 {
		t.Fatal("an error without causes must unwrap to nothing")
	}
}

func TestWin32Cause(t *testing.T) {
	if win32Cause(nil) != nil {
		t.Error("nil last error must give no cause")
	}
	if win32Cause(syscall.Errno(0)) != nil {
		t.Error("ERROR_SUCCESS must not become a cause")
	}
	accessDenied := syscall.Errno(5)
	if c := win32Cause(accessDenied); !errors.Is(c, syscall.Errno(5)) {
		t.Errorf("cause = %v, want ERROR_ACCESS_DENIED", c)
	}
	other := errors.New("not an Errno")
	if win32Cause(other) != other {
		t.Error("a non-Errno last error is kept")
	}
	err := withCauses("GetAclInformation failed", win32Cause(accessDenied))
	var errno syscall.Errno
	if err.Error() != "GetAclInformation failed" || !errors.As(err, &errno) || errno != 5 {
		t.Fatalf("err = %v errno = %d", err, errno)
	}
	var ne *NCryptError
	if errors.As(err, &ne) {
		t.Fatal("a Win32 cause must not be an NCryptError")
	}
}
