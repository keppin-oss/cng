package windowscng_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
)

// classify is what a consumer can write in code shared between platforms: it
// uses only the error contract, which has no build tag.
func classify(err error) string {
	var ne *windowscng.NCryptError
	switch {
	case errors.Is(err, windowscng.ErrCleanupFailed):
		return "cleanup"
	case errors.Is(err, windowscng.ErrPostWriteVerification):
		return "post-write"
	case errors.Is(err, windowscng.ErrKeyNotFound):
		return "not found or not accessible"
	case errors.As(err, &ne) && ne.Code == windowscng.NTEPerm:
		return "denied"
	case errors.As(err, &ne):
		return fmt.Sprintf("ncrypt 0x%x", ne.Code)
	}
	return "other"
}

func TestConsumerContractCompilesOnEveryPlatform(t *testing.T) {
	denied := &windowscng.NCryptError{Op: "NCryptFinalizeKey", Code: windowscng.NTEPerm}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{denied, "denied"},
		{fmt.Errorf("wrapped: %w", denied), "denied"},
		{fmt.Errorf("x: %w", windowscng.ErrKeyNotFound), "not found or not accessible"},
		{errors.Join(denied, windowscng.ErrCleanupFailed), "cleanup"},
		// The form returned after a DACL write: the sentinel and the native
		// cause only, here a reopen that reported NTE_BAD_KEYSET.
		{fmt.Errorf("%w: reopen: %w", windowscng.ErrPostWriteVerification, &windowscng.NCryptError{Op: "NCryptOpenKey", Code: windowscng.NTEBadKeyset}), "post-write"},
		{&windowscng.NCryptError{Op: "NCryptSignHash", Code: 0x80090027}, "ncrypt 0x80090027"},
		{errors.New("plain"), "other"},
	} {
		if got := classify(tc.err); got != tc.want {
			t.Errorf("classify(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
	if !windowscng.IsKeyNotFound(uintptr(windowscng.NTEBadKeyset)) {
		t.Fatal("IsKeyNotFound(NTEBadKeyset) = false")
	}
}
