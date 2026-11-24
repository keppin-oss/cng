package windowscng_test

import (
	"errors"
	"fmt"

	"github.com/keppin-oss/cng/windowscng"
)

// ExampleApply_errorHandling shows the order in which a caller checks the
// error returned by Apply. The errors are built by hand, in the forms Apply
// returns, so that the example runs on every platform without a key; in real
// code err comes from windowscng.Apply(name, policy).
//
// The same native code, NTE_BAD_KEYSET from NCryptOpenKey, appears in two of
// them with opposite meanings: before the write it comes with ErrKeyNotFound
// (nothing was written), after the write with ErrPostWriteVerification (the
// DACL was written). Only the sentinels, checked in this order before the
// native code, tell them apart.
func ExampleApply_errorHandling() {
	handle := func(err error) string {
		var ne *windowscng.NCryptError
		switch {
		case err == nil:
			return "applied and verified"
		case errors.Is(err, windowscng.ErrPostWriteVerification):
			// Check it first. The DACL was written but could not be
			// confirmed, and nothing was rolled back: inspect the key. Do not
			// retry Apply and do not regenerate the key. The error matches no
			// other sentinel of the package; a native code, if any, is only
			// for the diagnosis: NTE_BAD_KEYSET on the reopen does not mean
			// that the key is missing.
			if errors.As(err, &ne) {
				return fmt.Sprintf("written but unverified: inspect the key (diagnostic 0x%08X)", ne.Code)
			}
			return "written but unverified: inspect the key"
		case errors.Is(err, windowscng.ErrPrivilegeRequired):
			return "not written: run as SYSTEM or as an elevated administrator"
		case errors.Is(err, windowscng.ErrKeyNotFound):
			// Not found or not accessible: never a reason to Create. The
			// error also holds the NCryptOpenKey status, so this case must
			// come before the generic native-code case below.
			return "not written: key not found or not accessible"
		case errors.Is(err, windowscng.ErrPolicyMismatch):
			// Unrecognized DACL, a change that would widen access, or a key
			// that is not non-exportable P-256: the key was not modified.
			return "not written: the key is not in a state Apply accepts"
		case errors.As(err, &ne):
			return fmt.Sprintf("failed: NCrypt 0x%08X", ne.Code)
		case err != nil:
			return "failed: " + err.Error()
		}
		return ""
	}

	badKeyset := &windowscng.NCryptError{Op: "NCryptOpenKey", Code: windowscng.NTEBadKeyset}
	for _, err := range []error{
		nil,
		// After the write: the reopen of the key failed.
		fmt.Errorf("key %q: %w: reopen: %w", "Example.Key", windowscng.ErrPostWriteVerification, badKeyset),
		fmt.Errorf("apply: %w", windowscng.ErrPrivilegeRequired),
		// Before the write: the open of the key failed, same native status.
		fmt.Errorf("key %q: %w: %w", "Example.Key", badKeyset, windowscng.ErrKeyNotFound),
		fmt.Errorf("key %q: %w: unrecognized DACL", "Example.Key", windowscng.ErrPolicyMismatch),
		&windowscng.NCryptError{Op: "NCryptSetProperty", Code: windowscng.NTEPerm},
	} {
		fmt.Println(handle(err))
	}
	// Output:
	// applied and verified
	// written but unverified: inspect the key (diagnostic 0x80090016)
	// not written: run as SYSTEM or as an elevated administrator
	// not written: key not found or not accessible
	// not written: the key is not in a state Apply accepts
	// failed: NCrypt 0x80090010
}
