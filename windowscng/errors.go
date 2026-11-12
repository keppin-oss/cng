package windowscng

import (
	"errors"
	"fmt"
	"syscall"
)

// This file holds the error contract of the package. It has no build tag, so
// that code shared between platforms can use errors.Is and errors.As with
// these symbols; on other platforms the functions of the package still only
// report that the platform is not supported.

// NCrypt SECURITY_STATUS codes that the package classifies. Code of an
// NCryptError is compared against these values.
const (
	// NTENotFound is NTE_NOT_FOUND (0x8009000D): object was not found.
	NTENotFound uint32 = 0x8009000D
	// NTEPerm is NTE_PERM (0x80090010): access denied.
	NTEPerm uint32 = 0x80090010
	// NTEBadKeyset is NTE_BAD_KEYSET (0x80090016): the keyset does not
	// exist, or is not accessible to the caller (see ErrKeyNotFound).
	NTEBadKeyset uint32 = 0x80090016
)

// NCryptError is a failed NCrypt call: the 32-bit SECURITY_STATUS in Code and
// the operation in Op. Retrieve it with errors.As.
//
// When the error text of the package is the NCryptError itself, it reads
// "<Op>: hr=0x<Code>" in lowercase hex without padding, and Op is that label
// (for example "NCryptSignHash (query size)"). When the status is part of a
// longer message, for example one that names the key or wraps a sentinel,
// that message is unchanged and Op is the name of the NCrypt function (for
// example "NCryptOpenKey"). Code is the stable reference. Op is descriptive
// only: the same NCrypt function can appear under different labels, and some
// labels name the step rather than the function (for example
// "set export policy"), so Op must not be compared.
//
// An error can hold more than one NCryptError, for example the original
// failure and the failed delete of a cleanup. errors.As returns the first one
// in the order of the error tree, which is the original failure; to see every
// code, walk the tree through Unwrap() error and Unwrap() []error.
//
// An NCrypt status is not a Win32 error: it is never converted to
// syscall.Errno. NTE_PERM and the Win32 ERROR_ACCESS_DENIED (syscall.Errno(5))
// are distinct values.
type NCryptError struct {
	Op   string
	Code uint32
}

func (e *NCryptError) Error() string {
	return fmt.Sprintf("%s: hr=0x%x", e.Op, e.Code)
}

// ErrKeyNotFound indicates that the native open of the exact persisted CNG key
// reported NTE_NOT_FOUND or NTE_BAD_KEYSET: the key was not found OR is not
// accessible to the caller. The Microsoft Software KSP has been observed to
// report NTE_BAD_KEYSET to a caller that the key's DACL does not grant, so the
// error alone does not prove that the key is absent. The wrapping error keeps
// the native status, also as an NCryptError. Not even a caller that the
// expected DACL would grant can read it as proof of absence, and it must never
// by itself trigger an automatic reset, regeneration or overwrite of an
// identity key.
var ErrKeyNotFound = errors.New("windowscng: persisted CNG key not found or not accessible")

// ErrCleanupFailed indicates that a call failed after creating a new persisted
// key and that deleting that key also failed: the key created by the call may
// still exist and must be inspected. It is joined with the original failure,
// and the delete failure is reachable through the error tree. Keys that
// existed before the call are never deleted on this path. One combination is
// not a cleanup failure, for a non-privileged caller only: NCryptFinalizeKey
// denied with NTE_PERM and the delete of that never finalized handle reporting
// NTE_BAD_KEYSET means that the key was not persisted; the finalize error is
// returned alone. For a privileged caller it is still ErrCleanupFailed. The
// privilege is read from the token of the calling thread at the time of the
// rollback: a caller that impersonates must keep the same OS thread for the
// whole call (runtime.LockOSThread), as for any impersonated NCrypt call.
var ErrCleanupFailed = errors.New("windowscng: deleting the key created by the failed call also failed; the key may persist")

// ErrPostWriteVerification indicates that ApplyPolicy or ApplyServicePolicy
// wrote the new DACL but could not then confirm it: a read-back on the same
// handle, the reopen of the key or a read-back on the fresh handle failed or
// did not match. Only the native causes (NCryptError, syscall.Errno) are
// reachable through the error tree: no other sentinel of this package matches,
// so a read-back mismatch is not ErrPolicyMismatch and a reopen reporting the
// key as not found is not ErrKeyNotFound. The text describes the cause.
// It does not mean that the DACL is certainly wrong or that it was restored:
// nothing was rolled back, the persisted DACL must be inspected, and the error
// must not trigger an automatic retry of the migration or a regeneration of
// the key.
var ErrPostWriteVerification = errors.New("windowscng: post-write DACL verification failed; persisted state is unverified and was not rolled back")

// IsKeyNotFound reports whether an NCrypt status is NTE_NOT_FOUND or
// NTE_BAD_KEYSET, which this package reports as ErrKeyNotFound. Only the low
// 32 bits of r are read. It does not distinguish an absent key from one the
// caller cannot access; it does distinguish them from other failures such as
// NTE_PERM.
func IsKeyNotFound(r uintptr) bool {
	hr := uint32(r)
	return hr == NTENotFound || hr == NTEBadKeyset
}

// ncryptStatusError returns the NCryptError for a failed NCrypt status, whose
// text is "op: hr=0x<status>". NCrypt functions return their status as a
// 32-bit SECURITY_STATUS and do not set the thread's last error, so the error
// value returned by Proc.Call is deliberately not included: it would show
// ERROR_SUCCESS or an unrelated stale error.
func ncryptStatusError(op string, r uint32) error {
	return &NCryptError{Op: op, Code: r}
}

// contextualError keeps an existing error text exactly while making its causes
// reachable by errors.Is and errors.As. The text is not derived from the
// causes.
type contextualError struct {
	message string
	causes  []error
}

func (e *contextualError) Error() string { return e.message }

func (e *contextualError) Unwrap() []error { return e.causes }

// withCauses returns an error with text message and the non-nil causes.
func withCauses(message string, causes ...error) error {
	kept := make([]error, 0, len(causes))
	for _, c := range causes {
		if c != nil {
			kept = append(kept, c)
		}
	}
	return &contextualError{message: message, causes: kept}
}

// nativeCausesOnly returns an error with the text of err whose only causes are
// the native ones in its tree: every *NCryptError and syscall.Errno, in tree
// order. Sentinels of this package and any other error are not reachable
// through it. It is used after a DACL write, where a cause such as
// ErrPolicyMismatch ("the key was not modified") or ErrKeyNotFound would
// contradict ErrPostWriteVerification.
func nativeCausesOnly(err error) error {
	var natives []error
	var walk func(error)
	walk = func(e error) {
		switch v := e.(type) {
		case nil:
			return
		case *NCryptError:
			natives = append(natives, v)
		case syscall.Errno:
			natives = append(natives, v)
		}
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			for _, c := range u.Unwrap() {
				walk(c)
			}
		case interface{ Unwrap() error }:
			walk(u.Unwrap())
		}
	}
	walk(err)
	return withCauses(err.Error(), natives...)
}

// win32Cause returns the last error of a failed Win32 call as a cause, or nil
// when there is none to report: a missing error or ERROR_SUCCESS is not
// turned into a cause.
func win32Cause(err error) error {
	if err == nil {
		return nil
	}
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return nil
	}
	return err
}
