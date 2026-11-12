//go:build windows

package windowscng

import (
	"crypto/rand"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"syscall"
	"testing"
)

// These tests check that the error texts of the package are unchanged and
// that the native statuses, sentinels and Win32 causes behind them are
// reachable with errors.Is and errors.As. The expected texts are the ones the
// package produced before NCryptError was introduced.

func requireNCrypt(t *testing.T, err error, op string, code uint32) {
	t.Helper()
	var ne *NCryptError
	if !errors.As(err, &ne) || ne.Op != op || ne.Code != code {
		t.Fatalf("errors.As(%v) = %+v, want Op %q Code 0x%x", err, ne, op, code)
	}
}

// ncryptCodes returns every NCryptError code in the tree of err, in order.
func ncryptCodes(err error) []uint32 {
	var out []uint32
	var walk func(error)
	walk = func(e error) {
		if e == nil {
			return
		}
		if ne, ok := e.(*NCryptError); ok {
			out = append(out, ne.Code)
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
	return out
}

func TestOpenKeyErrorTexts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		r        uint32
		label    string
		want     string
		notFound bool
	}{
		{"k1", NTEBadKeyset, "", `key "k1": NCryptOpenKey hr=0x80090016: windowscng: persisted CNG key not found or not accessible`, true},
		{"k1", NTENotFound, " (for delete)", `key "k1": NCryptOpenKey hr=0x8009000d: windowscng: persisted CNG key not found or not accessible`, true},
		{"k2", NTEPerm, "", `NCryptOpenKey "k2": hr=0x80090010`, false},
		{"k2", NTEPerm, " (for delete)", `NCryptOpenKey "k2" (for delete): hr=0x80090010`, false},
	} {
		err := openKeyStatusError(tc.name, tc.r, tc.label)
		if err.Error() != tc.want {
			t.Errorf("text = %q, want %q", err.Error(), tc.want)
		}
		if errors.Is(err, ErrKeyNotFound) != tc.notFound {
			t.Errorf("%q: errors.Is(ErrKeyNotFound) = %v", tc.want, !tc.notFound)
		}
		requireNCrypt(t, err, "NCryptOpenKey", tc.r)
	}
}

func TestLegacyOpenErrorIsTyped(t *testing.T) {
	o := newFakeLegacyOps(t)
	o.openHR = NTEPerm
	_, err := openKeyWith(o, legacyTestKey)
	if err == nil || err.Error() != `NCryptOpenKey "`+legacyTestKey+`": hr=0x80090010` {
		t.Fatalf("err = %v", err)
	}
	requireNCrypt(t, err, "NCryptOpenKey", NTEPerm)
	o.requireReleased()
}

func TestCleanupKeepsBothCauses(t *testing.T) {
	cause := ncryptStatusError("NCryptFinalizeKey", 0x80090009)
	deleteErr := ncryptStatusError("NCryptDeleteKey", NTEPerm)
	err := cleanupCreatedKey(cause, func() error { return deleteErr })
	want := "NCryptFinalizeKey: hr=0x80090009\n" +
		"windowscng: deleting the key created by the failed call also failed; the key may persist: NCryptDeleteKey: hr=0x80090010"
	if err.Error() != want {
		t.Fatalf("text = %q, want %q", err.Error(), want)
	}
	if !errors.Is(err, ErrCleanupFailed) || !errors.Is(err, cause) || !errors.Is(err, deleteErr) {
		t.Fatalf("causes not reachable: %v", err)
	}
	// errors.As returns the first NCryptError: the original failure.
	requireNCrypt(t, err, "NCryptFinalizeKey", 0x80090009)
	if got := ncryptCodes(err); len(got) != 2 || got[0] != 0x80090009 || got[1] != NTEPerm {
		t.Fatalf("codes = %#x, want finalize then delete", got)
	}
}

func TestFinalizeFailureErrorsAreTyped(t *testing.T) {
	t.Run("not persisted", func(t *testing.T) {
		err := cleanupAfterFinalizeFailure(NTEPerm, func() uint32 { return NTEBadKeyset }, notPrivileged)
		want := "NCryptFinalizeKey: hr=0x80090010 (the key created by this call was not persisted; NCryptDeleteKey: hr=0x80090016 on its unfinalized handle)"
		if err.Error() != want || errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %q", err)
		}
		requireNCrypt(t, err, "NCryptFinalizeKey", NTEPerm)
		if got := ncryptCodes(err); len(got) != 2 || got[1] != NTEBadKeyset {
			t.Fatalf("codes = %#x, want the delete status reachable", got)
		}
	})
	t.Run("cleanup failed", func(t *testing.T) {
		err := cleanupAfterFinalizeFailure(NTEPerm, func() uint32 { return NTEPerm }, notPrivileged)
		if !errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v", err)
		}
		if got := ncryptCodes(err); len(got) != 2 || got[0] != NTEPerm || got[1] != NTEPerm {
			t.Fatalf("codes = %#x", got)
		}
	})
}

func TestExportErrorsAreTyped(t *testing.T) {
	_, err := exportPublicKeyWith(1, func(_ uintptr, out []byte, _ *uint32) uint32 { return NTEPerm })
	if err == nil || err.Error() != "NCryptExportKey (query size): hr=0x80090010" {
		t.Fatalf("err = %v", err)
	}
	requireNCrypt(t, err, "NCryptExportKey (query size)", NTEPerm)

	_, err = exportPublicKeyWith(1, func(_ uintptr, out []byte, n *uint32) uint32 {
		if out == nil {
			*n = 72
			return 0
		}
		return 0x80090027
	})
	if err == nil || err.Error() != "NCryptExportKey: hr=0x80090027" {
		t.Fatalf("err = %v", err)
	}
	requireNCrypt(t, err, "NCryptExportKey", 0x80090027)
}

func TestSignerErrorsAreTyped(t *testing.T) {
	digest := make([]byte, 32)
	t.Run("sign", func(t *testing.T) {
		f := newFakeSignerNative(nil)
		f.sizeHR = NTEPerm
		s := newTestSigner(f, nil)
		_, err := s.Sign(rand.Reader, digest, nil)
		if err == nil || err.Error() != "NCryptSignHash (query size): hr=0x80090010" {
			t.Fatalf("err = %v", err)
		}
		requireNCrypt(t, err, "NCryptSignHash (query size)", NTEPerm)
	})
	t.Run("close", func(t *testing.T) {
		f := newFakeSignerNative(nil)
		s := newTestSigner(f, nil)
		f.freeHR[s.key] = 0x80090026
		f.freeHR[s.provider] = 0x80090029
		err := s.Close()
		want := "NCryptFreeObject (key " + s.name + "): hr=0x80090026\nNCryptFreeObject (provider): hr=0x80090029"
		if err == nil || err.Error() != want {
			t.Fatalf("err = %q, want %q", err, want)
		}
		requireNCrypt(t, err, "NCryptFreeObject", 0x80090026)
		if got := ncryptCodes(err); len(got) != 2 || got[1] != 0x80090029 {
			t.Fatalf("codes = %#x", got)
		}
	})
}

func notPrivileged() (bool, error) { return false, nil }

// After the DACL write, the error wraps ErrPostWriteVerification and keeps the
// native causes, but no sentinel of the package: ErrPolicyMismatch means "the
// key was not modified" and ErrKeyNotFound "not found or not accessible", and
// both would contradict a DACL that was written (review #29, findings 1, 5).
func TestPostWriteVerificationKeepsOnlyNativeCauses(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	prefix := `key "` + testKey + `": ` + ErrPostWriteVerification.Error()
	for _, tc := range []struct {
		name  string
		setup func(s *fakeStore)
		want  string // text after prefix; "" checks only the start
		code  uint32 // NCryptError code expected, 0 for none
	}{
		{"reopen denied", func(s *fakeStore) { s.reopenErr = openKeyStatusError(testKey, NTEPerm, "") },
			`: reopen: NCryptOpenKey "` + testKey + `": hr=0x80090010`, NTEPerm},
		{"reopen not found", func(s *fakeStore) { s.reopenErr = openKeyStatusError(testKey, NTEBadKeyset, "") },
			`: reopen: key "` + testKey + `": NCryptOpenKey hr=0x80090016: ` + ErrKeyNotFound.Error(), NTEBadKeyset},
		{"read-back mismatch on open handle", func(s *fakeStore) { s.writeResult = serviceSIDDescriptor(t, p.SID(), 0x80120089) },
			"", 0},
		{"read-back mismatch on fresh handle", func(s *fakeStore) { s.reopenResult = serviceSIDDescriptor(t, p.SID(), 0x80120089) },
			"", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newFakeStore(t)
			s.privileged = true
			s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
			tc.setup(s)
			err := applyServicePolicy(s, testKey, p)
			if err == nil || !strings.HasPrefix(err.Error(), prefix) || (tc.want != "" && err.Error() != prefix+tc.want) {
				t.Fatalf("err = %q, want %q", err, prefix+tc.want)
			}
			if !errors.Is(err, ErrPostWriteVerification) {
				t.Fatalf("ErrPostWriteVerification lost: %v", err)
			}
			for _, sentinel := range []error{ErrPolicyMismatch, ErrKeyNotFound, ErrCleanupFailed, ErrPrivilegeRequired} {
				if errors.Is(err, sentinel) {
					t.Fatalf("errors.Is(err, %q) = true after the DACL write: %v", sentinel, err)
				}
			}
			if tc.code != 0 {
				requireNCrypt(t, err, "NCryptOpenKey", tc.code)
			}
			if len(s.writes) != 1 || len(s.deleted) != 0 || len(s.creates) != 0 {
				t.Fatal("post-write rollback semantics changed")
			}
			assertHandlesReleased(t, s)
		})
	}
}

func TestNativeCausesOnly(t *testing.T) {
	status := &NCryptError{Op: "NCryptOpenKey", Code: NTEBadKeyset}
	src := fmt.Errorf("outer: %w", withCauses("inner", status, ErrKeyNotFound, syscall.Errno(5), errors.New("other")))
	got := nativeCausesOnly(src)
	if got.Error() != src.Error() {
		t.Fatalf("text = %q, want %q", got, src)
	}
	if errors.Is(got, ErrKeyNotFound) {
		t.Fatal("a package sentinel is still reachable")
	}
	var ne *NCryptError
	if !errors.As(got, &ne) || ne != status || !errors.Is(got, syscall.Errno(5)) {
		t.Fatalf("native causes lost: %v", got)
	}
	if n := len(got.(*contextualError).causes); n != 2 {
		t.Fatalf("%d causes, want the 2 native ones", n)
	}
}

func TestPrivilegeCheckKeepsCause(t *testing.T) {
	cause := withCauses("CheckTokenMembership(S-1-5-18): Access is denied.", syscall.Errno(5))
	s := newFakeStore(t)
	s.privErr = cause
	err := requirePrivilege(s)
	if err == nil || err.Error() != ErrPrivilegeRequired.Error()+": privilege check failed: CheckTokenMembership(S-1-5-18): Access is denied." {
		t.Fatalf("err = %v", err)
	}
	if !errors.Is(err, ErrPrivilegeRequired) || !errors.Is(err, syscall.Errno(5)) {
		t.Fatalf("sentinel or Win32 cause lost: %v", err)
	}
}

// TestWin32CausesReadFromTheSameCall checks, on the source, that the three
// DACL inspection calls whose failure used to drop the cause now take their
// last error from the same Proc.Call through win32BOOLAndCallErr, and pass it
// through win32Cause.
func TestWin32CausesReadFromTheSameCall(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "cng_windows.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var verify *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "verifyDACL" {
			verify = fd
		}
	}
	if verify == nil {
		t.Fatal("verifyDACL not found")
	}
	want := map[string]bool{"procGetSecurityDescriptorDacl": false, "procGetAclInformation": false, "procGetAce": false}
	ast.Inspect(verify, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, ok := call.Fun.(*ast.Ident)
		if !ok || fn.Name != "win32BOOLAndCallErr" || len(call.Args) != 1 {
			return true
		}
		inner, ok := call.Args[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := inner.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Call" {
			if id, ok := sel.X.(*ast.Ident); ok {
				if _, tracked := want[id.Name]; tracked {
					want[id.Name] = true
				}
			}
		}
		return true
	})
	for name, found := range want {
		if !found {
			t.Errorf("%s is not read through win32BOOLAndCallErr in verifyDACL", name)
		}
	}
	src := fileText(t, "cng_windows.go")
	for _, msg := range []string{`"GetSecurityDescriptorDacl failed", win32Cause(callErr)`, `"GetAclInformation failed", win32Cause(callErr)`, `"GetAce(%d) failed", i), win32Cause(callErr)`} {
		if !strings.Contains(src, msg) {
			t.Errorf("cng_windows.go: missing %s", msg)
		}
	}
}

func fileText(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}
