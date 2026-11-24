//go:build windows

package windowscng

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Failure injection on the unified primitives, repeated for each of the three
// policies, against the in-memory fake keyStore. They never open, create,
// modify or delete a real persisted CNG key.

// allPolicies returns the three policy states: service-signer, privileged-only
// and the service SID of testServiceName.
func allPolicies(t *testing.T) []KeyPolicy {
	t.Helper()
	return []KeyPolicy{PolicyServiceSigner, PolicyPrivilegedOnly, mustServicePolicy(t, testServiceName)}
}

func policyLabel(p KeyPolicy) string { return p.(interface{ String() string }).String() }

// matchingDescriptor is a persisted descriptor exactly in the state of p.
func matchingDescriptor(t *testing.T, p KeyPolicy) []byte {
	t.Helper()
	switch v := p.(type) {
	case Policy:
		if v == PolicyPrivilegedOnly {
			return privilegedOnlyDescriptor(t)
		}
		return serviceSignerDescriptor(t, genericRead|genericExecute)
	case ServicePolicy:
		return serviceSIDDescriptor(t, v.SID(), genericRead|genericExecute)
	}
	t.Fatalf("unexpected policy %T", p)
	return nil
}

// otherDescriptor is a recognized descriptor in a state other than p.
func otherDescriptor(t *testing.T, p KeyPolicy) []byte {
	t.Helper()
	if p == KeyPolicy(PolicyPrivilegedOnly) {
		return serviceSignerDescriptor(t, genericRead)
	}
	return privilegedOnlyDescriptor(t)
}

// allSentinels lists every exported sentinel of the package.
var allSentinels = []struct {
	name string
	err  error
}{
	{"ErrKeyNotFound", ErrKeyNotFound},
	{"ErrPolicyMismatch", ErrPolicyMismatch},
	{"ErrPrivilegeRequired", ErrPrivilegeRequired},
	{"ErrKeyExists", ErrKeyExists},
	{"ErrCleanupFailed", ErrCleanupFailed},
	{"ErrDeleteVerificationFailed", ErrDeleteVerificationFailed},
	{"ErrPostWriteVerification", ErrPostWriteVerification},
}

// assertSentinels requires err to carry exactly the sentinels in want: each
// expected sentinel is present and every other exported sentinel is absent.
func assertSentinels(t *testing.T, err error, want ...error) {
	t.Helper()
	for _, sentinel := range allSentinels {
		expected := false
		for _, w := range want {
			if w == sentinel.err {
				expected = true
			}
		}
		if errors.Is(err, sentinel.err) != expected {
			t.Fatalf("err = %v: errors.Is(err, %s) = %v, want %v", err, sentinel.name, !expected, expected)
		}
	}
}

// TestCreateFailuresWithEveryPolicy: whatever the policy, a failure after the
// create deletes exactly the key object created by the call, once, through its
// own handle and without reopening it; a failed delete adds ErrCleanupFailed.
func TestCreateFailuresWithEveryPolicy(t *testing.T) {
	exportErr := errors.New("NCryptExportKey: hr=0x80090009")
	signerErr := errors.New("export public key for " + testKey + ": NCryptExportKey: hr=0x80090009")
	sdErr := errors.New("synthetic descriptor read failure")
	deleteErr := ncryptStatusError("NCryptDeleteKey", NTEPerm)
	for _, p := range allPolicies(t) {
		for _, tc := range []struct {
			name     string
			setup    func(*fakeStore)
			cause    error
			mismatch bool
			signer   int // signer() calls expected
		}{
			{"first public-key export fails", func(s *fakeStore) { s.pubErr = exportErr }, exportErr, true, 0},
			{"second public-key export (signer) fails", func(s *fakeStore) { s.signerErr = signerErr }, signerErr, false, 1},
			{"first descriptor read fails", func(s *fakeStore) { s.sdErr = sdErr }, sdErr, false, 0},
			{"created key reads back in another state", func(s *fakeStore) { s.writeResult = otherDescriptor(t, p) }, nil, true, 0},
		} {
			for _, deleteFails := range []bool{false, true} {
				name := policyLabel(p) + ": " + tc.name
				if deleteFails {
					name += ", delete fails"
				}
				t.Run(name, func(t *testing.T) {
					s := newFakeStore(t)
					s.privileged = true
					tc.setup(s)
					if deleteFails {
						s.deleteErr = deleteErr
					}
					signer, err := createWith(s, testKey, p)
					if signer != nil || err == nil {
						t.Fatalf("signer=%v err=%v, want a failure and no signer", signer, err)
					}
					if tc.cause != nil && !errors.Is(err, tc.cause) {
						t.Fatalf("err = %v, want the primary cause %v", err, tc.cause)
					}
					var want []error
					if tc.mismatch {
						want = append(want, ErrPolicyMismatch)
					}
					if deleteFails {
						want = append(want, ErrCleanupFailed)
					}
					assertSentinels(t, err, want...)
					if deleteFails && !errors.Is(err, deleteErr) {
						t.Fatalf("err = %v, want the delete status kept", err)
					}
					if tc.cause == sdErr && (!strings.Contains(err.Error(), "descriptor unavailable") || strings.Contains(err.Error(), "persisted_sd_dacl_hex=")) {
						t.Fatalf("err = %v, a read failure must not fabricate descriptor evidence", err)
					}
					if len(s.creates) != 1 || s.signerCalls != tc.signer || s.opens != 0 {
						t.Fatalf("creates=%d signerCalls=%d opens=%d, want 1/%d/0", len(s.creates), s.signerCalls, s.opens, tc.signer)
					}
					if len(s.deletedKeys) != 1 || !s.deletedKeys[0].created {
						t.Fatalf("deletedKeys = %v, want exactly the created key object, once", s.deletedKeys)
					}
					if _, ok := s.persisted[testKey]; ok != deleteFails {
						t.Fatalf("persisted=%v, want %v", ok, deleteFails)
					}
					assertHandlesReleased(t, s)
				})
			}
		}
	}
}

// TestCreateRollbackKeepsAReplacementUnderTheName: when another writer binds a
// new key to the name after the create, the rollback deletes the object it
// created, through its handle, and leaves the replacement in place.
func TestCreateRollbackKeepsAReplacementUnderTheName(t *testing.T) {
	signerErr := errors.New("export public key for " + testKey + ": NCryptExportKey: hr=0x80090009")
	for _, p := range allPolicies(t) {
		for _, failure := range []string{"signer fails", "verification fails"} {
			t.Run(policyLabel(p)+": "+failure, func(t *testing.T) {
				s := newFakeStore(t)
				s.privileged = true
				replacement := matchingDescriptor(t, p)
				if failure == "signer fails" {
					s.signerErr = signerErr
				} else {
					s.writeResult = otherDescriptor(t, p)
				}
				s.afterCreate = func() { s.rebind(testKey, replacement) }
				if _, err := createWith(s, testKey, p); err == nil || errors.Is(err, ErrCleanupFailed) {
					t.Fatalf("err = %v, want the failure with the created key deleted", err)
				}
				if len(s.deletedKeys) != 1 || !s.deletedKeys[0].created || s.deletedKeys[0].binding != 1 {
					t.Fatalf("deletedKeys = %v, want exactly the object created by the call", s.deletedKeys)
				}
				if got, ok := s.persisted[testKey]; !ok || !bytes.Equal(got, replacement) || s.bindings[testKey] != 2 {
					t.Fatal("the replacement bound under the name was removed or changed")
				}
				if s.opens != 0 {
					t.Fatalf("opens = %d, want 0: the rollback must not look the key up by name", s.opens)
				}
				assertHandlesReleased(t, s)
			})
		}
	}
}

// TestOpenNativeFailureIsReturnedUnchanged: an open failure other than
// not-found keeps its typed native cause, is not ErrKeyNotFound, and never
// leads to a create, a write or a delete.
func TestOpenNativeFailureIsReturnedUnchanged(t *testing.T) {
	for _, p := range allPolicies(t) {
		t.Run(policyLabel(p), func(t *testing.T) {
			s := newFakeStore(t)
			s.privileged = true // reaches the open also for privileged-only
			s.openErr = openKeyStatusError(testKey, NTEPerm, "")
			signer, err := openWith(s, testKey, p)
			if signer != nil || err == nil {
				t.Fatalf("signer=%v err=%v, want the open failure", signer, err)
			}
			assertSentinels(t, err) // neither ErrKeyNotFound nor any other sentinel
			assertNCryptOpCode(t, err, "NCryptOpenKey", NTEPerm)
			if s.opens != 1 {
				t.Fatalf("opens = %d, want 1", s.opens)
			}
			assertNoMutation(t, s)
		})
	}
}

// TestOpenExportFailuresWithEveryPolicy: on an existing key in the right
// state, a failed first export is ErrPolicyMismatch and a failed second export
// (signer) is returned as is; the key is never created, written or deleted.
func TestOpenExportFailuresWithEveryPolicy(t *testing.T) {
	exportErr := errors.New("NCryptExportKey: hr=0x80090009")
	signerErr := errors.New("export public key for " + testKey + ": NCryptExportKey: hr=0x80090009")
	for _, p := range allPolicies(t) {
		for _, first := range []bool{true, false} {
			label := "second export (signer) fails"
			if first {
				label = "first export fails"
			}
			t.Run(policyLabel(p)+": "+label, func(t *testing.T) {
				s := newFakeStore(t)
				s.privileged = true
				s.persisted[testKey] = matchingDescriptor(t, p)
				if first {
					s.pubErr = exportErr
				} else {
					s.signerErr = signerErr
				}
				_, err := openWith(s, testKey, p)
				if first {
					if !errors.Is(err, exportErr) {
						t.Fatalf("err = %v, want the export cause", err)
					}
					assertSentinels(t, err, ErrPolicyMismatch)
				} else {
					if !errors.Is(err, signerErr) {
						t.Fatalf("err = %v, want the signer cause", err)
					}
					assertSentinels(t, err) // the signer cause only
				}
				assertNoMutation(t, s)
				assertHandlesReleased(t, s)
			})
		}
	}
}

// TestDeleteVerificationFailuresWithEveryPolicy: each verification failure
// already covered for ServicePolicy deletes nothing with the two Policy values
// either.
func TestDeleteVerificationFailuresWithEveryPolicy(t *testing.T) {
	pub, spki := testP256(t)
	_, otherSPKI := testP256(t)
	exportErr := errors.New("export policy allows export")
	pubErr := errors.New("export public key failed")
	sdErr := ncryptStatusError("NCryptGetProperty", NTEPerm)
	for _, p := range allPolicies(t) {
		for name, tc := range map[string]struct {
			setup    func(*fakeStore)
			spki     []byte
			cause    error // injected cause that must be kept, nil for none
			mismatch bool
		}{
			"SPKI mismatch":         {func(*fakeStore) {}, otherSPKI, nil, false},
			"exportable key":        {func(s *fakeStore) { s.exportErr = exportErr }, spki, exportErr, false},
			"public key unreadable": {func(s *fakeStore) { s.pubErr = pubErr }, spki, pubErr, true},
			"descriptor unreadable": {func(s *fakeStore) { s.sdErr = sdErr }, spki, sdErr, false},
		} {
			t.Run(policyLabel(p)+": "+name, func(t *testing.T) {
				s := newFakeStore(t)
				s.privileged = true
				s.pub = pub
				s.allowDeleteExisting = true
				s.persisted[testKey] = matchingDescriptor(t, p)
				tc.setup(s)
				err := deleteWith(s, testKey, p, tc.spki)
				want := []error{ErrDeleteVerificationFailed}
				if tc.mismatch {
					want = append(want, ErrPolicyMismatch)
				}
				assertSentinels(t, err, want...)
				if tc.cause != nil && !errors.Is(err, tc.cause) {
					t.Fatalf("err = %v, want the injected cause %v kept", err, tc.cause)
				}
				if tc.cause == sdErr {
					assertNCryptOpCode(t, err, "NCryptGetProperty", NTEPerm)
				}
				if len(s.deleted) != 0 || len(s.writes) != 0 || len(s.creates) != 0 {
					t.Fatalf("deleted=%v writes=%v creates=%v, want no mutation", s.deleted, s.writes, s.creates)
				}
				if _, ok := s.persisted[testKey]; !ok {
					t.Fatal("key no longer persisted")
				}
				assertHandlesReleased(t, s)
			})
		}
	}
}
