//go:build windows

package windowscng

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// These tests exercise the policy engine against an in-memory fake keyStore.
// They never open, create, modify or delete a real persisted CNG key.

type fakeSigner struct{ name string }

func (s *fakeSigner) Public() crypto.PublicKey { return &ecdsa.PublicKey{Curve: elliptic.P256()} }
func (s *fakeSigner) Close() error             { return nil }
func (s *fakeSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("fake signer")
}

type fakeStore struct {
	t          *testing.T
	privileged bool
	privErr    error
	// persisted maps key name to its persisted descriptor.
	persisted map[string][]byte
	openErr   error
	createErr error
	// writeResult, if set, overrides what a DACL write persists (simulates
	// provider canonicalization or a racing writer).
	writeResult []byte
	// reopenResult, if set, is what a second open of the key observes.
	reopenResult []byte
	exportErr    error
	pubErr       error
	setErr       error
	sdErr        error
	deleteErr    error // failure of deleteCreated; the key then persists
	sdReads      int
	events       []string // descriptor read/delete ordering, no native operations

	privilegeChecks int
	opens           int
	creates         []string // SDDLs passed to create
	writes          []string // SDDLs passed to setSecurityDescriptor
	deleted         []string
	openHandles     int // currently open handles
}

func newFakeStore(t *testing.T) *fakeStore {
	return &fakeStore{t: t, persisted: map[string][]byte{}}
}

func (s *fakeStore) callerPrivileged() (bool, error) {
	s.privilegeChecks++
	return s.privileged, s.privErr
}

func (s *fakeStore) open(name string) (storedKey, error) {
	s.opens++
	if s.openErr != nil {
		return nil, s.openErr
	}
	sd, ok := s.persisted[name]
	if !ok {
		return nil, fmt.Errorf("key %q: %w", name, ErrKeyNotFound)
	}
	if s.opens > 1 && s.reopenResult != nil {
		sd = s.reopenResult
	}
	s.openHandles++
	return &fakeKey{store: s, name: name, sd: sd}, nil
}

func (s *fakeStore) create(name, sddl string) (storedKey, error) {
	s.creates = append(s.creates, sddl)
	if s.createErr != nil {
		return nil, s.createErr
	}
	if _, exists := s.persisted[name]; exists {
		return nil, errors.New("NTE_EXISTS")
	}
	sd := s.descriptorFor(sddl)
	if s.writeResult != nil {
		sd = s.writeResult
	}
	s.persisted[name] = sd
	s.openHandles++
	return &fakeKey{store: s, name: name, sd: sd, created: true}, nil
}

func (s *fakeStore) descriptorFor(sddl string) []byte {
	switch sddl {
	case keySecuritySDDL:
		return serviceSignerDescriptor(s.t, genericRead|genericExecute)
	case privilegedOnlySDDL:
		return privilegedOnlyDescriptor(s.t)
	}
	if sid, ok := strings.CutPrefix(sddl, "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;"); ok && strings.HasSuffix(sid, ")") {
		return serviceSIDDescriptor(s.t, strings.TrimSuffix(sid, ")"), genericRead|genericExecute)
	}
	s.t.Fatalf("unexpected SDDL %q", sddl)
	return nil
}

type fakeKey struct {
	store   *fakeStore
	name    string
	sd      []byte
	created bool
	done    bool
}

func (k *fakeKey) verifyNonExportable() error { return k.store.exportErr }
func (k *fakeKey) securityDescriptor() ([]byte, error) {
	if k.done {
		k.store.t.Fatal("descriptor read after key lifetime ended")
	}
	k.store.sdReads++
	k.store.events = append(k.store.events, "read-descriptor")
	if k.store.sdErr != nil {
		return nil, k.store.sdErr
	}
	return k.sd, nil
}
func (k *fakeKey) publicKey() (*ecdsa.PublicKey, error) { return &ecdsa.PublicKey{}, k.store.pubErr }

func (k *fakeKey) setSecurityDescriptor(sddl string) error {
	k.store.writes = append(k.store.writes, sddl)
	if k.store.setErr != nil {
		return k.store.setErr
	}
	sd := k.store.descriptorFor(sddl)
	if k.store.writeResult != nil {
		sd = k.store.writeResult
	}
	k.sd = sd
	k.store.persisted[k.name] = sd
	return nil
}

func (k *fakeKey) signer() (Signer, error) {
	k.end()
	return &fakeSigner{name: k.name}, nil
}

func (k *fakeKey) deleteCreated() error {
	if !k.created {
		k.store.t.Fatalf("deleteCreated called on pre-existing key %q", k.name)
	}
	k.store.deleted = append(k.store.deleted, k.name)
	k.store.events = append(k.store.events, "delete-created")
	defer k.end()
	if k.store.deleteErr != nil {
		return k.store.deleteErr
	}
	delete(k.store.persisted, k.name)
	return nil
}

func (k *fakeKey) close() { k.end() }

func (k *fakeKey) end() {
	if !k.done {
		k.done = true
		k.store.openHandles--
	}
}

const testKey = "Example.Policy.Key.v1"

func assertNoMutation(t *testing.T, s *fakeStore) {
	t.Helper()
	if len(s.creates) != 0 || len(s.writes) != 0 || len(s.deleted) != 0 {
		t.Fatalf("unexpected mutation: creates=%v writes=%v deleted=%v", s.creates, s.writes, s.deleted)
	}
}

func assertHandlesReleased(t *testing.T, s *fakeStore) {
	t.Helper()
	if s.openHandles != 0 {
		t.Fatalf("%d key handle(s) leaked", s.openHandles)
	}
}

func TestPolicyAPIsRejectInvalidPolicy(t *testing.T) {
	for _, p := range []Policy{0, 3} {
		s := newFakeStore(t)
		s.privileged = true
		if _, err := openWithPolicy(s, testKey, p); err == nil {
			t.Errorf("openWithPolicy accepted %v", p)
		}
		if _, err := loadOrCreateWithPolicy(s, testKey, p); err == nil {
			t.Errorf("loadOrCreateWithPolicy accepted %v", p)
		}
		if err := applyPolicy(s, testKey, p); err == nil {
			t.Errorf("applyPolicy accepted %v", p)
		}
		if s.opens != 0 || s.privilegeChecks != 0 {
			t.Errorf("invalid policy %v reached the key store", p)
		}
		assertNoMutation(t, s)
	}
}

func TestOpenWithPolicy(t *testing.T) {
	t.Run("privileged-only rejects non-privileged caller before open", func(t *testing.T) {
		s := newFakeStore(t)
		s.persisted[testKey] = privilegedOnlyDescriptor(t)
		_, err := openWithPolicy(s, testKey, PolicyPrivilegedOnly)
		if !errors.Is(err, ErrPrivilegeRequired) {
			t.Fatalf("err = %v, want ErrPrivilegeRequired", err)
		}
		if s.opens != 0 {
			t.Fatal("key was opened for a non-privileged caller")
		}
	})
	t.Run("privilege check failure fails closed", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.privErr = errors.New("CheckTokenMembership failed")
		_, err := openWithPolicy(s, testKey, PolicyPrivilegedOnly)
		if !errors.Is(err, ErrPrivilegeRequired) || s.opens != 0 {
			t.Fatalf("err = %v opens=%d, want ErrPrivilegeRequired and no open", err, s.opens)
		}
	})
	t.Run("privileged-only match", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = privilegedOnlyDescriptor(t)
		signer, err := openWithPolicy(s, testKey, PolicyPrivilegedOnly)
		if err != nil || signer == nil {
			t.Fatalf("openWithPolicy: %v", err)
		}
		assertNoMutation(t, s)
		assertHandlesReleased(t, s)
	})
	t.Run("service-signer does not require privilege", func(t *testing.T) {
		s := newFakeStore(t)
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		if _, err := openWithPolicy(s, testKey, PolicyServiceSigner); err != nil {
			t.Fatalf("openWithPolicy: %v", err)
		}
		if s.privilegeChecks != 0 {
			t.Fatal("service-signer open must not require a privilege check")
		}
	})
	for _, tc := range []struct {
		name   string
		policy Policy
		sd     func(*testing.T) []byte
	}{
		{"service key opened as privileged-only", PolicyPrivilegedOnly, func(t *testing.T) []byte { return serviceSignerDescriptor(t, genericRead) }},
		{"privileged key opened as service-signer", PolicyServiceSigner, privilegedOnlyDescriptor},
		{"unknown DACL", PolicyServiceSigner, func(t *testing.T) []byte {
			return buildDescriptor(t, protectedControl, allow(genericAll, sidSYSTEM), allow(genericAll, sidAdministrators), allow(genericRead, sidEveryone))
		}},
	} {
		t.Run("mismatch: "+tc.name, func(t *testing.T) {
			s := newFakeStore(t)
			s.privileged = true
			s.persisted[testKey] = tc.sd(t)
			_, err := openWithPolicy(s, testKey, tc.policy)
			if !errors.Is(err, ErrPolicyMismatch) {
				t.Fatalf("err = %v, want ErrPolicyMismatch", err)
			}
			assertNoMutation(t, s)
			assertHandlesReleased(t, s)
		})
	}
	t.Run("not found passes through", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		_, err := openWithPolicy(s, testKey, PolicyPrivilegedOnly)
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("err = %v, want ErrKeyNotFound", err)
		}
		assertNoMutation(t, s)
	})
	t.Run("exportable key rejected", func(t *testing.T) {
		s := newFakeStore(t)
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		s.exportErr = errors.New("export policy permits export")
		if _, err := openWithPolicy(s, testKey, PolicyServiceSigner); err == nil {
			t.Fatal("exportable key accepted")
		}
		assertHandlesReleased(t, s)
	})
	t.Run("non-P-256 key rejected", func(t *testing.T) {
		s := newFakeStore(t)
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		s.pubErr = errors.New("not P-256")
		if _, err := openWithPolicy(s, testKey, PolicyServiceSigner); !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want ErrPolicyMismatch", err)
		}
		assertHandlesReleased(t, s)
	})
}

func TestLoadOrCreateWithPolicy(t *testing.T) {
	t.Run("privileged-only requires privilege before open", func(t *testing.T) {
		s := newFakeStore(t)
		_, err := loadOrCreateWithPolicy(s, testKey, PolicyPrivilegedOnly)
		if !errors.Is(err, ErrPrivilegeRequired) || s.opens != 0 {
			t.Fatalf("err = %v opens=%d, want ErrPrivilegeRequired and no open", err, s.opens)
		}
		assertNoMutation(t, s)
	})
	t.Run("existing matching key is opened, not recreated", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = privilegedOnlyDescriptor(t)
		if _, err := loadOrCreateWithPolicy(s, testKey, PolicyPrivilegedOnly); err != nil {
			t.Fatal(err)
		}
		assertNoMutation(t, s)
		assertHandlesReleased(t, s)
	})
	t.Run("existing mismatching key is not converted", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		_, err := loadOrCreateWithPolicy(s, testKey, PolicyPrivilegedOnly)
		if !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want ErrPolicyMismatch", err)
		}
		assertNoMutation(t, s)
		assertHandlesReleased(t, s)
	})
	t.Run("access denied is not treated as missing", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.openErr = errors.New("NCryptOpenKey: hr=0x80070005")
		_, err := loadOrCreateWithPolicy(s, testKey, PolicyServiceSigner)
		if err == nil || errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("err = %v, want the open error", err)
		}
		assertNoMutation(t, s)
	})
	t.Run("not found for non-privileged caller does not create", func(t *testing.T) {
		s := newFakeStore(t)
		_, err := loadOrCreateWithPolicy(s, testKey, PolicyServiceSigner)
		if !errors.Is(err, ErrPrivilegeRequired) {
			t.Fatalf("err = %v, want ErrPrivilegeRequired", err)
		}
		if errors.Is(err, ErrKeyNotFound) {
			t.Fatal("ambiguous not-found must not be reported as ErrKeyNotFound to a non-privileged caller")
		}
		assertNoMutation(t, s)
	})
	t.Run("privilege check error does not create", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.privErr = errors.New("CheckTokenMembership failed")
		if _, err := loadOrCreateWithPolicy(s, testKey, PolicyServiceSigner); !errors.Is(err, ErrPrivilegeRequired) {
			t.Fatalf("err = %v, want ErrPrivilegeRequired", err)
		}
		assertNoMutation(t, s)
	})
	for _, p := range []Policy{PolicyServiceSigner, PolicyPrivilegedOnly} {
		t.Run("creates with "+p.String()+" SDDL", func(t *testing.T) {
			s := newFakeStore(t)
			s.privileged = true
			if _, err := loadOrCreateWithPolicy(s, testKey, p); err != nil {
				t.Fatal(err)
			}
			if len(s.creates) != 1 || s.creates[0] != policySDDL(p) {
				t.Fatalf("creates = %v, want [%s]", s.creates, policySDDL(p))
			}
			if len(s.writes) != 0 || len(s.deleted) != 0 {
				t.Fatalf("unexpected writes=%v deleted=%v", s.writes, s.deleted)
			}
			assertHandlesReleased(t, s)
		})
	}
	t.Run("created key failing verification is deleted", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		// Simulate provider canonicalization of GA for Administrators.
		s.writeResult = buildDescriptor(t, protectedControl, allow(genericAll, sidSYSTEM), allow(0x001F0003, sidAdministrators))
		_, err := loadOrCreateWithPolicy(s, testKey, PolicyPrivilegedOnly)
		if !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want ErrPolicyMismatch", err)
		}
		if len(s.deleted) != 1 {
			t.Fatalf("deleted = %v, want the created key deleted", s.deleted)
		}
		if _, ok := s.persisted[testKey]; ok {
			t.Fatal("created key still persisted")
		}
		assertHandlesReleased(t, s)
	})
	t.Run("create failure does not delete anything", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.createErr = errors.New("NTE_EXISTS")
		if _, err := loadOrCreateWithPolicy(s, testKey, PolicyServiceSigner); err == nil {
			t.Fatal("create failure not reported")
		}
		if len(s.deleted) != 0 {
			t.Fatal("create failure must not delete")
		}
	})
}

func TestApplyPolicy(t *testing.T) {
	t.Run("requires privilege before open", func(t *testing.T) {
		for _, p := range []Policy{PolicyServiceSigner, PolicyPrivilegedOnly} {
			s := newFakeStore(t)
			s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
			if err := applyPolicy(s, testKey, p); !errors.Is(err, ErrPrivilegeRequired) {
				t.Fatalf("%s: err = %v, want ErrPrivilegeRequired", p, err)
			}
			if s.opens != 0 {
				t.Fatalf("%s: key opened for non-privileged caller", p)
			}
			assertNoMutation(t, s)
		}
	})
	t.Run("missing key is never created", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		if err := applyPolicy(s, testKey, PolicyPrivilegedOnly); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("err = %v, want ErrKeyNotFound", err)
		}
		assertNoMutation(t, s)
	})
	for _, lsMask := range []uint32{genericRead, genericRead | genericExecute, 0x801200A9} {
		t.Run(fmt.Sprintf("tightens service-signer (LS 0x%08X) to privileged-only", lsMask), func(t *testing.T) {
			s := newFakeStore(t)
			s.privileged = true
			s.persisted[testKey] = serviceSignerDescriptor(t, lsMask)
			if err := applyPolicy(s, testKey, PolicyPrivilegedOnly); err != nil {
				t.Fatal(err)
			}
			if len(s.writes) != 1 || s.writes[0] != privilegedOnlySDDL {
				t.Fatalf("writes = %v, want exactly one privileged-only write", s.writes)
			}
			if len(s.creates) != 0 || len(s.deleted) != 0 {
				t.Fatal("ApplyPolicy must not create or delete")
			}
			if st, _ := classifyDescriptor(s.persisted[testKey]); st != daclPrivilegedOnly {
				t.Fatalf("persisted state = %s", st)
			}
			if s.opens != 2 {
				t.Fatalf("opens = %d, want 2 (operate + fresh read-back)", s.opens)
			}
			assertHandlesReleased(t, s)
		})
	}
	t.Run("idempotent when already in target state", func(t *testing.T) {
		for _, tc := range []struct {
			p  Policy
			sd func(*testing.T) []byte
		}{
			{PolicyPrivilegedOnly, privilegedOnlyDescriptor},
			{PolicyServiceSigner, func(t *testing.T) []byte { return serviceSignerDescriptor(t, genericRead) }},
		} {
			s := newFakeStore(t)
			s.privileged = true
			s.persisted[testKey] = tc.sd(t)
			if err := applyPolicy(s, testKey, tc.p); err != nil {
				t.Fatalf("%s: %v", tc.p, err)
			}
			assertNoMutation(t, s)
			assertHandlesReleased(t, s)
		}
	})
	t.Run("refuses to widen privileged-only to service-signer", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = privilegedOnlyDescriptor(t)
		if err := applyPolicy(s, testKey, PolicyServiceSigner); !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want ErrPolicyMismatch", err)
		}
		assertNoMutation(t, s)
		assertHandlesReleased(t, s)
	})
	for _, tc := range []struct {
		name string
		sd   func(*testing.T) []byte
	}{
		{"extra principal", func(t *testing.T) []byte {
			return buildDescriptor(t, protectedControl, allow(genericAll, sidSYSTEM), allow(genericAll, sidAdministrators), allow(genericRead, sidLocalService), allow(genericRead, sidBuiltinUsers))
		}},
		{"unprotected DACL", func(t *testing.T) []byte {
			return buildDescriptor(t, seSelfRelative|seDACLPresent, allow(genericAll, sidSYSTEM), allow(genericAll, sidAdministrators), allow(genericRead, sidLocalService))
		}},
		{"LS with write", func(t *testing.T) []byte { return serviceSignerDescriptor(t, genericRead|genericWrite) }},
		{"garbage", func(*testing.T) []byte { return []byte{1, 2, 3} }},
	} {
		t.Run("unknown state is not modified: "+tc.name, func(t *testing.T) {
			s := newFakeStore(t)
			s.privileged = true
			s.persisted[testKey] = tc.sd(t)
			if err := applyPolicy(s, testKey, PolicyPrivilegedOnly); !errors.Is(err, ErrPolicyMismatch) {
				t.Fatalf("err = %v, want ErrPolicyMismatch", err)
			}
			assertNoMutation(t, s)
			assertHandlesReleased(t, s)
		})
	}
	t.Run("exportable key is not modified", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		s.exportErr = errors.New("export policy permits export")
		if err := applyPolicy(s, testKey, PolicyPrivilegedOnly); err == nil {
			t.Fatal("exportable key accepted")
		}
		assertNoMutation(t, s)
	})
	t.Run("non-P-256 key is not modified", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		s.pubErr = errors.New("not P-256")
		if err := applyPolicy(s, testKey, PolicyPrivilegedOnly); !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want ErrPolicyMismatch", err)
		}
		assertNoMutation(t, s)
	})
	t.Run("write failure is reported", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		s.setErr = errors.New("set security descriptor: hr=0x80090010")
		if err := applyPolicy(s, testKey, PolicyPrivilegedOnly); err == nil {
			t.Fatal("write failure not reported")
		}
		assertHandlesReleased(t, s)
	})
	t.Run("read-back mismatch on open handle fails without rollback", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		s.writeResult = buildDescriptor(t, protectedControl, allow(genericAll, sidSYSTEM), allow(0x001F0003, sidAdministrators))
		err := applyPolicy(s, testKey, PolicyPrivilegedOnly)
		if !errors.Is(err, errPostWriteVerification) {
			t.Fatalf("err = %v, want errPostWriteVerification", err)
		}
		if len(s.writes) != 1 {
			t.Fatalf("writes = %v, want exactly one (no rollback)", s.writes)
		}
		assertHandlesReleased(t, s)
	})
	t.Run("read-back mismatch on fresh handle fails without rollback", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		s.reopenResult = serviceSignerDescriptor(t, genericRead)
		err := applyPolicy(s, testKey, PolicyPrivilegedOnly)
		if !errors.Is(err, errPostWriteVerification) {
			t.Fatalf("err = %v, want errPostWriteVerification", err)
		}
		if len(s.writes) != 1 {
			t.Fatalf("writes = %v, want exactly one (no rollback)", s.writes)
		}
		assertHandlesReleased(t, s)
	})
}

// TestPolicySDDLMatchesWindowsEncoding converts the SDDL strings this package
// requests into binary descriptors with the real Windows API (an in-memory
// conversion; no key is touched) and checks that the classifier recognizes
// them as the intended states. It does not prove how the Microsoft Software
// KSP persists these descriptors.
func TestPolicySDDLMatchesWindowsEncoding(t *testing.T) {
	for _, tc := range []struct {
		sddl string
		want daclState
	}{
		{keySecuritySDDL, daclServiceSigner},
		{privilegedOnlySDDL, daclPrivilegedOnly},
	} {
		sd, err := buildSecurityDescriptor(tc.sddl)
		if err != nil {
			t.Fatalf("buildSecurityDescriptor(%s): %v", tc.sddl, err)
		}
		got, err := classifyDescriptor(sd)
		if err != nil {
			t.Fatalf("classifyDescriptor(%s): %v", tc.sddl, err)
		}
		if got != tc.want {
			t.Fatalf("classifyDescriptor(%s) = %s, want %s", tc.sddl, got, tc.want)
		}
	}
	// A widened SDDL must not be recognized.
	sd, err := buildSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	if st, err := classifyDescriptor(sd); err == nil {
		t.Fatalf("widened descriptor classified as %s", st)
	}
}

func TestPolicySDDLConstants(t *testing.T) {
	if keySecuritySDDL != "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;LS)" {
		t.Fatalf("service-signer SDDL changed: %s", keySecuritySDDL)
	}
	if privilegedOnlySDDL != "D:P(A;;GA;;;SY)(A;;GA;;;BA)" {
		t.Fatalf("privileged-only SDDL changed: %s", privilegedOnlySDDL)
	}
	if policySDDL(PolicyServiceSigner) != keySecuritySDDL || policySDDL(PolicyPrivilegedOnly) != privilegedOnlySDDL {
		t.Fatal("policySDDL mapping changed")
	}
}

// TestCheckTokenMembershipReadOnly calls the real token-membership query used
// for privilege checks. It only reads the calling thread's token; it does not
// open any key. The result depends on how the test is run, so only the absence
// of an API error is asserted.
func TestCheckTokenMembershipReadOnly(t *testing.T) {
	if _, err := (nativeKeyStore{}).callerPrivileged(); err != nil {
		t.Fatalf("callerPrivileged: %v", err)
	}
}
