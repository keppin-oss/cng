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

type fakeSigner struct {
	name string
	pub  *ecdsa.PublicKey // the public key passed to fakeKey.signer
}

func (s *fakeSigner) Public() crypto.PublicKey {
	if s.pub != nil {
		return s.pub
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256()}
}

func (s *fakeSigner) Close() error { return nil }
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
	// reopenErr, if set, is what a second open of the key returns.
	reopenErr error
	exportErr error
	pubErr    error
	// pub, if set, is the public key the fake reports; otherwise a zero key.
	pub *ecdsa.PublicKey
	// allowDeleteExisting lets deleteAndRelease run on a key the fake did not
	// create, as Delete does after verification.
	allowDeleteExisting bool
	// pubReads counts publicKey calls on every handle.
	pubReads int
	setErr   error
	sdErr    error
	// sdErrAt, if set, makes only the descriptor read with that 1-based
	// number (counted by sdReads, across all handles) fail. In Apply
	// and Apply read 1 is before the write, read 2 the read-back
	// on the open handle and read 3 the read-back on the fresh handle.
	sdErrAt   map[int]error
	deleteErr error // failure of deleteAndRelease; the key then persists
	sdReads   int
	events    []string // descriptor read/delete ordering, no native operations

	// signerCalls counts signer() calls; signerPub is the public key the last
	// one received. Like nativeKey.signer, signer() cannot fail: it takes the
	// key verified by checkKeyPolicyPublic and makes no further read.
	signerCalls int
	signerPub   *ecdsa.PublicKey
	deletedKeys []*fakeKey // identity of each key passed to deleteAndRelease

	privilegeChecks int
	opens           int
	creates         []string // SDDLs passed to create
	writes          []string // SDDLs passed to setSecurityDescriptor
	deleted         []string
	openHandles     int // currently open handles

	// bindings gives each key object an identity distinct from its name: it
	// counts the objects bound to a name, by create or by rebind. A handle
	// keeps the binding it was opened or created on, and deleting it removes
	// the name only while that binding is still current, as NCryptDeleteKey
	// acts on the object behind the handle, not on the name.
	bindings map[string]int
	// afterCreate, if set, runs once the create has persisted the new key
	// (for example to simulate another writer replacing it under the name).
	afterCreate func()
}

// rebind binds a new key object with descriptor sd to name, replacing the
// object currently visible under it, as a concurrent creator would.
func (s *fakeStore) rebind(name string, sd []byte) {
	s.bindings[name]++
	s.persisted[name] = sd
}

func newFakeStore(t *testing.T) *fakeStore {
	return &fakeStore{t: t, persisted: map[string][]byte{}, bindings: map[string]int{}}
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
	if s.opens > 1 && s.reopenErr != nil {
		return nil, s.reopenErr
	}
	if s.opens > 1 && s.reopenResult != nil {
		sd = s.reopenResult
	}
	s.openHandles++
	return &fakeKey{store: s, name: name, sd: sd, binding: s.bindings[name]}, nil
}

func (s *fakeStore) create(name, sddl string) (storedKey, error) {
	s.creates = append(s.creates, sddl)
	if s.createErr != nil {
		return nil, s.createErr
	}
	if _, exists := s.persisted[name]; exists {
		return nil, nativeCollision()
	}
	sd := s.descriptorFor(sddl)
	if s.writeResult != nil {
		sd = s.writeResult
	}
	s.bindings[name]++
	s.persisted[name] = sd
	s.openHandles++
	k := &fakeKey{store: s, name: name, sd: sd, created: true, binding: s.bindings[name]}
	if s.afterCreate != nil {
		s.afterCreate()
	}
	return k, nil
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
	binding int // the object identity, see fakeStore.bindings
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
	if err := k.store.sdErrAt[k.store.sdReads]; err != nil {
		return nil, err
	}
	return k.sd, nil
}
func (k *fakeKey) publicKey() (*ecdsa.PublicKey, error) {
	k.store.pubReads++
	if k.store.pub != nil {
		return k.store.pub, k.store.pubErr
	}
	return &ecdsa.PublicKey{}, k.store.pubErr
}

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

func (k *fakeKey) signer(pub *ecdsa.PublicKey) Signer {
	if k.done {
		k.store.t.Fatal("signer() called after key lifetime ended")
	}
	k.store.signerCalls++
	k.store.signerPub = pub
	k.end()
	return &fakeSigner{name: k.name, pub: pub}
}

func (k *fakeKey) deleteAndRelease() error {
	if !k.created && !k.store.allowDeleteExisting {
		k.store.t.Fatalf("deleteAndRelease called on pre-existing key %q", k.name)
	}
	if k.done {
		k.store.t.Fatalf("deleteAndRelease called after key %q lifetime ended", k.name)
	}
	k.store.deleted = append(k.store.deleted, k.name)
	k.store.deletedKeys = append(k.store.deletedKeys, k)
	k.store.events = append(k.store.events, "delete-created")
	defer k.end()
	if k.store.deleteErr != nil {
		return k.store.deleteErr
	}
	if k.store.bindings[k.name] == k.binding {
		delete(k.store.persisted, k.name)
	}
	return nil
}

func (k *fakeKey) close() {
	if k.done {
		k.store.t.Fatalf("close called after key %q lifetime ended (double release)", k.name)
	}
	k.end()
}

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
		if _, err := openWith(s, testKey, p); err == nil {
			t.Errorf("openWithPolicy accepted %v", p)
		}
		if _, err := createWith(s, testKey, p); err == nil {
			t.Errorf("createWith accepted %v", p)
		}
		if err := applyWith(s, testKey, p); err == nil {
			t.Errorf("applyPolicy accepted %v", p)
		}
		if s.opens != 0 || s.privilegeChecks != 0 {
			t.Errorf("invalid policy %v reached the key store", p)
		}
		assertNoMutation(t, s)
	}
}

func TestOpenPolicy(t *testing.T) {
	t.Run("privileged-only rejects non-privileged caller before open", func(t *testing.T) {
		s := newFakeStore(t)
		s.persisted[testKey] = privilegedOnlyDescriptor(t)
		_, err := openWith(s, testKey, PolicyPrivilegedOnly)
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
		_, err := openWith(s, testKey, PolicyPrivilegedOnly)
		if !errors.Is(err, ErrPrivilegeRequired) || s.opens != 0 {
			t.Fatalf("err = %v opens=%d, want ErrPrivilegeRequired and no open", err, s.opens)
		}
	})
	t.Run("privileged-only match", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = privilegedOnlyDescriptor(t)
		signer, err := openWith(s, testKey, PolicyPrivilegedOnly)
		if err != nil || signer == nil {
			t.Fatalf("openWithPolicy: %v", err)
		}
		assertNoMutation(t, s)
		assertHandlesReleased(t, s)
	})
	t.Run("service-signer does not require privilege", func(t *testing.T) {
		s := newFakeStore(t)
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		if _, err := openWith(s, testKey, PolicyServiceSigner); err != nil {
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
			_, err := openWith(s, testKey, tc.policy)
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
		_, err := openWith(s, testKey, PolicyPrivilegedOnly)
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("err = %v, want ErrKeyNotFound", err)
		}
		assertNoMutation(t, s)
	})
	t.Run("exportable key rejected", func(t *testing.T) {
		s := newFakeStore(t)
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		s.exportErr = errors.New("export policy permits export")
		if _, err := openWith(s, testKey, PolicyServiceSigner); err == nil {
			t.Fatal("exportable key accepted")
		}
		assertHandlesReleased(t, s)
	})
	t.Run("non-P-256 key rejected", func(t *testing.T) {
		s := newFakeStore(t)
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		s.pubErr = errors.New("not P-256")
		if _, err := openWith(s, testKey, PolicyServiceSigner); !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want ErrPolicyMismatch", err)
		}
		assertHandlesReleased(t, s)
	})
}

func TestCreateWithPolicy(t *testing.T) {
	for _, p := range []Policy{PolicyServiceSigner, PolicyPrivilegedOnly} {
		t.Run(p.String()+" requires privilege before any create", func(t *testing.T) {
			s := newFakeStore(t)
			_, err := createWith(s, testKey, p)
			if !errors.Is(err, ErrPrivilegeRequired) || s.opens != 0 {
				t.Fatalf("err = %v opens=%d, want ErrPrivilegeRequired and no open", err, s.opens)
			}
			assertNoMutation(t, s)
		})
		t.Run("creates with "+p.String()+" SDDL without opening", func(t *testing.T) {
			s := newFakeStore(t)
			s.privileged = true
			signer, err := createWith(s, testKey, p)
			if err != nil || signer == nil {
				t.Fatalf("createWith: %v", err)
			}
			if len(s.creates) != 1 || s.creates[0] != policySDDL(p) {
				t.Fatalf("creates = %v, want [%s]", s.creates, policySDDL(p))
			}
			if s.opens != 0 || len(s.writes) != 0 || len(s.deleted) != 0 {
				t.Fatalf("unexpected opens=%d writes=%v deleted=%v", s.opens, s.writes, s.deleted)
			}
			assertHandlesReleased(t, s)
		})
	}
	t.Run("privilege check error does not create", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.privErr = errors.New("CheckTokenMembership failed")
		if _, err := createWith(s, testKey, PolicyServiceSigner); !errors.Is(err, ErrPrivilegeRequired) {
			t.Fatalf("err = %v, want ErrPrivilegeRequired", err)
		}
		assertNoMutation(t, s)
	})
	t.Run("existing key: ErrKeyExists, key untouched", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		existing := privilegedOnlyDescriptor(t)
		s.persisted[testKey] = existing
		_, err := createWith(s, testKey, PolicyPrivilegedOnly)
		if !errors.Is(err, ErrKeyExists) {
			t.Fatalf("err = %v, want ErrKeyExists", err)
		}
		if s.opens != 0 || len(s.deleted) != 0 || len(s.writes) != 0 || string(s.persisted[testKey]) != string(existing) {
			t.Fatal("the existing key must not be opened, modified or deleted")
		}
		assertHandlesReleased(t, s)
	})
	t.Run("created key failing verification is deleted", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		// Simulate provider canonicalization of GA for Administrators.
		s.writeResult = buildDescriptor(t, protectedControl, allow(genericAll, sidSYSTEM), allow(0x001F0003, sidAdministrators))
		_, err := createWith(s, testKey, PolicyPrivilegedOnly)
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
		s.createErr = errors.New("NCryptCreatePersistedKey: hr=0x80090009")
		if _, err := createWith(s, testKey, PolicyServiceSigner); err == nil || errors.Is(err, ErrKeyExists) {
			t.Fatalf("err = %v, want the create failure without ErrKeyExists", err)
		}
		if len(s.deleted) != 0 {
			t.Fatal("create failure must not delete")
		}
	})
}

// TestOpenAndCreateExportThePublicKeyOnce: the signer returned by Open and
// Create is built from the public key read and verified on the same handle.
// The public key is exported once per call, the handles are transferred to the
// signer once and nothing is deleted, for every policy.
func TestOpenAndCreateExportThePublicKeyOnce(t *testing.T) {
	requireNCryptNotLoaded(t)
	pub, _ := testP256(t)
	for _, p := range allPolicies(t) {
		for _, op := range []string{"Open", "Create"} {
			t.Run(policyLabel(p)+": "+op, func(t *testing.T) {
				s := newFakeStore(t)
				s.privileged = true
				s.pub = pub
				var signer Signer
				var err error
				if op == "Open" {
					s.persisted[testKey] = matchingDescriptor(t, p)
					signer, err = openWith(s, testKey, p)
				} else {
					signer, err = createWith(s, testKey, p)
				}
				if err != nil || signer == nil {
					t.Fatalf("signer=%v err=%v, want a signer", signer, err)
				}
				if s.pubReads != 1 {
					t.Fatalf("pubReads = %d, want 1: the public key is exported once", s.pubReads)
				}
				if s.signerCalls != 1 || s.signerPub != pub {
					t.Fatalf("signerCalls=%d signerPub=%p, want 1 call with the verified key %p", s.signerCalls, s.signerPub, pub)
				}
				if got, ok := signer.Public().(*ecdsa.PublicKey); !ok || !got.Equal(pub) {
					t.Fatalf("Public() = %v, want the verified public key", signer.Public())
				}
				if len(s.deleted) != 0 {
					t.Fatalf("deleted = %v, want none on success", s.deleted)
				}
				assertHandlesReleased(t, s)
			})
		}
	}
}

func TestApplyPolicyValues(t *testing.T) {
	t.Run("requires privilege before open", func(t *testing.T) {
		for _, p := range []Policy{PolicyServiceSigner, PolicyPrivilegedOnly} {
			s := newFakeStore(t)
			s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
			if err := applyWith(s, testKey, p); !errors.Is(err, ErrPrivilegeRequired) {
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
		if err := applyWith(s, testKey, PolicyPrivilegedOnly); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("err = %v, want ErrKeyNotFound", err)
		}
		assertNoMutation(t, s)
	})
	for _, lsMask := range []uint32{genericRead, genericRead | genericExecute, 0x801200A9} {
		t.Run(fmt.Sprintf("tightens service-signer (LS 0x%08X) to privileged-only", lsMask), func(t *testing.T) {
			s := newFakeStore(t)
			s.privileged = true
			s.persisted[testKey] = serviceSignerDescriptor(t, lsMask)
			if err := applyWith(s, testKey, PolicyPrivilegedOnly); err != nil {
				t.Fatal(err)
			}
			if len(s.writes) != 1 || s.writes[0] != privilegedOnlySDDL {
				t.Fatalf("writes = %v, want exactly one privileged-only write", s.writes)
			}
			if len(s.creates) != 0 || len(s.deleted) != 0 {
				t.Fatal("Apply must not create or delete")
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
			if err := applyWith(s, testKey, tc.p); err != nil {
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
		if err := applyWith(s, testKey, PolicyServiceSigner); !errors.Is(err, ErrPolicyMismatch) {
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
			if err := applyWith(s, testKey, PolicyPrivilegedOnly); !errors.Is(err, ErrPolicyMismatch) {
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
		if err := applyWith(s, testKey, PolicyPrivilegedOnly); err == nil {
			t.Fatal("exportable key accepted")
		}
		assertNoMutation(t, s)
	})
	t.Run("non-P-256 key is not modified", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		s.pubErr = errors.New("not P-256")
		if err := applyWith(s, testKey, PolicyPrivilegedOnly); !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want ErrPolicyMismatch", err)
		}
		assertNoMutation(t, s)
	})
	t.Run("write failure is reported", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		s.setErr = errors.New("set security descriptor: hr=0x80090010")
		if err := applyWith(s, testKey, PolicyPrivilegedOnly); err == nil {
			t.Fatal("write failure not reported")
		}
		assertHandlesReleased(t, s)
	})
	t.Run("read-back mismatch on open handle fails without rollback", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
		s.writeResult = buildDescriptor(t, protectedControl, allow(genericAll, sidSYSTEM), allow(0x001F0003, sidAdministrators))
		err := applyWith(s, testKey, PolicyPrivilegedOnly)
		if !errors.Is(err, ErrPostWriteVerification) {
			t.Fatalf("err = %v, want ErrPostWriteVerification", err)
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
		err := applyWith(s, testKey, PolicyPrivilegedOnly)
		if !errors.Is(err, ErrPostWriteVerification) {
			t.Fatalf("err = %v, want ErrPostWriteVerification", err)
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

// TestPolicyZeroSizeExportComposition feeds the error that exportPublicKeyWith
// really returns for a zero-size query into the policy/service fake, at the
// public-key export (publicKey, used by checkKeyPolicyPublic and applySpec),
// the only one Open and Create make.
func TestPolicyZeroSizeExportComposition(t *testing.T) {
	requireNCryptNotLoaded(t)
	zeroErr := zeroSizeExportError(t)
	servicePolicy := mustServicePolicy(t, testServiceName)
	create := func(s *fakeStore, service bool) (Signer, error) {
		if service {
			return createWith(s, testKey, servicePolicy)
		}
		return createWith(s, testKey, PolicyServiceSigner)
	}
	for _, service := range []bool{false, true} {
		label := "with-policy"
		if service {
			label = "for-service"
		}
		for _, deleteFails := range []bool{false, true} {
			suffix := ", delete succeeds"
			if deleteFails {
				suffix = ", delete fails"
			}
			t.Run(label+": new key, zero at the public-key export"+suffix, func(t *testing.T) {
				s := newFakeStore(t)
				s.privileged = true
				s.pubErr = zeroErr
				if deleteFails {
					s.deleteErr = errors.New("NCryptDeleteKey: hr=0x80090010")
				}
				_, err := create(s, service)
				if !errors.Is(err, ErrPolicyMismatch) || !errors.Is(err, zeroErr) {
					t.Fatalf("err = %v, want ErrPolicyMismatch and the zero-size cause (C2)", err)
				}
				if errors.Is(err, ErrCleanupFailed) != deleteFails {
					t.Fatalf("err = %v, ErrCleanupFailed must be present only when the delete fails", err)
				}
				if len(s.creates) != 1 || len(s.deleted) != 1 || s.signerCalls != 0 {
					t.Fatalf("creates=%d deleted=%d signerCalls=%d, want 1/1/0", len(s.creates), len(s.deleted), s.signerCalls)
				}
				assertHandlesReleased(t, s)
			})
		}
	}
	t.Run("existing key, zero at the public-key export: no delete", func(t *testing.T) {
		for _, privileged := range []bool{false, true} {
			s := newFakeStore(t)
			s.privileged = privileged
			s.persisted[testKey] = serviceSignerDescriptor(t, genericRead|genericExecute)
			s.pubErr = zeroErr
			_, err := openWith(s, testKey, PolicyServiceSigner)
			if !errors.Is(err, ErrPolicyMismatch) || !errors.Is(err, zeroErr) || errors.Is(err, ErrCleanupFailed) {
				t.Fatalf("privileged=%v err = %v", privileged, err)
			}
			assertNoMutation(t, s)
			assertHandlesReleased(t, s)
		}
	})
	t.Run("existing service-SID key via Open, zero at the public-key export", func(t *testing.T) {
		s := newFakeStore(t)
		s.persisted[testKey] = s.descriptorFor(servicePolicy.sddl())
		s.pubErr = zeroErr
		_, err := openWith(s, testKey, servicePolicy)
		if !errors.Is(err, ErrPolicyMismatch) || !errors.Is(err, zeroErr) {
			t.Fatalf("err = %v", err)
		}
		assertNoMutation(t, s)
		assertHandlesReleased(t, s)
	})
	t.Run("Apply, zero at publicKey", func(t *testing.T) {
		for _, service := range []bool{false, true} {
			s := newFakeStore(t)
			s.privileged = true
			s.persisted[testKey] = serviceSignerDescriptor(t, genericRead|genericExecute)
			s.pubErr = zeroErr
			var err error
			if service {
				err = applyWith(s, testKey, servicePolicy)
			} else {
				err = applyWith(s, testKey, PolicyPrivilegedOnly)
			}
			if !errors.Is(err, ErrPolicyMismatch) || !errors.Is(err, zeroErr) {
				t.Fatalf("service=%v err = %v, want ErrPolicyMismatch and the zero-size cause (C2)", service, err)
			}
			if !strings.Contains(err.Error(), "key is not a valid ECDSA P-256 key: NCryptExportKey (query size): reported size 0") {
				t.Fatalf("service=%v err = %v, diagnostic text changed", service, err)
			}
			if s.opens != 1 || s.sdReads != 0 {
				t.Fatalf("service=%v opens=%d sdReads=%d, want the export checked before any DACL read", service, s.opens, s.sdReads)
			}
			assertNoMutation(t, s)
			assertHandlesReleased(t, s)
		}
	})
}

// racingStore runs hook once, immediately before the first DACL write through
// any key it opened, to simulate a second writer that completes between the
// read and the write of the first.
type racingStore struct {
	*fakeStore
	hook func()
}

func (s *racingStore) open(name string) (storedKey, error) {
	k, err := s.fakeStore.open(name)
	if err != nil {
		return nil, err
	}
	return &racingKey{storedKey: k, store: s}, nil
}

type racingKey struct {
	storedKey
	store *racingStore
}

func (k *racingKey) setSecurityDescriptor(sddl string) error {
	if h := k.store.hook; h != nil {
		k.store.hook = nil
		h()
	}
	return k.storedKey.setSecurityDescriptor(sddl)
}

// TestOverlappingWritersAreNotCoordinated documents the current outcome, not a
// guarantee: the package does not serialize writers (see the godoc of
// Apply and "Limits to be aware of" in
// docs/README.md; callers must serialize changes to the same key, also across
// processes). A reads service-signer; B completes Apply(PolicyPrivilegedOnly);
// A then writes the service-SID DACL from its stale read. Both return nil and
// the final state is service-SID: the service access B removed is granted again.
// If a coordination is ever added, this test must change with it.
func TestOverlappingWritersAreNotCoordinated(t *testing.T) {
	svc, err := NewServicePolicy("Example.Policy.Agent")
	if err != nil {
		t.Fatal(err)
	}
	inner := newFakeStore(t)
	inner.privileged = true
	inner.persisted[testKey] = serviceSignerDescriptor(t, genericRead|genericExecute)

	var errB error
	store := &racingStore{fakeStore: inner}
	store.hook = func() { errB = applyWith(inner, testKey, PolicyPrivilegedOnly) }

	errA := applyWith(store, testKey, svc)

	if errB != nil || errA != nil {
		t.Fatalf("B = %v, A = %v; the documented outcome is that both return nil", errB, errA)
	}
	state, sid, err := classifyDescriptorSID(inner.persisted[testKey])
	if err != nil {
		t.Fatal(err)
	}
	if state != daclServiceSID || sid != svc.SID() {
		t.Fatalf("final state = %s, want the service-sid state of A (B's tightening was overwritten)", describeState(state, sid))
	}
	if len(inner.writes) != 2 || inner.writes[0] != privilegedOnlySDDL || inner.writes[1] != svc.sddl() {
		t.Fatalf("writes = %v, want B's privileged-only then A's service-sid", inner.writes)
	}
	assertHandlesReleased(t, inner)
}
