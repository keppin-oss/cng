//go:build windows

package windowscng

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

// Offline tests of Create and Delete (contract C1–C3):
// the policy engine against the in-memory fake keyStore, and the create step
// against the simulated createKeyNative backend. They never open, create,
// modify or delete a real persisted CNG key.

// nativeCollision is the error createPersistedKeyWith returns when
// NCryptCreatePersistedKey reports NTE_EXISTS.
func nativeCollision() error {
	status := ncryptStatusError("NCryptCreatePersistedKey", NTEExists)
	return withCauses(status.Error(), status, errCreateCollision)
}

func testP256(t *testing.T) (*ecdsa.PublicKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &k.PublicKey, der
}

func assertNCryptCode(t *testing.T, err error, code uint32) {
	t.Helper()
	var ne *NCryptError
	if !errors.As(err, &ne) || ne.Code != code {
		t.Fatalf("err = %v, want an *NCryptError with Code 0x%08X", err, code)
	}
}

// assertNCryptOpCode also checks the operation label of the first NCryptError,
// to tell the original native status from one of a later step.
func assertNCryptOpCode(t *testing.T, err error, op string, code uint32) {
	t.Helper()
	var ne *NCryptError
	if !errors.As(err, &ne) || ne.Op != op || ne.Code != code {
		t.Fatalf("err = %v, want first *NCryptError {Op %q, Code 0x%08X}", err, op, code)
	}
}

func TestCreatePersistedKeyMarksOnlyTheCreateCollision(t *testing.T) {
	t.Run("NTE_EXISTS from create: marker, same text and NCryptError", func(t *testing.T) {
		f := &fakeCreateOps{t: t, createStatus: NTEExists}
		h, err := f.run()
		if h != 0 || !errors.Is(err, errCreateCollision) {
			t.Fatalf("h=0x%x err=%v, want the collision marker", h, err)
		}
		if err.Error() != "NCryptCreatePersistedKey: hr=0x8009000f" {
			t.Fatalf("text = %q, want it unchanged", err.Error())
		}
		assertNCryptCode(t, err, NTEExists)
		if errors.Is(err, ErrKeyExists) {
			t.Fatal("the create step itself must not expose ErrKeyExists (only Create maps it to ErrKeyExists)")
		}
		f.requireCalls("create")
	})
	t.Run("another create status: no marker", func(t *testing.T) {
		f := &fakeCreateOps{t: t, createStatus: nteBadFlags}
		_, err := f.run()
		if err == nil || errors.Is(err, errCreateCollision) {
			t.Fatalf("err = %v, want a create failure without the marker", err)
		}
	})
	t.Run("NTE_EXISTS from a later step: no marker", func(t *testing.T) {
		f := &fakeCreateOps{t: t, exportStatus: NTEExists}
		_, err := f.run()
		if err == nil || errors.Is(err, errCreateCollision) {
			t.Fatalf("err = %v, want no marker for a status that is not the create's", err)
		}
		f.requireReleasedOnce()
	})
}

func TestCreateContract(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)

	t.Run("invalid input reaches no native call", func(t *testing.T) {
		for name, run := range map[string]func(*fakeStore) error{
			"empty name": func(s *fakeStore) error { _, err := createWith(s, "", p); return err },
			"NUL in name": func(s *fakeStore) error {
				_, err := createWith(s, "a\x00b", p)
				return err
			},
			"invalid policy": func(s *fakeStore) error {
				_, err := createWith(s, testKey, ServicePolicy{name: testServiceName})
				return err
			},
		} {
			s := newFakeStore(t)
			s.privileged = true
			if err := run(s); err == nil || errors.Is(err, ErrPrivilegeRequired) || errors.Is(err, ErrKeyExists) {
				t.Errorf("%s: err = %v, want a plain input error", name, err)
			}
			if s.privilegeChecks != 0 || s.opens != 0 || len(s.creates) != 0 {
				t.Errorf("%s: reached the key store", name)
			}
		}
	})
	t.Run("NUL in name: input error even for a non-privileged caller", func(t *testing.T) {
		s := newFakeStore(t)
		_, err := createWith(s, "a\x00b", p)
		if err == nil || errors.Is(err, ErrPrivilegeRequired) || s.privilegeChecks != 0 {
			t.Fatalf("err=%v privilegeChecks=%d, want an input error before the token check", err, s.privilegeChecks)
		}
		assertNoMutation(t, s)
	})
	t.Run("non-privileged caller: no create", func(t *testing.T) {
		s := newFakeStore(t)
		_, err := createWith(s, testKey, p)
		if !errors.Is(err, ErrPrivilegeRequired) {
			t.Fatalf("err = %v, want ErrPrivilegeRequired", err)
		}
		assertNoMutation(t, s)
		if s.opens != 0 {
			t.Fatal("opened a key")
		}
	})
	t.Run("privilege check failure fails closed", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.privErr = errors.New("token query failed")
		_, err := createWith(s, testKey, p)
		if !errors.Is(err, ErrPrivilegeRequired) {
			t.Fatalf("err = %v, want ErrPrivilegeRequired", err)
		}
		assertNoMutation(t, s)
	})
	t.Run("success: one create, no open, no delete", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		signer, err := createWith(s, testKey, p)
		if err != nil {
			t.Fatal(err)
		}
		_ = signer.Close()
		if s.opens != 0 || len(s.creates) != 1 || s.creates[0] != p.sddl() || len(s.deleted) != 0 {
			t.Fatalf("opens=%d creates=%v deleted=%v", s.opens, s.creates, s.deleted)
		}
		assertHandlesReleased(t, s)
	})
	t.Run("existing key: ErrKeyExists, never opened, adopted or deleted", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		before := serviceSIDDescriptor(t, p.SID(), genericRead|genericExecute)
		s.persisted[testKey] = before
		signer, err := createWith(s, testKey, p)
		if signer != nil || !errors.Is(err, ErrKeyExists) {
			t.Fatalf("signer=%v err=%v, want ErrKeyExists", signer, err)
		}
		assertNCryptOpCode(t, err, "NCryptCreatePersistedKey", NTEExists)
		if errors.Is(err, ErrCleanupFailed) || errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("err = %v, want the collision only", err)
		}
		if s.opens != 0 || len(s.deleted) != 0 || len(s.writes) != 0 || string(s.persisted[testKey]) != string(before) {
			t.Fatalf("existing key touched: opens=%d deleted=%v writes=%v", s.opens, s.deleted, s.writes)
		}
		assertHandlesReleased(t, s)
	})
	t.Run("other create failure: not ErrKeyExists", func(t *testing.T) {
		for name, cerr := range map[string]error{
			"plain":                      errors.New("provider unavailable"),
			"NTE_EXISTS not from create": withCauses("set export policy: hr=0x8009000f", ncryptStatusError("set export policy", NTEExists)),
		} {
			s := newFakeStore(t)
			s.privileged = true
			s.createErr = cerr
			_, err := createWith(s, testKey, p)
			if err == nil || errors.Is(err, ErrKeyExists) {
				t.Errorf("%s: err = %v, want a create failure without ErrKeyExists", name, err)
			}
			assertHandlesReleased(t, s)
		}
	})
	t.Run("created key fails verification: deleted on the same handle", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.writeResult = serviceSignerDescriptor(t, genericRead|genericExecute)
		_, err := createWith(s, testKey, p)
		if !errors.Is(err, ErrPolicyMismatch) || errors.Is(err, ErrKeyExists) || errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v, want ErrPolicyMismatch with confirmed cleanup", err)
		}
		if len(s.deletedKeys) != 1 || !s.deletedKeys[0].created {
			t.Fatalf("deleted = %v, want the created key only", s.deleted)
		}
		if _, ok := s.persisted[testKey]; ok {
			t.Fatal("created key still persisted")
		}
		assertHandlesReleased(t, s)
	})
	t.Run("rollback not confirmed: cause kept, ErrCleanupFailed", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.writeResult = serviceSignerDescriptor(t, genericRead|genericExecute)
		s.deleteErr = ncryptStatusError("NCryptDeleteKey", NTEPerm)
		_, err := createWith(s, testKey, p)
		if !errors.Is(err, ErrPolicyMismatch) || !errors.Is(err, ErrCleanupFailed) {
			t.Fatalf("err = %v, want ErrPolicyMismatch and ErrCleanupFailed", err)
		}
		assertHandlesReleased(t, s)
	})
	t.Run("signer construction fails: created key deleted on the same handle", func(t *testing.T) {
		s := newFakeStore(t)
		s.privileged = true
		s.signerErr = errors.New("second export failed")
		_, err := createWith(s, testKey, p)
		if err == nil || errors.Is(err, ErrCleanupFailed) || s.signerCalls != 1 {
			t.Fatalf("err=%v signerCalls=%d", err, s.signerCalls)
		}
		if len(s.deletedKeys) != 1 || !s.deletedKeys[0].created {
			t.Fatalf("deleted = %v", s.deleted)
		}
		assertHandlesReleased(t, s)
	})
}

func TestDeleteContract(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	other := mustServicePolicy(t, "Example.Policy.Other")
	pub, spki := testP256(t)
	_, otherSPKI := testP256(t)

	store := func(t *testing.T) *fakeStore {
		s := newFakeStore(t)
		s.privileged = true
		s.pub = pub
		s.allowDeleteExisting = true
		s.persisted[testKey] = serviceSIDDescriptor(t, p.SID(), genericRead|genericExecute)
		return s
	}
	assertKept := func(t *testing.T, s *fakeStore) {
		t.Helper()
		if len(s.deleted) != 0 {
			t.Fatalf("deleted %v", s.deleted)
		}
		if _, ok := s.persisted[testKey]; !ok {
			t.Fatal("key no longer persisted")
		}
		assertHandlesReleased(t, s)
	}

	t.Run("verified key is deleted on the opened handle", func(t *testing.T) {
		s := store(t)
		if err := deleteWith(s, testKey, p, spki); err != nil {
			t.Fatal(err)
		}
		if s.opens != 1 || len(s.deletedKeys) != 1 || len(s.creates) != 0 || len(s.writes) != 0 {
			t.Fatalf("opens=%d deleted=%v creates=%v writes=%v", s.opens, s.deleted, s.creates, s.writes)
		}
		if _, ok := s.persisted[testKey]; ok {
			t.Fatal("key still persisted")
		}
		if s.pubReads != 1 {
			t.Fatalf("public key read %d times, want once (validated and compared from one read)", s.pubReads)
		}
		assertHandlesReleased(t, s)
	})

	rsaKey := func() []byte {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		return der
	}()
	p384Key := func() []byte {
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		return der
	}()
	trailing := append(append([]byte{}, spki...), 0x00)
	t.Run("invalid input reaches no native call", func(t *testing.T) {
		for name, tc := range map[string]struct {
			run  func(*fakeStore) error
			text string
		}{
			"empty name":                   {func(s *fakeStore) error { return deleteWith(s, "", p, spki) }, "key name is empty"},
			"NUL in name":                  {func(s *fakeStore) error { return deleteWith(s, "a\x00b", p, spki) }, "NUL character"},
			"invalid policy":               {func(s *fakeStore) error { return deleteWith(s, testKey, ServicePolicy{}, spki) }, ""},
			"nil SPKI":                     {func(s *fakeStore) error { return deleteWith(s, testKey, p, nil) }, "is empty"},
			"malformed SPKI":               {func(s *fakeStore) error { return deleteWith(s, testKey, p, []byte{0x30, 0x03, 0x01}) }, "not valid PKIX DER"},
			"trailing data after the SPKI": {func(s *fakeStore) error { return deleteWith(s, testKey, p, trailing) }, "not valid PKIX DER"},
			"RSA SPKI":                     {func(s *fakeStore) error { return deleteWith(s, testKey, p, rsaKey) }, "not an ECDSA P-256 key"},
			"P-384 SPKI":                   {func(s *fakeStore) error { return deleteWith(s, testKey, p, p384Key) }, "not an ECDSA P-256 key"},
		} {
			s := store(t)
			s.privileged = false // an input error must come before the token check
			err := tc.run(s)
			if err == nil || errors.Is(err, ErrPrivilegeRequired) || errors.Is(err, ErrDeleteVerificationFailed) || errors.Is(err, ErrKeyNotFound) {
				t.Errorf("%s: err = %v, want a plain input error", name, err)
			} else if tc.text != "" && !strings.Contains(err.Error(), tc.text) {
				t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.text)
			}
			if s.privilegeChecks != 0 || s.opens != 0 {
				t.Errorf("%s: reached the key store", name)
			}
			assertKept(t, s)
		}
	})
	t.Run("canonical-form check after a successful parse", func(t *testing.T) {
		// An extra ASN.1 NULL inside the outer SEQUENCE: encoding/asn1 ignores
		// trailing SEQUENCE elements that have no matching field, so the parser
		// accepts it, but it is not the canonical encoding of the key. Without
		// the re-marshal comparison this input would be accepted.
		if spki[0] != 0x30 || int(spki[1]) != len(spki)-2 || spki[1] > 0x7d {
			t.Fatalf("fixture expects a short-form outer SEQUENCE, got % x", spki[:2])
		}
		extra := append([]byte{0x30, spki[1] + 2}, spki[2:]...)
		extra = append(extra, 0x05, 0x00)
		pub, err := x509.ParsePKIXPublicKey(extra)
		if err != nil {
			t.Fatalf("parser rejected the fixture (%v): it no longer reaches the canonical-form branch", err)
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok || ec.Curve != elliptic.P256() {
			t.Fatalf("fixture parsed as %T, want a P-256 key", pub)
		}
		if again, _ := x509.MarshalPKIXPublicKey(ec); string(again) == string(extra) {
			t.Fatal("fixture re-marshals to the same bytes: it does not test the canonical form")
		}
		if err := canonicalP256SPKI(extra); err == nil || !strings.Contains(err.Error(), "canonical") {
			t.Fatalf("err = %v, want the canonical-form rejection", err)
		}
		s := store(t)
		s.privileged = false
		if err := deleteWith(s, testKey, p, extra); err == nil || errors.Is(err, ErrPrivilegeRequired) || s.privilegeChecks != 0 || s.opens != 0 {
			t.Fatalf("err=%v privilegeChecks=%d opens=%d, want an input error before any native call", err, s.privilegeChecks, s.opens)
		}
		assertKept(t, s)
	})
	t.Run("non-privileged caller: nothing opened or deleted", func(t *testing.T) {
		s := store(t)
		s.privileged = false
		if err := deleteWith(s, testKey, p, spki); !errors.Is(err, ErrPrivilegeRequired) {
			t.Fatalf("err = %v, want ErrPrivilegeRequired", err)
		}
		if s.opens != 0 {
			t.Fatal("key opened")
		}
		assertKept(t, s)
	})
	t.Run("open failure is returned unchanged", func(t *testing.T) {
		s := store(t)
		delete(s.persisted, testKey)
		err := deleteWith(s, testKey, p, spki)
		if !errors.Is(err, ErrKeyNotFound) || errors.Is(err, ErrDeleteVerificationFailed) {
			t.Fatalf("err = %v, want ErrKeyNotFound only", err)
		}
		if len(s.deleted) != 0 {
			t.Fatal("deleted")
		}
	})
	cases := map[string]struct {
		setup          func(*fakeStore)
		spki           []byte
		policyMismatch bool
	}{
		"other service SID": {setup: func(s *fakeStore) {
			s.persisted[testKey] = serviceSIDDescriptor(t, other.SID(), genericRead|genericExecute)
		}, spki: spki, policyMismatch: true},
		"privileged-only DACL":  {setup: func(s *fakeStore) { s.persisted[testKey] = privilegedOnlyDescriptor(t) }, spki: spki, policyMismatch: true},
		"SPKI mismatch":         {setup: func(*fakeStore) {}, spki: otherSPKI},
		"exportable key":        {setup: func(s *fakeStore) { s.exportErr = errors.New("export policy allows export") }, spki: spki},
		"public key unreadable": {setup: func(s *fakeStore) { s.pubErr = errors.New("export public key failed") }, spki: spki, policyMismatch: true},
		"descriptor unreadable": {setup: func(s *fakeStore) { s.sdErr = ncryptStatusError("NCryptGetProperty", NTEPerm) }, spki: spki},
	}
	for name, tc := range cases {
		t.Run("verification fails, nothing deleted: "+name, func(t *testing.T) {
			s := store(t)
			tc.setup(s)
			err := deleteWith(s, testKey, p, tc.spki)
			if !errors.Is(err, ErrDeleteVerificationFailed) {
				t.Fatalf("err = %v, want ErrDeleteVerificationFailed", err)
			}
			if errors.Is(err, ErrPolicyMismatch) != tc.policyMismatch {
				t.Fatalf("err = %v, ErrPolicyMismatch = %v, want %v", err, !tc.policyMismatch, tc.policyMismatch)
			}
			if len(s.writes) != 0 {
				t.Fatal("policy was rewritten")
			}
			assertKept(t, s)
		})
	}
	t.Run("delete itself fails: delete error, handle released once", func(t *testing.T) {
		s := store(t)
		s.deleteErr = ncryptStatusError("NCryptDeleteKey", NTEPerm)
		err := deleteWith(s, testKey, p, spki)
		if err == nil || errors.Is(err, ErrDeleteVerificationFailed) || errors.Is(err, ErrCleanupFailed) || !strings.Contains(err.Error(), "delete key") {
			t.Fatalf("err = %v, want the delete failure only", err)
		}
		assertNCryptOpCode(t, err, "NCryptDeleteKey", NTEPerm)
		if len(s.deletedKeys) != 1 {
			t.Fatalf("delete attempted %d times, want once", len(s.deletedKeys))
		}
		assertHandlesReleased(t, s)
	})
}
