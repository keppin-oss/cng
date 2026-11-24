//go:build windows

package windowscng

import (
	"errors"
	"strings"
	"testing"
)

// Tests of the unified primitives (Open, Create, Delete, Apply) and of the
// KeyPolicy resolver against the in-memory fake keyStore. They never open,
// create, modify or delete a real persisted CNG key.

// embeddedPolicy satisfies KeyPolicy through the promoted method of Policy:
// the unexported method alone does not keep it out, the resolver must.
type embeddedPolicy struct{ Policy }

// embeddedServicePolicy and embeddedKeyPolicy do the same through
// ServicePolicy and through the interface itself.
type (
	embeddedServicePolicy struct{ ServicePolicy }
	embeddedKeyPolicy     struct{ KeyPolicy }
)

// primitives runs each of the four primitives with name and p on s.
func primitives(t *testing.T, spki []byte) map[string]func(s *fakeStore, name string, p KeyPolicy) error {
	t.Helper()
	return map[string]func(s *fakeStore, name string, p KeyPolicy) error{
		"Open": func(s *fakeStore, name string, p KeyPolicy) error {
			_, err := openWith(s, name, p)
			return err
		},
		"Create": func(s *fakeStore, name string, p KeyPolicy) error {
			_, err := createWith(s, name, p)
			return err
		},
		"Delete": func(s *fakeStore, name string, p KeyPolicy) error { return deleteWith(s, name, p, spki) },
		"Apply":  func(s *fakeStore, name string, p KeyPolicy) error { return applyWith(s, name, p) },
	}
}

// requireInputError fails unless err is a plain input error that reached
// neither the privilege check nor the key store.
func requireInputError(t *testing.T, what string, err error, s *fakeStore) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: accepted", what)
	}
	for _, sentinel := range []error{ErrPrivilegeRequired, ErrKeyNotFound, ErrPolicyMismatch, ErrKeyExists, ErrDeleteVerificationFailed, ErrCleanupFailed, ErrPostWriteVerification} {
		if errors.Is(err, sentinel) {
			t.Fatalf("%s: err = %v matches %v, want a plain input error", what, err, sentinel)
		}
	}
	if s.privilegeChecks != 0 || s.opens != 0 {
		t.Fatalf("%s: reached the key store (privilegeChecks=%d opens=%d)", what, s.privilegeChecks, s.opens)
	}
	assertNoMutation(t, s)
}

func TestKeyPolicyResolverRejectsEverythingButTheConcreteValues(t *testing.T) {
	_, spki := testP256(t)
	valid := PolicyServiceSigner
	var nilPolicy *Policy
	var nilService *ServicePolicy
	sp := mustServicePolicy(t, testServiceName)
	for name, p := range map[string]KeyPolicy{
		"nil":                          nil,
		"zero Policy":                  Policy(0),
		"undefined Policy":             Policy(3),
		"zero ServicePolicy":           ServicePolicy{},
		"forged ServicePolicy":         ServicePolicy{name: testServiceName, sid: "S-1-5-80-1-2-3-4-5"},
		"pointer to a valid Policy":    &valid,
		"typed nil *Policy":            nilPolicy,
		"pointer to ServicePolicy":     &sp,
		"typed nil *ServicePolicy":     nilService,
		"type embedding Policy":        embeddedPolicy{PolicyServiceSigner},
		"type embedding ServicePolicy": embeddedServicePolicy{sp},
		"type embedding KeyPolicy":     embeddedKeyPolicy{PolicyPrivilegedOnly},
		"pointer to an embedding type": &embeddedPolicy{PolicyServiceSigner},
	} {
		for op, run := range primitives(t, spki) {
			s := newFakeStore(t)
			s.privileged = true
			s.persisted[testKey] = serviceSignerDescriptor(t, genericRead|genericExecute)
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s(%s) panicked: %v", op, name, r)
					}
				}()
				err = run(s, testKey, p)
			}()
			requireInputError(t, op+"("+name+")", err, s)
		}
	}
}

func TestPrimitivesValidateTheNameFirst(t *testing.T) {
	_, spki := testP256(t)
	for _, tc := range []struct{ name, text string }{
		{"", "key name is empty"},
		{"a\x00b", "NUL character"},
	} {
		for op, run := range primitives(t, spki) {
			s := newFakeStore(t)
			s.privileged = true
			// An invalid policy too: the name is reported first.
			err := run(s, tc.name, Policy(0))
			requireInputError(t, op, err, s)
			if !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("%s(%q): err = %v, want it to mention %q", op, tc.name, err, tc.text)
			}
		}
	}
}

func TestDeleteWithEveryPolicy(t *testing.T) {
	pub, spki := testP256(t)
	sp := mustServicePolicy(t, testServiceName)
	descriptors := map[string]func(*testing.T) []byte{
		PolicyServiceSigner.String():  func(t *testing.T) []byte { return serviceSignerDescriptor(t, genericRead) },
		PolicyPrivilegedOnly.String(): privilegedOnlyDescriptor,
		sp.String():                   func(t *testing.T) []byte { return serviceSIDDescriptor(t, sp.SID(), 0x801200A9) },
	}
	policies := []KeyPolicy{PolicyServiceSigner, PolicyPrivilegedOnly, sp}
	label := func(p KeyPolicy) string { return p.(interface{ String() string }).String() }
	for _, held := range policies {
		for _, asked := range policies {
			t.Run(label(held)+" key, Delete with "+label(asked), func(t *testing.T) {
				s := newFakeStore(t)
				s.privileged = true
				s.pub = pub
				s.allowDeleteExisting = true
				s.persisted[testKey] = descriptors[label(held)](t)
				err := deleteWith(s, testKey, asked, spki)
				if label(held) == label(asked) {
					if err != nil {
						t.Fatalf("err = %v, want the verified key deleted", err)
					}
					if _, ok := s.persisted[testKey]; ok || len(s.deletedKeys) != 1 {
						t.Fatal("key not deleted")
					}
				} else {
					if !errors.Is(err, ErrDeleteVerificationFailed) || !errors.Is(err, ErrPolicyMismatch) {
						t.Fatalf("err = %v, want ErrDeleteVerificationFailed and ErrPolicyMismatch", err)
					}
					if _, ok := s.persisted[testKey]; !ok || len(s.deleted) != 0 {
						t.Fatal("a key in another policy state was deleted")
					}
				}
				assertHandlesReleased(t, s)
			})
		}
	}
	t.Run("every policy requires a privileged caller", func(t *testing.T) {
		for _, p := range policies {
			s := newFakeStore(t)
			s.pub = pub
			s.persisted[testKey] = serviceSignerDescriptor(t, genericRead)
			if err := deleteWith(s, testKey, p, spki); !errors.Is(err, ErrPrivilegeRequired) || s.opens != 0 {
				t.Fatalf("%s: err = %v opens=%d, want ErrPrivilegeRequired before any open", label(p), err, s.opens)
			}
			assertNoMutation(t, s)
		}
	})
}

func TestOpenPrivilegeDependsOnlyOnThePolicy(t *testing.T) {
	sp := mustServicePolicy(t, testServiceName)
	for _, tc := range []struct {
		p          KeyPolicy
		sd         func(*testing.T) []byte
		privileged bool
	}{
		{PolicyServiceSigner, func(t *testing.T) []byte { return serviceSignerDescriptor(t, genericRead) }, false},
		{sp, func(t *testing.T) []byte { return serviceSIDDescriptor(t, sp.SID(), 0x801200A9) }, false},
		{PolicyPrivilegedOnly, privilegedOnlyDescriptor, true},
	} {
		s := newFakeStore(t) // not privileged
		s.persisted[testKey] = tc.sd(t)
		signer, err := openWith(s, testKey, tc.p)
		if tc.privileged {
			if !errors.Is(err, ErrPrivilegeRequired) || s.opens != 0 {
				t.Fatalf("%v: err = %v opens=%d, want ErrPrivilegeRequired before any open", tc.p, err, s.opens)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%v: err = %v, want the key opened without privilege", tc.p, err)
		}
		_ = signer.Close()
		if s.privilegeChecks != 0 {
			t.Fatalf("%v: the privilege was checked", tc.p)
		}
		assertNoMutation(t, s)
		assertHandlesReleased(t, s)
	}
}

func TestApplyIdempotentStillRequiresPrivilege(t *testing.T) {
	for _, p := range allPolicies(t) {
		s := newFakeStore(t) // not privileged
		s.persisted[testKey] = matchingDescriptor(t, p)
		if err := applyWith(s, testKey, p); !errors.Is(err, ErrPrivilegeRequired) || s.opens != 0 {
			t.Fatalf("%s: err = %v opens=%d, want ErrPrivilegeRequired before any open", policyLabel(p), err, s.opens)
		}
		assertNoMutation(t, s)
	}
}
