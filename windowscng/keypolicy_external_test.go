package windowscng_test

import (
	"crypto"
	"runtime"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
)

// The four primitives keep the same signatures on every platform, so code
// shared between platforms compiles against them.
var (
	_ func(string, windowscng.KeyPolicy) (windowscng.Signer, error) = windowscng.Open
	_ func(string, windowscng.KeyPolicy) (windowscng.Signer, error) = windowscng.Create
	_ func(string, windowscng.KeyPolicy, []byte) error              = windowscng.Delete
	_ func(string, windowscng.KeyPolicy) error                      = windowscng.Apply
	_ crypto.Signer                                                 = windowscng.Signer(nil)
)

// TestBothPoliciesFromAnExternalPackage passes a Policy and a ServicePolicy as
// a KeyPolicy from outside the package. Off Windows it also calls the stubs,
// which must report the unsupported platform; on Windows it makes no call, so
// that no persisted key is touched.
func TestBothPoliciesFromAnExternalPackage(t *testing.T) {
	sp, err := windowscng.NewServicePolicy("Example.Policy.Agent")
	if err != nil {
		t.Fatal(err)
	}
	policies := []windowscng.KeyPolicy{windowscng.PolicyServiceSigner, windowscng.PolicyPrivilegedOnly, sp}
	if runtime.GOOS == "windows" {
		return
	}
	for _, p := range policies {
		if _, err := windowscng.Open("any", p); err == nil {
			t.Fatalf("Open(%v) must fail off Windows", p)
		}
		if _, err := windowscng.Create("any", p); err == nil {
			t.Fatalf("Create(%v) must fail off Windows", p)
		}
		if err := windowscng.Delete("any", p, []byte{0x30}); err == nil {
			t.Fatalf("Delete(%v) must fail off Windows", p)
		}
		if err := windowscng.Apply("any", p); err == nil {
			t.Fatalf("Apply(%v) must fail off Windows", p)
		}
	}
}
