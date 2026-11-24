//go:build !windows

package windowscng

import "testing"

func TestPlatformUnsupported(t *testing.T) {
	sp, err := NewServicePolicy("Example.Policy.Agent")
	if err != nil {
		t.Fatal(err)
	}
	// Valid and invalid policies alike, including nil: off Windows every call
	// reports the unsupported platform and none panics.
	for _, p := range []KeyPolicy{PolicyServiceSigner, PolicyPrivilegedOnly, sp, nil, Policy(0), ServicePolicy{}} {
		if _, err := Open("any", p); err == nil {
			t.Fatalf("Open(%v) must fail on non-Windows", p)
		}
		if _, err := Create("any", p); err == nil {
			t.Fatalf("Create(%v) must fail on non-Windows", p)
		}
		if err := Delete("any", p, []byte{0x30}); err == nil {
			t.Fatalf("Delete(%v) must fail on non-Windows", p)
		}
		if err := Apply("any", p); err == nil {
			t.Fatalf("Apply(%v) must fail on non-Windows", p)
		}
	}
}
