//go:build !windows

package windowscng

import "testing"

func TestPlatformUnsupported(t *testing.T) {
	if _, err := Open("any"); err == nil {
		t.Fatal("Open must fail on non-Windows")
	}
	if _, err := LoadOrCreate("any"); err == nil {
		t.Fatal("LoadOrCreate must fail on non-Windows")
	}
	if err := Delete("any"); err == nil {
		t.Fatal("Delete must fail on non-Windows")
	}
	for _, p := range []Policy{PolicyServiceSigner, PolicyPrivilegedOnly} {
		if _, err := OpenWithPolicy("any", p); err == nil {
			t.Fatalf("OpenWithPolicy(%s) must fail on non-Windows", p)
		}
		if _, err := LoadOrCreateWithPolicy("any", p); err == nil {
			t.Fatalf("LoadOrCreateWithPolicy(%s) must fail on non-Windows", p)
		}
		if err := ApplyPolicy("any", p); err == nil {
			t.Fatalf("ApplyPolicy(%s) must fail on non-Windows", p)
		}
	}
	sp, err := NewServicePolicy("Example.Policy.Agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenForService("any", sp); err == nil {
		t.Fatal("OpenForService must fail on non-Windows")
	}
	if _, err := LoadOrCreateForService("any", sp); err == nil {
		t.Fatal("LoadOrCreateForService must fail on non-Windows")
	}
	if err := ApplyServicePolicy("any", sp); err == nil {
		t.Fatal("ApplyServicePolicy must fail on non-Windows")
	}
}
