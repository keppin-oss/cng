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
}
