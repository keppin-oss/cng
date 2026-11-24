//go:build !windows

package windowscng

import "fmt"

// errUnsupportedPlatform is returned by every key function off Windows. Input
// validation is not performed first: its precedence is a Windows behavior.
func errUnsupportedPlatform() error {
	return fmt.Errorf("windowscng: machine-scoped CNG keys are not supported on this platform")
}

// Open is not supported on non-Windows platforms.
func Open(name string, policy KeyPolicy) (Signer, error) {
	return nil, errUnsupportedPlatform()
}

// Create is not supported on non-Windows platforms.
func Create(name string, policy KeyPolicy) (Signer, error) {
	return nil, errUnsupportedPlatform()
}

// Delete is not supported on non-Windows platforms.
func Delete(name string, policy KeyPolicy, expectedSPKI []byte) error {
	return errUnsupportedPlatform()
}

// Apply is not supported on non-Windows platforms.
func Apply(name string, policy KeyPolicy) error {
	return errUnsupportedPlatform()
}
