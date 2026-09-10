//go:build !windows

package windowscng

import "fmt"

// Open is not supported on non-Windows platforms.
func Open(name string) (Signer, error) {
	return nil, fmt.Errorf("windowscng: machine-scoped CNG keys are not supported on this platform")
}

// LoadOrCreate is not supported on non-Windows platforms.
func LoadOrCreate(name string) (Signer, error) {
	return nil, fmt.Errorf("windowscng: machine-scoped CNG keys are not supported on this platform")
}

// Delete is not supported on non-Windows platforms.
func Delete(name string) error {
	return fmt.Errorf("windowscng: machine-scoped CNG keys are not supported on this platform")
}
