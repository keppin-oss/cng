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

// OpenWithPolicy is not supported on non-Windows platforms.
func OpenWithPolicy(name string, policy Policy) (Signer, error) {
	return nil, fmt.Errorf("windowscng: machine-scoped CNG keys are not supported on this platform")
}

// LoadOrCreateWithPolicy is not supported on non-Windows platforms.
func LoadOrCreateWithPolicy(name string, policy Policy) (Signer, error) {
	return nil, fmt.Errorf("windowscng: machine-scoped CNG keys are not supported on this platform")
}

// ApplyPolicy is not supported on non-Windows platforms.
func ApplyPolicy(name string, policy Policy) error {
	return fmt.Errorf("windowscng: machine-scoped CNG keys are not supported on this platform")
}

// OpenForService is not supported on non-Windows platforms.
func OpenForService(name string, policy ServicePolicy) (Signer, error) {
	return nil, fmt.Errorf("windowscng: machine-scoped CNG keys are not supported on this platform")
}

// LoadOrCreateForService is not supported on non-Windows platforms.
func LoadOrCreateForService(name string, policy ServicePolicy) (Signer, error) {
	return nil, fmt.Errorf("windowscng: machine-scoped CNG keys are not supported on this platform")
}

// ApplyServicePolicy is not supported on non-Windows platforms.
func ApplyServicePolicy(name string, policy ServicePolicy) error {
	return fmt.Errorf("windowscng: machine-scoped CNG keys are not supported on this platform")
}
