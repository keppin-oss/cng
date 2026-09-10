package windowscng

import "crypto"

// Signer is the contract returned by Open and LoadOrCreate. It is a crypto.Signer
// plus a Close method that releases the underlying CNG provider and key handles.
//
// On Windows the concrete signer is backed by a persisted CNG key in the
// Microsoft Software Key Storage Provider; the private key is never exported.
// On non-Windows platforms no implementation exists and the constructor
// functions return an error.
type Signer interface {
	crypto.Signer
	Close() error
}
