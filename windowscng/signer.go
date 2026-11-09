package windowscng

import "crypto"

// Signer is the contract returned by Open and LoadOrCreate. It is a crypto.Signer
// plus a Close method that releases the underlying CNG provider and key handles.
//
// On Windows the concrete signer is backed by a persisted CNG key in the
// Microsoft Software Key Storage Provider; the private key is never exported.
// On non-Windows platforms no implementation exists and the constructor
// functions return an error.
//
// Concurrency and lifetime: on Windows a Signer is safe for concurrent use.
// Sign may run in parallel with other Sign calls and with Close on the same
// Signer. Overlapping Sign and Close calls are ordered by an internal lock:
// Close waits for every Sign that already holds it, a Sign ordered before
// Close completes normally, and a Sign ordered after Close fails without
// calling CNG. Once Close has returned, every Sign fails without calling CNG.
// Close makes at most one release attempt per key and provider handle. Close
// is idempotent: the first call reports any failure to release a handle
// (which is not retried), later calls return nil and make no further attempt.
// Public stays valid after Close.
//
// Close does not drain callers: a Sign issued after Close simply fails. The
// consumer remains responsible for stopping and draining its users (for
// example, in-flight TLS handshakes) before closing the Signer. Close blocks
// for as long as an in-progress Sign takes inside CNG.
type Signer interface {
	crypto.Signer
	Close() error
}
