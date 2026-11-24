// Package windowscng provides shared Windows CNG/KSP machine-key primitives
// for Keppin.
//
// It consolidates the Microsoft Software Key Storage Provider machine-key
// custody behavior that is duplicated across the Keppin consumer modules. The
// package operates only on exact, caller-supplied key/container names and never
// owns, invents, or references any Keppin production key name or identity.
//
// Every key is a non-exportable, machine-scoped ECDSA P-256 key, used through
// a crypto.Signer, whose DACL is one of three exact states selected by a
// KeyPolicy: PolicyServiceSigner (SYSTEM, Administrators and LOCAL SERVICE),
// PolicyPrivilegedOnly (SYSTEM and Administrators only) or a ServicePolicy
// (SYSTEM, Administrators and one Windows service's own SID). Four primitives
// take the policy as a parameter:
//
//   - Open opens an existing key and verifies its export policy, P-256 public
//     key and exact DACL; it never creates, modifies or deletes a key;
//   - Create creates a new key and never adopts an existing one (ErrKeyExists
//     on a name collision with a key already persisted);
//   - Delete deletes a key only after verifying its export policy, P-256
//     public key, exact DACL and expected SubjectPublicKeyInfo on the handle it
//     opened;
//   - Apply tightens the DACL of an existing key in place, idempotently, to
//     privileged-only or from LOCAL SERVICE to one service SID.
//
// The package never creates a key as a side effect of a failed open: choosing
// between Open and Create, and serializing every lifecycle operation on the
// same name across processes, is the caller's job. ErrKeyNotFound never proves
// that a key is absent.
//
// A Signer is safe for concurrent use: Close waits for Sign calls in progress
// and makes at most one release attempt per handle; see Signer for the full
// contract.
//
// The package is Windows-only. It does not implement X.509, certificate-store,
// enrollment, trust-store, or orchestration behavior.
package windowscng
