// Package windowscng provides shared Windows CNG/KSP machine-key primitives
// for Keppin.
//
// It consolidates the Microsoft Software Key Storage Provider machine-key
// custody behavior that is duplicated across the Keppin consumer modules. The
// package operates only on exact, caller-supplied key/container names and never
// owns, invents, or references any Keppin production key name or identity.
//
// Capabilities:
//
//   - open an exact persisted machine-scoped key without creating a replacement;
//   - create-or-open a non-exportable, machine-scoped ECDSA P-256 signing key
//     returned through a crypto.Signer;
//   - delete an exact machine-scoped key with correct NCryptDeleteKey handle
//     ownership;
//   - enforce the shared least-privilege DACL (SYSTEM, Administrators, and
//     LOCAL SERVICE only).
//
// The package is Windows-only. It does not implement X.509, certificate-store,
// enrollment, trust-store, or orchestration behavior.
package windowscng
