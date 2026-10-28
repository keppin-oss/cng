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
//   - request a restrictive machine-key DACL at provisioning and validate that
//     the required principals (SYSTEM, Administrators, and LOCAL SERVICE) are
//     present while rejecting specific disallowed principals; validation does
//     not establish an exclusive allow-list or fully evaluate owner,
//     inheritance, every additional ACE, or Windows effective access;
//   - with the additive policy API (OpenWithPolicy, LoadOrCreateWithPolicy,
//     ApplyPolicy), select a per-key DACL policy, PolicyServiceSigner or
//     PolicyPrivilegedOnly, verify the persisted DACL against an exact-match
//     allow-list, and tighten an existing service-signer key to privileged-only
//     in place. The legacy functions are unchanged;
//   - with ServicePolicy (OpenForService, LoadOrCreateForService,
//     ApplyServicePolicy), provision and verify a key whose DACL grants one
//     Windows service's own SID instead of LOCAL SERVICE as a whole, and
//     migrate a service-signer key to it in place.
//
// The package is Windows-only. It does not implement X.509, certificate-store,
// enrollment, trust-store, or orchestration behavior.
package windowscng
