# Keppin CNG

Keppin CNG is a small Go module that keeps signing keys inside Windows. It lets
a Go application create, open and use a **machine-scoped ECDSA P-256 key** held
by the Microsoft Software Key Storage Provider (KSP), and sign through the
standard `crypto.Signer` interface. The private key is never exported: your
code only ever sees the public key and the signatures.

The module is deliberately low-level. It does not issue certificates, manage
trust stores or decide who your application is; you choose the key names and
own the key lifecycle.

## When to use it

Use it when a Windows service or tool needs a signing key that

- survives restarts and is shared by processes on the machine;
- cannot be copied out of the machine as a file;
- is usable only by the accounts you intend (SYSTEM, Administrators, and
  optionally LOCAL SERVICE or one specific Windows service).

## Features

- **Windows CNG keys** — `Open`, `LoadOrCreate` and `Delete` act on an exact,
  caller-supplied key name. There is no enumeration, no wildcard deletion and
  no private-key export.
- **Signing** — keys are returned as a `Signer`, a `crypto.Signer` with a
  `Close` method. Signatures are ASN.1 DER ECDSA over a digest you compute.
- **Access policies (ACL)** — each key carries a protected DACL, chosen when
  the key is created. The policy functions below verify it exactly each time
  the key is opened. `Open` and `LoadOrCreate` check less: SYSTEM,
  Administrators and LOCAL SERVICE must be granted, listed broad principals
  (Everyone, Users, Authenticated Users, …) must not be, and for LOCAL SERVICE
  only the generic bits of the mask are checked. They do not require a
  protected DACL and accept additional entries:

  | Policy | Who can use the key |
  |---|---|
  | `PolicyServiceSigner` | SYSTEM, Administrators, and LOCAL SERVICE (read/execute) |
  | `PolicyPrivilegedOnly` | SYSTEM and Administrators only |
  | `ServicePolicy` | SYSTEM, Administrators, and **one** Windows service |

  Functions: `OpenWithPolicy`, `LoadOrCreateWithPolicy`, `ApplyPolicy`.
- **Per-service keys (service SID)** — `NewServicePolicy("MyService")` grants
  the key to that service's own SID (`NT SERVICE\MyService`) instead of to
  every LOCAL SERVICE process. Functions: `OpenForService`,
  `LoadOrCreateForService`, `ApplyServicePolicy`, `ServiceSID`.
- **Tighten-only changes** — `ApplyPolicy` and `ApplyServicePolicy` rewrite the
  DACL of an existing key in place, only toward less access (for example
  service-signer to privileged-only, or LOCAL SERVICE to one service). They
  never widen access and never recreate or delete the key.

## Requirements

- Windows, with the Microsoft Software Key Storage Provider.
- Go 1.26.8 or later (`go.mod`). On other operating systems the package
  compiles, but its constructors return an error.
- No third-party dependencies.
- Creating, deleting or re-protecting a machine key needs a privileged context
  (SYSTEM or an elevated Administrator); the package never elevates or
  impersonates. Opening an existing key needs only the access its DACL grants.

## Example

Provision a key for one service from a privileged context, then sign with it.
Inside the service itself, call `OpenForService` instead of
`LoadOrCreateForService`.

```go
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"log"

	"github.com/keppin-oss/cng/windowscng"
)

func main() {
	policy, err := windowscng.NewServicePolicy("ExampleAgent")
	if err != nil {
		log.Fatal(err)
	}

	// Opens the key, or creates it if absent (privileged callers only).
	signer, err := windowscng.LoadOrCreateForService("Example.Agent.Key.v1", policy)
	if err != nil {
		log.Fatal(err)
	}
	defer signer.Close() // releases handles; the persisted key stays

	digest := sha256.Sum256([]byte("message"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		log.Fatal(err)
	}

	pub := signer.Public().(*ecdsa.PublicKey)
	log.Println("verified:", ecdsa.VerifyASN1(pub, digest[:], sig))
}
```

For a key shared by LOCAL SERVICE processes, use
`windowscng.LoadOrCreateWithPolicy(name, windowscng.PolicyServiceSigner)` and
`windowscng.OpenWithPolicy(name, windowscng.PolicyServiceSigner)`, which verify
the DACL exactly. `LoadOrCreate(name)` creates a key with the same DACL, but
`LoadOrCreate` and `Open(name)` also accept an existing key whose DACL has
additional entries. Runnable examples, which use the policy functions, are in
[`examples/`](../examples/).

## Security model

- Keys are created in machine scope, non-exportable, in the Microsoft Software
  KSP. Only public-key material leaves the package.
- The requested DACL is set **before** the key is finalized, then read back. A
  signer is returned only if the persisted DACL passes validation; otherwise
  the call fails and tries to delete the key it just created. See
  [Provisioning window](#provisioning-window).
- The policy functions accept a key only if its DACL matches the requested
  policy **exactly** (protected, explicit allow entries, known principals and
  masks). Anything else returns `ErrPolicyMismatch`.
- `ncrypt.dll` and `advapi32.dll` are loaded only from the Windows system
  directory; key operations fail if a different module of the same name is
  already loaded.
- Existing keys are never deleted, overwritten or regenerated by a failed call.

### Provisioning window

A new key gets Export Policy `0` and the requested DACL **before**
`NCryptFinalizeKey`, so it is meant to be persisted with that DACL and never
to carry the provider's default security descriptor. Earlier versions wrote the
DACL only after finalize. Established in code:

- the private key is never exportable;
- a failure before finalize persists nothing and only releases the handle;
- no signer is returned for a new key unless the DACL read back after finalize
  passes validation (for the policy functions, the exact policy). If the
  provider did not apply the DACL, the call fails closed and deletes the key it
  created (see **Not transactional** below).

Observed natively in one P3 run (`R20261028T090457Z-691bc4a2`, Windows NT
10.0.26200, Microsoft Software KSP), in that configuration only: the KSP
persisted a descriptor set before finalize, both with raw NCrypt calls and
through `LoadOrCreateForService`. The first descriptor read after finalize was
already the requested one, with no inheritance flags:
`D:P(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x801200a9;;;<service-SID>)`.
A key finalized with no descriptor set carried
`D:P(A;OICI;0xd01f01ff;;;SY)(A;OICI;0xd01f01ff;;;BA)`, so on that build the
default that earlier versions briefly exposed granted only SYSTEM and
Administrators. Any state inside the KSP during `NCryptFinalizeKey` is not
observable and is not established. On other providers, builds or
configurations, a provider that ignored the pre-finalize descriptor would make
provisioning fail closed rather than produce a key.

A process that opened a key before its DACL changed keeps its handle, which
still matters for `ApplyPolicy` and `ApplyServicePolicy`. Provision keys from a
trusted, quiescent context.

## Errors

| Error | Meaning |
|---|---|
| `ErrKeyNotFound` | Key not found **or** not accessible to the caller. |
| `ErrPolicyMismatch` | The key's DACL is not the requested policy, or the change would widen access. No pre-existing key was modified; a key just created by `LoadOrCreate...` is deleted, or the error also wraps `ErrCleanupFailed`. |
| `ErrPrivilegeRequired` | The operation needs SYSTEM or an elevated Administrator. |
| `ErrCleanupFailed` | A failed call created a key and could not delete it; inspect it. |
| `ErrPostWriteVerification` | `ApplyPolicy`/`ApplyServicePolicy` wrote the DACL but could not confirm it; nothing was rolled back, inspect the key. Never retry or regenerate automatically. |

Use `errors.Is` for these sentinels, not the error text. They, `NCryptError`
and the `NTE*` codes are declared on every platform, so shared code compiles
on Windows and elsewhere; outside Windows the functions still only report that
the platform is not supported.

**Native causes.** Every failed NCrypt call is reachable as an
`*NCryptError` with `errors.As`: `Code` is the 32-bit `SECURITY_STATUS`
(compare it with `NTENotFound`, `NTEPerm`, `NTEBadKeyset` or another value),
`Op` describes the operation for people reading the error: it is not a
stable identifier and the same NCrypt function can appear under different
labels, so do not compare it. Win32 failures keep their `syscall.Errno`, so
`ERROR_ACCESS_DENIED` (`syscall.Errno(5)`) is distinct from `NTE_PERM`. The
error texts are unchanged.

```go
var ne *windowscng.NCryptError
if errors.As(err, &ne) && ne.Code == windowscng.NTEPerm {
	// NCrypt denied the operation
}
```

- An error can hold several causes: `ErrCleanupFailed` keeps the original
  failure and the failed delete, and `errors.As` returns the first
  `NCryptError`, the original failure. Walk `Unwrap() []error` to see every
  code.
- `ErrPrivilegeRequired` keeps the cause of a failed privilege check,
  including its `syscall.Errno`.
- After the DACL write, `ErrPostWriteVerification` keeps only the native
  causes (`NCryptError`, `syscall.Errno`) and never matches another sentinel
  of this package: a read-back that does not match is not `ErrPolicyMismatch`
  (which means no pre-existing key was modified), and a reopen that reports
  the key as not found is not `ErrKeyNotFound`. The text still describes the
  cause, and the native code stays reachable: code that classifies by
  `NCryptError.Code` (for example with `IsKeyNotFound`) must check
  `ErrPostWriteVerification` first.

## Limits to be aware of

- **"Not found" is ambiguous.** For a caller the DACL does not grant, the KSP
  reports the same status as for a missing key. Never treat `ErrKeyNotFound`
  as proof of absence, and never regenerate an identity key because of it.
- **Static check only.** DACL validation inspects the descriptor; it is not a
  computation of Windows effective access (owner rights, privileges, SACL).
- **Not transactional.** After an error a new key may still exist. If a key was
  created and validated but building the signer then failed, the call deletes
  that key; if the delete also fails, the error wraps `ErrCleanupFailed` and
  the key may persist. One case is not a cleanup failure: for a
  **non-privileged** caller (for example an Administrator with a UAC-filtered
  token), when `NCryptFinalizeKey` is denied with `NTE_PERM` and deleting the
  never finalized key reports `NTE_BAD_KEYSET`, the key was not persisted and
  the error is the finalize denial alone. For a privileged caller, or if the
  privilege check fails, and for any other combination, the error still wraps
  `ErrCleanupFailed`. Only that case was verified natively, on one setup
  (Windows NT 10.0.26200, Microsoft Software KSP, Administrator with a
  UAC-filtered token, the `LoadOrCreate` DACL): an elevated caller found the
  name absent by enumeration and by exact open both before and after the
  denied finalize, with a temporary control key found by both methods. The
  check is the opt-in test `TestFinalizeFailureProbe` (build tag
  `cng_finalize_probe`).
- **Open handles are not revoked.** After `ApplyPolicy` or
  `ApplyServicePolicy`, processes that already opened the key keep working;
  restart or reopen consumers.
- **Service SID.** A service key works only if the service has its SID enabled,
  for example `sc.exe sidtype <service> unrestricted`.
- **Verified scope.** Per-service isolation was verified natively on one setup:
  Windows NT 10.0.26200, Microsoft Software KSP, services running as LOCAL
  SERVICE with an unrestricted service SID, keys created by
  `LoadOrCreateForService`. Other KSPs, Windows builds, restricted SIDs and
  keys migrated with `ApplyServicePolicy` are not covered.
- **Lifecycle.** Call `Close` when done. A signer is safe for concurrent use:
  `Sign` calls may run in parallel, and `Close` waits for those already in
  progress, then makes at most one release attempt per handle. Overlapping
  `Sign` and `Close` calls are ordered by an internal lock, so a `Sign` that
  overlaps `Close` may still complete; once `Close` has returned, every `Sign`
  fails without reaching CNG. Repeated `Close` calls are harmless; only the
  first reports a failure to release a handle, and none retries it. `Close` does
  not drain your callers: stop and drain the users of the signer (for example,
  in-flight TLS handshakes) before closing it. Coordinate provisioning and
  deletion outside this module; use `Delete` only for keys your application
  owns.

## Building and testing

```text
go build ./...
go vet ./...
go test ./...
```

The default tests use an in-memory key store and do not create, modify or
delete any persisted key.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE).
