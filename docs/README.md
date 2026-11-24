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

Four functions act on an exact, caller-supplied key name, each with the
access policy of the key as a parameter. There is no enumeration, no wildcard
deletion and no private-key export.

| Function | What it does |
|---|---|
| `Open(name, policy)` | Opens an existing key and verifies that it is non-exportable, ECDSA P-256 and that its DACL is **exactly** the policy. Never creates, modifies or deletes a key. |
| `Create(name, policy)` | Creates a new key with the policy's DACL. **Never adopts** an existing key: if a key with that name is already persisted, it returns `ErrKeyExists` and leaves it untouched. It does **not** reserve the name against a concurrent creator (see "Concurrent creators" below). |
| `Delete(name, policy, expectedSPKI)` | Deletes a key only after checking, on the handle it opened, that it is non-exportable P-256, that its DACL is exactly the policy and that its public key is the expected `SubjectPublicKeyInfo`; otherwise it returns `ErrDeleteVerificationFailed` and deletes nothing. |
| `Apply(name, policy)` | Rewrites the DACL of an existing key in place, only toward less access, idempotently. Never widens access, never recreates or deletes the key. |

- **Signing** — `Open` and `Create` return a `Signer`, a `crypto.Signer` with a
  `Close` method. Signatures are ASN.1 DER ECDSA over a digest you compute.
- **Access policies (ACL)** — each key carries a protected DACL, chosen when
  the key is created and verified exactly each time it is opened, deleted or
  re-protected. The policy is a `KeyPolicy`, one of:

  | Policy | Who can use the key | `Open` needs a privileged caller |
  |---|---|---|
  | `PolicyServiceSigner` | SYSTEM, Administrators, and LOCAL SERVICE (read/execute) | no |
  | `PolicyPrivilegedOnly` | SYSTEM and Administrators only | yes |
  | `NewServicePolicy("MyService")` | SYSTEM, Administrators, and **one** Windows service (`NT SERVICE\MyService`) | no |

  A `ServicePolicy` grants the key to that service's own SID instead of to
  every LOCAL SERVICE process; `ServiceSID` computes that SID. Only these
  values are accepted: `nil`, a pointer, the zero value or any other type is
  an input error.
- **Tighten-only changes** — `Apply` allows service-signer or service-SID to
  privileged-only, and service-signer (LOCAL SERVICE) to one service SID.
- **No create on a failed open** — the package never creates a key as a side
  effect of an open. Choosing between `Open` and `Create`, and serializing
  them, is the caller's job: `ErrKeyNotFound` is not proof that a key is
  absent (see "Not found is ambiguous" below).

`Create`, `Delete` and `Apply` need a privileged caller whatever the policy.

## Requirements

- Windows, with the Microsoft Software Key Storage Provider.
- Go 1.26.8 or later (`go.mod`). On other operating systems the package
  compiles, but its functions return an error.
- No third-party dependencies.
- Creating, deleting or re-protecting a machine key needs a privileged context
  (SYSTEM or an elevated Administrator); the package never elevates or
  impersonates. Opening an existing key needs only the access its DACL grants,
  except for `PolicyPrivilegedOnly`.

## Example

Provision a key for one service from a privileged context, record its public
key, then sign with it. Inside the service itself, only call `Open`.

```go
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"log"

	"github.com/keppin-oss/cng/windowscng"
)

func main() {
	policy, err := windowscng.NewServicePolicy("ExampleAgent")
	if err != nil {
		log.Fatal(err)
	}

	// Provisioning (privileged): create the key; an existing key is never adopted.
	signer, err := windowscng.Create("Example.Agent.Key.v1", policy)
	if err != nil {
		log.Fatal(err) // ErrKeyExists if the name is already taken
	}
	defer signer.Close() // releases handles; the persisted key stays

	// Record the identity of the key before using it: every later Open should
	// compare it, and Delete requires it.
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		log.Fatal(err)
	}
	_ = spki // store it durably

	digest := sha256.Sum256([]byte("message"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		log.Fatal(err)
	}

	pub := signer.Public().(*ecdsa.PublicKey)
	log.Println("verified:", ecdsa.VerifyASN1(pub, digest[:], sig))
}
```

The service opens the same key with `windowscng.Open("Example.Agent.Key.v1",
policy)`; decommissioning deletes it with
`windowscng.Delete("Example.Agent.Key.v1", policy, spki)`. Runnable examples are
in [`examples/`](../examples/).

## Migrating from v0.4.0

v0.5.0 replaces the eleven key functions of v0.4.0 with the four above. There
is no deprecation period: code written for v0.4.0 must change.

| v0.4.0 | v0.5.0 |
|---|---|
| `OpenWithPolicy(n, p)`, `OpenForService(n, sp)` | `Open(n, p)`, `Open(n, sp)` |
| `CreateForService(n, sp)` | `Create(n, sp)`; `Create(n, p)` is new for `PolicyServiceSigner` and `PolicyPrivilegedOnly` |
| `DeleteForService(n, sp, spki)` | `Delete(n, sp, spki)`; also for the two `Policy` values |
| `ApplyPolicy(n, p)`, `ApplyServicePolicy(n, sp)` | `Apply(n, p)`, `Apply(n, sp)` |
| `Open(n)` | `Open(n, PolicyServiceSigner)` — see below |
| `LoadOrCreate(n)`, `LoadOrCreateWithPolicy`, `LoadOrCreateForService` | removed: `Open`, and `Create` only where creating is intended, serialized by the caller |
| `Delete(n)` | removed: `Delete(n, policy, spki)` with the recorded `SubjectPublicKeyInfo` |

- **The legacy functions are gone.** `LoadOrCreate` created the key after
  *any* failed open, and a key it opened might not have been created by the
  caller. A key that cannot be opened is now an error to handle, never a
  reason to create one.
- **Legacy keys and `PolicyServiceSigner`.** Every release requested the same
  DACL for keys created by `LoadOrCreate`:
  `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;LS)`. A key with a valid profile and a
  DACL in one of the forms this package explicitly accepts (below) opens with
  `Open(n, PolicyServiceSigner)`. That the requested SDDL was identical does
  not prove compatibility with a future canonicalization of the KSP. The
  tolerant check of the legacy `Open` is gone; `Open` now rejects keys it used
  to accept:
  - a DACL that is not protected;
  - access-allowed entries for principals that the legacy check neither
    required nor listed as forbidden (for example a user, NETWORK SERVICE,
    Guests or ALL APPLICATION PACKAGES), and entries of other types (deny,
    callback), which the legacy check ignored; the broad principals it already
    rejected (Everyone, Authenticated Users, Users, Interactive, Service,
    Anonymous) stay rejected;
  - inheritance or inherit-only flags on the required entries;
  - SYSTEM or Administrators masks that contain `GENERIC_ALL` but are not
    exactly `0x10000000` or `0xD01F01FF`;
  - a LOCAL SERVICE mask that is not exactly `0x80000000`, `0xA0000000` or
    `0x801200A9`, for example one that adds `WRITE_DAC`, `WRITE_OWNER`,
    `DELETE` or is `0x801F01FF`.

  `Apply` does not repair a DACL it does not recognize.
- **Delete needs the recorded identity.** A key whose `SubjectPublicKeyInfo`
  was never recorded cannot be deleted through this package; do not derive the
  expected value by opening the same name just before deleting it.
- **Errors.** The sentinels are unchanged. The texts of the removed legacy
  validation (for example "existing key … failed security validation") and its
  Win32 causes no longer appear.

## Security model

- Keys are created in machine scope, non-exportable, in the Microsoft Software
  KSP. Only public-key material leaves the package.
- The requested DACL is set **before** the key is finalized, then read back. A
  signer is returned only if the persisted DACL is exactly the policy;
  otherwise the call fails and tries to delete the key it just created. See
  [Provisioning window](#provisioning-window).
- Every function accepts a key only if its DACL matches the requested policy
  **exactly** (protected, explicit allow entries, known principals and masks).
  Anything else returns `ErrPolicyMismatch`. The accepted masks are those the
  Microsoft Software KSP was observed to persist: `0x10000000` and `0xD01F01FF`
  for SYSTEM and Administrators; `0x80000000`, `0xA0000000` and `0x801200A9`
  for LOCAL SERVICE; `0xA0000000` and `0x801200A9` for a service SID.
- `ncrypt.dll` and `advapi32.dll` are loaded only from the Windows system
  directory; key operations fail if a different module of the same name is
  already loaded.
- Existing keys are never deleted, overwritten or regenerated by a failed
  call. The only function that deletes an existing key is `Delete`, and only
  after verifying it.

### Provisioning window

A new key gets Export Policy `0` and the requested DACL **before**
`NCryptFinalizeKey`, so it is meant to be persisted with that DACL and never
to carry the provider's default security descriptor. Earlier versions wrote the
DACL only after finalize. Established in code:

- the private key is never exportable;
- a failure before finalize persists nothing and only releases the handle;
- no signer is returned for a new key unless the DACL read back after finalize,
  on the same handle, is exactly the policy. If the provider did not apply the
  DACL, the call fails closed and deletes the key it created through that
  handle, never by name (see **Not transactional** below).

Observed natively in one P3 run (`R20261028T090457Z-691bc4a2`, Windows NT
10.0.26200, Microsoft Software KSP), in that configuration only: the KSP
persisted a descriptor set before finalize, both with raw NCrypt calls and
through `LoadOrCreateForService` (the create path that `Create` now runs). The
first descriptor read after finalize was already the requested one, with no
inheritance flags:
`D:P(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x801200a9;;;<service-SID>)`.
A key finalized with no descriptor set carried
`D:P(A;OICI;0xd01f01ff;;;SY)(A;OICI;0xd01f01ff;;;BA)`, so on that build the
default that earlier versions briefly exposed granted only SYSTEM and
Administrators. Any state inside the KSP during `NCryptFinalizeKey` is not
observable and is not established. On other providers, builds or
configurations, a provider that ignored the pre-finalize descriptor would make
provisioning fail closed rather than produce a key.

A process that opened a key before its DACL changed keeps its handle, which
still matters for `Apply`. Provision keys from a trusted, quiescent context.

## Errors

| Error | Returned by | Meaning |
|---|---|---|
| input error (no sentinel) | all | Empty name, name with a NUL, invalid policy (`nil`, pointer, zero value, other type) or, for `Delete`, an empty, malformed or non-canonical P-256 `SubjectPublicKeyInfo`. No native call was made. |
| `ErrPrivilegeRequired` | all | The operation needs SYSTEM or an elevated Administrator: `Create`, `Delete` and `Apply` always, `Open` only with `PolicyPrivilegedOnly`. Checked before any key is opened or created. |
| `ErrKeyNotFound` | `Open`, `Delete`, `Apply` | Key not found **or** not accessible to the caller (`NTE_NOT_FOUND` or `NTE_BAD_KEYSET`). Never proof of absence, never a reason to `Create`. |
| `ErrPolicyMismatch` | `Open`, `Create`, `Apply`, `Delete` | The key's DACL is not the requested policy or its public key is not P-256, or the change would widen access. A failure to *read* the DACL or the export policy is its own error. No pre-existing key was modified; a key just created by `Create` is deleted, or the error also wraps `ErrCleanupFailed`. |
| `ErrKeyExists` | `Create` | `NCryptCreatePersistedKey` reported `NTE_EXISTS` (also reachable as an `NCryptError` with `Code` `NTEExists`), and only that step. The existing key was not opened, adopted, modified or deleted. |
| `ErrCleanupFailed` | `Create` | The call failed after creating a key and could not delete it through the same handle; the key may persist, inspect it. Joined with the primary cause. |
| `ErrDeleteVerificationFailed` | `Delete` | The key was opened but a check did not pass or could not be completed (export policy, P-256 public key, exact DACL, expected SPKI). Nothing was deleted. Also wraps `ErrPolicyMismatch` for a policy mismatch. A failure of `NCryptDeleteKey` itself is reported separately, with its `NCryptError`. |
| `ErrPostWriteVerification` | `Apply` | The DACL was written but could not be confirmed; nothing was rolled back, inspect the key. It is the only sentinel of this package in that error. Never retry or regenerate automatically. |

Use `errors.Is` for these sentinels, not the error text. They, `NCryptError`
and the `NTE*` codes are declared on every platform, so shared code compiles
on Windows and elsewhere; outside Windows the functions only report that the
platform is not supported.

`ExampleApply_errorHandling` (in the package documentation, source
[`windowscng/example_apply_errors_test.go`](../windowscng/example_apply_errors_test.go))
checks the outcome of `Apply` in the right order: `ErrPostWriteVerification`
first (written but unverified: inspect, never retry or regenerate), then the
sentinels that mean the DACL was not written, then the native code.

**Native causes.** Every failed NCrypt call is reachable as an
`*NCryptError` with `errors.As`: `Code` is the 32-bit `SECURITY_STATUS`
(compare it with `NTENotFound`, `NTEPerm`, `NTEBadKeyset` or another value),
`Op` describes the operation for people reading the error: it is not a
stable identifier and the same NCrypt function can appear under different
labels, so do not compare it. Win32 failures keep their `syscall.Errno`, so
`ERROR_ACCESS_DENIED` (`syscall.Errno(5)`) is distinct from `NTE_PERM`.

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

- **Writers must be serialized by the caller.** Provisioning and policy
  changes on the same key must be serialized by the caller, also across
  processes. The package does not guarantee tighten-only transitions with
  concurrent writers: `Apply` reads the state and then writes, so an
  overlapping writer can make a stale write succeed (for example a service-SID
  DACL written over a key that was just tightened to privileged-only, both
  calls returning `nil`).
- **Verified delete is not a transaction.** `Delete` checks and deletes the
  same open key object, but does not stop a concurrent writer from changing
  the DACL in between; serialize deletion with provisioning and policy
  changes. Record the key's expected `SubjectPublicKeyInfo` before the key is
  used: a key whose SPKI was never recorded cannot be deleted through this
  package, and the expected value must never be derived by opening the same
  name just before the delete.
- **Concurrent creators.** `Create` relies on `NTE_EXISTS` from
  `NCryptCreatePersistedKey`, which the documentation states for a key that
  "already exists": it does not reserve a name between create and
  `NCryptFinalizeKey`. On the Microsoft Software KSP, two overlapping creates
  of the same name were observed to both succeed with different keys, the last
  finalize silently replacing the other (native test, Windows 11). The package
  does not serialize creators. The caller must:
  - serialize every lifecycle operation on the same name (create, rotation,
    delete, recovery, maintenance tools) across processes, from before the
    create until the key's identity is recorded or the attempt is cleaned up;
  - record the `SubjectPublicKeyInfo` of the returned key and compare it at
    every later open: a mismatch is a conflict (possible tampering) to report,
    never a key to adopt or to delete by name.
- **Size limits on native reads.** Each read first asks the provider for the
  size, then allocates. A size above the limit is refused before any
  allocation, with an error naming the operation, the reported size and the
  limit (no new sentinel):
  - signature (`NCryptSignHash`): 64 bytes, a P-256 signature in IEEE P1363
    form;
  - public key (`NCryptExportKey`, `ECCPUBLICBLOB`): 72 bytes, the 8-byte header
    and the P-256 coordinates. A provider that reports a larger buffer for a
    valid blob is no longer accepted;
  - security descriptor (DACL only): 128 KiB. This is a budget, not a limit of
    the format: a DACL-only self-relative descriptor is a 20-byte header plus
    an ACL of at most 65535 bytes. An oversized descriptor is a failed read
    ("descriptor unavailable"), never `ErrPolicyMismatch`.

  A writer that does not take part in that serialization (another software,
  an administrator acting on the same names) is outside the guarantee; the
  SPKI comparison detects the replacement afterwards, it does not prevent it.
  In particular, "open, and create if not found" is not a safe pattern by
  itself.
- **"Not found" is ambiguous.** For a caller the DACL does not grant, the KSP
  reports the same status as for a missing key. Never treat `ErrKeyNotFound`
  as proof of absence, and never create or regenerate an identity key because
  of it.
- **Static check only.** DACL validation inspects the descriptor; it is not a
  computation of Windows effective access (owner rights, privileges, SACL).
- **Not transactional.** After an error a new key may still exist. If `Create`
  created a key and a later step failed (the read-back of the DACL, the public
  key, the signer), the call deletes that key through the same handle; if the
  delete also fails, the error wraps `ErrCleanupFailed` and the key may
  persist. One case is not a cleanup failure: for a **non-privileged** caller
  (for example an Administrator with a UAC-filtered token), when
  `NCryptFinalizeKey` is denied with `NTE_PERM` and deleting the never
  finalized key reports `NTE_BAD_KEYSET` on that same handle, the key was not
  persisted and the error is the finalize denial alone. For a privileged
  caller, or if the privilege check fails, and for any other combination, the
  error still wraps `ErrCleanupFailed`; after a successful finalize,
  `NTE_BAD_KEYSET` never proves that the cleanup succeeded. Because `Create`
  stops a non-privileged caller before the create, that case is not normally
  reachable through it. It was verified natively on Windows NT 10.0.26200 with
  the Microsoft Software KSP, for an Administrator with a UAC-filtered token,
  a standard user and LOCAL SERVICE (run from a scheduled task), each with the
  service-signer, privileged-only and service-SID DACLs: in all nine cases
  finalize was denied with `NTE_PERM`, the delete reported `NTE_BAD_KEYSET`,
  and an elevated caller found the name absent by enumeration and by exact
  open both before and after, with a temporary control key found by both
  methods. Not covered: other Windows builds or KSPs, a caller whose token
  holds a service SID (a process running as that service), and files left on
  disk that the KSP does not expose. The check is the opt-in test
  `TestFinalizeFailureProbe` (build tag `cng_finalize_probe`); see
  [finalize-probe.md](finalize-probe.md) for the procedure and the matrix.
- **Open handles are not revoked.** After `Apply`, processes that already
  opened the key keep working with the access they had; restart or reopen
  consumers.
- **Service SID.** A service key works only if the service has its SID enabled,
  for example `sc.exe sidtype <service> unrestricted`.
- **Verified scope.** Per-service isolation was verified natively on one setup:
  Windows NT 10.0.26200, Microsoft Software KSP, services running as LOCAL
  SERVICE with an unrestricted service SID, keys created by
  `LoadOrCreateForService` (v0.4.0; the create path of `Create`). Other KSPs,
  Windows builds, restricted SIDs and keys migrated with `Apply` are not
  covered.
- **Lifecycle.** Call `Close` when done. A signer is safe for concurrent use:
  `Sign` calls may run in parallel, and `Close` waits for those already in
  progress, then makes at most one release attempt per handle. Overlapping
  `Sign` and `Close` calls are ordered by an internal lock, so a `Sign` that
  overlaps `Close` may still complete; once `Close` has returned, every `Sign`
  fails without reaching CNG. Repeated `Close` calls are harmless; only the
  first reports a failure to release a handle, and none retries it. `Close` does
  not drain your callers: stop and drain the users of the signer (for example,
  in-flight TLS handshakes) before closing it. Coordinate provisioning and
  deletion outside this module.

## Building and testing

```text
go build ./...
go vet ./...
go test ./...
```

The default tests use an in-memory key store and do not create, modify or
delete any persisted key.

The native smoke tests are opt-in and use real keys: on a test machine, from an elevated context (SYSTEM or an elevated Administrator), run `go test -tags cng_smoke ./windowscng`.
With `KEPPIN_CNG_SMOKE_REQUIRED=1` an unmet precondition fails the smoke tests instead of skipping them.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE).
