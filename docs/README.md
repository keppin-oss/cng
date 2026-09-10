# Keppin-OSS CNG Documentation

This document contains the technical documentation for
[`github.com/keppin-oss/cng`](https://github.com/keppin-oss/cng).

## Requirements

- **Operating system:** Windows for CNG operations.
- **Provider:** Microsoft Software Key Storage Provider.
- **Algorithm:** ECDSA P-256.
- **Key scope:** persisted keys use Windows machine scope.
- **Go:** 1.26.5, as declared by the module.

The package includes non-Windows stubs for the core operations, but CNG key
operations themselves are Windows-specific.

## Installation

```text
go get github.com/keppin-oss/cng
```

```go
import "github.com/keppin-oss/cng/windowscng"
```

## Quick Start

The following example acquires a persisted signer, signs a SHA-256 digest, and
verifies the signature using the public key.

If the named key needs to be provisioned, run the example from an appropriately
authorized Windows context.

```go
package main

import (
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/sha256"
    "fmt"
    "log"

    "github.com/keppin-oss/cng/windowscng"
)

func main() {
    if err := run(); err != nil {
        log.Fatal(err)
    }
}

func run() error {
    const name = "Example.CNG.QuickStart.Disposable.v1"

    signer, err := windowscng.LoadOrCreate(name)
    if err != nil {
        return fmt.Errorf("load or create key: %w", err)
    }
    defer signer.Close()

    pub, ok := signer.Public().(*ecdsa.PublicKey)
    if !ok {
        return fmt.Errorf("unexpected public key type %T", signer.Public())
    }

    digest := sha256.Sum256([]byte("hello keppin-oss-cng"))
    signature, err := signer.Sign(rand.Reader, digest[:], nil)
    if err != nil {
        return fmt.Errorf("sign: %w", err)
    }

    if !ecdsa.VerifyASN1(pub, digest[:], signature) {
        return fmt.Errorf("signature did not verify")
    }

    return nil
}
```

`Close` releases signer resources. It does not delete the persisted key.

Only delete an exact key name that your application owns.

## Public API

On Windows, the package exposes:

```go
type Signer interface {
    crypto.Signer
    Close() error
}

func Open(name string) (Signer, error)
func LoadOrCreate(name string) (Signer, error)
func Delete(name string) error

var ErrKeyNotFound error
func IsKeyNotFound(r uintptr) bool
```

### `Open(name)`

Opens the existing persisted machine-scoped key identified by the exact name.

`Open` does not create a key. Before returning a signer, the implementation
validates the persisted key's export policy and access-control configuration and
loads its ECDSA P-256 public key.

If the native open operation reports that the key does not exist, the returned
error wraps `ErrKeyNotFound`.

Use `Open` when the application expects provisioning to have already occurred.

### `LoadOrCreate(name)`

Attempts to acquire the exact named persisted key. When creation is required,
the package requests a machine-scoped ECDSA P-256 key from the Microsoft
Software Key Storage Provider and configures the package's security settings.

Existing keys are validated before a signer is returned.

Applications that require a strict separation between provisioning and runtime
key use should provision separately and use `Open` at runtime.

### `Delete(name)`

Deletes the exact named persisted machine-scoped key.

`Delete` does not enumerate keys and does not perform wildcard or prefix-based
deletion.

If the native open operation reports that the key is already absent, the
returned error wraps `ErrKeyNotFound`.

### `Signer`

`Public` returns the ECDSA public key associated with the signer without
exporting private-key material.

`Sign` signs the supplied digest through Windows CNG and returns an ASN.1
DER-encoded ECDSA signature suitable for `ecdsa.VerifyASN1`. Pass a digest
rather than an unhashed message.

`Close` releases resources associated with the signer. It does not delete the
persisted key.

### `ErrKeyNotFound`

Use Go's standard error matching to recognize an absent persisted key:

```go
if errors.Is(err, windowscng.ErrKeyNotFound) {
    // key is absent
}
```

`IsKeyNotFound` is available when classification of a raw native status is
required.

## Security Model

### Machine-scoped, non-exportable keys

New persisted keys are requested in Windows machine scope using the Microsoft
Software Key Storage Provider.

The package configures the key export policy to disallow the private-key export
and archiving modes checked by the implementation. Existing keys are validated
before being exposed through a signer.

The package exports only public-key material.

### Key access control

For newly created keys, the package requests the following protected DACL:

```text
D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;LS)
```

| Principal | Requested access |
|---|---|
| SYSTEM | `GENERIC_ALL` |
| Built-in Administrators | `GENERIC_ALL` |
| LOCAL SERVICE | `GENERIC_READ | GENERIC_EXECUTE` |

The package validates relevant properties of the persisted DACL before exposing
a signer. This is a structural security check and should not be interpreted as
a complete Windows effective-access calculation.

### Provisioning and runtime use

Key provisioning and key use are separate concerns.

Creating or deleting a machine-scoped persisted key must run in a Windows
security context authorized to perform the requested operation. The package
does not elevate or impersonate another identity.

Access granted to an existing key does not by itself establish permission to
create new machine-scoped keys.

For applications with a separate provisioning phase, provision the key from an
appropriately authorized context and use `Open` from the runtime process that
is expected to consume the existing key.

Actual access remains subject to Windows and Microsoft Software KSP
authorization.

## Lifecycle and Concurrency

Persisted-key lifetime and signer lifetime are independent.

Call `Close` when a signer is no longer needed. Use `Delete` only when the
application intentionally wants to remove the exact persisted key that it owns.

Do not use deletion as a substitute for closing signer handles.

The package does not provide provisioning coordination or multi-process
lifecycle management. Applications should coordinate provisioning and deletion
outside this module.

## Examples

Windows examples are included under `examples/`:

| Example | Purpose |
|---|---|
| `signverify` | Acquire a signer, sign a digest, and verify with public material. |
| `openexisting` | Open an existing key and handle an absent key without provisioning it. |
| `disposablelifecycle` | Exercise creation, signing, closing, and deletion with an example-owned key. |

Read the example source before running operations that may create or delete a
persisted machine key.

## Validation and Testing

Run the standard checks on Windows:

```text
go build ./...
go vet ./...
go test ./...
```

A Windows lifecycle smoke test is also available:

```text
go test -tags cng_smoke ./windowscng -run TestSmokeKeyLifecycle -v
```

The smoke test operates on a persisted machine key and should be run from an
appropriately authorized Windows context.

It uses the exact test key name:

```text
Keppin.OSS.Test.CNG.Lifecycle.v1
```

Reserve that name for testing.

The test suite validates implementation behavior covered by the repository. It
should not be interpreted as proof of authorization behavior for every Windows
execution identity or environment.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
