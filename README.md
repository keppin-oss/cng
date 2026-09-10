# Keppin-OSS CNG

Windows CNG machine-key custody for Go applications.

`cng` is a standalone Go module exposing the `windowscng` package for working
with persisted, machine-scoped ECDSA P-256 keys backed by the Microsoft Software
Key Storage Provider.

Private-key operations remain inside Windows CNG. The package exposes signing
through Go's `crypto.Signer` interface and does not provide an API for exporting
private-key material.

The module is intentionally low-level. It does not define application identity,
certificate enrollment, trust management, or provisioning workflows.

## Scope

Use this module when an application needs:

- a persisted, machine-scoped ECDSA P-256 key on Windows;
- private-key custody through the Microsoft Software Key Storage Provider;
- signing through the Go `crypto.Signer` interface;
- operations on exact, caller-supplied key names;
- validation of key export policy and key access-control configuration.

The caller owns key naming, application identity, provisioning orchestration,
certificate lifecycle, and the decision to delete a persisted key.

The module does not implement certificate enrollment, certificate-store
management, application authorization, network-overlay integration, key
enumeration, wildcard deletion, private-key export, or a PEM fallback.

## Resources

- [Documentation](docs/README.md) — Complete API reference, security model, lifecycle guidance, and validation instructions.
- [Examples](examples/) — Runnable examples showing the main package workflows.
- [Package source](windowscng/) — Source code and tests for the `windowscng` package.
