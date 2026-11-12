//go:build windows

// Command openexisting demonstrates opening an exact existing machine-scoped
// key with windowscng.OpenWithPolicy and PolicyServiceSigner, with correct
// ErrKeyNotFound and ErrPolicyMismatch handling. OpenWithPolicy never creates
// a replacement key and never modifies the key; it rejects a key whose DACL is
// not exactly the service-signer policy.
//
// Authorization to open/sign an existing key is governed by the persisted DACL
// and is not equivalent to permission to create/delete. Those operations need
// a Windows context authorized by the KSP. An elevated PowerShell is one way
// to open a key you already created:
//
//	go run ./examples/openexisting -name "Example.CNG.Disposable.SignVerify.v1"
//
// If the native open reports the key as not found or not accessible
// (ErrKeyNotFound: NTE_NOT_FOUND or the ambiguous NTE_BAD_KEYSET, which the
// KSP also returns to a caller the key's DACL does not grant), the program
// reports it with the native HRESULT and exits without creating a replacement.
// It does not conclude that the key is absent.
package main

import (
	"crypto/ecdsa"
	"errors"
	"flag"
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
	name := flag.String("name", "Example.CNG.Disposable.SignVerify.v1",
		"exact machine-scoped CNG key name to open (never created if absent)")
	flag.Parse()

	signer, err := windowscng.OpenWithPolicy(*name, windowscng.PolicyServiceSigner)
	if err != nil {
		switch {
		case errors.Is(err, windowscng.ErrKeyNotFound):
			return fmt.Errorf("key %q was not found or is not accessible to this caller; OpenWithPolicy never creates a replacement (%w)", *name, err)
		case errors.Is(err, windowscng.ErrPolicyMismatch):
			return fmt.Errorf("key %q exists but its DACL is not exactly the service-signer policy; it was not modified (%w)", *name, err)
		}
		return fmt.Errorf("OpenWithPolicy: %w", err)
	}
	// Register cleanup immediately after successful acquisition.
	defer signer.Close()

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}

	fmt.Printf("opened existing key %q (public key present: %v)\n", *name, pub != nil)
	return nil
}
