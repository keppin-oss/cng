//go:build windows

// Command signverify demonstrates the shortest correct consumer flow against a
// disposable machine-scoped key: create it with Create and PolicyServiceSigner
// (a key LOCAL SERVICE can use, with its DACL verified exactly), register
// cleanup immediately, sign through crypto.Signer, and verify using public
// material only. The private key is never exported or materialized.
//
// The key is left in place so that examples/openexisting can open it. Create
// never adopts an existing key: a second run reports ErrKeyExists, and the key
// must be removed first (examples/disposablelifecycle shows the verified
// Delete).
//
// Creating the key requires a privileged caller (SYSTEM or an elevated
// Administrator); otherwise the call returns ErrPrivilegeRequired. An elevated
// PowerShell is one way to run it:
//
//	go run ./examples/signverify
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/keppin-oss/cng/windowscng"
)

// exampleKeyName is a clearly disposable, example-specific container name. It
// is not a production Keppin key name.
const exampleKeyName = "Example.CNG.Disposable.SignVerify.v1"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// Creation needs a privileged caller. An existing key is never adopted.
	signer, err := windowscng.Create(exampleKeyName, windowscng.PolicyServiceSigner)
	if errors.Is(err, windowscng.ErrKeyExists) {
		return fmt.Errorf("key %q already exists and was not opened or modified; open it with examples/openexisting (%w)", exampleKeyName, err)
	}
	if err != nil {
		return fmt.Errorf("Create: %w", err)
	}
	// Register cleanup immediately, before any later fallible operation.
	// Close releases handles but does not delete the persisted key.
	defer signer.Close()

	// Public material only; the private key stays inside CNG.
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}

	// Record the identity of the key right after Create and before using it:
	// a later verified Delete needs it, also if a step below fails. A real
	// consumer stores the SubjectPublicKeyInfo and the policy durably here; it
	// never derives them later by opening the same name again.
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("MarshalPKIXPublicKey: %w", err)
	}
	fmt.Printf("created key %q; SubjectPublicKeyInfo (hex): %s\n", exampleKeyName, hex.EncodeToString(spki))

	digest := sha256.Sum256([]byte("keppin-oss-cng-signverify"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("signature did not verify")
	}

	fmt.Println("sign/verify succeeded using public material only; the key is left in place")
	return nil
}
