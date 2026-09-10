//go:build windows

// Command signverify demonstrates the shortest correct consumer flow against a
// disposable machine-scoped key: acquire a signer with LoadOrCreate, register
// cleanup immediately, sign through crypto.Signer, and verify using public
// material only. The private key is never exported or materialized.
//
// LoadOrCreate may create a machine-scoped CNG key, which requires an
// Administrator-elevated process. Run from an elevated PowerShell:
//
//	go run ./examples/signverify
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/keppin-oss/cng/windowscng"
)

// exampleKeyName is a clearly disposable, example-specific container name. It
// is not a production Keppin key name.
const exampleKeyName = "Example.CNG.Disposable.SignVerify.v1"

func main() {
	// Requires Administrator elevation: this may create a machine-scoped key.
	signer, err := windowscng.LoadOrCreate(exampleKeyName)
	if err != nil {
		log.Fatalf("LoadOrCreate: %v", err)
	}
	// Register cleanup immediately, before any later fallible operation.
	// Close releases handles but does not delete the persisted key.
	defer signer.Close()

	// Public material only; the private key stays inside CNG.
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}

	digest := sha256.Sum256([]byte("keppin-oss-cng-signverify"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}

	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		log.Fatal("signature did not verify")
	}

	fmt.Println("sign/verify succeeded using public material only")
}
