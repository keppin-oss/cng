//go:build windows

// Command signverify demonstrates the shortest correct consumer flow against a
// disposable machine-scoped key: acquire a signer with LoadOrCreateWithPolicy
// and PolicyServiceSigner (a key LOCAL SERVICE can use, with its DACL verified
// exactly), register cleanup immediately, sign through crypto.Signer, and
// verify using public material only. The private key is never exported or
// materialized.
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
	// Creation needs a privileged caller; an existing key must hold exactly the
	// service-signer DACL.
	signer, err := windowscng.LoadOrCreateWithPolicy(exampleKeyName, windowscng.PolicyServiceSigner)
	if err != nil {
		return fmt.Errorf("LoadOrCreateWithPolicy: %w", err)
	}
	// Register cleanup immediately, before any later fallible operation.
	// Close releases handles but does not delete the persisted key.
	defer signer.Close()

	// Public material only; the private key stays inside CNG.
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}

	digest := sha256.Sum256([]byte("keppin-oss-cng-signverify"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("signature did not verify")
	}

	fmt.Println("sign/verify succeeded using public material only")
	return nil
}
