//go:build windows

// Command disposablelifecycle demonstrates the full create/use/close/delete
// lifecycle with a uniquely generated, example-owned disposable container name.
//
// Safety invariant: this program deletes only the name it generates for this
// invocation. It never accepts or deletes an arbitrary production key name and
// performs no wildcard/prefix deletion.
//
// Machine-scoped key creation and deletion require an Administrator-elevated
// process. Run from an elevated PowerShell:
//
//	go run ./examples/disposablelifecycle
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	"github.com/keppin-oss/cng/windowscng"
)

func main() {
	// A name unique to this invocation. The example owns this name and deletes
	// only this name.
	name := fmt.Sprintf("Example.CNG.Disposable.%d", time.Now().UnixNano())

	// Requires Administrator elevation: this creates a machine-scoped key.
	signer, err := windowscng.LoadOrCreate(name)
	if err != nil {
		log.Fatalf("LoadOrCreate: %v", err)
	}
	// Immediate cleanup registration. Close is idempotent and releases handles
	// but does not delete the persisted key; the explicit Close below is the
	// pre-delete close and the deferred Close is then a no-op.
	defer signer.Close()

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}

	digest := sha256.Sum256([]byte("keppin-oss-cng-disposable-lifecycle"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		log.Fatal("signature did not verify")
	}

	// Close the signer before the destructive delete, as the ownership
	// contract requires.
	if err := signer.Close(); err != nil {
		log.Fatalf("close: %v", err)
	}

	if err := windowscng.Delete(name); err != nil {
		log.Fatalf("delete %q: %v", name, err)
	}

	fmt.Printf("created, signed, verified, closed, and deleted %q\n", name)
}
