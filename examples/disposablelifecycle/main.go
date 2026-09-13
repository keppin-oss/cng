//go:build windows

// Command disposablelifecycle demonstrates the full create/use/close/delete
// lifecycle with a uniquely generated, example-owned disposable container name.
//
// Safety invariant: this program deletes only the name it generates for this
// invocation. It never accepts or deletes an arbitrary production key name and
// performs no wildcard/prefix deletion.
//
// Machine-scoped key creation and deletion need a Windows context authorized
// for those operations. An elevated PowerShell is one way to run this example:
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
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// A name unique to this invocation. The example owns this name and deletes
	// only this name.
	name := fmt.Sprintf("Example.CNG.Disposable.%d", time.Now().UnixNano())

	// The process must be authorized if a machine-scoped key is created.
	signer, err := windowscng.LoadOrCreate(name)
	if err != nil {
		return fmt.Errorf("LoadOrCreate: %w", err)
	}
	// Immediate cleanup registration. Close is idempotent and releases handles
	// but does not delete the persisted key; the explicit Close below is the
	// pre-delete close and the deferred Close is then a no-op.
	defer signer.Close()

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}

	digest := sha256.Sum256([]byte("keppin-oss-cng-disposable-lifecycle"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("signature did not verify")
	}

	// Close the signer before the destructive delete, as the ownership
	// contract requires.
	if err := signer.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	if err := windowscng.Delete(name); err != nil {
		return fmt.Errorf("delete %q: %w", name, err)
	}

	fmt.Printf("created, signed, verified, closed, and deleted %q\n", name)
	return nil
}
