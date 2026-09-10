//go:build windows

// Command openexisting demonstrates opening an exact existing machine-scoped
// key with windowscng.Open and correct ErrKeyNotFound handling. Open never
// creates a replacement key.
//
// Authorization to open/sign an existing key is governed by the persisted DACL
// and is not equivalent to permission to create/delete (which requires
// Administrator elevation). To open a key you already created, run from an
// elevated PowerShell:
//
//	go run ./examples/openexisting -name "Example.CNG.Disposable.SignVerify.v1"
//
// If the key does not exist, the program reports ErrKeyNotFound and exits
// without creating a replacement.
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
	name := flag.String("name", "Example.CNG.Disposable.SignVerify.v1",
		"exact machine-scoped CNG key name to open (never created if absent)")
	flag.Parse()

	signer, err := windowscng.Open(*name)
	if err != nil {
		if errors.Is(err, windowscng.ErrKeyNotFound) {
			log.Fatalf("key %q does not exist: Open never creates a replacement (%v)", *name, err)
		}
		log.Fatalf("Open: %v", err)
	}
	// Register cleanup immediately after successful acquisition.
	defer signer.Close()

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}

	fmt.Printf("opened existing key %q (public key present: %v)\n", *name, pub != nil)
}
