//go:build windows && cng_smoke

package windowscng

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
)

// testLifecycleKeyName is a dedicated test-namespace key used by the smoke
// lifecycle test. It must never equal any consumer production key name.
const testLifecycleKeyName = "Keppin.OSS.Test.CNG.Lifecycle.v1"

// TestSmokeKeyLifecycle exercises the real persisted machine-scoped key end to
// end with the four primitives: create, sign, verify, delete against the
// recorded SubjectPublicKeyInfo, confirm absent, and repeat. It is gated
// behind the cng_smoke build tag and needs a privileged Windows context. It is
// not run by `go test ./...` without that tag.
//
// The name is fixed: a key left behind by an interrupted run makes the first
// Create fail with ErrKeyExists, and that key is never adopted or deleted by
// this test; it must be inspected and removed by hand.
func TestSmokeKeyLifecycle(t *testing.T) {
	privileged, err := nativeKeyStore{}.callerPrivileged()
	if err != nil {
		smokeUnmet(t, "privilege check failed: %v — lifecycle iterations NOT EXECUTED", err)
	}
	if !privileged {
		smokeUnmet(t, "the caller is not privileged (SYSTEM or an elevated Administrator) — lifecycle iterations NOT EXECUTED")
	}
	if s, err := Open(testLifecycleKeyName, PolicyServiceSigner); s != nil || !errors.Is(err, ErrKeyNotFound) {
		if s != nil {
			_ = s.Close()
		}
		t.Fatalf("precondition: Open(%q) = %v, want ErrKeyNotFound; a key left by an earlier run must be removed by hand", testLifecycleKeyName, err)
	}

	for i := 1; i <= 2; i++ {
		if err := runLifecycle(testLifecycleKeyName); err != nil {
			t.Fatalf("lifecycle iteration %d: %v", i, err)
		}
	}
}

func runLifecycle(name string) error {
	// 1. create the persisted test key.
	signer, err := Create(name, PolicyServiceSigner)
	if err != nil {
		return fmt.Errorf("Create: %w", err)
	}

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		_ = signer.Close()
		return fmt.Errorf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		_ = signer.Close()
		return fmt.Errorf("MarshalPKIXPublicKey: %w", err)
	}

	// 2. sign and verify through crypto.Signer.
	digest := sha256.Sum256([]byte("keppin-oss-cng-smoke"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		_ = signer.Close()
		return fmt.Errorf("sign: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		_ = signer.Close()
		return fmt.Errorf("signature did not verify")
	}

	// 3. close signer (ownership contract: close before delete).
	if err := signer.Close(); err != nil {
		return err
	}

	// 4. delete the exact key, verified against the recorded SPKI.
	if err := Delete(name, PolicyServiceSigner, spki); err != nil {
		return fmt.Errorf("Delete: %w", err)
	}

	// 5. verify open-only fails because the key is absent.
	if _, err := Open(name, PolicyServiceSigner); !errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("Open after delete = %v, want ErrKeyNotFound", err)
	}

	// 5b. a repeated delete deletes nothing and returns ErrKeyNotFound.
	if err := Delete(name, PolicyServiceSigner, spki); !errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("second Delete = %v, want ErrKeyNotFound", err)
	}

	return nil
}
