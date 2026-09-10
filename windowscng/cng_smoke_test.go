//go:build windows && cng_smoke

package windowscng

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

// testLifecycleKeyName is a dedicated test-namespace key used by the smoke
// lifecycle test. It must never equal any consumer production key name.
const testLifecycleKeyName = "Keppin.OSS.Test.CNG.Lifecycle.v1"

// TestSmokeKeyLifecycle exercises the real persisted machine-scoped key end to
// end: create/open, sign, verify, delete, confirm absent, and repeat. It is
// gated behind the cng_smoke build tag and requires an elevated (Administrator)
// process, so it is never run by `go test ./...`.
func TestSmokeKeyLifecycle(t *testing.T) {
	// Probe elevation by creating the test key once; skip if not elevated.
	signer, err := LoadOrCreate(testLifecycleKeyName)
	if err != nil {
		t.Skipf("skipping cng smoke test (requires elevated process): %v — NOT EXECUTED", err)
	}
	_ = signer.Close()

	for i := 1; i <= 2; i++ {
		if err := runLifecycle(testLifecycleKeyName); err != nil {
			t.Fatalf("lifecycle iteration %d: %v", i, err)
		}
	}
}

func runLifecycle(name string) error {
	// 1. create persisted test key using the production profile.
	signer, err := LoadOrCreate(name)
	if err != nil {
		return fmt.Errorf("LoadOrCreate: %w", err)
	}

	if _, ok := signer.Public().(*ecdsa.PublicKey); !ok {
		_ = signer.Close()
		return fmt.Errorf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}

	// 2. sign and verify through crypto.Signer.
	digest := sha256.Sum256([]byte("keppin-oss-cng-smoke"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		_ = signer.Close()
		return fmt.Errorf("sign: %w", err)
	}
	if !ecdsa.VerifyASN1(signer.Public().(*ecdsa.PublicKey), digest[:], sig) {
		_ = signer.Close()
		return fmt.Errorf("signature did not verify")
	}

	// 3. close signer (ownership contract: close before delete).
	if err := signer.Close(); err != nil {
		return err
	}

	// 4. delete the exact key.
	if err := Delete(name); err != nil {
		return fmt.Errorf("Delete: %w", err)
	}

	// 5. verify open-only fails because the key is absent.
	if _, err := Open(name); !errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("Open after delete = %v, want ErrKeyNotFound", err)
	}

	// 5b. a repeated delete is idempotent and returns ErrKeyNotFound.
	if err := Delete(name); !errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("second Delete = %v, want ErrKeyNotFound", err)
	}

	return nil
}
