//go:build windows

package windowscng

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Size limits checked against the size query of the three native reads
// before a buffer is allocated. Only fakes are used: no key is opened.

// TestSecurityDescriptorSizeLimit: a query at the limit goes on to the fill
// with a buffer of that size; above it the read fails before the fill, without
// a large allocation or a panic, also at the maximum DWORD on 386.
func TestSecurityDescriptorSizeLimit(t *testing.T) {
	requireNCryptNotLoaded(t)
	run := func(queried uint32) (*getPropertyFake, []byte, error) {
		f := &getPropertyFake{t: t, property: "Security Descr", flags: daclSecurityInformation, answer: func(n int, out []byte) (uint32, uint32) {
			if n == 1 {
				return 0, queried
			}
			if uint32(len(out)) != queried {
				t.Errorf("fill buffer = %d bytes, want %d", len(out), queried)
			}
			copy(out, []byte{1, 2, 3, 4})
			return 0, 4
		}}
		sd, err := getSecurityDescriptorWith(0x1234, f.get)
		return f, sd, err
	}
	t.Run("at the limit: normal read", func(t *testing.T) {
		f, sd, err := run(maxSecurityDescriptorSize)
		if err != nil || len(sd) != 4 || f.calls != 2 {
			t.Fatalf("sd=%v err=%v calls=%d, want the 4 written bytes after 2 calls", sd, err, f.calls)
		}
	})
	for _, queried := range []uint32{maxSecurityDescriptorSize + 1, 0x80000000, 0xFFFFFFFF} {
		t.Run(fmt.Sprintf("query %d above the limit: error before the fill", queried), func(t *testing.T) {
			f, sd, err := run(queried)
			want := fmt.Sprintf("cannot read persisted security descriptor: reported size %d exceeds the limit of 131072 bytes", queried)
			if sd != nil || err == nil || err.Error() != want {
				t.Fatalf("sd=%v err=%v, want %q", sd, err, want)
			}
			if f.calls != 1 {
				t.Fatalf("calls = %d, want only the size query", f.calls)
			}
			if ne := (*NCryptError)(nil); errors.As(err, &ne) {
				t.Fatalf("err = %v carries *NCryptError, want a local size error", err)
			}
		})
	}
}

// TestPublicKeyAndSignatureLimitsAtTheBoundary: the two format-derived limits
// accept a query equal to the P-256 size and go on to the second call.
func TestPublicKeyAndSignatureLimitsAtTheBoundary(t *testing.T) {
	requireNCryptNotLoaded(t)
	if maxECCPublicBlobSize != 72 || maxP1363SignatureSize != 64 {
		t.Fatalf("limits = %d/%d, want 72/64 (P-256)", maxECCPublicBlobSize, maxP1363SignatureSize)
	}
	pub, err := runFakeExport(t,
		exportStep{result: maxECCPublicBlobSize},
		exportStep{fill: true, wantCap: maxECCPublicBlobSize, result: maxECCPublicBlobSize, data: validP256Blob()})
	if err != nil || pub == nil {
		t.Fatalf("export at the limit: pub=%v err=%v", pub, err)
	}
	fx := newSignFixture(t)
	f := newFakeSignerNative(fx.p1363)
	f.sizeOut, f.writeOut = maxP1363SignatureSize, maxP1363SignatureSize
	s := newTestSigner(f, fx.pub)
	if _, err := s.Sign(nil, fx.digest, nil); err != nil {
		t.Fatalf("Sign at the limit: %v", err)
	}
	if snap := f.snapshot(); snap.signCalls != 1 {
		t.Fatalf("signCalls = %d, want 1", snap.signCalls)
	}
}

// TestCreateDescriptorAboveLimitIsUnavailableNotMismatch: the real error of an
// oversized descriptor query, fed into Create through the fake store, is a
// failed read ("descriptor unavailable"), never ErrPolicyMismatch with
// descriptor evidence; the created key is deleted on its own handle.
func TestCreateDescriptorAboveLimitIsUnavailableNotMismatch(t *testing.T) {
	requireNCryptNotLoaded(t)
	_, sizeErr := (&getPropertyFake{t: t, property: "Security Descr", flags: daclSecurityInformation, answer: func(int, []byte) (uint32, uint32) {
		return 0, 0xFFFFFFFF
	}}).readSD()
	if sizeErr == nil {
		t.Fatal("oversized query accepted")
	}
	for _, p := range allPolicies(t) {
		t.Run(policyLabel(p), func(t *testing.T) {
			s := newFakeStore(t)
			s.privileged = true
			s.sdErr = sizeErr
			signer, err := createWith(s, testKey, p)
			if signer != nil || !errors.Is(err, sizeErr) {
				t.Fatalf("signer=%v err=%v, want the size error", signer, err)
			}
			if !strings.Contains(err.Error(), "descriptor unavailable") || strings.Contains(err.Error(), "persisted_sd_dacl_hex=") {
				t.Fatalf("err = %v, want a read failure without descriptor evidence", err)
			}
			assertSentinels(t, err) // neither ErrPolicyMismatch nor any other sentinel
			if len(s.deletedKeys) != 1 || !s.deletedKeys[0].created || s.opens != 0 {
				t.Fatalf("deletedKeys=%v opens=%d, want the created key deleted on its handle", s.deletedKeys, s.opens)
			}
			assertHandlesReleased(t, s)
		})
	}
}

func (f *getPropertyFake) readSD() ([]byte, error) { return getSecurityDescriptorWith(0x1234, f.get) }
