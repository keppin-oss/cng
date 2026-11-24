//go:build windows

package windowscng

import (
	"encoding/binary"
	"errors"
	"testing"
)

// These tests exercise the verifiers of a persisted key on injected
// NCryptGetProperty results. They never call an NCrypt function and never
// open, create, modify or delete a CNG key.

// getPropertyFake is an ncryptGetPropertyFunc that answers from a script and
// fails the test if the key, the property or the flags are not those the
// verifier must pass.
type getPropertyFake struct {
	t        *testing.T
	property string
	flags    uint32
	calls    int
	// answer returns the status and the size or bytes written for call number
	// n (1-based); it fills out as the native call would.
	answer func(n int, out []byte) (status uint32, result uint32)
}

func (f *getPropertyFake) get(key uintptr, property string, out []byte, result *uint32, flags uint32) uint32 {
	f.t.Helper()
	f.calls++
	if key != 0x1234 || property != f.property || flags != f.flags {
		f.t.Errorf("call %d: key=%#x property=%q flags=%#x, want key=0x1234 property=%q flags=%#x",
			f.calls, key, property, flags, f.property, f.flags)
	}
	status, res := f.answer(f.calls, out)
	*result = res
	return status
}

func TestVerifyExportPolicy(t *testing.T) {
	policyAnswer := func(status, size, policy uint32) func(int, []byte) (uint32, uint32) {
		return func(_ int, out []byte) (uint32, uint32) {
			if len(out) != 4 {
				t.Errorf("buffer length = %d, want 4", len(out))
				return status, size
			}
			if status == 0 {
				binary.LittleEndian.PutUint32(out, policy)
			}
			return status, size
		}
	}
	run := func(answer func(int, []byte) (uint32, uint32)) error {
		f := &getPropertyFake{t: t, property: "Export Policy", flags: ncryptSilentFlag, answer: answer}
		return verifyExportPolicyWith(0x1234, f.get)
	}

	t.Run("policy 0 with 4 bytes is accepted", func(t *testing.T) {
		if err := run(policyAnswer(0, 4, 0)); err != nil {
			t.Fatal(err)
		}
	})
	for _, tc := range []struct {
		bit  uint32
		want string
	}{
		{0x1, "export policy permits forbidden export/archiving (actual=0x1)"},
		{0x2, "export policy permits forbidden export/archiving (actual=0x2)"},
		{0x4, "export policy permits forbidden export/archiving (actual=0x4)"},
		{0x8, "export policy permits forbidden export/archiving (actual=0x8)"},
	} {
		if err := run(policyAnswer(0, 4, tc.bit)); err == nil || err.Error() != tc.want {
			t.Errorf("policy bit 0x%x: error = %v, want %q", tc.bit, err, tc.want)
		}
	}
	for _, tc := range []struct {
		size uint32
		want string
	}{
		{0, "cannot verify export policy: reported size 0, want 4"},
		{1, "cannot verify export policy: reported size 1, want 4"},
		{3, "cannot verify export policy: reported size 3, want 4"},
		{8, "cannot verify export policy: reported size 8, want 4"},
	} {
		if err := run(policyAnswer(0, tc.size, 0)); err == nil || err.Error() != tc.want {
			t.Errorf("reported size %d: error = %v, want %q", tc.size, err, tc.want)
		}
	}
	t.Run("status is propagated as NCryptError", func(t *testing.T) {
		const status uint32 = 0x80090016
		err := run(policyAnswer(status, 4, 0))
		if err == nil || err.Error() != "cannot verify export policy: hr=0x80090016" {
			t.Fatalf("error = %v", err)
		}
		var ne *NCryptError
		if !errors.As(err, &ne) || ne.Code != status || ne.Op != "NCryptGetProperty" {
			t.Fatalf("error %v does not carry NCryptError{NCryptGetProperty, 0x%x}", err, status)
		}
	})
}

func TestGetSecurityDescriptorWith(t *testing.T) {
	const name = "NCryptGetProperty(Security Descr)"
	run := func(answer func(int, []byte) (uint32, uint32)) ([]byte, error) {
		f := &getPropertyFake{t: t, property: "Security Descr", flags: daclSecurityInformation, answer: answer}
		return getSecurityDescriptorWith(0x1234, f.get)
	}

	t.Run("returns the bytes written", func(t *testing.T) {
		got, err := run(func(n int, out []byte) (uint32, uint32) {
			if n == 1 {
				if len(out) != 0 {
					t.Errorf("size query passed a buffer of %d bytes", len(out))
				}
				return 0, 8
			}
			if len(out) != 8 {
				t.Errorf("fill buffer = %d bytes, want 8", len(out))
				return 0, 0
			}
			copy(out, []byte{1, 2, 3, 4, 5, 6, 7, 8})
			return 0, 5
		})
		if err != nil || string(got) != string([]byte{1, 2, 3, 4, 5}) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("zero bytes written is an error, not an empty descriptor", func(t *testing.T) {
		got, err := run(func(n int, out []byte) (uint32, uint32) {
			if n == 1 {
				return 0, 8
			}
			return 0, 0
		})
		if got != nil || err == nil || err.Error() != name+": reported 0 bytes written" {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("size query status", func(t *testing.T) {
		_, err := run(func(int, []byte) (uint32, uint32) { return 0x80090016, 0 })
		var ne *NCryptError
		if err == nil || err.Error() != "cannot read persisted security descriptor: hr=0x80090016" || !errors.As(err, &ne) || ne.Code != 0x80090016 {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("size query reports 0", func(t *testing.T) {
		_, err := run(func(int, []byte) (uint32, uint32) { return 0, 0 })
		if err == nil || err.Error() != "cannot read persisted security descriptor: reported size 0" {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("fill status", func(t *testing.T) {
		_, err := run(func(n int, _ []byte) (uint32, uint32) {
			if n == 1 {
				return 0, 8
			}
			return 0x8009000B, 0
		})
		want := ncryptStatusError(name, 0x8009000B)
		if err == nil || err.Error() != want.Error() {
			t.Fatalf("error = %v, want %v", err, want)
		}
	})
	t.Run("fill reports more than the buffer", func(t *testing.T) {
		_, err := run(func(n int, _ []byte) (uint32, uint32) {
			if n == 1 {
				return 0, 8
			}
			return 0, 9
		})
		if err == nil || err.Error() != name+": reported size 9 exceeds buffer 8" {
			t.Fatalf("error = %v", err)
		}
	})
}
