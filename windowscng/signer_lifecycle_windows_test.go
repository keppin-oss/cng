//go:build windows

package windowscng

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// D3: tests of the cngSigner Sign/Close lifecycle. A simulated signerNative
// backend replaces ncrypt.dll, so no test opens, creates or deletes a CNG key.
//
// Barrier tests force one specific interleaving, never with sleeps: channels
// inside the simulated syscalls hold an operation at a known point, and the
// test proceeds only once the other operation is observed at its own known
// point (waitCloseQueued, waitBlockedInLock, or both Sign calls inside the
// backend). Timeouts in recvOrFail are failure guards only.
//
// Schedule-dependent tests (TestSignerConcurrentCloseFreesOnce and
// TestSignerSignCloseStress) assert invariants that must hold under any
// interleaving, but do not force a specific one: they can detect a
// regression only probabilistically.
//
// Panic tests prove that a panic inside the native seam releases the signer's
// lock. They do not promise that native resources are released after such a
// panic.

const (
	fakeKeyHandle      uintptr = 0x1111
	fakeProviderHandle uintptr = 0x2222
)

// fakeSignerNative simulates NCryptSignHash and NCryptFreeObject. It records
// every call and flags any use of a key handle after it was freed.
type fakeSignerNative struct {
	mu sync.Mutex

	sig      []byte // P1363 signature written by signHash
	sizeOut  uint32 // size reported by signHashSize (default len(sig))
	writeOut uint32 // size reported by signHash (default len(sig))
	sizeHR   uintptr
	signHR   uintptr
	freeHR   map[uintptr]uintptr

	// Optional last-error values returned with a failing sizeHR or signHR,
	// as Proc.Call would return them; nil keeps the default simulated error.
	sizeCallErr error
	signCallErr error

	// Optional hooks run inside the simulated syscall, without fake.mu held.
	sizeHook func()
	signHook func()
	freeHook func(h uintptr)

	sizeCalls       int
	signCalls       int
	freed           map[uintptr]int
	freeOrder       []uintptr
	useAfterFreeOps []string
}

func newFakeSignerNative(sig []byte) *fakeSignerNative {
	return &fakeSignerNative{
		sig:      sig,
		sizeOut:  uint32(len(sig)),
		writeOut: uint32(len(sig)),
		freeHR:   map[uintptr]uintptr{},
		freed:    map[uintptr]int{},
	}
}

func (f *fakeSignerNative) checkKey(op string, key uintptr) {
	if f.freed[key] > 0 {
		f.useAfterFreeOps = append(f.useAfterFreeOps, op)
	}
}

func (f *fakeSignerNative) signHashSize(key uintptr, digest []byte, size *uint32) (uintptr, error) {
	f.mu.Lock()
	f.sizeCalls++
	f.checkKey("signHashSize/enter", key)
	hook := f.sizeHook
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkKey("signHashSize/return", key)
	if f.sizeHR != 0 {
		if f.sizeCallErr != nil {
			return f.sizeHR, f.sizeCallErr
		}
		return f.sizeHR, errors.New("simulated size failure")
	}
	*size = f.sizeOut
	return 0, nil
}

func (f *fakeSignerNative) signHash(key uintptr, digest, sig []byte, size *uint32) (uintptr, error) {
	f.mu.Lock()
	f.signCalls++
	f.checkKey("signHash/enter", key)
	hook := f.signHook
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkKey("signHash/return", key)
	if f.signHR != 0 {
		if f.signCallErr != nil {
			return f.signHR, f.signCallErr
		}
		return f.signHR, errors.New("simulated sign failure")
	}
	copy(sig, f.sig)
	*size = f.writeOut
	return 0, nil
}

func (f *fakeSignerNative) freeObject(h uintptr) uintptr {
	f.mu.Lock()
	hook := f.freeHook
	f.mu.Unlock()
	if hook != nil {
		hook(h)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.freed[h]++
	f.freeOrder = append(f.freeOrder, h)
	return f.freeHR[h]
}

type fakeSnapshot struct {
	sizeCalls, signCalls int
	keyFrees, provFrees  int
	freeOrder            []uintptr
	useAfterFree         []string
}

func (f *fakeSignerNative) snapshot() fakeSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeSnapshot{
		sizeCalls:    f.sizeCalls,
		signCalls:    f.signCalls,
		keyFrees:     f.freed[fakeKeyHandle],
		provFrees:    f.freed[fakeProviderHandle],
		freeOrder:    append([]uintptr(nil), f.freeOrder...),
		useAfterFree: append([]string(nil), f.useAfterFreeOps...),
	}
}

// signFixture is a real P-256 key, a digest, and the P1363 form of a valid
// signature over it, so the ASN.1 output of Sign can be verified.
type signFixture struct {
	pub    *ecdsa.PublicKey
	digest []byte
	p1363  []byte
}

func newSignFixture(t *testing.T) signFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("d3-sign-close-lifecycle"))
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return signFixture{pub: &key.PublicKey, digest: d[:], p1363: p1363(r, s)}
}

func newTestSigner(f *fakeSignerNative, pub *ecdsa.PublicKey) *cngSigner {
	return &cngSigner{
		provider:  fakeProviderHandle,
		key:       fakeKeyHandle,
		name:      "d3-test-key",
		publicKey: pub,
		native:    f,
	}
}

// waitCloseQueued returns once a Close call is blocked in s.mu.Lock while a
// Sign holds the read lock: sync.RWMutex refuses new readers (TryRLock fails)
// only when a writer is waiting or holds the lock.
func waitCloseQueued(t *testing.T, s *cngSigner) {
	t.Helper()
	for i := 0; ; i++ {
		if !s.mu.TryRLock() {
			return
		}
		s.mu.RUnlock()
		if i > 1_000_000 {
			t.Fatal("Close never queued behind the in-progress Sign")
		}
		runtime.Gosched()
	}
}

// waitBlockedInLock returns once a goroutine whose stack contains marker (a
// function name) is blocked in sync.(*RWMutex).Lock. It inspects goroutine
// stacks, so it proves where that goroutine is blocked instead of assuming it
// was scheduled.
func waitBlockedInLock(t *testing.T, marker string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	deadline := time.Now().Add(10 * time.Second) // failure guard only
	for {
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, marker) && strings.Contains(g, "sync.(*RWMutex).Lock") {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no goroutine in %s reached sync.(*RWMutex).Lock", marker)
		}
		runtime.Gosched()
	}
}

// recvOrFail receives from ch, failing the test if nothing arrives within a
// generous guard. The guard only turns a hang into a failure.
func recvOrFail[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

// d3SecondClose is a named function so that waitBlockedInLock can find the
// goroutine running it.
func d3SecondClose(s *cngSigner, out chan<- error) { out <- s.Close() }

func assertFreedOnce(t *testing.T, snap fakeSnapshot) {
	t.Helper()
	if snap.keyFrees != 1 || snap.provFrees != 1 {
		t.Fatalf("frees: key=%d provider=%d, want 1 each", snap.keyFrees, snap.provFrees)
	}
	if len(snap.freeOrder) != 2 || snap.freeOrder[0] != fakeKeyHandle || snap.freeOrder[1] != fakeProviderHandle {
		t.Fatalf("free order = %#x, want key then provider", snap.freeOrder)
	}
}

func assertNoUseAfterFree(t *testing.T, snap fakeSnapshot) {
	t.Helper()
	if len(snap.useAfterFree) != 0 {
		t.Fatalf("key handle used after free in: %v", snap.useAfterFree)
	}
}

func TestSignerSignValidSignatureAndClose(t *testing.T) {
	fx := newSignFixture(t)
	f := newFakeSignerNative(fx.p1363)
	s := newTestSigner(f, fx.pub)

	for i := 0; i < 3; i++ {
		sig, err := s.Sign(nil, fx.digest, nil)
		if err != nil {
			t.Fatalf("Sign #%d: %v", i, err)
		}
		if !ecdsa.VerifyASN1(fx.pub, fx.digest, sig) {
			t.Fatalf("Sign #%d: signature does not verify", i)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	snap := f.snapshot()
	if snap.sizeCalls != 3 || snap.signCalls != 3 {
		t.Fatalf("calls: size=%d sign=%d, want 3/3", snap.sizeCalls, snap.signCalls)
	}
	assertFreedOnce(t, snap)
	assertNoUseAfterFree(t, snap)
	if s.Public() != fx.pub {
		t.Fatal("Public changed after Close")
	}
}

func TestSignerSignAfterCloseMakesNoNativeCall(t *testing.T) {
	fx := newSignFixture(t)
	f := newFakeSignerNative(fx.p1363)
	s := newTestSigner(f, fx.pub)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.Sign(nil, fx.digest, nil); !errors.Is(err, errSignerClosed) {
			t.Fatalf("Sign after Close: err = %v, want errSignerClosed", err)
		}
	}
	snap := f.snapshot()
	if snap.sizeCalls != 0 || snap.signCalls != 0 {
		t.Fatalf("native sign calls after Close: size=%d sign=%d", snap.sizeCalls, snap.signCalls)
	}
	assertFreedOnce(t, snap)
}

// Close issued while Sign is inside one of the two NCryptSignHash calls must
// wait; the in-flight Sign completes with a valid signature, handles are freed
// once afterwards, and a Sign queued behind Close fails without native calls.
func TestSignerCloseWaitsForInFlightSign(t *testing.T) {
	for _, phase := range []string{"size-query", "sign"} {
		t.Run(phase, func(t *testing.T) {
			fx := newSignFixture(t)
			f := newFakeSignerNative(fx.p1363)
			entered := make(chan struct{})
			release := make(chan struct{})
			hook := func() { close(entered); <-release }
			if phase == "size-query" {
				f.sizeHook = hook
			} else {
				f.signHook = hook
			}
			s := newTestSigner(f, fx.pub)

			type result struct {
				sig []byte
				err error
			}
			first := make(chan result, 1)
			go func() {
				sig, err := s.Sign(nil, fx.digest, nil)
				first <- result{sig, err}
			}()
			<-entered

			closed := make(chan error, 1)
			go func() { closed <- s.Close() }()
			waitCloseQueued(t, s)

			// A Sign that starts while Close is queued must not run.
			late := make(chan error, 1)
			go func() {
				_, err := s.Sign(nil, fx.digest, nil)
				late <- err
			}()

			if snap := f.snapshot(); snap.keyFrees != 0 || snap.provFrees != 0 {
				t.Fatalf("handles freed while Sign in progress: %+v", snap)
			}
			select {
			case err := <-closed:
				t.Fatalf("Close returned (%v) before in-flight Sign finished", err)
			default:
			}

			close(release)
			r := <-first
			if r.err != nil {
				t.Fatalf("in-flight Sign: %v", r.err)
			}
			if !ecdsa.VerifyASN1(fx.pub, fx.digest, r.sig) {
				t.Fatal("in-flight Sign: signature does not verify")
			}
			if err := <-closed; err != nil {
				t.Fatalf("Close: %v", err)
			}
			if err := <-late; !errors.Is(err, errSignerClosed) {
				t.Fatalf("Sign queued behind Close: err = %v, want errSignerClosed", err)
			}

			snap := f.snapshot()
			if snap.sizeCalls != 1 || snap.signCalls != 1 {
				t.Fatalf("calls: size=%d sign=%d, want 1/1", snap.sizeCalls, snap.signCalls)
			}
			assertFreedOnce(t, snap)
			assertNoUseAfterFree(t, snap)
		})
	}
}

// Close queued behind a Sign that then fails in either syscall still frees
// both handles exactly once, after the failing Sign returned.
func TestSignerCloseWaitsForFailingSign(t *testing.T) {
	for _, phase := range []string{"size-query", "sign"} {
		t.Run(phase, func(t *testing.T) {
			fx := newSignFixture(t)
			f := newFakeSignerNative(fx.p1363)
			entered := make(chan struct{})
			release := make(chan struct{})
			hook := func() { close(entered); <-release }
			if phase == "size-query" {
				f.sizeHook, f.sizeHR = hook, 0x80090016
			} else {
				f.signHook, f.signHR = hook, 0x80090016
			}
			s := newTestSigner(f, fx.pub)

			signErr := make(chan error, 1)
			go func() {
				_, err := s.Sign(nil, fx.digest, nil)
				signErr <- err
			}()
			<-entered
			closed := make(chan error, 1)
			go func() { closed <- s.Close() }()
			waitCloseQueued(t, s)
			if snap := f.snapshot(); snap.keyFrees != 0 {
				t.Fatal("key freed while failing Sign in progress")
			}
			close(release)

			if err := <-signErr; err == nil || !strings.Contains(err.Error(), "0x80090016") {
				t.Fatalf("Sign err = %v, want simulated hr", err)
			}
			if err := <-closed; err != nil {
				t.Fatalf("Close: %v", err)
			}
			snap := f.snapshot()
			assertFreedOnce(t, snap)
			assertNoUseAfterFree(t, snap)
		})
	}
}

func TestSignerSignErrorPaths(t *testing.T) {
	fx := newSignFixture(t)
	cases := []struct {
		name          string
		setup         func(f *fakeSignerNative)
		wantErr       string
		wantSignCalls int
	}{
		{"size query fails", func(f *fakeSignerNative) { f.sizeHR = 0x80090016 }, "query size): hr=0x80090016", 0},
		{"size query reports zero", func(f *fakeSignerNative) { f.sizeOut = 0 }, "reported size 0", 0},
		{"sign fails", func(f *fakeSignerNative) { f.signHR = 0x8009000b }, "NCryptSignHash: hr=0x8009000b", 1},
		{"sign reports size beyond buffer", func(f *fakeSignerNative) { f.writeOut = 65 }, "exceeds buffer", 1},
		// F5: extreme sizes from the second call, with a 64-byte buffer from the
		// first. int(0x80000000) is negative on 32-bit Windows; the check must
		// still return an error instead of slicing out of range.
		{"sign reports size 0x80000000", func(f *fakeSignerNative) { f.writeOut = 0x80000000 }, "reported size 2147483648 exceeds buffer 64", 1},
		{"sign reports size 0xFFFFFFFF", func(f *fakeSignerNative) { f.writeOut = 0xFFFFFFFF }, "reported size 4294967295 exceeds buffer 64", 1},
		{"sign reports short signature", func(f *fakeSignerNative) { f.writeOut = 63 }, "P1363 signature length = 63", 1},
		{"size query reports wrong length", func(f *fakeSignerNative) { f.sizeOut, f.writeOut = 72, 72 }, "P1363 signature length = 72", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSignerNative(fx.p1363)
			tc.setup(f)
			s := newTestSigner(f, fx.pub)
			_, err := s.Sign(nil, fx.digest, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
			if snap := f.snapshot(); snap.signCalls != tc.wantSignCalls || snap.keyFrees != 0 {
				t.Fatalf("after error: signCalls=%d keyFrees=%d", snap.signCalls, snap.keyFrees)
			}

			// A failed Sign leaves the signer open and usable.
			f.mu.Lock()
			f.sizeHR, f.signHR = 0, 0
			f.sizeOut, f.writeOut = uint32(len(fx.p1363)), uint32(len(fx.p1363))
			f.mu.Unlock()
			sig, err := s.Sign(nil, fx.digest, nil)
			if err != nil || !ecdsa.VerifyASN1(fx.pub, fx.digest, sig) {
				t.Fatalf("Sign after recoverable error: err=%v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			assertFreedOnce(t, f.snapshot())
		})
	}
}

func TestSignerEmptyDigestMakesNoNativeCall(t *testing.T) {
	f := newFakeSignerNative(nil)
	s := newTestSigner(f, nil)
	if _, err := s.Sign(nil, nil, nil); err == nil {
		t.Fatal("empty digest accepted")
	}
	if snap := f.snapshot(); snap.sizeCalls != 0 {
		t.Fatal("empty digest reached NCryptSignHash")
	}
}

// Barrier test: the second Close is proven to be blocked on the signer's lock
// (goroutine stack inspection) while the first one is inside NCryptFreeObject;
// it then returns nil without freeing anything again.
func TestSignerCloseCloseFreesOnce(t *testing.T) {
	f := newFakeSignerNative(nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	f.freeHook = func(h uintptr) {
		if h == fakeKeyHandle {
			once.Do(func() { close(entered); <-release })
		}
	}
	s := newTestSigner(f, nil)

	first := make(chan error, 1)
	go func() { first <- s.Close() }()
	<-entered

	second := make(chan error, 1)
	go d3SecondClose(s, second)
	waitBlockedInLock(t, "windowscng.d3SecondClose")
	select {
	case err := <-second:
		t.Fatalf("second Close returned (%v) while the first was still freeing", err)
	default:
	}
	if snap := f.snapshot(); snap.keyFrees != 0 || snap.provFrees != 0 {
		t.Fatalf("frees recorded before the first free was released: %+v", snap)
	}
	close(release)

	if err := <-first; err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second Close: %v", err)
	}
	assertFreedOnce(t, f.snapshot())
}

// Barrier test: two Sign calls are inside the same simulated syscall at the
// same time (both entered before either is released), proving that Sign calls
// run in parallel under the read lock. A Close queued behind both waits for
// both, and frees each handle once afterwards.
func TestSignerSignSignInsideBackendTogether(t *testing.T) {
	for _, phase := range []string{"size-query", "sign"} {
		t.Run(phase, func(t *testing.T) {
			fx := newSignFixture(t)
			f := newFakeSignerNative(fx.p1363)
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			hook := func() { entered <- struct{}{}; <-release }
			if phase == "size-query" {
				f.sizeHook = hook
			} else {
				f.signHook = hook
			}
			s := newTestSigner(f, fx.pub)

			type result struct {
				sig []byte
				err error
			}
			results := make(chan result, 2)
			for i := 0; i < 2; i++ {
				go func() {
					sig, err := s.Sign(nil, fx.digest, nil)
					results <- result{sig, err}
				}()
			}
			recvOrFail(t, entered, "first Sign inside the backend")
			recvOrFail(t, entered, "second Sign inside the backend while the first is held")

			closed := make(chan error, 1)
			go func() { closed <- s.Close() }()
			waitCloseQueued(t, s)
			if snap := f.snapshot(); snap.keyFrees != 0 || snap.provFrees != 0 {
				t.Fatalf("handles freed while two Sign calls in progress: %+v", snap)
			}
			select {
			case err := <-closed:
				t.Fatalf("Close returned (%v) before the in-flight Sign calls finished", err)
			default:
			}

			close(release)
			for i := 0; i < 2; i++ {
				r := recvOrFail(t, results, "Sign result")
				if r.err != nil {
					t.Fatalf("in-flight Sign: %v", r.err)
				}
				if !ecdsa.VerifyASN1(fx.pub, fx.digest, r.sig) {
					t.Fatal("in-flight Sign: signature does not verify")
				}
			}
			if err := recvOrFail(t, closed, "Close"); err != nil {
				t.Fatalf("Close: %v", err)
			}
			snap := f.snapshot()
			if snap.sizeCalls != 2 || snap.signCalls != 2 {
				t.Fatalf("calls: size=%d sign=%d, want 2/2", snap.sizeCalls, snap.signCalls)
			}
			assertFreedOnce(t, snap)
			assertNoUseAfterFree(t, snap)
		})
	}
}

// A panic inside either NCryptSignHash call of the seam must not leave the
// read lock held: the lock is free afterwards (TryLock succeeds), the signer
// stays usable, and a later Close frees each handle once.
func TestSignerPanicInSignReleasesLock(t *testing.T) {
	for _, phase := range []string{"size-query", "sign"} {
		t.Run(phase, func(t *testing.T) {
			fx := newSignFixture(t)
			f := newFakeSignerNative(fx.p1363)
			boom := func() { panic("simulated panic in " + phase) }
			if phase == "size-query" {
				f.sizeHook = boom
			} else {
				f.signHook = boom
			}
			s := newTestSigner(f, fx.pub)

			func() {
				defer func() {
					if r := recover(); r == nil {
						t.Fatal("Sign did not propagate the simulated panic")
					}
				}()
				_, _ = s.Sign(nil, fx.digest, nil)
			}()
			if !s.mu.TryLock() {
				t.Fatal("signer lock still held after a panic in Sign")
			}
			s.mu.Unlock()

			f.mu.Lock()
			f.sizeHook, f.signHook = nil, nil
			f.mu.Unlock()
			sig, err := s.Sign(nil, fx.digest, nil)
			if err != nil || !ecdsa.VerifyASN1(fx.pub, fx.digest, sig) {
				t.Fatalf("Sign after recovered panic: err=%v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			snap := f.snapshot()
			assertFreedOnce(t, snap)
			assertNoUseAfterFree(t, snap)
		})
	}
}

// A panic inside NCryptFreeObject during Close must not leave the write lock
// held. This test also pins down what is NOT guaranteed after such a panic:
// the signer is already marked closed, the provider handle is never
// attempted, and a later Close does not resume the release sequence. Lock
// release is panic-safe; native resource release is not.
func TestSignerPanicInCloseReleasesLock(t *testing.T) {
	fx := newSignFixture(t)
	f := newFakeSignerNative(fx.p1363)
	f.freeHook = func(h uintptr) {
		if h == fakeKeyHandle {
			panic("simulated panic in key free")
		}
	}
	s := newTestSigner(f, fx.pub)

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("Close did not propagate the simulated panic")
			}
		}()
		_ = s.Close()
	}()
	if !s.mu.TryLock() {
		t.Fatal("signer lock still held after a panic in Close")
	}
	s.mu.Unlock()

	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := s.Sign(nil, fx.digest, nil); !errors.Is(err, errSignerClosed) {
		t.Fatalf("Sign after panicked Close: err = %v, want errSignerClosed", err)
	}
	snap := f.snapshot()
	if snap.sizeCalls != 0 || snap.signCalls != 0 {
		t.Fatalf("Sign reached the backend after Close: size=%d sign=%d", snap.sizeCalls, snap.signCalls)
	}
	// The key free panicked before completing and the provider was never
	// attempted; the second Close made no further attempt.
	if snap.keyFrees != 0 || snap.provFrees != 0 || len(snap.freeOrder) != 0 {
		t.Fatalf("free attempts after panicked Close = %+v, want none recorded", snap)
	}
}

// Schedule-dependent: 32 concurrent Close calls released by one barrier.
// Whatever the interleaving, each handle is freed once and every Close
// returns nil; the deterministic Close/Close case is TestSignerCloseCloseFreesOnce.
func TestSignerConcurrentCloseFreesOnce(t *testing.T) {
	f := newFakeSignerNative(nil)
	s := newTestSigner(f, nil)
	const n = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- s.Close()
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	assertFreedOnce(t, f.snapshot())
}

func TestSignerCloseReportsFreeFailuresOnce(t *testing.T) {
	cases := []struct {
		name    string
		freeHR  map[uintptr]uintptr
		wantErr []string
	}{
		{"key free fails", map[uintptr]uintptr{fakeKeyHandle: 0x80090026}, []string{"key d3-test-key): hr=0x80090026"}},
		{"provider free fails", map[uintptr]uintptr{fakeProviderHandle: 0x80090026}, []string{"provider): hr=0x80090026"}},
		{"both fail", map[uintptr]uintptr{fakeKeyHandle: 0x1, fakeProviderHandle: 0x2}, []string{"key d3-test-key): hr=0x1", "provider): hr=0x2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newSignFixture(t)
			f := newFakeSignerNative(fx.p1363)
			f.freeHR = tc.freeHR
			s := newTestSigner(f, fx.pub)

			err := s.Close()
			if err == nil {
				t.Fatal("Close hid a free failure")
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("Close err = %v, want containing %q", err, want)
				}
			}
			// Each handle was attempted exactly once, and never retried.
			if err := s.Close(); err != nil {
				t.Fatalf("second Close: %v", err)
			}
			assertFreedOnce(t, f.snapshot())
			if _, err := s.Sign(nil, fx.digest, nil); !errors.Is(err, errSignerClosed) {
				t.Fatalf("Sign after failed Close: err = %v, want errSignerClosed", err)
			}
			if snap := f.snapshot(); snap.sizeCalls != 0 {
				t.Fatal("Sign reached CNG after a failed Close")
			}
		})
	}
}

func TestSignerClosePartialHandles(t *testing.T) {
	cases := []struct {
		name          string
		provider, key uintptr
		want          []uintptr
	}{
		{"key only", 0, fakeKeyHandle, []uintptr{fakeKeyHandle}},
		{"provider only", fakeProviderHandle, 0, []uintptr{fakeProviderHandle}},
		{"none", 0, 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSignerNative(nil)
			s := &cngSigner{provider: tc.provider, key: tc.key, native: f}
			if err := s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("second Close: %v", err)
			}
			got := f.snapshot().freeOrder
			if len(got) != len(tc.want) {
				t.Fatalf("freed %#x, want %#x", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("freed %#x, want %#x", got, tc.want)
				}
			}
			if _, err := s.Sign(nil, []byte("d"), nil); !errors.Is(err, errSignerClosed) {
				t.Fatalf("Sign: err = %v, want errSignerClosed", err)
			}
		})
	}
}

// Schedule-dependent (probabilistic) stress, not a barrier test: many
// goroutines race Sign against Close. Every Sign either verifies or fails
// with errSignerClosed, the key is never used after free, and each handle is
// freed once. Most useful under -race.
func TestSignerSignCloseStress(t *testing.T) {
	fx := newSignFixture(t)
	for round := 0; round < 50; round++ {
		f := newFakeSignerNative(fx.p1363)
		f.sizeHook = runtime.Gosched
		f.signHook = runtime.Gosched
		s := newTestSigner(f, fx.pub)

		start := make(chan struct{})
		var wg sync.WaitGroup
		failures := make(chan string, 64)
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for j := 0; j < 4; j++ {
					sig, err := s.Sign(nil, fx.digest, nil)
					switch {
					case errors.Is(err, errSignerClosed):
					case err != nil:
						failures <- err.Error()
					case !ecdsa.VerifyASN1(fx.pub, fx.digest, sig):
						failures <- "invalid signature"
					}
				}
			}()
		}
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				runtime.Gosched()
				if err := s.Close(); err != nil {
					failures <- err.Error()
				}
			}()
		}
		close(start)
		wg.Wait()
		close(failures)
		for msg := range failures {
			t.Fatalf("round %d: %s", round, msg)
		}
		snap := f.snapshot()
		assertFreedOnce(t, snap)
		assertNoUseAfterFree(t, snap)
	}
}
