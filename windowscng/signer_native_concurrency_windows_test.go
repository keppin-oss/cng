//go:build windows && cng_native_concurrency

package windowscng

// NATIVE D3 integration tests: concurrent Sign/Close and Close/Close on a
// cngSigner backed by REAL NCrypt provider/key handles of a REAL persisted
// ECDSA P-256 key in the Microsoft Software Key Storage Provider.
//
// Unlike signer_lifecycle_windows_test.go (simulated backend), these tests
// call ncrypt.dll. They create and delete machine-scoped keys, so they need an
// elevated (or otherwise authorized) Windows context and are gated behind the
// cng_native_concurrency build tag:
//
//	go test -race -count=1 -tags cng_native_concurrency -run TestNativeD3 -v ./windowscng/
//
// Key safety: each test creates exactly one disposable key with a unique,
// random, test-namespace name, verifies first that the name does not exist,
// and deletes only that name. No wildcard/prefix deletion. t.Cleanup is
// registered immediately after the key is created, before any other check.
//
// Known limit (TOCTOU): the absence pre-check (Open == ErrKeyNotFound) and
// LoadOrCreate are not atomic, LoadOrCreate does not report whether it
// opened or created the key, and ErrKeyNotFound also covers "not
// accessible". Exclusivity of the name therefore rests on the pre-check plus
// 64 random bits, not on a formal proof that this test created the key.
//
// Known limit (cleanup): t.Cleanup cannot run if the process dies: a native
// crash (for example an access violation inside ncrypt.dll), a killed
// process, or a `go test -timeout` expiry. The disposable key name is logged
// before creation so that a leftover key can be identified; no exploratory
// cleanup is performed. Goroutine panics are recovered and turned into test
// failures (see nativeConcGroup), so they do not prevent t.Cleanup. If a round
// hangs past its deadline and goroutines are still active after abort, the
// test fails with a goroutine dump and cleanup deliberately leaves the signer
// and the key untouched, reporting the key name.
//
// Starts are coordinated with barriers (channels), never with sleeps; no
// assertion depends on a particular scheduling order. The probe observes the
// boundary between cngSigner and ncrypt.dll from the Go side only: it does
// not observe KSP or ncrypt.dll internals, and the Go race detector does not
// instrument native code. Absence of crashes or race reports is not a proof
// of the absence of native races.

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
	"time"
)

const (
	nativeConcKeyPrefix      = "Keppin.OSS.Test.CNG.D3Concurrency."
	nativeConcRounds         = 200 // Sign/Close rounds per test invocation
	nativeConcCloseRounds    = 200 // Close/Close rounds per test invocation
	nativeConcPlainRounds    = 100 // uninstrumented production-path rounds
	nativeConcClosers        = 4   // concurrent Close calls in Sign/Close rounds
	nativeConcCloseOnlyCount = 16  // concurrent Close calls in Close/Close rounds
	nativeConcMaxSignsWorker = 100000

	// nativeConcRoundDeadline bounds one round, which normally takes
	// milliseconds. It only turns a hang into a diagnosed FAIL; no assertion
	// depends on timing.
	nativeConcRoundDeadline = 2 * time.Minute
	// nativeConcAbortGrace is how long the coordinator waits for goroutines
	// to finish after signalling abort.
	nativeConcAbortGrace = 30 * time.Second
)

// nativeConcProbe wraps the REAL nativeSignerOps. Every NCrypt call still goes
// to ncrypt.dll; the probe only records, Go-side and per round, in-flight
// NCryptSignHash calls and NCryptFreeObject calls, to detect use of a freed
// handle, a free while a Sign is in flight, and double frees at the
// cngSigner/ncrypt.dll boundary.
type nativeConcProbe struct {
	inner nativeSignerOps

	mu         sync.Mutex
	inFlight   int
	maxFlight  int
	freed      map[uintptr]int
	signCalls  int
	violations []string

	firstSignOnce sync.Once
	firstSign     chan struct{}
}

func newNativeConcProbe() *nativeConcProbe {
	return &nativeConcProbe{freed: map[uintptr]int{}, firstSign: make(chan struct{})}
}

func (p *nativeConcProbe) enter(key uintptr, op string) {
	p.mu.Lock()
	if p.freed[key] > 0 {
		p.violations = append(p.violations, fmt.Sprintf("%s on freed key handle 0x%x", op, key))
	}
	p.inFlight++
	if p.inFlight > p.maxFlight {
		p.maxFlight = p.inFlight
	}
	p.signCalls++
	p.mu.Unlock()
	p.firstSignOnce.Do(func() { close(p.firstSign) })
}

func (p *nativeConcProbe) exit() {
	p.mu.Lock()
	p.inFlight--
	p.mu.Unlock()
}

func (p *nativeConcProbe) signHashSize(key uintptr, digest []byte, size *uint32) (uint32, error) {
	p.enter(key, "NCryptSignHash(size)")
	defer p.exit()
	return p.inner.signHashSize(key, digest, size)
}

func (p *nativeConcProbe) signHash(key uintptr, digest, sig []byte, size *uint32) (uint32, error) {
	p.enter(key, "NCryptSignHash")
	defer p.exit()
	return p.inner.signHash(key, digest, sig, size)
}

func (p *nativeConcProbe) freeObject(h uintptr) uint32 {
	p.mu.Lock()
	if p.inFlight > 0 {
		p.violations = append(p.violations, fmt.Sprintf("NCryptFreeObject(0x%x) while %d NCryptSignHash in flight", h, p.inFlight))
	}
	p.freed[h]++
	if p.freed[h] > 1 {
		p.violations = append(p.violations, fmt.Sprintf("double NCryptFreeObject on handle 0x%x", h))
	}
	p.mu.Unlock()
	return p.inner.freeObject(h)
}

// nativeConcGroup runs the goroutines of one round. Each goroutine recovers
// its own panic, with stack, and reports it to the coordinator instead of
// terminating the process, so the test fails from the test goroutine and
// t.Cleanup still runs. A panic or the round deadline closes abort, which
// every goroutine observes at each of its waiting points. Goroutines never
// call t.Fatal.
type nativeConcGroup struct {
	start     chan struct{}
	abort     chan struct{}
	abortOnce sync.Once
	ready     sync.WaitGroup
	done      sync.WaitGroup

	mu     sync.Mutex
	panics []string
}

func newNativeConcGroup() *nativeConcGroup {
	return &nativeConcGroup{start: make(chan struct{}), abort: make(chan struct{})}
}

func (g *nativeConcGroup) abortNow() { g.abortOnce.Do(func() { close(g.abort) }) }

func (g *nativeConcGroup) aborted() bool {
	select {
	case <-g.abort:
		return true
	default:
		return false
	}
}

// spawn starts fn in a goroutine that first waits on the start barrier.
// done.Done is deferred first so that it runs last, after recovery.
func (g *nativeConcGroup) spawn(label string, fn func()) {
	g.ready.Add(1)
	g.done.Add(1)
	go func() {
		defer g.done.Done()
		defer func() {
			if r := recover(); r != nil {
				g.mu.Lock()
				g.panics = append(g.panics, fmt.Sprintf("%s: panic: %v\n%s", label, r, debug.Stack()))
				g.mu.Unlock()
				g.abortNow()
			}
		}()
		g.ready.Done()
		select {
		case <-g.start:
		case <-g.abort:
			return
		}
		fn()
	}()
}

// run releases the barrier and waits for every goroutine. It reports false
// only if goroutines are still running after the deadline and the abort
// grace period; the caller must then not touch the signer or the key.
func (g *nativeConcGroup) run(t *testing.T) bool {
	t.Helper()
	g.ready.Wait()
	close(g.start)

	all := make(chan struct{})
	go func() { g.done.Wait(); close(all) }()

	deadline := time.NewTimer(nativeConcRoundDeadline)
	defer deadline.Stop()
	select {
	case <-all:
		return true
	case <-deadline.C:
	}
	t.Errorf("round exceeded %v (possible deadlock); signalling abort. Goroutine dump:\n%s", nativeConcRoundDeadline, nativeConcAllStacks())
	g.abortNow()

	grace := time.NewTimer(nativeConcAbortGrace)
	defer grace.Stop()
	select {
	case <-all:
		t.Errorf("round goroutines finished only after abort")
		return true
	case <-grace.C:
		t.Errorf("round goroutines still running %v after abort. Goroutine dump:\n%s", nativeConcAbortGrace, nativeConcAllStacks())
		return false
	}
}

func (g *nativeConcGroup) panicReports() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.panics...)
}

func nativeConcAllStacks() string {
	buf := make([]byte, 1<<20)
	return string(buf[:runtime.Stack(buf, true)])
}

// nativeConcEnv is one disposable key and the signers opened on it.
type nativeConcEnv struct {
	name string
	pub  *ecdsa.PublicKey

	mu      sync.Mutex
	signers []Signer
	stuck   bool
}

func (e *nativeConcEnv) track(s Signer) {
	e.mu.Lock()
	e.signers = append(e.signers, s)
	e.mu.Unlock()
}

// finishRound fails the test from the test goroutine if the round's
// goroutines panicked or did not terminate. All goroutines have returned when
// it proceeds, except when finished is false: the env is then marked stuck
// and cleanup leaves the signer and the key untouched.
func (e *nativeConcEnv) finishRound(t *testing.T, round int, g *nativeConcGroup, finished bool) {
	t.Helper()
	if !finished {
		e.mu.Lock()
		e.stuck = true
		e.mu.Unlock()
		t.Fatalf("round %d: goroutines still active; cleanup will NOT touch the signer or disposable key %q", round, e.name)
	}
	if p := g.panicReports(); len(p) > 0 {
		for _, s := range p {
			t.Errorf("round %d: %s", round, s)
		}
		t.Fatalf("round %d: %d goroutine panic(s) recovered; round aborted", round, len(p))
	}
}

// cleanup closes every tracked signer, deletes exactly e.name and verifies
// that it is absent. It runs only after every round goroutine has returned,
// unless the env is stuck, in which case it touches nothing.
func (e *nativeConcEnv) cleanup(t *testing.T) {
	e.mu.Lock()
	stuck := e.stuck
	signers := append([]Signer(nil), e.signers...)
	e.mu.Unlock()
	if stuck {
		t.Errorf("CLEANUP SKIPPED: round goroutines still active; disposable key %q left in place for diagnosis, not deleted", e.name)
		return
	}
	// Close is idempotent: round signers already closed return nil, and the
	// initial LoadOrCreate signer (index 0) makes its first and only release
	// attempt here. A failure is reported, never retried, and the key is
	// still deleted and checked below.
	for i, s := range signers {
		if err := s.Close(); err != nil {
			t.Errorf("CLEANUP: Close of signer %d on %q = %v (handle release failed; not retried)", i, e.name, err)
		}
	}
	if err := Delete(e.name); err != nil {
		t.Errorf("CLEANUP: Delete(%q) = %v — disposable key may persist, inspect manually", e.name, err)
		return
	}
	if s, err := Open(e.name); !errors.Is(err, ErrKeyNotFound) {
		if err == nil {
			if cerr := s.Close(); cerr != nil {
				t.Errorf("CLEANUP: Close of unexpected post-Delete signer on %q = %v", e.name, cerr)
			}
		}
		t.Errorf("CLEANUP: Open(%q) after Delete = %v, want ErrKeyNotFound", e.name, err)
		return
	}
	t.Logf("NATIVE: disposable key %q deleted and verified absent", e.name)
}

// nativeConcKey creates one disposable key and registers its deletion
// immediately after creation.
func nativeConcKey(t *testing.T) *nativeConcEnv {
	t.Helper()

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatalf("random name: %v", err)
	}
	name := fmt.Sprintf("%sR%s-%s", nativeConcKeyPrefix, time.Now().UTC().Format("20060102T150405Z"), hex.EncodeToString(rnd[:]))

	// The name must not exist: never reuse or touch a pre-existing key.
	if s, err := Open(name); err == nil {
		_ = s.Close()
		t.Fatalf("disposable key name %q already exists; refusing to use or delete it", name)
	} else if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("pre-check Open(%q) = %v, want ErrKeyNotFound; refusing to proceed", name, err)
	}

	// Logged before creation so that a key left by a process crash can be
	// identified.
	t.Logf("NATIVE: creating disposable key %q (MS Software KSP, ECDSA P-256, machine scope)", name)
	created, err := LoadOrCreate(name)
	if err != nil {
		// Not a SKIP: this test is explicitly opted into with its build tag.
		// The key is not deleted here: that this test created it cannot be
		// proven, so its presence is only reported.
		if s, openErr := Open(name); openErr == nil {
			_ = s.Close()
			t.Fatalf("NATIVE: LoadOrCreate(%q) failed: %v; a key with this name now exists and was NOT deleted, inspect manually", name, err)
		}
		t.Fatalf("NATIVE: LoadOrCreate(%q) failed (elevated context required): %v", name, err)
	}

	e := &nativeConcEnv{name: name, signers: []Signer{created}}
	t.Cleanup(func() { e.cleanup(t) }) // registered before any check that can fail

	pub, ok := created.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() = %T, want *ecdsa.PublicKey", created.Public())
	}
	e.pub = pub
	t.Logf("NATIVE: created disposable key %q", name)
	return e
}

// nativeConcOpen opens a fresh signer on the key (new real provider and key
// handles) and checks that it is the production cngSigner on real handles.
func nativeConcOpen(t *testing.T, e *nativeConcEnv) *cngSigner {
	t.Helper()
	s, err := Open(e.name)
	if err != nil {
		t.Fatalf("NATIVE: Open(%q): %v", e.name, err)
	}
	e.track(s)
	cs, ok := s.(*cngSigner)
	if !ok {
		t.Fatalf("Open returned %T, want *cngSigner", s)
	}
	if cs.native != nil {
		t.Fatalf("production signer has a non-native backend %T", cs.native)
	}
	if cs.key == 0 || cs.provider == 0 {
		t.Fatalf("NATIVE: zero handle(s): provider=0x%x key=0x%x", cs.provider, cs.key)
	}
	return cs
}

func nativeConcDigest(round, worker, i int) []byte {
	d := sha256.Sum256([]byte(fmt.Sprintf("keppin-d3-native-%d-%d-%d", round, worker, i)))
	return d[:]
}

type nativeConcStats struct {
	signOK, signClosed, interleaved, closeAfterFirstSign int
	maxFlight                                            int
}

// nativeConcSignCloseRound runs one round of GOMAXPROCS signing workers and
// nativeConcClosers closers on one signer, released by a single barrier.
// If probe is nil the plain production backend (nativeSignerOps) is used.
func nativeConcSignCloseRound(t *testing.T, e *nativeConcEnv, round int, cs *cngSigner, probe *nativeConcProbe, waitFirstSign bool, st *nativeConcStats) {
	t.Helper()
	workers := runtime.GOMAXPROCS(0)

	type wres struct {
		ok, closed int
		unexpected []string
	}
	wout := make([]wres, workers)
	cerr := make([]error, nativeConcClosers)
	cran := make([]bool, nativeConcClosers)

	g := newNativeConcGroup()
	defer g.abortNow() // releases barrier waiters if this coordinator unwinds early
	for w := 0; w < workers; w++ {
		g.spawn(fmt.Sprintf("worker %d", w), func() {
			r := &wout[w]
			for i := 0; i < nativeConcMaxSignsWorker; i++ {
				if g.aborted() {
					return
				}
				d := nativeConcDigest(round, w, i)
				sig, err := cs.Sign(rand.Reader, d, nil)
				if errors.Is(err, errSignerClosed) {
					r.closed++
					return
				}
				if err != nil {
					r.unexpected = append(r.unexpected, err.Error())
					return
				}
				if !ecdsa.VerifyASN1(e.pub, d, sig) {
					r.unexpected = append(r.unexpected, fmt.Sprintf("signature %d did not verify", i))
					return
				}
				r.ok++
			}
			r.unexpected = append(r.unexpected, "worker never observed errSignerClosed (Close starvation?)")
		})
	}
	for c := 0; c < nativeConcClosers; c++ {
		g.spawn(fmt.Sprintf("closer %d", c), func() {
			if waitFirstSign && probe != nil {
				select { // event-based, not time-based
				case <-probe.firstSign:
				case <-g.abort:
					return
				}
			}
			cerr[c] = cs.Close()
			cran[c] = true
		})
	}
	e.finishRound(t, round, g, g.run(t))

	roundOK, roundClosed := 0, 0
	for w, r := range wout {
		for _, u := range r.unexpected {
			t.Errorf("round %d worker %d: %s", round, w, u)
		}
		roundOK += r.ok
		roundClosed += r.closed
	}
	for c, err := range cerr {
		if !cran[c] {
			t.Errorf("round %d closer %d: did not run Close", round, c)
		}
		if err != nil {
			t.Errorf("round %d closer %d: Close = %v, want nil", round, c, err)
		}
	}
	if _, err := cs.Sign(rand.Reader, nativeConcDigest(round, -1, 0), nil); !errors.Is(err, errSignerClosed) {
		t.Errorf("round %d: Sign after Close = %v, want errSignerClosed", round, err)
	}
	if err := cs.Close(); err != nil {
		t.Errorf("round %d: extra Close = %v, want nil", round, err)
	}
	if roundClosed != workers {
		t.Errorf("round %d: %d/%d workers ended with errSignerClosed", round, roundClosed, workers)
	}
	st.signOK += roundOK
	st.signClosed += roundClosed
	if roundOK > 0 && roundClosed > 0 {
		st.interleaved++
	}
	if waitFirstSign {
		st.closeAfterFirstSign++
	}
}

func nativeConcCheckProbe(t *testing.T, round int, p *nativeConcProbe, provider, key uintptr, st *nativeConcStats) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, v := range p.violations {
		t.Errorf("round %d: %s", round, v)
	}
	if p.freed[key] != 1 || p.freed[provider] != 1 || len(p.freed) != 2 {
		t.Errorf("round %d: frees = %v, want key 0x%x and provider 0x%x freed exactly once", round, p.freed, key, provider)
	}
	if p.inFlight != 0 {
		t.Errorf("round %d: %d NCryptSignHash still in flight after Close", round, p.inFlight)
	}
	if p.maxFlight > st.maxFlight {
		st.maxFlight = p.maxFlight
	}
}

// TestNativeD3ConcurrentSignClose: concurrent Sign and Close on the same
// signer and the same real NCrypt key handle, instrumented with the probe.
func TestNativeD3ConcurrentSignClose(t *testing.T) {
	e := nativeConcKey(t)
	t.Logf("NATIVE: GOMAXPROCS=%d NumCPU=%d workers/round=%d closers/round=%d rounds=%d",
		runtime.GOMAXPROCS(0), runtime.NumCPU(), runtime.GOMAXPROCS(0), nativeConcClosers, nativeConcRounds)

	var st nativeConcStats
	for round := 0; round < nativeConcRounds; round++ {
		cs := nativeConcOpen(t, e)
		provider, key := cs.provider, cs.key
		if round == 0 {
			t.Logf("NATIVE: round 0 real handles provider=0x%x key=0x%x", provider, key)
		}
		probe := newNativeConcProbe()
		cs.native = probe // set before any goroutine starts; inner is the real nativeSignerOps
		nativeConcSignCloseRound(t, e, round, cs, probe, round%2 == 1, &st)
		nativeConcCheckProbe(t, round, probe, provider, key, &st)
		if t.Failed() {
			t.Fatalf("stopping after failing round %d", round)
		}
	}
	t.Logf("NATIVE RESULT: rounds=%d verified signatures=%d errSignerClosed=%d rounds with sign+closed interleaving=%d close-after-first-native-sign rounds=%d max in-flight NCryptSignHash calls (Go-side)=%d",
		nativeConcRounds, st.signOK, st.signClosed, st.interleaved, st.closeAfterFirstSign, st.maxFlight)
}

// nativeConcCloseCloseRound runs nativeConcCloseOnlyCount concurrent Close
// calls on one signer, released by a single barrier.
func nativeConcCloseCloseRound(t *testing.T, e *nativeConcEnv, round int, cs *cngSigner) {
	t.Helper()
	errs := make([]error, nativeConcCloseOnlyCount)
	ran := make([]bool, nativeConcCloseOnlyCount)
	g := newNativeConcGroup()
	defer g.abortNow() // releases barrier waiters if this coordinator unwinds early
	for c := 0; c < nativeConcCloseOnlyCount; c++ {
		g.spawn(fmt.Sprintf("closer %d", c), func() {
			errs[c] = cs.Close()
			ran[c] = true
		})
	}
	e.finishRound(t, round, g, g.run(t))

	for c, err := range errs {
		if !ran[c] {
			t.Errorf("round %d closer %d: did not run Close", round, c)
		}
		if err != nil {
			t.Errorf("round %d closer %d: Close = %v, want nil", round, c, err)
		}
	}
}

// TestNativeD3ConcurrentCloseClose: many concurrent Close calls on the same
// signer with real handles; each real handle must be freed exactly once.
func TestNativeD3ConcurrentCloseClose(t *testing.T) {
	e := nativeConcKey(t)
	var st nativeConcStats
	for round := 0; round < nativeConcCloseRounds; round++ {
		cs := nativeConcOpen(t, e)
		provider, key := cs.provider, cs.key
		probe := newNativeConcProbe()
		cs.native = probe

		// One real signature on these handles before closing.
		d := nativeConcDigest(round, 0, 0)
		sig, err := cs.Sign(rand.Reader, d, nil)
		if err != nil || !ecdsa.VerifyASN1(e.pub, d, sig) {
			t.Fatalf("round %d: pre-close Sign = %v / verify failed", round, err)
		}

		nativeConcCloseCloseRound(t, e, round, cs)
		if _, err := cs.Sign(rand.Reader, d, nil); !errors.Is(err, errSignerClosed) {
			t.Errorf("round %d: Sign after Close = %v, want errSignerClosed", round, err)
		}
		nativeConcCheckProbe(t, round, probe, provider, key, &st)
		if t.Failed() {
			t.Fatalf("stopping after failing round %d", round)
		}
	}
	t.Logf("NATIVE RESULT: rounds=%d concurrent Close per round=%d, every real handle freed exactly once",
		nativeConcCloseRounds, nativeConcCloseOnlyCount)
}

// TestNativeD3PlainProductionPath repeats Sign/Close concurrency on the
// uninstrumented production backend (cs.native == nil, i.e. nativeSignerOps
// called directly), to exclude any effect of the probe.
func TestNativeD3PlainProductionPath(t *testing.T) {
	e := nativeConcKey(t)
	var st nativeConcStats
	for round := 0; round < nativeConcPlainRounds; round++ {
		cs := nativeConcOpen(t, e)
		nativeConcSignCloseRound(t, e, round, cs, nil, false, &st)
		if t.Failed() {
			t.Fatalf("stopping after failing round %d", round)
		}
	}
	t.Logf("NATIVE RESULT (uninstrumented): rounds=%d verified signatures=%d errSignerClosed=%d rounds with sign+closed interleaving=%d",
		nativeConcPlainRounds, st.signOK, st.signClosed, st.interleaved)
}
