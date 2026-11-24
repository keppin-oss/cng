//go:build windows && cng_finalize_probe

package windowscng

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// TestFinalizeFailureProbe is the native check behind the "not persisted"
// rule of cleanupAfterFinalizeFailure. It is gated behind the
// cng_finalize_probe build tag and is never run by `go test ./...`. The
// procedure, the matrix of contexts and SDDLs and the evidence to keep are in
// docs/finalize-probe.md.
//
// Each process runs one phase, chosen with -probe.phase (or the environment
// variable KEPPIN_FINALIZE_PROBE_PHASE; every flag below has such a fallback):
//
//   - observe (elevated Administrator or SYSTEM): the unique temporary name
//     must be absent both by enumeration of the machine keys of the Microsoft
//     Software KSP and by NCryptOpenKey on the exact name. As a positive
//     control the phase creates "<name>.Control", requires both methods to
//     find it, deletes it and requires both methods to stop finding it.
//   - run (non-privileged caller): the production create path
//     (createPersistedKeyWith: create -> export policy -> DACL -> finalize)
//     runs with the SDDL chosen by -probe.sddl, in the context declared by
//     -probe.context, which is checked against the token first.
//
// The run phase classifies its result and passes only for EXPECTED:
//
//   - EXPECTED: every step up to finalize ran in order, finalize returned
//     NTE_PERM, the delete of the same handle returned NTE_BAD_KEYSET, the
//     handle was freed exactly once, the privilege check ran once and reported
//     a non-privileged caller, and the error is the finalize NCryptError with
//     the not-persisted note and without ErrCleanupFailed;
//   - DIFFERENT: finalize was reached but anything above differs, including a
//     finalize that succeeded (the key is then deleted through its handle);
//   - NOT_EXERCISED: a step before finalize failed, so the rule was not
//     reached;
//   - INVALID_CONFIGURATION: the token does not match the declared context,
//     the name already exists, or the inputs are invalid. Nothing is created.
//
// Every phase appends one JSON record to the file given by -probe.log. Only
// the absence seen by an elevated caller counts: for a non-privileged caller
// NTE_BAD_KEYSET cannot distinguish an absent key from an inaccessible one.
// Enumeration and exact open show only what the KSP exposes; they do not
// prove that no partial file exists on disk.
func TestFinalizeFailureProbe(t *testing.T) {
	cfg := probeConfigFromFlags(t)
	tok := probeReadToken(t)
	rec := probeRecord{
		Time:         time.Now().UTC().Format(time.RFC3339Nano),
		Phase:        cfg.phase,
		Name:         cfg.name,
		Commit:       cfg.commit,
		WindowsBuild: probeWindowsBuild(),
		KSP:          msSoftwareKSP,
		Token:        tok,
	}

	switch cfg.phase {
	case "observe":
		probeObserve(t, cfg, &rec)
	case "run":
		probeRun(t, cfg, &rec)
	default:
		t.Fatal("-probe.phase must be observe or run")
	}
}

// Flags of the probe, with environment fallbacks so that both
// `go test ... -args -probe.phase=run` and the earlier environment variables
// work. Flags reach a test binary started by runas or by a scheduled task,
// where the caller's environment does not.
var (
	probePhase   = flag.String("probe.phase", os.Getenv("KEPPIN_FINALIZE_PROBE_PHASE"), "observe or run")
	probeName    = flag.String("probe.name", os.Getenv("KEPPIN_FINALIZE_PROBE_NAME"), "unique temporary key name starting with "+probeNamePrefix)
	probeContext = flag.String("probe.context", os.Getenv("KEPPIN_FINALIZE_PROBE_CONTEXT"), "run phase: filtered-admin, standard-user or local-service")
	probeSDDL    = flag.String("probe.sddl", envOr("KEPPIN_FINALIZE_PROBE_SDDL", "legacy"), "run phase: legacy, privileged-only or service:<ServiceName>")
	probeLog     = flag.String("probe.log", os.Getenv("KEPPIN_FINALIZE_PROBE_LOG"), "file to which one JSON record per phase is appended")
	probeCommit  = flag.String("probe.commit", os.Getenv("KEPPIN_FINALIZE_PROBE_COMMIT"), "commit of the code under test, recorded in the log")
)

const probeNamePrefix = "Keppin.OSS.Test."

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Outcomes recorded in the log.
const (
	outcomeExpected      = "EXPECTED"
	outcomeDifferent     = "DIFFERENT"
	outcomeNotExercised  = "NOT_EXERCISED"
	outcomeInvalidConfig = "INVALID_CONFIGURATION"
	outcomeAbsent        = "ABSENT"
	outcomePresent       = "PRESENT_OR_NOT_PROVABLY_ABSENT"
	outcomeInvalidObs    = "INVALID_OBSERVATION"
)

type probeConfig struct {
	phase, name, context, sddlLabel, sddl, log, commit string
}

func probeConfigFromFlags(t *testing.T) probeConfig {
	t.Helper()
	cfg := probeConfig{phase: *probePhase, name: *probeName, context: *probeContext, sddlLabel: *probeSDDL, log: *probeLog, commit: *probeCommit}
	if !strings.HasPrefix(cfg.name, probeNamePrefix) || len(cfg.name) == len(probeNamePrefix) {
		t.Fatalf("-probe.name must be a unique temporary name starting with %s", probeNamePrefix)
	}
	if cfg.log == "" {
		t.Fatal("-probe.log is required: every phase must leave a record")
	}
	return cfg
}

// probeRecord is the JSON record appended to the log for each phase.
type probeRecord struct {
	Time         string            `json:"time"`
	Phase        string            `json:"phase"`
	Name         string            `json:"name"`
	Commit       string            `json:"commit,omitempty"`
	WindowsBuild string            `json:"windows_build"`
	KSP          string            `json:"ksp"`
	Token        probeToken        `json:"token"`
	Context      string            `json:"context,omitempty"`
	SDDLLabel    string            `json:"sddl_label,omitempty"`
	SDDL         string            `json:"sddl,omitempty"`
	Steps        []probeStep       `json:"steps,omitempty"`
	Error        string            `json:"error,omitempty"`
	Observation  *probeObservation `json:"observation,omitempty"`
	Outcome      string            `json:"outcome"`
	Details      []string          `json:"details,omitempty"`
}

type probeObservation struct {
	ControlEnumerated  bool   `json:"control_enumerated"`
	ControlOpen        string `json:"control_open"`
	ControlGoneEnum    bool   `json:"control_gone_enumeration"`
	ControlGoneOpen    string `json:"control_gone_open"`
	NameEnumerated     bool   `json:"name_enumerated"`
	NameOpen           string `json:"name_open"`
	MachineKeysVisible int    `json:"machine_keys_visible"`
}

// finish records the outcome, writes the log and fails the test unless the
// outcome is one of pass.
func (rec *probeRecord) finish(t *testing.T, cfg probeConfig, outcome string, pass ...string) {
	t.Helper()
	rec.Outcome = outcome
	line, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("encode record: %v", err)
	}
	t.Logf("RECORD %s", line)
	f, err := os.OpenFile(cfg.log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open log %s: %v", cfg.log, err)
	}
	_, werr := f.Write(append(line, '\n'))
	cerr := f.Close()
	if werr != nil || cerr != nil {
		t.Fatalf("write log %s: %v %v", cfg.log, werr, cerr)
	}
	t.Logf("RESULT: %s", outcome)
	for _, p := range pass {
		if outcome == p {
			return
		}
	}
	t.Fatalf("RESULT: %s (%s)", outcome, strings.Join(rec.Details, "; "))
}

func probeObserve(t *testing.T, cfg probeConfig, rec *probeRecord) {
	if !rec.Token.Privileged {
		rec.Details = append(rec.Details, "observe must run elevated: a non-privileged caller cannot distinguish absent from inaccessible")
		rec.finish(t, cfg, outcomeInvalidConfig)
	}
	obs := &probeObservation{}
	rec.Observation = obs
	control := cfg.name + ".Control"
	if hr := probeOpenStatus(t, control); !IsKeyNotFound(uintptr(hr)) {
		rec.Details = append(rec.Details, fmt.Sprintf("control key %q already exists or cannot be checked (NCryptOpenKey hr=0x%x): not touched", control, hr))
		rec.finish(t, cfg, outcomeInvalidObs)
	}
	s, err := Create(control, PolicyServiceSigner)
	if err != nil {
		rec.Details = append(rec.Details, fmt.Sprintf("create control key: %v", err))
		rec.finish(t, cfg, outcomeInvalidObs)
	}
	controlSPKI, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		rec.Details = append(rec.Details, fmt.Sprintf("control key SPKI: %v", err))
	}
	if err := s.Close(); err != nil {
		rec.Details = append(rec.Details, fmt.Sprintf("close control signer: %v", err))
	}

	enumerated := probeEnumMachineKeys(t)
	obs.MachineKeysVisible = len(enumerated)
	obs.ControlEnumerated = enumerated[control]
	obs.ControlOpen = hex32(probeOpenStatus(t, control))
	obs.NameEnumerated = enumerated[cfg.name]
	nameOpen := probeOpenStatus(t, cfg.name)
	obs.NameOpen = hex32(nameOpen)

	// The control key is deleted and checked before the outcome is decided,
	// so that the record always shows whether it is gone.
	if err := Delete(control, PolicyServiceSigner, controlSPKI); err != nil {
		rec.Details = append(rec.Details, fmt.Sprintf("delete control key %q: %v", control, err))
	}
	gone := probeEnumMachineKeys(t)
	obs.ControlGoneEnum = !gone[control]
	goneOpen := probeOpenStatus(t, control)
	obs.ControlGoneOpen = hex32(goneOpen)

	switch {
	case !obs.ControlEnumerated || obs.ControlOpen != hex32(0):
		rec.Details = append(rec.Details, "positive control not observed by both methods")
		rec.finish(t, cfg, outcomeInvalidObs)
	case !obs.ControlGoneEnum || !IsKeyNotFound(uintptr(goneOpen)):
		rec.Details = append(rec.Details, "control key still observed after delete")
		rec.finish(t, cfg, outcomeInvalidObs)
	case obs.NameEnumerated || !IsKeyNotFound(uintptr(nameOpen)):
		rec.finish(t, cfg, outcomePresent)
	default:
		rec.finish(t, cfg, outcomeAbsent, outcomeAbsent)
	}
}

func probeRun(t *testing.T, cfg probeConfig, rec *probeRecord) {
	rec.Context = cfg.context
	rec.SDDLLabel = cfg.sddlLabel
	sddl, err := probeSDDLFor(cfg.sddlLabel)
	if err != nil {
		rec.Details = append(rec.Details, err.Error())
		rec.finish(t, cfg, outcomeInvalidConfig)
	}
	rec.SDDL = sddl
	if why := rec.Token.mismatch(cfg.context); why != "" {
		rec.Details = append(rec.Details, why)
		rec.finish(t, cfg, outcomeInvalidConfig)
	}
	if hr := probeOpenStatus(t, cfg.name); hr == 0 {
		rec.Details = append(rec.Details, fmt.Sprintf("%q already exists: not touched", cfg.name))
		rec.finish(t, cfg, outcomeInvalidConfig)
	}

	provider, err := openProvider()
	if err != nil {
		rec.Details = append(rec.Details, fmt.Sprintf("open provider: %v", err))
		rec.finish(t, cfg, outcomeNotExercised)
	}
	defer procNCryptFreeObject.Call(provider)
	nameUTF16, err := syscall.UTF16PtrFromString(cfg.name)
	if err != nil {
		rec.Details = append(rec.Details, err.Error())
		rec.finish(t, cfg, outcomeInvalidConfig)
	}

	ops := &recordingCreateOps{createKeyNative: nativeCreateKeyOps{}, freeStatus: func(h uintptr) uint32 { return ncryptStatus(procNCryptFreeObject.Call(h)) }}
	h, err := createPersistedKeyWith(ops, provider, nameUTF16, sddl)
	rec.Steps = ops.steps
	if err != nil {
		rec.Error = err.Error()
	}
	if err == nil {
		// Finalize succeeded: the key is persisted. It is not the case under
		// test; delete it through the same handle so that nothing is left.
		derr := deleteKeyHandle(h)
		rec.Steps = append(rec.Steps, probeStep{Op: "probe-delete-finalized", Status: errString(derr)})
		rec.Details = append(rec.Details, "finalize succeeded: the key was persisted and has been deleted by the probe")
		rec.finish(t, cfg, outcomeDifferent)
	}
	if !ops.reached("finalize") {
		rec.Details = append(rec.Details, "a step before finalize failed: the rule was not reached")
		rec.finish(t, cfg, outcomeNotExercised)
	}
	rec.Details = append(rec.Details, probeExpectedDiffs(ops, err)...)
	if len(rec.Details) > 0 {
		rec.finish(t, cfg, outcomeDifferent)
	}
	rec.finish(t, cfg, outcomeExpected, outcomeExpected)
}

func probeReadToken(t *testing.T) probeToken {
	t.Helper()
	var tok probeToken
	priv, perr := nativeKeyStore{}.callerPrivileged()
	tok.Privileged = priv && perr == nil
	if perr != nil {
		tok.PrivilegeError = perr.Error()
	}
	pt, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer pt.Close()

	if u, err := pt.GetTokenUser(); err == nil {
		tok.User, _ = u.User.Sid.String()
	}
	if b := probeTokenInfo(pt, syscall.TokenElevationType); len(b) >= 4 {
		switch *(*uint32)(unsafe.Pointer(&b[0])) {
		case 1:
			tok.ElevationType = "default"
		case 2:
			tok.ElevationType = "full"
		case 3:
			tok.ElevationType = "limited"
		}
	}
	if b := probeTokenInfo(pt, syscall.TokenIntegrityLevel); len(b) > 0 {
		label := (*syscall.SIDAndAttributes)(unsafe.Pointer(&b[0]))
		tok.Integrity, _ = label.Sid.String()
	}
	tok.Administrators = "absent"
	if b := probeTokenInfo(pt, syscall.TokenGroups); len(b) >= 4 {
		count := *(*uint32)(unsafe.Pointer(&b[0]))
		groups := unsafe.Slice((*syscall.SIDAndAttributes)(unsafe.Add(unsafe.Pointer(&b[0]), unsafe.Offsetof(tokenGroupsHeader{}.Groups))), count)
		for _, g := range groups {
			s, err := g.Sid.String()
			if err != nil {
				continue
			}
			switch {
			case s == sidAdministrators && g.Attributes&seGroupUseForDenyOnly != 0:
				tok.Administrators = "deny-only"
			case s == sidAdministrators && g.Attributes&seGroupEnabled != 0:
				tok.Administrators = "enabled"
			case strings.HasPrefix(s, "S-1-5-80-"):
				tok.ServiceSIDs = append(tok.ServiceSIDs, s)
			}
		}
	}
	return tok
}

// tokenGroupsHeader mirrors the start of TOKEN_GROUPS, for the offset of its
// array, which follows the pointer alignment of the platform.
type tokenGroupsHeader struct {
	GroupCount uint32
	Groups     [1]syscall.SIDAndAttributes
}

// probeTokenInfo returns the raw GetTokenInformation buffer, or nil.
func probeTokenInfo(t syscall.Token, class uint32) []byte {
	var n uint32
	_ = syscall.GetTokenInformation(t, class, nil, 0, &n)
	if n == 0 {
		return nil
	}
	b := make([]byte, n)
	if err := syscall.GetTokenInformation(t, class, &b[0], n, &n); err != nil {
		return nil
	}
	return b
}

// probeWindowsBuild returns major.minor.build from RtlGetVersion, which is
// not subject to the compatibility shims of GetVersionEx.
func probeWindowsBuild() string {
	type osVersionInfo struct {
		size, major, minor, build, platform uint32
		csd                                 [128]uint16
	}
	v := osVersionInfo{}
	v.size = uint32(unsafe.Sizeof(v))
	proc := syscall.NewLazyDLL("ntdll.dll").NewProc("RtlGetVersion")
	if proc.Find() != nil {
		return "unknown"
	}
	proc.Call(uintptr(unsafe.Pointer(&v)))
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.build)
}

var (
	procNCryptEnumKeys   = ncrypt.NewProc("NCryptEnumKeys")
	procNCryptFreeBuffer = ncrypt.NewProc("NCryptFreeBuffer")
)

const nteNoMoreItems = 0x8009002A

// ncryptKeyName mirrors NCryptKeyName.
type ncryptKeyName struct {
	name          *uint16
	algID         *uint16
	legacyKeySpec uint32
	flags         uint32
}

// probeEnumMachineKeys returns the names of all machine keys of the Microsoft
// Software KSP visible to the caller.
func probeEnumMachineKeys(t *testing.T) map[string]bool {
	t.Helper()
	provider, err := openProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer procNCryptFreeObject.Call(provider)
	out := map[string]bool{}
	var state uintptr
	defer func() {
		if state != 0 {
			procNCryptFreeBuffer.Call(state)
		}
	}()
	for {
		var kn *ncryptKeyName
		hr := ncryptStatus(procNCryptEnumKeys.Call(
			provider, 0,
			uintptr(unsafe.Pointer(&kn)),
			uintptr(unsafe.Pointer(&state)),
			uintptr(ncryptMachineKeyFlag|ncryptSilentFlag),
		))
		if hr == nteNoMoreItems {
			return out
		}
		if hr != 0 {
			t.Fatalf("NCryptEnumKeys: hr=0x%x", hr)
		}
		out[syscall.UTF16ToString(unsafe.Slice(kn.name, probeUTF16Len(kn.name)))] = true
		procNCryptFreeBuffer.Call(uintptr(unsafe.Pointer(kn)))
	}
}

func probeUTF16Len(p *uint16) int {
	n := 0
	for ptr := unsafe.Pointer(p); *(*uint16)(ptr) != 0; n++ {
		ptr = unsafe.Add(ptr, 2)
	}
	return n
}

// probeOpenStatus runs NCryptOpenKey on the exact name and releases the handle.
func probeOpenStatus(t *testing.T, name string) uint32 {
	t.Helper()
	provider, err := openProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer procNCryptFreeObject.Call(provider)
	nameUTF16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	var key uintptr
	hr := ncryptStatus(procNCryptOpenKey.Call(provider, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(nameUTF16)), 0, uintptr(openKeyFlags)))
	if hr == 0 {
		procNCryptFreeObject.Call(key)
	}
	return hr
}
