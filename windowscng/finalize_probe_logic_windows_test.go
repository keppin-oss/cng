//go:build windows

package windowscng

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// This file holds the logic of the finalize probe (finalize_probe_windows_test.go,
// tag cng_finalize_probe) that needs no native call: SDDL selection, the
// recording wrapper, the classification against the EXPECTED outcome and the
// check of the declared context. It is part of the default test suite and is
// tested with the simulated backend of finalize_cleanup_windows_test.go.

// probeSDDLFor returns the SDDL selected by label.
func probeSDDLFor(label string) (string, error) {
	switch {
	case label == "legacy":
		return keySecuritySDDL, nil
	case label == "privileged-only":
		return privilegedOnlySDDL, nil
	case strings.HasPrefix(label, "service:"):
		p, err := NewServicePolicy(strings.TrimPrefix(label, "service:"))
		if err != nil {
			return "", err
		}
		return p.sddl(), nil
	}
	return "", fmt.Errorf("unknown SDDL %q", label)
}

// probeStep is one native operation of the run phase, in call order.
type probeStep struct {
	Op     string `json:"op"`
	Status string `json:"status,omitempty"` // 32-bit status as 0x..., or the Go error
}

// probeExpectedDiffs lists every way the run differs from the EXPECTED
// outcome; an empty list means EXPECTED.
func probeExpectedDiffs(ops *recordingCreateOps, err error) []string {
	var d []string
	wantSeq := []string{"create", "export", "sd", "finalize", "delete", "free", "privileged"}
	var got []string
	for _, s := range ops.steps {
		got = append(got, s.Op)
	}
	if strings.Join(got, ",") != strings.Join(wantSeq, ",") {
		d = append(d, fmt.Sprintf("steps %v, want %v", got, wantSeq))
	}
	if ops.finalizeHR != NTEPerm {
		d = append(d, fmt.Sprintf("finalize hr=0x%x, want NTE_PERM", ops.finalizeHR))
	}
	if ops.deleteHR != NTEBadKeyset {
		d = append(d, fmt.Sprintf("delete hr=0x%x, want NTE_BAD_KEYSET", ops.deleteHR))
	}
	if ops.frees != 1 {
		d = append(d, fmt.Sprintf("%d frees of the key handle, want 1", ops.frees))
	}
	if ops.privChecks != 1 || ops.privileged || ops.privErr != nil {
		d = append(d, fmt.Sprintf("privilege checks=%d privileged=%v err=%v, want one non-privileged check", ops.privChecks, ops.privileged, ops.privErr))
	}
	if errors.Is(err, ErrCleanupFailed) {
		d = append(d, "error wraps ErrCleanupFailed")
	}
	var ne *NCryptError
	if !errors.As(err, &ne) || ne.Op != "NCryptFinalizeKey" || ne.Code != NTEPerm {
		d = append(d, fmt.Sprintf("first NCryptError = %+v, want NCryptFinalizeKey NTE_PERM", ne))
	}
	if err == nil || !strings.Contains(err.Error(), "was not persisted") {
		d = append(d, "error does not carry the not-persisted note")
	}
	return d
}

// recordingCreateOps records every native operation of a production create,
// in call order, with its status. The key handle is freed through a single
// NCryptFreeObject whose status is recorded: there is never a second free.
type recordingCreateOps struct {
	createKeyNative
	steps                []probeStep
	finalizeHR, deleteHR uint32
	frees                int
	privChecks           int
	privileged           bool
	privErr              error
	// freeStatus frees the key handle once and returns the 32-bit status of
	// that call. The probe passes the native NCryptFreeObject; tests pass a
	// function that frees the simulated handle.
	freeStatus func(h uintptr) uint32
}

func (r *recordingCreateOps) add(op, status string) {
	r.steps = append(r.steps, probeStep{Op: op, Status: status})
}

func (r *recordingCreateOps) reached(op string) bool {
	for _, s := range r.steps {
		if s.Op == op {
			return true
		}
	}
	return false
}

func (r *recordingCreateOps) createPersisted(p uintptr, n *uint16) (uintptr, uint32) {
	h, hr := r.createKeyNative.createPersisted(p, n)
	r.add("create", hex32(hr))
	return h, hr
}

func (r *recordingCreateOps) setExportPolicyNone(h uintptr) uint32 {
	hr := r.createKeyNative.setExportPolicyNone(h)
	r.add("export", hex32(hr))
	return hr
}

func (r *recordingCreateOps) setSecurityDescriptor(h uintptr, sddl string) error {
	err := r.createKeyNative.setSecurityDescriptor(h, sddl)
	r.add("sd", errString(err))
	return err
}

func (r *recordingCreateOps) finalize(h uintptr) uint32 {
	r.finalizeHR = r.createKeyNative.finalize(h)
	r.add("finalize", hex32(r.finalizeHR))
	return r.finalizeHR
}

func (r *recordingCreateOps) deleteKey(h uintptr) uint32 {
	r.deleteHR = r.createKeyNative.deleteKey(h)
	r.add("delete", hex32(r.deleteHR))
	return r.deleteHR
}

func (r *recordingCreateOps) free(h uintptr) {
	r.frees++
	r.add("free", hex32(r.freeStatus(h)))
}

func (r *recordingCreateOps) callerPrivileged() (bool, error) {
	r.privChecks++
	r.privileged, r.privErr = r.createKeyNative.callerPrivileged()
	r.add("privileged", fmt.Sprintf("privileged=%v err=%v", r.privileged, r.privErr))
	return r.privileged, r.privErr
}

func hex32(v uint32) string { return fmt.Sprintf("0x%x", v) }

func errString(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// probeToken describes the token of the process.
type probeToken struct {
	User           string   `json:"user"`
	ElevationType  string   `json:"elevation_type"`
	Integrity      string   `json:"integrity"`
	Privileged     bool     `json:"privileged"`
	PrivilegeError string   `json:"privilege_error,omitempty"`
	Administrators string   `json:"administrators"` // absent, enabled or deny-only
	ServiceSIDs    []string `json:"service_sids,omitempty"`
}

const (
	sidLocalServiceAccount = "S-1-5-19"
	seGroupEnabled         = 0x00000004
	seGroupUseForDenyOnly  = 0x00000010
)

// mismatch returns why the token does not match the declared context, or "".
func (tok probeToken) mismatch(context string) string {
	if tok.Privileged {
		return "the run phase needs a non-privileged caller; this token is privileged"
	}
	switch context {
	case "filtered-admin":
		if tok.Administrators != "deny-only" || tok.User == sidLocalServiceAccount {
			return fmt.Sprintf("filtered-admin needs an Administrators group that is deny-only; got %q (user %s)", tok.Administrators, tok.User)
		}
	case "standard-user":
		if tok.Administrators != "absent" || tok.User == sidLocalServiceAccount || strings.HasPrefix(tok.User, "S-1-5-18") || strings.HasPrefix(tok.User, "S-1-5-20") {
			return fmt.Sprintf("standard-user needs a user account without Administrators; got %q (user %s)", tok.Administrators, tok.User)
		}
	case "local-service":
		if tok.User != sidLocalServiceAccount {
			return fmt.Sprintf("local-service needs user %s; got %s", sidLocalServiceAccount, tok.User)
		}
	default:
		return "-probe.context must be filtered-admin, standard-user or local-service"
	}
	return ""
}

// runRecorded drives the production create path through the recording
// wrapper over the simulated backend, as the probe does over the native one.
func runRecorded(t *testing.T, f *fakeCreateOps) (*recordingCreateOps, error) {
	t.Helper()
	ops := &recordingCreateOps{createKeyNative: f, freeStatus: func(h uintptr) uint32 { f.free(h); return 0 }}
	name := []uint16{'k', 0}
	_, err := createPersistedKeyWith(ops, fakeCreateProviderHandle, &name[0], keySecuritySDDL)
	return ops, err
}

func TestFinalizeProbeClassification(t *testing.T) {
	t.Run("expected combination", func(t *testing.T) {
		f := &fakeCreateOps{t: t, finalizeStatus: NTEPerm, deleteStatus: NTEBadKeyset}
		ops, err := runRecorded(t, f)
		if d := probeExpectedDiffs(ops, err); len(d) != 0 {
			t.Fatalf("diffs = %v, want EXPECTED", d)
		}
		if ops.frees != 1 || f.frees != 1 || f.live {
			t.Fatalf("frees recorded=%d simulated=%d live=%v, want the handle freed once", ops.frees, f.frees, f.live)
		}
		if last := ops.steps[len(ops.steps)-1]; last.Op != "privileged" || !strings.Contains(last.Status, "privileged=false") {
			t.Fatalf("last step = %+v, want the non-privileged check", last)
		}
	})
	for _, tc := range []struct {
		name string
		f    fakeCreateOps
		want string // substring of one diff
	}{
		{"privileged caller", fakeCreateOps{finalizeStatus: NTEPerm, deleteStatus: NTEBadKeyset, privileged: true}, "error wraps ErrCleanupFailed"},
		{"privilege check fails", fakeCreateOps{finalizeStatus: NTEPerm, deleteStatus: NTEBadKeyset, privErr: errors.New("CheckTokenMembership failed")}, "want one non-privileged check"},
		{"other finalize status", fakeCreateOps{finalizeStatus: nteBadFlags, deleteStatus: NTEBadKeyset}, "finalize hr=0x80090009"},
		{"delete denied", fakeCreateOps{finalizeStatus: NTEPerm, deleteStatus: NTEPerm}, "delete hr=0x80090010"},
		{"delete succeeds", fakeCreateOps{finalizeStatus: NTEPerm}, "steps"},
	} {
		t.Run(tc.name+" is DIFFERENT", func(t *testing.T) {
			f := tc.f
			f.t = t
			ops, err := runRecorded(t, &f)
			if !ops.reached("finalize") {
				t.Fatal("finalize not reached")
			}
			d := probeExpectedDiffs(ops, err)
			if !strings.Contains(strings.Join(d, "; "), tc.want) {
				t.Fatalf("diffs = %v, want one containing %q", d, tc.want)
			}
		})
	}
	t.Run("failure before finalize is NOT_EXERCISED", func(t *testing.T) {
		for _, f := range []*fakeCreateOps{
			{t: t, createStatus: NTEPerm},
			{t: t, exportStatus: NTEPerm},
			{t: t, sdErr: errors.New("before finalize: set security descriptor: hr=0x80090010")},
		} {
			ops, err := runRecorded(t, f)
			if err == nil || ops.reached("finalize") {
				t.Fatalf("steps %+v err %v: want a failure before finalize", ops.steps, err)
			}
		}
	})
	t.Run("finalize success is reported, not classified as EXPECTED", func(t *testing.T) {
		f := &fakeCreateOps{t: t}
		ops, err := runRecorded(t, f)
		if err != nil || !ops.reached("finalize") || ops.finalizeHR != 0 {
			t.Fatalf("err=%v steps=%+v", err, ops.steps)
		}
		if d := probeExpectedDiffs(ops, err); len(d) == 0 {
			t.Fatal("a successful finalize must not classify as EXPECTED")
		}
	})
}

func TestFinalizeProbeContextCheck(t *testing.T) {
	filtered := probeToken{User: "S-1-5-21-1-2-3-1001", Administrators: "deny-only"}
	standard := probeToken{User: "S-1-5-21-1-2-3-1002", Administrators: "absent"}
	localService := probeToken{User: sidLocalServiceAccount, Administrators: "absent"}
	elevated := probeToken{User: "S-1-5-21-1-2-3-1001", Administrators: "enabled", Privileged: true}
	for _, tc := range []struct {
		tok     probeToken
		context string
		ok      bool
	}{
		{filtered, "filtered-admin", true},
		{standard, "standard-user", true},
		{localService, "local-service", true},
		{filtered, "standard-user", false},
		{standard, "filtered-admin", false},
		{standard, "local-service", false},
		{localService, "standard-user", false},
		{elevated, "filtered-admin", false},
		{filtered, "", false},
	} {
		why := tc.tok.mismatch(tc.context)
		if (why == "") != tc.ok {
			t.Errorf("mismatch(%+v, %q) = %q, want ok=%v", tc.tok, tc.context, why, tc.ok)
		}
	}
}

func TestFinalizeProbeSDDL(t *testing.T) {
	if s, err := probeSDDLFor("legacy"); err != nil || s != keySecuritySDDL {
		t.Fatalf("legacy = %q, %v", s, err)
	}
	if s, err := probeSDDLFor("privileged-only"); err != nil || s != privilegedOnlySDDL {
		t.Fatalf("privileged-only = %q, %v", s, err)
	}
	p, err := NewServicePolicy("KeppinProbeSvc")
	if err != nil {
		t.Fatal(err)
	}
	if s, err := probeSDDLFor("service:KeppinProbeSvc"); err != nil || s != p.sddl() || !strings.Contains(s, p.SID()) {
		t.Fatalf("service = %q, %v", s, err)
	}
	for _, bad := range []string{"", "other", "service:"} {
		if _, err := probeSDDLFor(bad); err == nil {
			t.Errorf("probeSDDLFor(%q) accepted", bad)
		}
	}
}
