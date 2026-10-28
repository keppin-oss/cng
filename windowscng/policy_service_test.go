package windowscng

import (
	"errors"
	"strings"
	"testing"
)

// Pure tests of ServicePolicy, ServiceSID and the service-sid DACL form. They
// never touch a persisted CNG key.

// testServiceName is a disposable name; it is not a Keppin production service.
const testServiceName = "Example.Policy.Agent"

func serviceSIDDescriptor(t *testing.T, sid string, mask uint32) []byte {
	return buildDescriptor(t, protectedControl,
		allow(genericAll, sidSYSTEM),
		allow(genericAll, sidAdministrators),
		allow(mask, sid))
}

func mustServicePolicy(t *testing.T, name string) ServicePolicy {
	t.Helper()
	p, err := NewServicePolicy(name)
	if err != nil {
		t.Fatalf("NewServicePolicy(%q): %v", name, err)
	}
	return p
}

// TestServiceSIDKnownVectors checks the derivation against SIDs that Windows
// reported for existing services (LookupAccountName of NT SERVICE\<name>).
func TestServiceSIDKnownVectors(t *testing.T) {
	for name, want := range map[string]string{
		"TrustedInstaller": "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
		"W32Time":          "S-1-5-80-4267341169-2882910712-659946508-2704364837-2204554466",
		"Dnscache":         "S-1-5-80-859482183-879914841-863379149-1145462774-2388618682",
		"EventLog":         "S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122",
	} {
		got, err := ServiceSID(name)
		if err != nil || got != want {
			t.Errorf("ServiceSID(%q) = %q, %v; want %q", name, got, err, want)
		}
		lower, err := ServiceSID(strings.ToLower(name))
		if err != nil || lower != want {
			t.Errorf("ServiceSID is not case-insensitive for %q: %q, %v", name, lower, err)
		}
		if !isServiceSID(got) {
			t.Errorf("derived SID %q is not recognized as a service SID", got)
		}
	}
}

func TestServiceSIDRejectsUnsupportedNames(t *testing.T) {
	for _, name := range []string{"", strings.Repeat("a", maxServiceNameLen+1), "a b", "a/b", `a\b`, "AgentÄ", "x$", "a\x00b", "tab\tname"} {
		if sid, err := ServiceSID(name); err == nil {
			t.Errorf("ServiceSID(%q) accepted: %s", name, sid)
		}
		if _, err := NewServicePolicy(name); err == nil {
			t.Errorf("NewServicePolicy(%q) accepted", name)
		}
	}
	if _, err := ServiceSID(strings.Repeat("a", maxServiceNameLen)); err != nil {
		t.Errorf("maximum-length name rejected: %v", err)
	}
}

func TestNewServicePolicy(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	want, _ := ServiceSID(testServiceName)
	if p.SID() != want || p.ServiceName() != testServiceName {
		t.Fatalf("policy = %+v", p)
	}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.String(), want) {
		t.Fatalf("String() = %q", p.String())
	}
	sddl := p.sddl()
	if sddl != "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;"+want+")" {
		t.Fatalf("sddl = %q", sddl)
	}
	// The server-key DACL grants nothing to LOCAL SERVICE or to all services.
	for _, forbidden := range []string{";LS)", sidLocalService, ";S-1-5-80-0)", ";WD)", ";AU)", ";BU)"} {
		if strings.Contains(sddl, forbidden) {
			t.Fatalf("service SDDL %q contains %q", sddl, forbidden)
		}
	}
	for _, bad := range []ServicePolicy{{}, {name: testServiceName}, {name: testServiceName, sid: sidLocalService}, {name: "Other", sid: want}} {
		if err := bad.validate(); err == nil {
			t.Errorf("invalid policy %+v accepted", bad)
		}
	}
}

func TestIsServiceSID(t *testing.T) {
	good := []string{"S-1-5-80-1-2-3-4-5", "S-1-5-80-4294967295-0-0-0-0", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"}
	for _, s := range good {
		if !isServiceSID(s) {
			t.Errorf("%s rejected", s)
		}
	}
	bad := []string{"S-1-5-80-0", "S-1-5-80", "S-1-5-80-1-2-3-4", "S-1-5-80-1-2-3-4-5-6", "S-1-5-80-01-2-3-4-5",
		"S-1-5-80-4294967296-1-2-3-4", "S-1-5-80-+1-2-3-4-5", "S-1-5-80-1--3-4-5", "S-1-5-19", "S-1-5-32-544", "S-1-5-82-1-2-3-4-5", ""}
	for _, s := range bad {
		if isServiceSID(s) {
			t.Errorf("%s accepted", s)
		}
	}
}

func TestClassifyServiceSIDForms(t *testing.T) {
	p := mustServicePolicy(t, testServiceName)
	for _, mask := range []uint32{genericRead | genericExecute, 0x801200A9} {
		st, sid, err := classifyDescriptorSID(serviceSIDDescriptor(t, p.SID(), mask))
		if err != nil || st != daclServiceSID || sid != p.SID() {
			t.Fatalf("mask 0x%08X: %s %q %v", mask, st, sid, err)
		}
	}
	// Order is not significant.
	st, sid, err := classifyDescriptorSID(buildDescriptor(t, protectedControl,
		allow(genericRead|genericExecute, p.SID()), allow(genericAll, sidAdministrators), allow(genericAll, sidSYSTEM)))
	if err != nil || st != daclServiceSID || sid != p.SID() {
		t.Fatalf("reordered: %s %q %v", st, sid, err)
	}
	// The other recognized states report no service SID.
	if _, sid, _ := classifyDescriptorSID(serviceSignerDescriptor(t, genericRead)); sid != "" {
		t.Fatalf("service-signer reported SID %q", sid)
	}

	sy, ba := allow(genericAll, sidSYSTEM), allow(genericAll, sidAdministrators)
	other := mustServicePolicy(t, "Example.Policy.Other")
	rejects := map[string][]byte{
		"LS and service SID":       buildDescriptor(t, protectedControl, sy, ba, allow(genericRead, sidLocalService), allow(genericRead|genericExecute, p.SID())),
		"two service SIDs":         buildDescriptor(t, protectedControl, sy, ba, allow(genericRead|genericExecute, p.SID()), allow(genericRead|genericExecute, other.SID())),
		"unobserved service GR":    serviceSIDDescriptor(t, p.SID(), genericRead),
		"service SID GENERIC_ALL":  buildDescriptor(t, protectedControl, sy, ba, allow(genericAll, p.SID())),
		"service SID write":        buildDescriptor(t, protectedControl, sy, ba, allow(genericRead|genericWrite, p.SID())),
		"service SID inheritable":  buildDescriptor(t, protectedControl, sy, ba, testACE{aceType: aceTypeAccessAllowed, flags: 0x03, mask: genericRead | genericExecute, sid: p.SID()}),
		"ALL SERVICES":             buildDescriptor(t, protectedControl, sy, ba, allow(genericRead|genericExecute, "S-1-5-80-0")),
		"service SID without BA":   buildDescriptor(t, protectedControl, sy, allow(genericRead|genericExecute, p.SID())),
		"service SID unprotected":  buildDescriptor(t, seSelfRelative|seDACLPresent, sy, ba, allow(genericRead|genericExecute, p.SID())),
		"duplicate service SID":    buildDescriptor(t, protectedControl, sy, ba, allow(genericRead|genericExecute, p.SID()), allow(genericRead|genericExecute, p.SID())),
		"service SID deny ACE":     buildDescriptor(t, protectedControl, sy, ba, testACE{aceType: 1, mask: genericRead | genericExecute, sid: p.SID()}),
		"service SID and everyone": buildDescriptor(t, protectedControl, sy, ba, allow(genericRead|genericExecute, p.SID()), allow(genericRead, sidEveryone)),
	}
	for name, sd := range rejects {
		st, sid, err := classifyDescriptorSID(sd)
		if err == nil || st != daclUnknown || sid != "" || !errors.Is(err, errDescriptorUnrecognized) {
			t.Errorf("%s: classified as %s %q (%v)", name, st, sid, err)
		}
	}
}
