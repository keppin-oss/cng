package windowscng

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// staleLastErrorFormat matches an NCrypt status format followed by a second
// verb, as in "hr=0x%x %v". With Proc.Call that second value is the thread's
// last error, which NCrypt does not set: it prints ERROR_SUCCESS or an
// unrelated stale error after the real status.
var staleLastErrorFormat = regexp.MustCompile(`hr=0x%x\s*%[vsdqx]`)

// TestNoLastErrorAfterNCryptStatus guards the NCrypt call sites that have no
// test seam: no non-test source file of this package may format a status as
// "hr=0x%x" followed by another value. Use ncryptStatusError instead.
func TestNoLastErrorAfterNCryptStatus(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for i, line := range strings.Split(string(src), "\n") {
			if staleLastErrorFormat.MatchString(line) {
				t.Errorf("%s:%d formats a last error after an NCrypt status: %s", name, i+1, strings.TrimSpace(line))
			}
		}
	}
	if checked == 0 {
		t.Fatal("no source files checked; the test is not running in the package directory")
	}
}
