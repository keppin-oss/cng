package windowscng

import (
	"go/ast"
	"go/parser"
	"go/token"
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

// nativeReturn classifies what a native procedure returns, which decides how
// its Proc.Call results may be used.
type nativeReturn int

const (
	// returnNCryptStatus is a 32-bit SECURITY_STATUS: the call must be passed
	// directly to ncryptStatus or ncryptStatusAndCallErr.
	returnNCryptStatus nativeReturn = iota
	// returnNCryptStatusOrCleanup is a SECURITY_STATUS that may also be
	// discarded: the call goes through ncryptStatus, or is a plain or
	// deferred statement whose results are not used at all.
	returnNCryptStatusOrCleanup
	// returnBOOL is a 32-bit Win32 BOOL: the call must be passed directly to
	// win32BOOL or win32BOOLAndCallErr.
	returnBOOL
	// returnIgnored is a result this package never uses: the call must be a
	// plain or deferred statement.
	returnIgnored
	// returnFullWidth is a handle or pointer that uses the whole register.
	returnFullWidth
	// returnLength32Raw is a 32-bit length (UINT or DWORD) handed raw to a
	// loop that normalizes it; see lengthSeams.
	returnLength32Raw
)

// nativeProcReturns classifies every native procedure of the package by the
// type its native function returns. A procedure that is declared but missing
// here, or listed here but not declared, fails the test: a new native call
// must be classified before it can be used.
var nativeProcReturns = map[string]nativeReturn{
	"procNCryptOpenStorageProvider": returnNCryptStatus,
	"procNCryptOpenKey":             returnNCryptStatus,
	"procNCryptCreatePersistedKey":  returnNCryptStatus,
	"procNCryptSetProperty":         returnNCryptStatus,
	"procNCryptGetProperty":         returnNCryptStatus,
	"procNCryptFinalizeKey":         returnNCryptStatus,
	"procNCryptExportKey":           returnNCryptStatus,
	"procNCryptSignHash":            returnNCryptStatus,
	"procNCryptDeleteKey":           returnNCryptStatus,
	"procNCryptFreeObject":          returnNCryptStatusOrCleanup,

	"procConvertStringSecurityDescriptorToSecurityDescriptorW": returnBOOL,
	"procGetSecurityDescriptorDacl":                            returnBOOL,
	"procGetAclInformation":                                    returnBOOL,
	"procGetAce":                                               returnBOOL,
	"procEqualSid":                                             returnBOOL,
	"procConvertStringSidToSidW":                               returnBOOL,
	"procCheckTokenMembership":                                 returnBOOL,

	"procLocalFree":   returnIgnored,
	"procFreeLibrary": returnIgnored,

	"procLoadLibraryExW": returnFullWidth,

	"procGetModuleFileNameW":  returnLength32Raw,
	"procGetSystemDirectoryW": returnLength32Raw,
}

var (
	ncryptStatusWrappers = map[string]bool{"ncryptStatus": true, "ncryptStatusAndCallErr": true}
	win32BOOLWrappers    = map[string]bool{"win32BOOL": true, "win32BOOLAndCallErr": true}
)

// TestNativeReturnsUsedByType parses every non-test source file of the package
// and checks each use of a native procedure against nativeProcReturns, so that
// a 32-bit status or BOOL is never compared or formatted as a raw uintptr.
// Working on the syntax tree, it also catches method values (proc.Call without
// a call), direct field access (proc.proc.Call) and calls split across lines,
// and it ignores comments.
func TestNativeReturnsUsedByType(t *testing.T) {
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no source files parsed; the test is not running in the package directory")
	}

	declared := declaredNativeProcs(files)
	for name := range declared {
		if _, ok := nativeProcReturns[name]; !ok {
			t.Errorf("%s: native procedure %s is not classified in nativeProcReturns", fset.Position(declared[name]), name)
		}
	}
	for name := range nativeProcReturns {
		if _, ok := declared[name]; !ok {
			t.Errorf("nativeProcReturns lists %s, which is not declared", name)
		}
	}

	uses := 0
	for _, f := range files {
		var stack []ast.Node
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			if id, ok := n.(*ast.Ident); ok {
				if kind, ok := nativeProcReturns[id.Name]; ok && declared[id.Name] != id.Pos() {
					uses++
					if why := checkNativeUse(id, kind, stack); why != "" {
						t.Errorf("%s: %s %s", fset.Position(id.Pos()), id.Name, why)
					}
				}
			}
			stack = append(stack, n)
			return true
		})
	}
	if uses == 0 {
		t.Fatal("no use of a native procedure found")
	}
}

// declaredNativeProcs returns the package-level variables initialized with a
// NewProc call, with the position of their declaring identifier.
func declaredNativeProcs(files []*ast.File) map[string]token.Pos {
	out := map[string]token.Pos{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, v := range vs.Values {
					call, ok := v.(*ast.CallExpr)
					if !ok {
						continue
					}
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "NewProc" && i < len(vs.Names) {
						out[vs.Names[i].Name] = vs.Names[i].Pos()
					}
				}
			}
		}
	}
	return out
}

// checkNativeUse returns why the use id of a procedure of the given kind is
// not allowed, or "" if it is. stack holds the ancestors of id, innermost last.
func checkNativeUse(id *ast.Ident, kind nativeReturn, stack []ast.Node) string {
	parent := func(i int) ast.Node {
		if i <= len(stack) {
			return stack[len(stack)-i]
		}
		return nil
	}
	if kind == returnFullWidth {
		return ""
	}
	sel, ok := parent(1).(*ast.SelectorExpr)
	if !ok || sel.X != id || sel.Sel.Name != "Call" {
		return "is used other than as proc.Call(...)"
	}
	call, ok := parent(2).(*ast.CallExpr)
	if !ok || call.Fun != sel {
		return "has its Call used as a value instead of called"
	}
	wrapped := func(wrappers map[string]bool) bool {
		outer, ok := parent(3).(*ast.CallExpr)
		if !ok || len(outer.Args) != 1 || outer.Args[0] != call {
			return false
		}
		fn, ok := outer.Fun.(*ast.Ident)
		return ok && wrappers[fn.Name]
	}
	discarded := func() bool {
		switch s := parent(3).(type) {
		case *ast.ExprStmt:
			return s.X == call
		case *ast.DeferStmt:
			return s.Call == call
		}
		return false
	}
	switch kind {
	case returnNCryptStatus:
		if !wrapped(ncryptStatusWrappers) {
			return "result is not read through ncryptStatus or ncryptStatusAndCallErr"
		}
	case returnNCryptStatusOrCleanup:
		if !wrapped(ncryptStatusWrappers) && !discarded() {
			return "result is used without ncryptStatus"
		}
	case returnBOOL:
		if !wrapped(win32BOOLWrappers) {
			return "result is not read through win32BOOL or win32BOOLAndCallErr"
		}
	case returnIgnored:
		if !discarded() {
			return "result must not be used"
		}
	case returnLength32Raw:
		// The raw register goes only from the native seam to the loop that
		// normalizes it: the call must be the value of an assignment inside
		// the seam named in lengthSeams.
		if _, ok := parent(3).(*ast.AssignStmt); !ok {
			return "result is not assigned in its native seam"
		}
		seam := ""
		for i := len(stack) - 1; i >= 0; i-- {
			if fd, ok := stack[i].(*ast.FuncDecl); ok {
				seam = fd.Name.Name
				break
			}
		}
		if seam != lengthSeams[id.Name] {
			return "is called outside its native seam " + lengthSeams[id.Name] + ", whose callers normalize the length to uint32"
		}
	}
	return ""
}

// lengthSeams names, for each procedure returning a 32-bit length, the only
// function that may call it. That function hands the raw register to a loop
// (systemDirectoryWith, moduleFileNameWith) that reads it as uint32 and whose
// tests inject dirty upper bits.
var lengthSeams = map[string]string{
	"procGetSystemDirectoryW": "nativeGetSystemDirectory",
	"procGetModuleFileNameW":  "nativeGetModuleFileName",
}
