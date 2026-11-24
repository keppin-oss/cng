package windowscng

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
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
	// directly to ncryptStatus.
	returnNCryptStatus nativeReturn = iota
	// returnNCryptStatusOrCleanup is a SECURITY_STATUS that may also be
	// discarded: the call goes through ncryptStatus, or is a plain or
	// deferred statement whose results are not used at all.
	returnNCryptStatusOrCleanup
	// returnBOOL is a 32-bit Win32 BOOL: the call must be passed directly to
	// win32BOOLAndCallErr.
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
	"procConvertStringSidToSidW":                               returnBOOL,
	"procCheckTokenMembership":                                 returnBOOL,

	"procLocalFree":   returnIgnored,
	"procFreeLibrary": returnIgnored,

	"procLoadLibraryExW": returnFullWidth,

	"procGetModuleFileNameW":  returnLength32Raw,
	"procGetSystemDirectoryW": returnLength32Raw,
}

var (
	ncryptStatusWrappers = map[string]bool{"ncryptStatus": true}
	win32BOOLWrappers    = map[string]bool{"win32BOOLAndCallErr": true}
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
			return "result is not read through ncryptStatus"
		}
	case returnNCryptStatusOrCleanup:
		if !wrapped(ncryptStatusWrappers) && !discarded() {
			return "result is used without ncryptStatus"
		}
	case returnBOOL:
		if !wrapped(win32BOOLWrappers) {
			return "result is not read through win32BOOLAndCallErr"
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

// The tests below check, on the syntax tree, that the native wrappers without a
// test seam pass the intended arguments. They parse the non-test sources and
// never call a native function.

// parseNonTestSources parses every non-test source file of the package.
func parseNonTestSources(t *testing.T) []*ast.File {
	t.Helper()
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
	return files
}

// funcKey names a function declaration as "name" or "Receiver.name".
func funcKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	return types.ExprString(typ) + "." + fd.Name.Name
}

// sourceFuncs returns the function declarations with a body, by funcKey.
func sourceFuncs(files []*ast.File) map[string]*ast.FuncDecl {
	out := map[string]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				out[funcKey(fd)] = fd
			}
		}
	}
	return out
}

// callsIn returns the calls in body whose callee, printed, is callee.
func callsIn(body ast.Node, callee string) []*ast.CallExpr {
	var out []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && types.ExprString(c.Fun) == callee {
			out = append(out, c)
		}
		return true
	})
	return out
}

// isUintptrOf reports whether e is uintptr(arg) with arg printed as want.
func isUintptrOf(e ast.Expr, want string) bool {
	c, ok := e.(*ast.CallExpr)
	return ok && types.ExprString(c.Fun) == "uintptr" && len(c.Args) == 1 && types.ExprString(c.Args[0]) == want
}

// TestNativeOpenAndCreateFlagsSource checks that the key flags reach the native
// calls: ncryptOpenKey forwards its flags parameter as the dwFlags argument of
// NCryptOpenKey, its three callers pass the intended constants (machine scope
// and silent), and NCryptCreatePersistedKey receives the machine key flag. The
// values of the constants are tested elsewhere; this tests their use.
func TestNativeOpenAndCreateFlagsSource(t *testing.T) {
	files := parseNonTestSources(t)
	funcs := sourceFuncs(files)

	open, ok := funcs["ncryptOpenKey"]
	if !ok {
		t.Fatal("ncryptOpenKey not found")
	}
	var params []string
	for _, f := range open.Type.Params.List {
		for _, n := range f.Names {
			params = append(params, n.Name)
		}
	}
	if len(params) != 3 {
		t.Fatalf("ncryptOpenKey has parameters %v, want provider, name, flags", params)
	}
	calls := callsIn(open.Body, "procNCryptOpenKey.Call")
	if len(calls) != 1 || len(calls[0].Args) != 5 {
		t.Fatalf("ncryptOpenKey must make one NCryptOpenKey call with 5 arguments, got %d call(s)", len(calls))
	}
	if !isUintptrOf(calls[0].Args[4], params[2]) {
		t.Errorf("ncryptOpenKey passes %s as the NCryptOpenKey dwFlags argument, want uintptr(%s)",
			types.ExprString(calls[0].Args[4]), params[2])
	}

	want := map[string]string{
		"nativeKeyStore.open": "openKeyFlags",
	}
	got := map[string]string{}
	for key, fd := range funcs {
		for _, c := range callsIn(fd.Body, "ncryptOpenKey") {
			if len(c.Args) != 3 {
				t.Errorf("%s: ncryptOpenKey called with %d arguments", key, len(c.Args))
				continue
			}
			got[key] = types.ExprString(c.Args[2])
		}
	}
	for key, flag := range want {
		if got[key] != flag {
			t.Errorf("%s passes %q to ncryptOpenKey, want %s", key, got[key], flag)
		}
	}
	for key := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("%s calls ncryptOpenKey and is not covered by this test", key)
		}
	}

	total := 0
	for key, fd := range funcs {
		for _, c := range callsIn(fd.Body, "procNCryptCreatePersistedKey.Call") {
			total++
			if len(c.Args) != 6 || !isUintptrOf(c.Args[5], "ncryptMachineKeyFlag") {
				t.Errorf("%s: NCryptCreatePersistedKey must receive uintptr(ncryptMachineKeyFlag) as dwFlags", key)
			}
		}
	}
	if total != 1 {
		t.Errorf("found %d NCryptCreatePersistedKey calls, want 1", total)
	}
}

// TestNativeKeyDelegatesToVerifiersSource checks that the policy adapter of a
// native key delegates to the package verifiers on the key handle, so that
// Apply and the Open functions cannot silently skip them.
func TestNativeKeyDelegatesToVerifiersSource(t *testing.T) {
	funcs := sourceFuncs(parseNonTestSources(t))
	for method, target := range map[string]string{
		"nativeKey.verifyNonExportable": "verifyExportPolicy",
		"nativeKey.publicKey":           "exportPublicKey",
		"nativeKey.securityDescriptor":  "getSecurityDescriptor",
	} {
		fd, ok := funcs[method]
		if !ok {
			t.Errorf("%s not found", method)
			continue
		}
		recv := fd.Recv.List[0].Names[0].Name
		var ret *ast.ReturnStmt
		if len(fd.Body.List) == 1 {
			ret, _ = fd.Body.List[0].(*ast.ReturnStmt)
		}
		var call *ast.CallExpr
		if ret != nil && len(ret.Results) == 1 {
			call, _ = ret.Results[0].(*ast.CallExpr)
		}
		if call == nil || types.ExprString(call.Fun) != target || len(call.Args) != 1 || types.ExprString(call.Args[0]) != recv+".key" {
			t.Errorf("%s must be a single return of %s(%s.key)", method, target, recv)
		}
	}
}

// singleReturnCall returns the call of a function whose whole body is one
// return of one call, and nil otherwise.
func singleReturnCall(fd *ast.FuncDecl) *ast.CallExpr {
	if len(fd.Body.List) != 1 {
		return nil
	}
	ret, _ := fd.Body.List[0].(*ast.ReturnStmt)
	if ret == nil || len(ret.Results) != 1 {
		return nil
	}
	call, _ := ret.Results[0].(*ast.CallExpr)
	return call
}

func exprStrings(es []ast.Expr) []string {
	var out []string
	for _, e := range es {
		out = append(out, types.ExprString(e))
	}
	return out
}

// TestNativeWrappersDelegateSource checks that the production wrappers reach
// the functions that hold the logic with the production inputs, so that the
// real path cannot silently skip or weaken a verification:
//
//	verifyExportPolicy     -> return verifyExportPolicyWith(key, nativeGetProperty)
//	getSecurityDescriptor  -> return getSecurityDescriptorWith(key, nativeGetProperty)
//	loadSystemDLL          -> return loadSystemDLLWith(name, verifyModule)
func TestNativeWrappersDelegateSource(t *testing.T) {
	funcs := sourceFuncs(parseNonTestSources(t))
	get := func(name string) *ast.FuncDecl {
		fd, ok := funcs[name]
		if !ok {
			t.Errorf("%s not found", name)
		}
		return fd
	}
	param := func(fd *ast.FuncDecl, i int) string {
		var names []string
		for _, f := range fd.Type.Params.List {
			for _, n := range f.Names {
				names = append(names, n.Name)
			}
		}
		if i >= len(names) {
			t.Fatalf("%s has %d parameters, want at least %d", fd.Name.Name, len(names), i+1)
		}
		return names[i]
	}

	for _, c := range []struct {
		fn, target, second string
	}{
		{"verifyExportPolicy", "verifyExportPolicyWith", "nativeGetProperty"},
		{"getSecurityDescriptor", "getSecurityDescriptorWith", "nativeGetProperty"},
		{"loadSystemDLL", "loadSystemDLLWith", "verifyModule"},
	} {
		fd := get(c.fn)
		if fd == nil {
			continue
		}
		want := []string{param(fd, 0), c.second}
		call := singleReturnCall(fd)
		if call == nil || types.ExprString(call.Fun) != c.target || strings.Join(exprStrings(call.Args), ",") != strings.Join(want, ",") {
			t.Errorf("%s must be a single return of %s(%s)", c.fn, c.target, strings.Join(want, ", "))
		}
	}

	// nativeGetProperty: both NCryptGetProperty calls take the property name
	// from the property parameter and forward flags as the last argument.
	if fd := get("nativeGetProperty"); fd != nil {
		property, flags := param(fd, 1), param(fd, 4)
		calls := callsIn(fd.Body, "procNCryptGetProperty.Call")
		if len(calls) != 2 {
			t.Fatalf("nativeGetProperty makes %d NCryptGetProperty calls, want 2", len(calls))
		}
		for i, c := range calls {
			if len(c.Args) != 6 {
				t.Errorf("call %d: %d arguments, want 6", i, len(c.Args))
				continue
			}
			if got, want := types.ExprString(c.Args[1]), "uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("+property+")))"; got != want {
				t.Errorf("call %d: property name argument is %s, want %s", i, got, want)
			}
			if !isUintptrOf(c.Args[5], flags) {
				t.Errorf("call %d: last argument is %s, want uintptr(%s)", i, types.ExprString(c.Args[5]), flags)
			}
		}
	}
}
