package aws

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every AWS call this provider can make is a read, and that is a property the
// retry policy depends on.
//
// NewWithProfile sets WithRetryMaxAttempts(5) for the whole client, uniformly.
// A blanket retry is safe over reads and unsafe over mutations: retrying a
// non-idempotent write is how one logical operation becomes two real ones, and
// the failure being retried through is often the one that already half-succeeded.
// The policy is not keyed on the call because nothing here needs it to be —
// which is only true while nothing here mutates.
//
// Stating that in a comment would leave it true until the first `DeleteBucket`.
// This makes it a build failure instead: a mutating method added to any narrow
// SDK interface fails here, and whoever adds it has to decide the retry question
// rather than inherit an answer chosen for a different kind of call.
//
// The check runs over the AST, so a method named only in a comment is not a
// method and a method commented out is not present.

// readVerbs are the prefixes that name a read in the AWS SDK's vocabulary.
var readVerbs = []string{"Describe", "Get", "List", "Head", "Lookup", "Query", "Scan", "Batch Get"}

// readOnlyExempt names methods that do not start with a read verb and are still
// reads, each with the reason. An entry naming a method no interface declares
// fails below: an exemption applying to nothing has stopped applying.
var readOnlyExempt = map[string]string{}

func isReadMethod(name string) bool {
	for _, verb := range readVerbs {
		if strings.HasPrefix(name, strings.ReplaceAll(verb, " ", "")) {
			return true
		}
	}
	return false
}

func TestEveryDeclaredAWSCallIsARead(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	declared := map[string]string{} // method -> interface it is declared on
	interfaces := 0

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			iface, ok := spec.Type.(*ast.InterfaceType)
			if !ok {
				return true
			}
			interfaces++
			for _, method := range iface.Methods.List {
				for _, ident := range method.Names {
					declared[ident.Name] = spec.Name.Name
				}
			}
			return true
		})
	}

	if interfaces == 0 {
		t.Fatal("no interfaces found in the AWS provider package; this check would pass vacuously")
	}
	if len(declared) == 0 {
		t.Fatal("no interface methods found; this check would pass vacuously")
	}
	t.Logf("examined %d method(s) across %d narrow SDK interface(s)", len(declared), interfaces)

	for method, iface := range declared {
		if isReadMethod(method) {
			continue
		}
		if reason, ok := readOnlyExempt[method]; ok {
			t.Logf("%s.%s is exempt: %s", iface, method, reason)
			continue
		}
		t.Errorf("%s.%s does not name a read. cloudgov is read-only against cloud APIs and retries "+
			"every call uniformly (internal/cloud/aws/aws.go, WithRetryMaxAttempts). A mutating call "+
			"inherits that retry, so it needs its own policy — or, if this is a read the verb list does "+
			"not recognise, an entry in readOnlyExempt with the reason", iface, method)
	}

	for method, reason := range readOnlyExempt {
		if _, ok := declared[method]; !ok {
			t.Errorf("readOnlyExempt names %q, which no interface declares; the exemption applies to "+
				"nothing (reason on file: %s)", method, reason)
		}
	}
}

// A negative result is worth nothing until the looking is shown to work.
//
// TestEveryDeclaredAWSCallIsARead reports an absence — no mutating call in the
// package — and an absence is exactly what a broken walk also reports. So the
// walk is driven over a synthetic package containing a mutating method and
// required to find it. Without this, a parser that silently stopped recognising
// interface declarations would report the same clean sweep as a clean tree.
func TestInterfaceWalkFindsAMutatingMethod(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "probe.go", `package probe

// DeleteBucket is named in this comment and must not be found by a walk that
// reads comments as declarations.
type readerAPI interface {
	DescribeInstances(ctx context.Context) error
}

type writerAPI interface {
	DeleteBucket(ctx context.Context) error
}
`, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse probe: %v", err)
	}

	declared := map[string]string{}
	interfaces := 0
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		iface, ok := spec.Type.(*ast.InterfaceType)
		if !ok {
			return true
		}
		interfaces++
		for _, method := range iface.Methods.List {
			for _, ident := range method.Names {
				declared[ident.Name] = spec.Name.Name
			}
		}
		return true
	})

	if interfaces != 2 {
		t.Fatalf("walk found %d interfaces, want 2", interfaces)
	}
	if _, ok := declared["DeleteBucket"]; !ok {
		t.Fatal("the walk did not find a mutating method that is plainly declared; " +
			"a clean sweep from this walk would mean nothing")
	}
	if isReadMethod("DeleteBucket") {
		t.Fatal("the verb detector accepted DeleteBucket as a read")
	}
	if _, ok := declared["DescribeInstances"]; !ok {
		t.Error("the walk did not find the read method either; it is finding nothing at all")
	}
	if len(declared) != 2 {
		t.Errorf("walk found %d methods, want 2 — a name appearing only in a comment was counted", len(declared))
	}
}

// The detector has to be able to say no, or the check above passes whatever the
// package declares.
func TestIsReadMethodRejectsMutations(t *testing.T) {
	for _, name := range []string{"DescribeInstances", "GetBucketTagging", "ListRoles", "HeadBucket", "LookupEvents"} {
		if !isReadMethod(name) {
			t.Errorf("isReadMethod(%q) = false, want true", name)
		}
	}
	for _, name := range []string{
		"DeleteBucket", "PutBucketPolicy", "CreateRole", "UpdateFunctionCode",
		"ModifyInstanceAttribute", "TerminateInstances", "AttachRolePolicy",
		"TagResource", "UntagResource", "SetQueueAttributes",
	} {
		if isReadMethod(name) {
			t.Errorf("isReadMethod(%q) = true; a mutating call would inherit the blanket retry unchecked", name)
		}
	}
}
