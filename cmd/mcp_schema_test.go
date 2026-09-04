package cmd

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// publishedTools returns the tools this server publishes, as a client receives
// them.
//
// The schema an agent reads is produced by the SDK from struct tags, so reading
// the tags back is reading the input to the thing under test. This runs the real
// server over the SDK's in-memory transport and lists its tools, so what is
// asserted is the JSON that crosses the wire.
func publishedTools(t *testing.T) []*mcp.Tool {
	t.Helper()
	ctx := context.Background()

	server := mcp.NewServer(&mcp.Implementation{Name: "cloudgov", Version: Version}, nil)
	registerMCPTools(server)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })

	result, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(result.Tools) == 0 {
		t.Fatal("the server published no tools; the listing is broken, not the schemas")
	}
	return result.Tools
}

// severityProperty returns the `severity` property of a tool's input schema and
// whether the tool has one.
func severityProperty(t *testing.T, tool *mcp.Tool) (map[string]any, bool) {
	t.Helper()
	raw, err := json.Marshal(tool.InputSchema)
	if err != nil {
		t.Fatalf("%s: marshal input schema: %v", tool.Name, err)
	}
	var schema struct {
		Properties map[string]map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("%s: input schema is not a JSON object: %v", tool.Name, err)
	}
	property, ok := schema.Properties["severity"]
	return property, ok
}

// Over MCP a tool call carries no flags a person typed and no exit code. A
// severity argument left out is filtered at resolveMCPSeverity's default, so an
// agent that does not know the default cannot tell a quiet account from one whose
// findings were all below the cut.
//
// The default is stated in one place an agent can read: the `severity` property's
// description in the tool's published input schema. Every tool that accepts the
// argument must state it, and the population is the tools the server publishes
// rather than the structs the source declares — several tools share an input
// struct, so counting structs counts something an agent never sees.
func TestEveryToolTakingSeverityPublishesItsDefault(t *testing.T) {
	tools := publishedTools(t)

	// The word the schema has to carry is the value the resolver actually
	// applies, so renaming the default breaks the assertion rather than leaving
	// it describing a value the code stopped using.
	applied, err := resolveMCPSeverity("")
	if err != nil {
		t.Fatalf("resolve an omitted severity: %v", err)
	}
	if applied != cloud.SeverityLow {
		t.Fatalf("an omitted severity resolves to %s; this test states LOW", applied)
	}
	want := "default " + string(applied)

	published := map[string]bool{}
	for _, tool := range tools {
		property, ok := severityProperty(t, tool)
		if !ok {
			continue
		}
		published[tool.Name] = true
		description, _ := property["description"].(string)
		if description == "" {
			t.Errorf("tool %s accepts severity and publishes no description for it, so the "+
				"%s default reaches an agent nowhere", tool.Name, applied)
			continue
		}
		if !strings.Contains(strings.ToLower(description), strings.ToLower(want)) {
			t.Errorf("tool %s describes severity as %q, which does not state %q; an agent "+
				"omitting the argument cannot tell what it was filtered at",
				tool.Name, description, want)
		}
	}

	// The denominator, by name rather than by count. Which tools take the
	// argument is a fact about the source, so it is read from there; whether each
	// published schema states the default is not, which is why the loop above
	// reads the listing. A floor would be a single total over a population this
	// walk partitions by tool, and one tool carrying the rest would meet it.
	declared := toolsDeclaringSeverity(t)
	for name := range declared {
		if !published[name] {
			t.Errorf("mcp.go registers %s with an input struct declaring Severity, and the "+
				"published listing has no severity property for it — the argument reaches an "+
				"agent through nothing this check saw", name)
		}
	}
	for name := range published {
		if !declared[name] {
			t.Errorf("the published listing offers severity on %s, which mcp.go's registrations "+
				"do not account for; the denominator has drifted from the server", name)
		}
	}
	if len(declared) == 0 {
		t.Fatal("no registration binds an input struct declaring Severity; the denominator is " +
			"broken, not the server")
	}
}

// toolsDeclaringSeverity names the tools whose registered input struct declares a
// Severity field, read from mcp.go.
//
// Several tools share one input struct, so the structs are not the population: an
// agent sees tools. This pairs each registration with the struct it binds and
// reports the tool names, which is the shape the published listing is compared
// against.
func toolsDeclaringSeverity(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "mcp.go", nil, 0)
	if err != nil {
		t.Fatalf("parse mcp.go: %v", err)
	}

	takesSeverity := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		structType, isStruct := spec.Type.(*ast.StructType)
		if !isStruct || structType.Fields == nil {
			return true
		}
		for _, field := range structType.Fields.List {
			for _, name := range field.Names {
				if name.Name == "Severity" {
					takesSeverity[spec.Name.Name] = true
				}
			}
		}
		return true
	})
	if len(takesSeverity) == 0 {
		t.Fatal("mcp.go declares no input struct with a Severity field; the scan is broken, not the file")
	}

	out := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel || sel.Sel == nil || sel.Sel.Name != "AddTool" {
			return true
		}
		if pkg, isIdent := sel.X.(*ast.Ident); !isIdent || pkg.Name != "mcp" {
			return true
		}
		if len(call.Args) < 3 {
			t.Errorf("an mcp.AddTool call has %d arguments; this check cannot read it", len(call.Args))
			return true
		}
		name := toolNameFromArg(call.Args[1])
		if name == "" {
			t.Error("an mcp.AddTool call declares no literal tool name; this check cannot pair it with an input struct")
			return true
		}
		handler, isFunc := call.Args[2].(*ast.FuncLit)
		if !isFunc || handler.Type.Params == nil || len(handler.Type.Params.List) == 0 {
			t.Errorf("the handler for %s takes no readable parameter list; this check cannot find its input struct", name)
			return true
		}
		params := handler.Type.Params.List
		input, isIdent := params[len(params)-1].Type.(*ast.Ident)
		if !isIdent {
			t.Errorf("the handler for %s takes an input this check cannot name", name)
			return true
		}
		if takesSeverity[input.Name] {
			out[name] = true
		}
		return true
	})
	return out
}
