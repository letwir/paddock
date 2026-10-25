package steward

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

type generatorFunc func(context.Context, Request) ([]byte, error)

func (f generatorFunc) Generate(ctx context.Context, request Request) ([]byte, error) {
	return f(ctx, request)
}

func TestProposeAllowsDistinctNestedJSONMembers(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(`{"outer":{"first":1,"second":{"third":2}}}`))
	root, err := decoder.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err := scanJSONValue(decoder, root); err != nil {
		t.Fatalf("distinct nested members rejected: %v", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		t.Fatalf("scanner did not consume exactly one value: %v", err)
	}
}

func TestProposeValidDecomposedDAG(t *testing.T) {
	p := NewProposer(generatorFunc(func(_ context.Context, got Request) ([]byte, error) {
		if got.Objective != "build widget" || got.Context != "existing repo" {
			t.Fatalf("request = %#v", got)
		}
		return []byte(`{"tasks":[{"key":"outline","title":"Outline","goal":"Plan the work","acceptance":"Plan exists","depends_on":[]},{"key":"build","title":"Build","goal":"Implement it","acceptance":"Tests pass","depends_on":["outline"]}]}`), nil
	}))
	got, err := p.Propose(context.Background(), Request{Objective: "build widget", Context: "existing repo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tasks) != 2 || got.Tasks[1].DependsOn[0] != "outline" {
		t.Fatalf("proposal = %#v", got)
	}
}

func TestProposeRejectsInvalidGraphAndText(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"empty", `{"tasks":[]}`},
		{"empty key", `{"tasks":[{"key":"","title":"T","goal":"G","acceptance":"A","depends_on":[]}]}`},
		{"missing dependencies array", `{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A"}]}`},
		{"null dependencies array", `{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":null}]}`},
		{"edge whitespace key", `{"tasks":[{"key":" key","title":"T","goal":"G","acceptance":"A","depends_on":[]}]}`},
		{"duplicate key", `{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":[]},{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":[]}]}`},
		{"blank title", `{"tasks":[{"key":"x","title":"  ","goal":"G","acceptance":"A","depends_on":[]}]}`},
		{"blank goal", `{"tasks":[{"key":"x","title":"T","goal":"\t","acceptance":"A","depends_on":[]}]}`},
		{"blank acceptance", `{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":" ","depends_on":[]}]}`},
		{"unknown dependency", `{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":["missing"]}]}`},
		{"duplicate dependency", `{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":[]},{"key":"y","title":"T","goal":"G","acceptance":"A","depends_on":["x","x"]}]}`},
		{"self dependency", `{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":["x"]}]}`},
		{"cycle", `{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":["y"]},{"key":"y","title":"T","goal":"G","acceptance":"A","depends_on":["x"]}]}`},
		{"unknown lease field", `{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":[]}],"lease":{}}`},
		{"unknown done field", `{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":[]}],"done":true}`},
		{"unknown task authority field", `{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":[],"authority":{}}]}`},
		{"duplicate top-level member", `{"tasks":[],"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":[]}]}`},
		{"duplicate task member", `{"tasks":[{"key":"x","key":"y","title":"T","goal":"G","acceptance":"A","depends_on":[]}]}`},
		{"duplicate nested unknown member", `{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":[]}],"unknown":{"nested":{"field":1,"field":2}}}`},
		{"trailing json", `{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":[]}]} {}`},
		{"multiple values", `{} {}`},
		{"malformed", `{"tasks":[`},
		{"not object", `[]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProposer(generatorFunc(func(context.Context, Request) ([]byte, error) { return []byte(tt.json), nil }))
			got, err := p.Propose(context.Background(), Request{Objective: "objective"})
			if err == nil {
				t.Fatalf("expected error, got proposal %#v", got)
			}
			if got.Tasks != nil {
				t.Fatalf("partial proposal returned on failure: %#v", got)
			}
		})
	}
}

func TestProposeFailsClosed(t *testing.T) {
	called := false
	generator := generatorFunc(func(context.Context, Request) ([]byte, error) {
		called = true
		return []byte(`{"tasks":[]}`), nil
	})
	cases := []struct {
		name string
		ctx  context.Context
		req  Request
		gen  Generator
	}{
		{"nil context", nil, Request{Objective: "x"}, generator},
		{"cancelled context", cancelledContext(t), Request{Objective: "x"}, generator},
		{"blank objective", context.Background(), Request{Objective: "  "}, generator},
		{"nil generator", context.Background(), Request{Objective: "x"}, nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProposer(tt.gen)
			got, err := p.Propose(tt.ctx, tt.req)
			if err == nil || got.Tasks != nil {
				t.Fatalf("got (%#v, %v), want empty proposal and error", got, err)
			}
		})
	}
	if called {
		t.Fatal("generator called for invalid request/context/port")
	}

	wantErr := errors.New("provider unavailable")
	p := NewProposer(generatorFunc(func(context.Context, Request) ([]byte, error) {
		return []byte(`{"tasks":[]}`), wantErr
	}))
	got, err := p.Propose(context.Background(), Request{Objective: "x"})
	if !errors.Is(err, wantErr) || got.Tasks != nil {
		t.Fatalf("got (%#v, %v), want empty proposal and wrapped generator error", got, err)
	}
}

func cancelledContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestProposeMutationIsolation(t *testing.T) {
	raw := []byte(`{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":["y"]},{"key":"y","title":"T","goal":"G","acceptance":"A","depends_on":[]}]}`)
	p := NewProposer(generatorFunc(func(context.Context, Request) ([]byte, error) { return raw, nil }))
	got, err := p.Propose(context.Background(), Request{Objective: "x"})
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = ' '
	}
	if got.Tasks[0].Key != "x" || got.Tasks[0].DependsOn[0] != "y" {
		t.Fatalf("provider buffer mutation leaked into proposal: %#v", got)
	}
	got.Tasks[0].DependsOn[0] = "changed"
	if raw[0] != ' ' {
		t.Fatal("proposal mutation leaked into provider buffer")
	}
}

func TestProposeDoesNotExposeProviderSlices(t *testing.T) {
	p := NewProposer(generatorFunc(func(context.Context, Request) ([]byte, error) {
		return []byte(`{"tasks":[{"key":"x","title":"T","goal":"G","acceptance":"A","depends_on":[]}]}`), nil
	}))
	first, err := p.Propose(context.Background(), Request{Objective: "x"})
	if err != nil {
		t.Fatal(err)
	}
	first.Tasks[0].Key = "caller mutation"
	second, err := p.Propose(context.Background(), Request{Objective: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if second.Tasks[0].Key != "x" {
		t.Fatalf("caller mutation leaked: %#v", second)
	}
}
