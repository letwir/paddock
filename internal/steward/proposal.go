// Package steward validates provider output as an untrusted, temporary proposal.
// It does not admit, persist, or dispatch proposal tasks.
package steward

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// Request contains the user-supplied inputs passed to a proposal generator.
type Request struct {
	Objective string
	Context   string
}

// Generator is a provider-neutral port. Implementations return untrusted JSON;
// they must not be treated as producing an admitted or authorized proposal.
type Generator interface {
	Generate(context.Context, Request) ([]byte, error)
}

// Proposal is a temporary-key task DAG. It intentionally contains no durable
// identifiers, execution state, grants, leases, or persistence metadata.
type Proposal struct {
	Tasks []TaskProposal `json:"tasks"`
}

// TaskProposal is one untrusted task definition in a proposed DAG.
type TaskProposal struct {
	Key        string   `json:"key"`
	Title      string   `json:"title"`
	Goal       string   `json:"goal"`
	Acceptance string   `json:"acceptance"`
	DependsOn  []string `json:"depends_on"`
}

// Proposer is the validated boundary exposed to callers.
type Proposer interface {
	Propose(context.Context, Request) (Proposal, error)
}

type proposalAdapter struct {
	generator Generator
}

// NewProposer wraps a provider-neutral generator with strict decoding and DAG
// validation. A nil generator (including a typed nil) is rejected on use.
func NewProposer(generator Generator) Proposer {
	return proposalAdapter{generator: generator}
}

// Propose obtains raw output, validates it completely, and returns no partial
// proposal on any error.
func (a proposalAdapter) Propose(ctx context.Context, request Request) (Proposal, error) {
	if ctx == nil {
		return Proposal{}, errors.New("steward: nil context")
	}
	if err := ctx.Err(); err != nil {
		return Proposal{}, fmt.Errorf("steward: request context: %w", err)
	}
	if strings.TrimSpace(request.Objective) == "" {
		return Proposal{}, errors.New("steward: objective must not be blank")
	}
	if nilGenerator(a.generator) {
		return Proposal{}, errors.New("steward: generator is nil")
	}

	raw, err := a.generator.Generate(ctx, Request{Objective: request.Objective, Context: request.Context})
	if err != nil {
		return Proposal{}, fmt.Errorf("steward: generate proposal: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Proposal{}, fmt.Errorf("steward: request context: %w", err)
	}

	proposal, err := decodeProposal(raw)
	if err != nil {
		return Proposal{}, err
	}
	if err := validateProposal(proposal); err != nil {
		return Proposal{}, err
	}
	return cloneProposal(proposal), nil
}

func nilGenerator(generator Generator) bool {
	if generator == nil {
		return true
	}
	value := reflect.ValueOf(generator)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func decodeProposal(raw []byte) (Proposal, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return Proposal{}, fmt.Errorf("steward: decode proposal object: %w", err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return Proposal{}, errors.New("steward: proposal must be exactly one JSON object")
	}
	if err := scanJSONValue(decoder, token); err != nil {
		return Proposal{}, fmt.Errorf("steward: scan proposal JSON: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return Proposal{}, errors.New("steward: trailing JSON value after proposal")
		}
		return Proposal{}, fmt.Errorf("steward: trailing data after proposal: %w", err)
	}

	// Decode the original object from its beginning so unknown fields at every
	// nesting level are rejected by the typed schema.
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var proposal Proposal
	if err := decoder.Decode(&proposal); err != nil {
		return Proposal{}, fmt.Errorf("steward: decode proposal: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Proposal{}, errors.New("steward: trailing JSON value after proposal")
		}
		return Proposal{}, fmt.Errorf("steward: trailing data after proposal: %w", err)
	}
	return proposal, nil
}

// scanJSONValue recursively consumes one tokenized JSON value and rejects
// repeated member names in every object, including objects outside the typed
// proposal schema. encoding/json otherwise silently keeps the last value.
func scanJSONValue(decoder *json.Decoder, token json.Token) error {
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object member name is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON object member %q", key)
			}
			seen[key] = struct{}{}
			valueToken, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanJSONValue(decoder, valueToken); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("malformed JSON object nesting")
		}
	case '[':
		for decoder.More() {
			valueToken, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanJSONValue(decoder, valueToken); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("malformed JSON array nesting")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func validateProposal(proposal Proposal) error {
	if len(proposal.Tasks) == 0 {
		return errors.New("steward: proposal must contain at least one task")
	}

	indices := make(map[string]int, len(proposal.Tasks))
	for i, task := range proposal.Tasks {
		if task.DependsOn == nil {
			return fmt.Errorf("steward: task %d depends_on must be an array", i)
		}
		if task.Key == "" || strings.TrimSpace(task.Key) != task.Key {
			return fmt.Errorf("steward: task %d key must be non-empty and have no edge whitespace", i)
		}
		if _, exists := indices[task.Key]; exists {
			return fmt.Errorf("steward: duplicate task key %q", task.Key)
		}
		indices[task.Key] = i
		if strings.TrimSpace(task.Title) == "" {
			return fmt.Errorf("steward: task %q title must not be blank", task.Key)
		}
		if strings.TrimSpace(task.Goal) == "" {
			return fmt.Errorf("steward: task %q goal must not be blank", task.Key)
		}
		if strings.TrimSpace(task.Acceptance) == "" {
			return fmt.Errorf("steward: task %q acceptance must not be blank", task.Key)
		}
	}

	for _, task := range proposal.Tasks {
		seen := make(map[string]struct{}, len(task.DependsOn))
		for _, dependency := range task.DependsOn {
			if dependency == task.Key {
				return fmt.Errorf("steward: task %q depends on itself", task.Key)
			}
			if _, exists := indices[dependency]; !exists {
				return fmt.Errorf("steward: task %q depends on unknown key %q", task.Key, dependency)
			}
			if _, exists := seen[dependency]; exists {
				return fmt.Errorf("steward: task %q repeats dependency %q", task.Key, dependency)
			}
			seen[dependency] = struct{}{}
		}
	}

	// Three-color DFS detects back edges; dependencies may reference tasks in
	// any order in the JSON array.
	colors := make([]uint8, len(proposal.Tasks))
	var visit func(int) bool
	visit = func(index int) bool {
		if colors[index] == 1 {
			return false
		}
		if colors[index] == 2 {
			return true
		}
		colors[index] = 1
		for _, dependency := range proposal.Tasks[index].DependsOn {
			if !visit(indices[dependency]) {
				return false
			}
		}
		colors[index] = 2
		return true
	}
	for i := range proposal.Tasks {
		if !visit(i) {
			return errors.New("steward: proposal dependencies contain a directed cycle")
		}
	}
	return nil
}

func cloneProposal(proposal Proposal) Proposal {
	clone := Proposal{Tasks: make([]TaskProposal, len(proposal.Tasks))}
	for i, task := range proposal.Tasks {
		clone.Tasks[i] = task
		clone.Tasks[i].DependsOn = append([]string(nil), task.DependsOn...)
	}
	return clone
}
