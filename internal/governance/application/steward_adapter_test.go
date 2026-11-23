package application

import (
	"context"
	"errors"
	"testing"
)

type stubStewardPlanner struct {
	raw []byte
	err error
}

func (p stubStewardPlanner) ProposeDecomposition(context.Context, string) ([]byte, error) {
	return p.raw, p.err
}

type fakeStewardStore struct {
	submissions []StewardSubmission
}

func (s *fakeStewardStore) SubmitProposal(_ context.Context, sub StewardSubmission) (StewardReceipt, error) {
	s.submissions = append(s.submissions, sub)
	return StewardReceipt{
		ProposalID: "prop-1",
		State:      sub.InitialState,
		OrderCount: len(sub.Orders),
	}, nil
}

func TestStewardAdapterProposesDAGAndRejectsDirectAuthorityOrDoneFields(t *testing.T) {
	validJSON := []byte(`{
		"schema_version": "paddock.steward-proposal/1",
		"root_id": "root-a",
		"orders": [
			{"local_id": "wo-top", "title": "Root task"},
			{"local_id": "wo-1", "parent_local_id": "wo-top", "title": "Step 1"},
			{"local_id": "wo-2", "parent_local_id": "wo-top", "title": "Step 2", "depends_on_local_ids": ["wo-1"]}
		]
	}`)

	store := &fakeStewardStore{}
	adapter, err := NewStewardAdapter(stubStewardPlanner{raw: validJSON}, store)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := adapter.ProposeWorkOrders(context.Background(), "implement feature")
	if err != nil {
		t.Fatalf("valid proposal rejected: %v", err)
	}
	if receipt.State != "PROPOSED" || receipt.OrderCount != 3 || len(store.submissions) != 1 {
		t.Fatalf("unexpected steward receipt: %+v", receipt)
	}

	// Adversarial / LLM boundary probes attempting to inject DONE, Lease, or Authority.
	rejectedPayloads := []struct {
		name string
		raw  string
	}{
		{
			name: "inject DONE state",
			raw:  `{"schema_version":"paddock.steward-proposal/1","root_id":"root-a","orders":[{"local_id":"wo-1","title":"t","status":"DONE"}]}`,
		},
		{
			name: "inject lease epoch",
			raw:  `{"schema_version":"paddock.steward-proposal/1","root_id":"root-a","lease_epoch":99,"orders":[{"local_id":"wo-1","title":"t"}]}`,
		},
		{
			name: "inject authority grant",
			raw:  `{"schema_version":"paddock.steward-proposal/1","root_id":"root-a","authority_grant":"admin","orders":[{"local_id":"wo-1","title":"t"}]}`,
		},
		{
			name: "execution cycle rejected",
			raw:  `{"schema_version":"paddock.steward-proposal/1","root_id":"root-a","orders":[{"local_id":"wo-top","title":"r"},{"local_id":"wo-1","parent_local_id":"wo-top","title":"a","depends_on_local_ids":["wo-2"]},{"local_id":"wo-2","parent_local_id":"wo-top","title":"b","depends_on_local_ids":["wo-1"]}]}`,
		},
	}
	for _, tc := range rejectedPayloads {
		t.Run(tc.name, func(t *testing.T) {
			s := &fakeStewardStore{}
			ad, err := NewStewardAdapter(stubStewardPlanner{raw: []byte(tc.raw)}, s)
			if err != nil {
				t.Fatal(err)
			}
			_, err = ad.ProposeWorkOrders(context.Background(), "goal")
			if !errors.Is(err, ErrStewardRejected) || len(s.submissions) != 0 {
				t.Fatalf("adversarial payload %s was not rejected cleanly: err=%v submissions=%d", tc.name, err, len(s.submissions))
			}
		})
	}
}
