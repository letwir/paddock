package port

import (
	"context"
	"testing"
)

type rolloutTxContract struct{ GovernanceTx }

func (rolloutTxContract) CreateRollout(context.Context, RolloutSnapshot) error { return nil }

type rolloutTransactorContract struct{}

func (rolloutTransactorContract) WithinRolloutTransaction(_ context.Context, fn func(RolloutTx) error) error {
	return fn(rolloutTxContract{})
}

func TestRolloutTransactionPortContract(t *testing.T) {
	var tx RolloutTx = rolloutTxContract{}
	if err := tx.CreateRollout(context.Background(), RolloutSnapshot{}); err != nil {
		t.Fatal(err)
	}
	var transactor RolloutTransactor = rolloutTransactorContract{}
	called := false
	if err := transactor.WithinRolloutTransaction(context.Background(), func(got RolloutTx) error {
		called = true
		return got.CreateRollout(context.Background(), RolloutSnapshot{})
	}); err != nil || !called {
		t.Fatalf("callback not executed: called=%v err=%v", called, err)
	}
}
