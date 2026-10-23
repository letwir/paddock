package port

import (
	"context"
)

// RolloutTx adds rollout creation to the existing governance transaction capability.
type RolloutTx interface {
	GovernanceTx
	CreateRollout(ctx context.Context, snapshot RolloutSnapshot) error
}

// RolloutTransactor scopes a callback to one rollout transaction.
type RolloutTransactor interface {
	WithinRolloutTransaction(ctx context.Context, fn func(RolloutTx) error) error
}
