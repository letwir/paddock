package postgres

import (
	"github.com/jackc/pgx/v5/pgxpool"
)

// safetyGovernanceTx overrides only the Scope/Root/Security Epoch/Receipt
// operations used by SafetyService with the app-only database capability API.
// Other GovernanceTx methods remain promoted from the generic adapter.
type safetyGovernanceTx struct{ *governanceTx }

func newSafetyGovernanceTx(tx transaction) *safetyGovernanceTx {
	return &safetyGovernanceTx{governanceTx: newGovernanceTx(tx)}
}

// NewSafetyTransactor creates a transaction adapter for SafetyService. Its pool
// must authenticate as paddock_app; the adapter routes safety persistence through
// narrow SECURITY DEFINER functions without granting direct authority-table access.
func NewSafetyTransactor(pool *pgxpool.Pool) (*Transactor, error) {
	transactor, err := NewTransactor(pool)
	if err != nil {
		return nil, err
	}
	transactor.safetyAPI = true
	return transactor, nil
}
