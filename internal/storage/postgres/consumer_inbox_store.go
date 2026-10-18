package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresConsumerInboxStore atomically inserts a consumer Inbox marker and
// increments the local processed-event projection in one PostgreSQL transaction.
type PostgresConsumerInboxStore struct {
	pool *pgxpool.Pool
}

func NewPostgresConsumerInboxStore(pool *pgxpool.Pool) (*PostgresConsumerInboxStore, error) {
	if pool == nil {
		return nil, errors.New("postgres consumer Inbox store: nil pool")
	}
	return &PostgresConsumerInboxStore{pool: pool}, nil
}

// ApplyEventOnce returns true only if this transaction inserted the Inbox key
// and incremented its projection counter. Concurrent duplicate deliveries are
// serialized by the Inbox primary key; failed effects roll back the marker.
func (s *PostgresConsumerInboxStore) ApplyEventOnce(ctx context.Context, consumerID, eventID string) (bool, error) {
	if err := s.ready(); err != nil {
		return false, err
	}
	if ctx == nil {
		return false, errors.New("consumer Inbox: nil context")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if consumerID == "" || strings.TrimSpace(consumerID) != consumerID || eventID == "" || strings.TrimSpace(eventID) != eventID {
		return false, errors.New("consumer Inbox: invalid consumer ID or Event ID")
	}

	applied := false
	err := withConsumerInboxTransaction(ctx, s.pool, func(tx pgx.Tx) error {
		var eventExists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM raw.domain_events WHERE event_id=$1)`, eventID).Scan(&eventExists); err != nil {
			return fmt.Errorf("verify durable Event exists: %w", err)
		}
		if !eventExists {
			return fmt.Errorf("Event %q is not present in the durable Event store", eventID)
		}

		// Do not name a conflict target: PostgreSQL requires SELECT on target
		// columns for ON CONFLICT inference. The guarded migration asserts the
		// Inbox has only its consumer/event primary-key index, allowing App to
		// retain INSERT-only Inbox access.
		inserted, err := tx.Exec(ctx, `
			INSERT INTO raw.event_inbox (consumer_id,event_id,processed_at)
			VALUES ($1,$2,pg_catalog.clock_timestamp())
			ON CONFLICT DO NOTHING`, consumerID, eventID)
		if err != nil {
			return fmt.Errorf("insert consumer Inbox marker: %w", err)
		}
		switch inserted.RowsAffected() {
		case 0:
			return nil
		case 1:
			// Continue and commit the effect only for the transaction that won
			// the unique Inbox key.
		default:
			return fmt.Errorf("consumer Inbox insert affected %d rows, want at most one", inserted.RowsAffected())
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO raw.event_consumer_projection (consumer_id,processed_event_count)
			VALUES ($1,1)
			ON CONFLICT (consumer_id) DO UPDATE
			SET processed_event_count=raw.event_consumer_projection.processed_event_count+1`, consumerID); err != nil {
			return fmt.Errorf("increment consumer event projection: %w", err)
		}
		applied = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("apply consumer Inbox Event %q for %q: %w", eventID, consumerID, err)
	}
	return applied, nil
}

func (s *PostgresConsumerInboxStore) ready() error {
	if s == nil || s.pool == nil {
		return errors.New("postgres consumer Inbox store is not initialized")
	}
	return nil
}

func withConsumerInboxTransaction(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin consumer Inbox transaction: %w", err)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			if rollbackErr := rollback(tx); rollbackErr != nil {
				panic(errors.Join(fmt.Errorf("consumer Inbox callback panic: %v", recovered), fmt.Errorf("rollback consumer Inbox transaction: %w", rollbackErr)))
			}
			panic(recovered)
		}
	}()
	if err := fn(tx); err != nil {
		if rollbackErr := rollback(tx); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback consumer Inbox transaction: %w", rollbackErr))
		}
		return err
	}
	if err := ctx.Err(); err != nil {
		if rollbackErr := rollback(tx); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback cancelled consumer Inbox transaction: %w", rollbackErr))
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit consumer Inbox transaction (outcome may be unknown): %w", err)
	}
	return nil
}
