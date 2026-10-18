package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/governance/domain"
	"github.com/letwir/paddock/internal/governance/port"
)

const outboxWakeupChannel = "paddock_event_outbox"

// PostgresOutboxStore uses only app-only SECURITY DEFINER Outbox functions.
// The pool must authenticate as paddock_app; no direct event_outbox ACL is needed.
type PostgresOutboxStore struct{ pool *pgxpool.Pool }

func NewPostgresOutboxStore(pool *pgxpool.Pool) (*PostgresOutboxStore, error) {
	if pool == nil {
		return nil, errors.New("postgres Outbox store: nil pool")
	}
	return &PostgresOutboxStore{pool: pool}, nil
}

func (s *PostgresOutboxStore) Claim(ctx context.Context, limit int) ([]port.OutboxClaim, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if limit < 1 || limit > port.MaxOutboxClaimBatch {
		return nil, fmt.Errorf("claim Outbox Events: limit must be 1..%d", port.MaxOutboxClaimBatch)
	}
	claims := make([]port.OutboxClaim, 0, limit)
	err := withOutboxTransaction(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT event_id,aggregate_kind,aggregate_id,aggregate_version,event_type,schema_version,payload,claim_token,attempt_count,lease_expires_at FROM raw.claim_event_outbox($1)`, limit)
		if err != nil {
			return fmt.Errorf("claim Outbox Events: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var eventID, aggregateKind, aggregateID, eventType, schemaVersion, claimToken string
			var version int64
			var payload []byte
			var attemptCount int32
			var leaseExpiresAt time.Time
			if err := rows.Scan(&eventID, &aggregateKind, &aggregateID, &version, &eventType, &schemaVersion, &payload, &claimToken, &attemptCount, &leaseExpiresAt); err != nil {
				return fmt.Errorf("scan claimed Outbox Event: %w", err)
			}
			event, err := domain.NewEvent(eventID, aggregateKind, aggregateID, version, eventType, schemaVersion, payload)
			if err != nil {
				return fmt.Errorf("build claimed Outbox Event %q: %w", eventID, err)
			}
			claims = append(claims, port.OutboxClaim{
				Event: event, ClaimToken: claimToken,
				AttemptCount: attemptCount, LeaseExpiresAt: leaseExpiresAt,
			})
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate claimed Outbox Events: %w", err)
		}
		if len(claims) > limit {
			return fmt.Errorf("claim Outbox Events returned %d rows, limit=%d", len(claims), limit)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func (s *PostgresOutboxStore) Ack(ctx context.Context, eventID, claimToken string) (bool, error) {
	if err := s.ready(ctx); err != nil {
		return false, err
	}
	if !validOutboxID(eventID) || !validClaimToken(claimToken) {
		return false, errors.New("ack Outbox Event: invalid event ID or claim token")
	}
	var acknowledged bool
	err := withOutboxTransaction(ctx, s.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT raw.ack_event_outbox($1,$2)`, eventID, claimToken).Scan(&acknowledged)
	})
	if err != nil {
		return false, fmt.Errorf("ack Outbox Event %q: %w", eventID, err)
	}
	return acknowledged, nil
}

func (s *PostgresOutboxStore) Retry(ctx context.Context, eventID, claimToken, errorCode string) (port.OutboxRetryDisposition, error) {
	if err := s.ready(ctx); err != nil {
		return "", err
	}
	if !validOutboxID(eventID) || !validClaimToken(claimToken) || !validOutboxErrorCode(errorCode) {
		return "", errors.New("retry Outbox Event: invalid event ID, claim token, or sanitized error code")
	}
	var disposition string
	err := withOutboxTransaction(ctx, s.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT raw.retry_event_outbox($1,$2,$3)`, eventID, claimToken, errorCode).Scan(&disposition)
	})
	if err != nil {
		return "", fmt.Errorf("retry Outbox Event %q: %w", eventID, err)
	}
	result := port.OutboxRetryDisposition(disposition)
	switch result {
	case port.OutboxRetryScheduled, port.OutboxDeadLettered, port.OutboxClaimStale:
		return result, nil
	default:
		return "", fmt.Errorf("retry Outbox Event %q: unknown database disposition %q", eventID, disposition)
	}
}

func (s *PostgresOutboxStore) Listen(ctx context.Context) (port.OutboxNotificationListener, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	connConfig := s.pool.Config().ConnConfig.Copy()
	conn, err := pgx.ConnectConfig(ctx, connConfig)
	if err != nil {
		return nil, errors.New("open dedicated Outbox listener connection failed")
	}
	var currentUser, sessionUser string
	if err := conn.QueryRow(ctx, `SELECT current_user,session_user`).Scan(&currentUser, &sessionUser); err != nil {
		_ = conn.Close(context.Background())
		return nil, errors.New("verify Outbox listener identity failed")
	}
	if currentUser != "paddock_app" || sessionUser != "paddock_app" {
		_ = conn.Close(context.Background())
		return nil, errors.New("Outbox listener requires paddock_app session identity")
	}
	if _, err := conn.Exec(ctx, `LISTEN `+outboxWakeupChannel); err != nil {
		_ = conn.Close(context.Background())
		return nil, errors.New("LISTEN for Outbox notification failed")
	}
	return &postgresOutboxListener{conn: conn}, nil
}

func (s *PostgresOutboxStore) ready(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return errors.New("postgres Outbox store is not initialized")
	}
	if ctx == nil {
		return errors.New("nil context")
	}
	return ctx.Err()
}

type postgresOutboxListener struct{ conn *pgx.Conn }

func (l *postgresOutboxListener) Wait(ctx context.Context) error {
	if l == nil || l.conn == nil {
		return errors.New("Outbox notification listener is closed")
	}
	_, err := l.conn.WaitForNotification(ctx)
	if err != nil {
		return fmt.Errorf("wait for Outbox notification: %w", err)
	}
	return nil
}

func (l *postgresOutboxListener) Close(ctx context.Context) error {
	if l == nil || l.conn == nil {
		return nil
	}
	conn := l.conn
	l.conn = nil
	_, unlistenErr := conn.Exec(ctx, `UNLISTEN `+outboxWakeupChannel)
	closeErr := conn.Close(ctx)
	if unlistenErr != nil && closeErr != nil {
		return errors.Join(errors.New("UNLISTEN Outbox channel failed"), errors.New("close dedicated Outbox listener connection failed"))
	}
	if unlistenErr != nil {
		return errors.New("UNLISTEN Outbox channel failed")
	}
	if closeErr != nil {
		return fmt.Errorf("close dedicated Outbox listener connection: %w", closeErr)
	}
	return nil
}

func validOutboxID(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
}

func validClaimToken(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, char := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if char != '-' {
				return false
			}
			continue
		}
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true
}

func validOutboxErrorCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && char != '_' {
			return false
		}
	}
	return true
}

func withOutboxTransaction(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) (err error) {
	if ctx == nil {
		return errors.New("nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin Outbox transaction: %w", err)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			if rollbackErr := rollback(tx); rollbackErr != nil {
				panic(errors.Join(fmt.Errorf("Outbox callback panic: %v", recovered), fmt.Errorf("rollback Outbox transaction: %w", rollbackErr)))
			}
			panic(recovered)
		}
	}()
	if err := fn(tx); err != nil {
		if rollbackErr := rollback(tx); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback Outbox transaction: %w", rollbackErr))
		}
		return err
	}
	if err := ctx.Err(); err != nil {
		if rollbackErr := rollback(tx); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback cancelled Outbox transaction: %w", rollbackErr))
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit Outbox transaction (outcome may be unknown): %w", err)
	}
	return nil
}
