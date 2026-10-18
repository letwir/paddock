package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/letwir/paddock/internal/governance/application"
	"github.com/letwir/paddock/internal/governance/domain"
)

// policyDB is implemented by pgxpool.Pool and keeps this adapter testable
// without opening a database connection.
type policyDB interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type OfflinePolicyStore struct{ db policyDB }

func NewOfflinePolicyStore(db policyDB) *OfflinePolicyStore { return &OfflinePolicyStore{db: db} }

// Configure persists a policy exactly once while the order remains QUEUED.
func (s *OfflinePolicyStore) Configure(ctx context.Context, root domain.RootID, order domain.WorkOrderID, policy domain.WorkOrderPolicy) (string, error) {
	if s == nil || s.db == nil || root.Validate() != nil || order.Validate() != nil || policy.Validate() != nil {
		return "", errors.New("invalid WorkOrder policy configuration")
	}
	bytes, err := policy.CanonicalBytes()
	if err != nil {
		return "", err
	}
	digest, err := policy.Digest()
	if err != nil {
		return "", err
	}
	var stored string
	err = s.db.QueryRow(ctx, `SELECT raw.configure_work_order_offline_policy($1,$2,$3,$4,$5,$6)`,
		string(root), string(order), string(policy.Mode), string(policy.Checkpoint), bytes, digest).Scan(&stored)
	if err != nil {
		return "", fmt.Errorf("configure WorkOrder policy: %w", err)
	}
	if stored != digest {
		return "", errors.New("database returned mismatched policy digest")
	}
	return stored, nil
}

// AuthorizeOnline delegates the complete live-state check to the guarded SQL
// function. It makes no claim that a later external effect is atomic with auth.
type OfflinePolicyAuthorizer struct{ db policyDB }

func NewOfflinePolicyAuthorizer(db policyDB) *OfflinePolicyAuthorizer {
	return &OfflinePolicyAuthorizer{db: db}
}

func (a *OfflinePolicyAuthorizer) AuthorizeOnline(ctx context.Context, op application.GatewayOperation) error {
	snapshot, err := a.ReadAuthorization(ctx, op)
	if err != nil || !snapshot.Allowed {
		return application.ErrGatewayDenied
	}
	return nil
}

// ReadAuthorization reads one DB-bound authorization snapshot. Only connection
// or transport failures are eligible for the application's LOW-risk fallback.
func (a *OfflinePolicyAuthorizer) ReadAuthorization(ctx context.Context, op application.GatewayOperation) (application.AuthorizationSnapshot, error) {
	if a == nil || a.db == nil || ctx == nil || ctx.Err() != nil ||
		op.RootID.Validate() != nil || op.WorkOrderID.Validate() != nil ||
		op.AttemptID == "" || op.WorkerID == "" || op.SessionID == "" || op.LeaseEpoch == 0 ||
		op.PolicyDigest.Validate() != nil || op.Action == "" || op.Action != strings.TrimSpace(op.Action) {
		return application.AuthorizationSnapshot{}, application.ErrGatewayDenied
	}
	var allowed bool
	var risk string
	var remainingUS int64
	err := a.db.QueryRow(ctx, `SELECT allowed,risk_tier,lease_remaining_us FROM raw.read_work_order_authorization($1,$2,$3,$4,$5,$6,$7,$8)`,
		string(op.RootID), string(op.WorkOrderID), op.AttemptID, op.WorkerID, op.SessionID,
		int64(op.LeaseEpoch), string(op.PolicyDigest), op.Action).Scan(&allowed, &risk, &remainingUS)
	if err != nil {
		if ctx.Err() != nil {
			return application.AuthorizationSnapshot{}, ctx.Err()
		}
		if authorizationTransportUnavailable(err) {
			return application.AuthorizationSnapshot{}, fmt.Errorf("read authorization snapshot: %w: %v", application.ErrAuthorizationUnavailable, err)
		}
		return application.AuthorizationSnapshot{}, fmt.Errorf("read authorization snapshot: %w", err)
	}
	if (risk != string(application.AuthorizationRiskHigh) && risk != string(application.AuthorizationRiskLow)) || remainingUS < 0 || remainingUS > math.MaxInt64/int64(time.Microsecond) {
		return application.AuthorizationSnapshot{}, errors.New("malformed authorization snapshot")
	}
	return application.AuthorizationSnapshot{Allowed: allowed, Risk: application.AuthorizationRisk(risk), LeaseRemaining: time.Duration(remainingUS) * time.Microsecond}, nil
}

func authorizationTransportUnavailable(err error) bool {
	var connectErr *pgconn.ConnectError
	var netErr net.Error
	return errors.As(err, &connectErr) || errors.As(err, &netErr) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
