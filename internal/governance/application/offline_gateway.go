package application

import (
	"context"
	"errors"
	"reflect"

	"github.com/letwir/paddock/internal/governance/domain"
)

var (
	ErrGatewayUnavailable    = errors.New("external gateway unavailable")
	ErrGatewayDenied         = errors.New("external operation denied")
	ErrGatewayInvalid        = errors.New("invalid external operation")
	ErrGatewayOutcomeUnknown = errors.New("external gateway outcome unknown")
)

// GatewayOperation is a caller-supplied request. The OnlineAuthorizer must bind
// every identity and policy field to current Coordinator/DB state; none of these
// caller values independently establishes authority.
type GatewayOperation struct {
	RootID       domain.RootID
	WorkOrderID  domain.WorkOrderID
	AttemptID    string
	WorkerID     string
	SessionID    string
	LeaseEpoch   domain.Epoch
	PolicyDigest domain.Digest
	OperationID  string
	Action       string
	Payload      []byte
}

func portPresent(port any) bool {
	if port == nil {
		return false
	}
	value := reflect.ValueOf(port)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}

// OnlineAuthorizer returns nil only after establishing live/online authority
// and checking the current DB lease, Attempt, lease epoch, and WorkOrder policy
// against the request. Implementations must fail closed if current state cannot
// be established. This facade does not implement that DB/network check.
type OnlineAuthorizer interface {
	AuthorizeOnline(context.Context, GatewayOperation) error
}

// ExternalAdapter performs the external effect. Implementations are injected;
// this package provides no concrete adapter.
type ExternalAdapter interface {
	DispatchExternal(context.Context, GatewayOperation) error
}

type Gateway struct {
	authorizer OnlineAuthorizer
	adapter    ExternalAdapter
}

func NewGateway(authorizer OnlineAuthorizer, adapter ExternalAdapter) *Gateway {
	return &Gateway{authorizer: authorizer, adapter: adapter}
}

// ExecuteExternal permits dispatch only after online authorization. If an
// OfflineSession is present it is checked first and external effects are denied
// without calling either injected port. An adapter error after invocation has
// an unknown outcome; callers must not blindly retry unless the adapter honors
// OperationID idempotency or supports reconciliation. This facade does not
// provide retries or exactly-once delivery. This in-process boundary cannot
// prevent callers from bypassing the facade and invoking other network paths directly.
func (g *Gateway) ExecuteExternal(ctx context.Context, op GatewayOperation, offline *domain.OfflineSession) error {
	if g == nil || !portPresent(g.authorizer) || !portPresent(g.adapter) {
		return ErrGatewayUnavailable
	}
	if ctx == nil || ctx.Err() != nil {
		return ErrGatewayDenied
	}
	if err := validateGatewayOperation(op); err != nil {
		return ErrGatewayInvalid
	}
	if offline != nil {
		_, _ = offline.Authorize(domain.ExternalEffect)
		return ErrGatewayDenied
	}

	// Give the authorizer and adapter separate deep copies so mutating the
	// authorization request cannot change what is ultimately dispatched.
	authorizationRequest := cloneGatewayOperation(op)
	if g.authorizer.AuthorizeOnline(ctx, authorizationRequest) != nil {
		return ErrGatewayDenied
	}
	if ctx.Err() != nil {
		return ErrGatewayDenied
	}
	if g.adapter.DispatchExternal(ctx, cloneGatewayOperation(op)) != nil {
		return ErrGatewayOutcomeUnknown
	}
	return nil
}

func validateGatewayOperation(op GatewayOperation) error {
	if op.RootID.Validate() != nil || op.WorkOrderID.Validate() != nil ||
		validateID(op.AttemptID) != nil || validateID(op.WorkerID) != nil ||
		validateID(op.SessionID) != nil || op.LeaseEpoch == 0 ||
		op.PolicyDigest.Validate() != nil || validateID(op.OperationID) != nil ||
		validateID(op.Action) != nil {
		return ErrGatewayInvalid
	}
	return nil
}

func cloneGatewayOperation(op GatewayOperation) GatewayOperation {
	op.Payload = append([]byte(nil), op.Payload...)
	return op
}

func validateID(value string) error {
	if value == "" || value != trimSpace(value) {
		return ErrGatewayInvalid
	}
	return nil
}

func trimSpace(value string) string {
	for len(value) > 0 && (value[0] == ' ' || value[0] == '\t' || value[0] == '\n' || value[0] == '\r') {
		value = value[1:]
	}
	for len(value) > 0 {
		last := value[len(value)-1]
		if last != ' ' && last != '\t' && last != '\n' && last != '\r' {
			break
		}
		value = value[:len(value)-1]
	}
	return value
}
