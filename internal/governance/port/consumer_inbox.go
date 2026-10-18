// Package port defines the persistence boundaries used by governance application code.
package port

import "context"

// ConsumerInboxStore atomically records an Event for a consumer and applies the
// corresponding local database projection effect. The implementation must use
// one transaction so an effect error cannot leave a committed Inbox marker.
type ConsumerInboxStore interface {
	// ApplyEventOnce returns true only when this call inserted the Inbox marker
	// and applied its database effect. Duplicate deliveries return false and do
	// not apply the effect again.
	ApplyEventOnce(ctx context.Context, consumerID, eventID string) (bool, error)
}
