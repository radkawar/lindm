// Package resourceprovider is the agent's per-kind resource provider contract:
// the executor-side Provider (Observe -> Plan -> Apply -> Verify), the uniform
// input every kind's root-helper half receives (NativeEnv), and the closed
// per-kind Registry through which all kind dispatch goes.
//
// Non-goals: it holds no provider logic, chooses no sandbox grants and performs
// no authorization; callers keep their signed-intent, ownership and journal
// checks. Native package transactions use their own staged helper protocol
// (stage, cancel, transaction) and device actions their own DeviceActionProvider;
// both are outside this resource-kind contract.
package resourceprovider

import (
	"context"
	"errors"
	"fmt"
	"maps"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// Provider is one opened resource of a kind. Observe reads current native
// state without effects. Plan observes again and binds the before snapshot, the
// ownership baseline used for release and restore, into the plan. Apply
// re-observes under the final gate (beforeEffect) and performs the only effect.
// Verify re-observes against the plan. Close releases the provider.
type Provider interface {
	Observe(ctx context.Context, desired *resourcev1.ResourceDesiredState) (*resourcev1.ResourceObservation, error)
	Plan(ctx context.Context, desired *resourcev1.ResourceDesiredState, operation resourcev1.ResourceOperation) (*resourcev1.ResourcePlan, error)
	Apply(ctx context.Context, plan *resourcev1.ResourcePlan, beforeEffect func(context.Context) error) (*resourcev1.ResourceVerification, error)
	Verify(ctx context.Context, plan *resourcev1.ResourcePlan) (*resourcev1.ResourceVerification, error)
	Close() error
}

// NativeEnv is the same input the fixed root helper hands every kind's native
// boundary. Each kind reads only its own section of Config.
type NativeEnv struct {
	Config         *agentv1.AgentConfig
	ProtectedPaths []string
	// Platform and ExecutorIncarnation come from the protected request.
	Platform            *resourcev1.PlatformProduct
	ExecutorIncarnation string
	// Directory is the action's private, root-owned scratch directory.
	Directory string
	// Digest keys private digests with the helper's custody key.
	Digest func(string, []byte) ([]byte, error)
}

// NativeApply applies one validated native transaction after the final gate
// and returns the after-image snapshot.
type NativeApply func(ctx context.Context, env NativeEnv, request *agentv1.NativeResourceTransactionRequest, gate func(context.Context) error) (*agentv1.ResourceOwnershipSnapshot, error)

// ErrUnsupportedKind reports a kind without a registered entry.
var ErrUnsupportedKind = errors.New("resourceprovider: kind_not_supported")

// Registry is a closed per-kind table built once; it is read-only afterwards.
type Registry[E any] struct {
	entries map[resourcev1.ResourceKind]E
}

// NewRegistry copies entries; later changes to the map do not affect it.
func NewRegistry[E any](entries map[resourcev1.ResourceKind]E) Registry[E] {
	r := Registry[E]{entries: make(map[resourcev1.ResourceKind]E, len(entries))}
	maps.Copy(r.entries, entries)
	return r
}

// Lookup returns the entry for kind or ErrUnsupportedKind.
func (r Registry[E]) Lookup(kind resourcev1.ResourceKind) (E, error) {
	entry, ok := r.entries[kind]
	if !ok {
		var zero E
		return zero, fmt.Errorf("%w: %s", ErrUnsupportedKind, kind)
	}
	return entry, nil
}
