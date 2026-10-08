//go:build linux

package serviceprovider

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sync"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/protodata"
)

var validator = sync.OnceValues(func() (protovalidate.Validator, error) {
	return protovalidate.New(protovalidate.WithMessages(
		&agentv1.ServiceDesiredState{}, &agentv1.ServiceObservation{},
		&agentv1.ServicePlan{}, &agentv1.ServiceVerification{},
	), protovalidate.WithDisableLazy())
})

func validateMessage(message proto.Message) error {
	if message == nil || !message.ProtoReflect().IsValid() {
		return fmt.Errorf("%w: absent service message", ErrUnsupported)
	}
	if err := protodata.ValidateClosed(message.ProtoReflect()); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	v, err := validator()
	if err != nil {
		return err
	}
	if err := v.Validate(message); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	return nil
}

func validateUnit(unit string) error {
	return validateMessage(&agentv1.ServiceDesiredState{
		Unit:       unit,
		Runtime:    agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE,
		Enablement: agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED,
	})
}

// fingerprint hashes the entire closed observation except its timestamp and the
// fingerprint itself. New native preconditions must become observation fields.
func fingerprint(observation *agentv1.ServiceObservation) []byte {
	bound := proto.CloneOf(observation)
	bound.ObservedAt = nil
	bound.FingerprintSha256 = nil
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(bound)
	if err != nil {
		// All fields have primitive/timestamp types and no required wire fields.
		// Invalid UTF-8 remains an input error, never an empty valid fingerprint.
		return nil
	}
	digest := sha256.Sum256(encoded)
	return digest[:]
}

func supportedObservation(o *agentv1.ServiceObservation) error {
	if o.GetLoadState() != "loaded" || o.GetTransient() || o.GetNeedDaemonReload() {
		return fmt.Errorf("%w: unit must be loaded, persistent and not need daemon reload", ErrUnsupported)
	}
	if o.GetJobPending() {
		return fmt.Errorf("%w: unit has a pending job", ErrConflict)
	}
	switch o.GetActiveState() {
	case "activating", "deactivating", "reloading", "refreshing":
		return fmt.Errorf("%w: unit is %s", ErrConflict, o.GetActiveState())
	case "inactive":
		if o.GetSubState() != "dead" {
			return fmt.Errorf("%w: inactive substate %q", ErrUnsupported, o.GetSubState())
		}
	case "active":
		if o.GetSubState() != "running" && (o.GetSubState() != "exited" || !o.GetRemainAfterExit()) {
			return fmt.Errorf("%w: active substate %q", ErrUnsupported, o.GetSubState())
		}
	default:
		return fmt.Errorf("%w: active state %q", ErrUnsupported, o.GetActiveState())
	}
	switch o.GetServiceType() {
	case "simple", "exec", "forking", "oneshot", "dbus", "notify", "notify-reload", "idle":
	default:
		return fmt.Errorf("%w: service type %q", ErrUnsupported, o.GetServiceType())
	}
	switch o.GetUnitFileState() {
	case "enabled", "disabled", "static", "indirect":
	default:
		return fmt.Errorf("%w: unit file state %q", ErrUnsupported, o.GetUnitFileState())
	}
	return nil
}

func drift(desired *agentv1.ServiceDesiredState, before *agentv1.ServiceObservation) (runtime, enablement bool, err error) {
	if desired.GetUnit() != before.GetUnit() {
		return false, false, fmt.Errorf("%w: plan unit mismatch", ErrConflict)
	}
	if err := supportedObservation(before); err != nil {
		return false, false, err
	}
	switch desired.GetRuntime() {
	case agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED:
	case agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE:
		if before.GetServiceType() == "oneshot" && !before.GetRemainAfterExit() {
			return false, false, fmt.Errorf("%w: nonpersistent oneshot cannot promise active", ErrUnsupported)
		}
		runtime = before.GetActiveState() != "active"
		if runtime && before.GetRefuseManualStart() {
			return false, false, fmt.Errorf("%w: RefuseManualStart", ErrUnsupported)
		}
	case agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE:
		runtime = before.GetActiveState() != "inactive"
		if runtime && before.GetRefuseManualStop() {
			return false, false, fmt.Errorf("%w: RefuseManualStop", ErrUnsupported)
		}
	default:
		return false, false, fmt.Errorf("%w: unknown desired runtime", ErrUnsupported)
	}
	switch desired.GetEnablement() {
	case agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED:
	case agentv1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED, agentv1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED:
		if before.GetUnitFileState() != "enabled" && before.GetUnitFileState() != "disabled" {
			return false, false, fmt.Errorf("%w: cannot manage enablement %q", ErrUnsupported, before.GetUnitFileState())
		}
		enablement = !enablementMatches(desired, before)
	default:
		return false, false, fmt.Errorf("%w: unknown desired enablement", ErrUnsupported)
	}
	return runtime, enablement, nil
}

func planFor(desired *agentv1.ServiceDesiredState, before *agentv1.ServiceObservation) (*agentv1.ServicePlan, error) {
	runtime, enablement, err := drift(desired, before)
	if err != nil {
		return nil, err
	}
	return &agentv1.ServicePlan{
		Desired:          proto.CloneOf(desired),
		Before:           before,
		ChangeRuntime:    runtime,
		ChangeEnablement: enablement,
	}, nil
}

func validatePlan(plan *agentv1.ServicePlan) error {
	if err := validateMessage(plan); err != nil {
		return err
	}
	if !bytes.Equal(fingerprint(plan.GetBefore()), plan.GetBefore().GetFingerprintSha256()) {
		return fmt.Errorf("%w: fabricated observation fingerprint", ErrConflict)
	}
	runtime, enablement, err := drift(plan.GetDesired(), plan.GetBefore())
	if err != nil {
		return err
	}
	if plan.GetChangeRuntime() != runtime || plan.GetChangeEnablement() != enablement {
		return fmt.Errorf("%w: fabricated plan drift", ErrConflict)
	}
	return nil
}

func checkFresh(plan *agentv1.ServicePlan, current *agentv1.ServiceObservation) error {
	if !bytes.Equal(plan.GetBefore().GetFingerprintSha256(), current.GetFingerprintSha256()) {
		return fmt.Errorf("%w: stale service plan", ErrConflict)
	}
	return nil
}

func runtimeMatches(desired *agentv1.ServiceDesiredState, o *agentv1.ServiceObservation) bool {
	switch desired.GetRuntime() {
	case agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_UNMANAGED:
		return true
	case agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE:
		return o.GetActiveState() == "active" && (o.GetServiceType() != "oneshot" || o.GetRemainAfterExit())
	case agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE:
		return o.GetActiveState() == "inactive"
	default:
		return false
	}
}

func enablementMatches(desired *agentv1.ServiceDesiredState, o *agentv1.ServiceObservation) bool {
	switch desired.GetEnablement() {
	case agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED:
		return true
	case agentv1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED:
		return o.GetUnitFileState() == "enabled"
	case agentv1.ServiceEnablement_SERVICE_ENABLEMENT_DISABLED:
		return o.GetUnitFileState() == "disabled"
	default:
		return false
	}
}

func verification(plan *agentv1.ServicePlan, after *agentv1.ServiceObservation) *agentv1.ServiceVerification {
	result := &agentv1.ServiceVerification{
		Observation:       after,
		RuntimeMatches:    runtimeMatches(plan.GetDesired(), after),
		EnablementMatches: enablementMatches(plan.GetDesired(), after),
		DefinitionMatches: bytes.Equal(plan.GetBefore().GetDefinitionSha256(), after.GetDefinitionSha256()),
	}
	result.Converged = result.GetRuntimeMatches() && result.GetEnablementMatches() && result.GetDefinitionMatches() &&
		after.GetUnit() == plan.GetDesired().GetUnit() && after.GetBootId() == plan.GetBefore().GetBootId() &&
		supportedObservation(after) == nil
	return result
}
