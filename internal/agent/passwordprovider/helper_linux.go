//go:build linux

package passwordprovider

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativefile"
	"lindm/internal/agent/resourceprovider"
	"lindm/internal/resource"
)

// ApplyNative is called only by the fixed separately confined root helper.
// No paths, profile snippets or argv come from the remote desired policy. The
// target is recomputed from signed policy and protected baseline. All native
// files are prepared without writes; the final gate precedes the first effect.
func ApplyNative(ctx context.Context, env resourceprovider.NativeEnv, request *agentv1.NativeResourceTransactionRequest, beforeEffect func(context.Context) error) (result *agentv1.ResourceOwnershipSnapshot, err error) {
	config := env.Config.GetPasswordProvider()
	if beforeEffect == nil {
		return nil, ErrUnsupported
	}
	for _, message := range []proto.Message{config, request} {
		if err := validateMessage(message); err != nil {
			return nil, err
		}
	}
	plan := request.GetPlan()
	if err := resource.ValidatePlan(plan); err != nil {
		return nil, err
	}
	desired := resource.PlanDesired(plan)
	if desired.GetPasswordPolicy() == nil {
		return nil, ErrUnsupported
	}
	if err := policySupported(desired.GetPasswordPolicy()); err != nil {
		return nil, err
	}
	if !proto.Equal(request.GetOwnership().GetRef(), passwordRef()) || !sameObserved(request.GetBefore().GetObservation(), plan.GetBefore()) || request.GetOwnership().GetState() == agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_UNKNOWN {
		return nil, ErrConflict
	}
	if err := checkPlatform(plan.GetBackend().GetProduct()); err != nil {
		return nil, err
	}
	backend := resourcev1.Backend_BACKEND_PAM_AUTH_UPDATE
	if authselectProduct(plan.GetBackend().GetProduct()) {
		backend = resourcev1.Backend_BACKEND_AUTHSELECT
	}
	if plan.GetBackend().GetBackend() != backend {
		return nil, ErrUnsupported
	}
	p := &Provider{config: Config{Platform: proto.CloneOf(plan.GetBackend().GetProduct()), Native: proto.CloneOf(config), ExecutorIncarnation: request.GetBefore().GetObservation().GetMetadata().GetExecutorIncarnation()}, backend: proto.CloneOf(plan.GetBackend()), run: runNative, dropins: readQualityDropins}
	fresh, err := p.snapshot(ctx, desired.GetPasswordPolicy())
	if err != nil {
		return nil, err
	}
	if !sameObserved(fresh.GetObservation(), request.GetBefore().GetObservation()) || !proto.Equal(fresh.GetPasswordPolicy(), request.GetBefore().GetPasswordPolicy()) {
		return nil, ErrConflict
	}
	target, err := p.target(ctx, desired.GetPasswordPolicy(), fresh, request.GetOwnership(), plan.GetOperation())
	if err != nil {
		return nil, err
	}
	if !proto.Equal(target.GetPasswordPolicy(), request.GetTarget().GetPasswordPolicy()) || !proto.Equal(target.GetObservation().GetPasswordPolicy(), request.GetTarget().GetObservation().GetPasswordPolicy()) {
		return nil, ErrConflict
	}
	digest, err := candidateDigest(target)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(digest, plan.GetPasswordPolicy().GetCandidateSha256()) {
		return nil, ErrConflict
	}
	expected, err := p.makePlan(desired, plan.GetOperation(), request.GetBefore(), target, request.GetOwnership())
	if err != nil {
		return nil, err
	}
	if !proto.Equal(expected.GetPasswordPolicy(), plan.GetPasswordPolicy()) || !proto.Equal(expected.GetSafety(), plan.GetSafety()) || !equalClaims(expected.GetClaims(), plan.GetClaims()) {
		return nil, ErrConflict
	}
	var changes []*nativefile.Transaction
	defer func() {
		for _, tx := range changes {
			err = errors.Join(err, tx.Close())
		}
	}()
	for _, file := range fresh.GetPasswordPolicy().GetFiles() {
		next := nativeFile(target, file.GetKind())
		if next == nil {
			return nil, ErrConflict
		}
		if file.GetState().GetExists() == next.GetState().GetExists() && bytes.Equal(file.GetContent(), next.GetContent()) {
			continue
		}
		tx, err := nativefile.Prepare(fileSnapshot(fresh, file), fileSnapshot(target, next))
		if err != nil {
			return nil, err
		}
		changes = append(changes, tx)
	}
	if err := accessGuard(ctx, config, p.run); err != nil {
		return nil, err
	}
	final, err := p.snapshot(ctx, desired.GetPasswordPolicy())
	if err != nil {
		return nil, err
	}
	if !sameObserved(fresh.GetObservation(), final.GetObservation()) || !proto.Equal(fresh.GetPasswordPolicy(), final.GetPasswordPolicy()) {
		return nil, ErrConflict
	}
	if err := beforeEffect(ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := accessGuard(ctx, config, p.run); err != nil {
		return nil, err
	}
	// Disable only acquired manager features before removing their profile files.
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RELEASE {
		if err := managerUnchanged(ctx, p.config.Platform, fresh, target, p.run); err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
		if err := changeManager(ctx, p.config.Platform, fresh, target, p.run); err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
	}
	for _, tx := range changes {
		if _, err := tx.Commit(ctx, func(c context.Context) error { return c.Err() }); err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
	}
	if plan.GetOperation() == resourcev1.ResourceOperation_RESOURCE_OPERATION_RECONCILE {
		if err := managerUnchanged(ctx, p.config.Platform, fresh, target, p.run); err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
		if err := changeManager(ctx, p.config.Platform, fresh, target, p.run); err != nil {
			return nil, errors.Join(ErrOutcomeUnknown, err)
		}
	}
	result, err = p.snapshot(ctx, desired.GetPasswordPolicy())
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if !targetMatches(result, target) {
		return nil, ErrOutcomeUnknown
	}
	result.PasswordPolicy.AcquiredFeatures = append([]agentv1.PasswordNativeFeature(nil), target.GetPasswordPolicy().GetAcquiredFeatures()...)
	return result, nil
}
func fileSnapshot(parent *agentv1.ResourceOwnershipSnapshot, file *agentv1.PasswordNativeFileSnapshot) *agentv1.ResourceOwnershipSnapshot {
	observation := proto.CloneOf(parent.GetObservation())
	observation.Observed = &resourcev1.ResourceObservation_ManagedFile{ManagedFile: proto.CloneOf(file.GetState())}
	// nativefile compares this stable identity with its independent recapture.
	observation.Metadata.NativeRevision = bytes.Clone(file.GetNativeRevisionSha256())
	return &agentv1.ResourceOwnershipSnapshot{Observation: observation, ManagedFileContent: bytes.Clone(file.GetContent()), ManagedFileXattrs: file.GetXattrs()}
}
func managerChangeSupported(ctx context.Context, platform *resourcev1.PlatformProduct, before, target *agentv1.ResourceOwnershipSnapshot, run commandRunner) error {
	if before.GetPasswordPolicy().GetManagerProfile() != target.GetPasswordPolicy().GetManagerProfile() {
		return ErrConflict
	}
	if !authselectProduct(platform) || slices.Equal(before.GetPasswordPolicy().GetEnabledFeatures(), target.GetPasswordPolicy().GetEnabledFeatures()) {
		return nil
	}
	var available []string
	for _, feature := range target.GetPasswordPolicy().GetEnabledFeatures() {
		if slices.Contains(before.GetPasswordPolicy().GetEnabledFeatures(), feature) {
			continue
		}
		if feature == 1 {
			return ErrUnsupported
		}
		if available == nil {
			output, err := run(ctx, "/usr/bin/authselect", "list-features", before.GetPasswordPolicy().GetManagerProfile())
			if err != nil {
				return err
			}
			available = strings.Fields(string(output))
		}
		if !slices.Contains(available, authselectFeature(feature)) {
			return ErrUnsupported
		}
	}
	return authselectNonPAMUnchanged(ctx, before, target, run)
}
func authselectFeature(feature agentv1.PasswordNativeFeature) string {
	switch feature {
	case 2:
		return "with-pwhistory"
	case 3:
		return "with-faillock"
	default:
		return ""
	}
}
func changeManager(ctx context.Context, platform *resourcev1.PlatformProduct, before, target *agentv1.ResourceOwnershipSnapshot, run commandRunner) error {
	for _, feature := range []agentv1.PasswordNativeFeature{1, 2, 3} {
		was := slices.Contains(before.GetPasswordPolicy().GetEnabledFeatures(), feature)
		want := slices.Contains(target.GetPasswordPolicy().GetEnabledFeatures(), feature)
		if was == want {
			continue
		}
		if authselectProduct(platform) {
			name := authselectFeature(feature)
			if name == "" {
				return ErrUnsupported
			}
			operation := "disable-feature"
			if want {
				operation = "enable-feature"
			}
			if _, err := run(ctx, "/usr/bin/authselect", operation, name); err != nil {
				return err
			}
		} else {
			operation := "--remove"
			if want {
				operation = "--enable"
			}
			args := []string{operation}
			for _, kind := range profileFiles(feature) {
				args = append(args, filepath.Base(filePath(kind)))
			}
			if _, err := run(ctx, "/usr/sbin/pam-auth-update", args...); err != nil {
				return err
			}
		}
	}
	return nil
}

func managerUnchanged(ctx context.Context, platform *resourcev1.PlatformProduct, before, target *agentv1.ResourceOwnershipSnapshot, run commandRunner) error {
	if slices.Equal(before.GetPasswordPolicy().GetEnabledFeatures(), target.GetPasswordPolicy().GetEnabledFeatures()) {
		return nil
	}
	state, err := inspectManager(ctx, platform, run)
	if err != nil {
		return err
	}
	if state.profile != before.GetPasswordPolicy().GetManagerProfile() || !bytes.Equal(state.generation, before.GetPasswordPolicy().GetManagerGenerationSha256()) || !bytes.Equal(state.profileDigest, before.GetPasswordPolicy().GetManagerProfileSha256()) {
		return ErrConflict
	}
	return nil
}

// Feature transactions must not change identity sources or desktop policy as an
// incidental custom-profile effect. Native test renders but never activates.
func authselectNonPAMUnchanged(ctx context.Context, before, target *agentv1.ResourceOwnershipSnapshot, run commandRunner) error {
	raw, err := run(ctx, "/usr/bin/authselect", "current", "--raw")
	if err != nil {
		return err
	}
	parts, err := authselectSelection(raw)
	if err != nil {
		return err
	}
	if parts[0] != before.GetPasswordPolicy().GetManagerProfile() {
		return ErrConflict
	}
	features := append([]string(nil), parts[1:]...)
	for _, feature := range []agentv1.PasswordNativeFeature{2, 3} {
		was := slices.Contains(before.GetPasswordPolicy().GetEnabledFeatures(), feature)
		want := slices.Contains(target.GetPasswordPolicy().GetEnabledFeatures(), feature)
		if was == want {
			continue
		}
		name := authselectFeature(feature)
		if want {
			if slices.Contains(features, name) {
				return ErrConflict
			}
			features = append(features, name)
		} else {
			if !slices.Contains(features, name) {
				return ErrConflict
			}
			features = slices.DeleteFunc(features, func(item string) bool { return item == name })
		}
	}
	arguments := []string{"test", parts[0], "--nsswitch", "--dconf-db", "--dconf-lock"}
	original, err := run(ctx, "/usr/bin/authselect", append(slices.Clone(arguments), parts[1:]...)...)
	if err != nil {
		return err
	}
	candidate, err := run(ctx, "/usr/bin/authselect", append(arguments, features...)...)
	if err != nil {
		return err
	}
	if !bytes.Equal(original, candidate) {
		return ErrUnsupported
	}
	return nil
}
