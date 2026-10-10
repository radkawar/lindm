//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func exerciseResourceFileAdoption(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence) error {
	r.profile, r.resource, r.revision = uuid.NewString(), uuid.NewString(), ""
	const path = resourceFileRoot + "/adopted"
	// Numeric IDs deliberately differ from the requested root-owned metadata;
	// this file is disposable and is never an account home or credential file.
	if err := lifecycleCommand(ctx, r.vm, "construct independently owned file baseline", "test ! -e "+path+"; printf 'baseline\\n' > "+path+"; chmod 0644 "+path+"; chown 65534:65534 "+path+"; setfattr -n user.lindm_resource_baseline -v preserved "+path+"; if command -v restorecon >/dev/null 2>&1; then restorecon -F "+path+"; fi"); err != nil {
		return err
	}
	baselineCommand := "test \"$(stat -c '%a:%u:%g' " + path + ")\" = '644:65534:65534'; test \"$(cat " + path + ")\" = baseline; test \"$(getfattr --only-values -n user.lindm_resource_baseline " + path + " 2>/dev/null)\" = preserved; stat -c '%n %a %u %g %s' " + path + "; sha256sum " + path + "; getfattr -d -m- --absolute-names " + path + "; if test -e /sys/fs/selinux/enforce; then test \"$(getenforce)\" = Enforcing; getenforce; fi"
	baseline, err := resourceOracle(ctx, r.vm, "adoption-baseline", baselineCommand)
	if err != nil {
		return err
	}
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: "approved-adoption", StartedAt: time.Now().UTC(), Native: []VMResourceNativeRecord{baseline}})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	desired := resourceFileDesired("adopted", "adopted-managed\n")
	ownership := &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}
	if err := r.assign(ctx, desired, ownership); err != nil {
		s.Failure = err.Error()
		return err
	}
	s.Action, err = r.action(ctx, false)
	if err != nil {
		s.Failure = err.Error()
		return err
	}
	native, err := fileOracle(ctx, r.vm, "adopted", "adopted-managed\n", true)
	if err != nil {
		s.Failure = err.Error()
		return err
	}
	s.Native = append(s.Native, native)
	s.Passed = true
	s.FinishedAt = time.Now().UTC()
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: "restore-adopted-baseline", StartedAt: time.Now().UTC()})
	s = &evidence.Scenarios[len(evidence.Scenarios)-1]
	s.Release, err = r.release(ctx, desired.GetRef(), false)
	if err != nil {
		s.Failure = err.Error()
		return err
	}
	restored, err := resourceOracle(ctx, r.vm, "restored-baseline", baselineCommand)
	if err != nil {
		s.Failure = err.Error()
		return err
	}
	if !bytes.Equal(restored.Bytes, baseline.Bytes) {
		return errors.New("adopted file release changed baseline content, mode, UID, GID, xattrs or SELinux label")
	}
	s.Native = []VMResourceNativeRecord{baseline, restored}
	s.Passed = true
	s.FinishedAt = time.Now().UTC()
	return nil
}
