//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

func resourceWrongSigner(ctx context.Context, vm *guestVM, rpm resourcePackaging) (func(context.Context) error, error) {
	configBytes, err := vm.run(ctx, "sudo -n cat /etc/lindm/executor.json", nil, 128<<10, 15*time.Second)
	if err != nil {
		return nil, err
	}
	config := new(agentv1.AgentConfig)
	if err := protojson.Unmarshal(configBytes, config); err != nil {
		return nil, err
	}
	path := resourceFixtureRoot + "/wrong.gpg"
	if rpm.rpm {
		path = resourceFixtureRoot + "/wrong.asc"
	}
	key, err := vm.run(ctx, "sudo -n cat "+path, nil, 16384, 15*time.Second)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(key)
	source := config.GetPackageProvider().GetSources()[0]
	source.SigningKeyFile = path
	source.SigningKeySha256 = digest[:]
	if rpm.rpm {
		artifact := source.GetRepository().GetRpm().GetSigningKeys()[0]
		artifact.Sha256 = digest[:]
		artifact.SizeBytes = uint64(len(key))
		listed, err := vm.run(ctx, "sudo -n cat "+resourceFixtureRoot+"/wrong-keys.colons", nil, 16384, 15*time.Second)
		if err != nil {
			return nil, err
		}
		source.RpmSigningKeyFingerprint = ""
		for line := range strings.SplitSeq(string(listed), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) > 9 && fields[0] == "fpr" {
				source.RpmSigningKeyFingerprint = fields[9]
				break
			}
		}
	} else {
		artifact := source.GetRepository().GetApt().GetSigningKey()
		artifact.Sha256 = digest[:]
		artifact.SizeBytes = uint64(len(key))
	}
	if err := protovalidate.Validate(config); err != nil {
		return nil, err
	}
	altered, err := protojson.Marshal(config)
	if err != nil {
		return nil, err
	}
	writeConfig := func(ctx context.Context, data []byte) error {
		if _, err := vm.run(ctx, "sudo -n /bin/sh -eu -c 'umask 077; cat > /etc/lindm/resource-config.upload; install -o root -g root -m 0600 /etc/lindm/resource-config.upload /etc/lindm/executor.json; rm /etc/lindm/resource-config.upload; systemctl restart lindm-executor.service'", bytes.NewReader(data), 16384, time.Minute); err != nil {
			return err
		}
		_, err := waitGuestExecutorReady(ctx, vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED)
		return err
	}
	if err := writeConfig(ctx, altered); err != nil {
		return nil, err
	}
	return func(ctx context.Context) error { return writeConfig(ctx, configBytes) }, nil
}

// Negative scenarios run while v1 is installed. Independent before/after
// evidence proves that an authenticated failure is not merely server rejection.
func exercisePackageRefusals(ctx context.Context, r *resourceDispatch, rpm resourcePackaging, evidence *VMResourceKindEvidence) error {
	for _, name := range []string{"wrong-signing-key-refused", "unavailable-exact-version-refused"} {
		evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: name, StartedAt: time.Now().UTC()})
		s := &evidence.Scenarios[len(evidence.Scenarios)-1]
		before, err := packageOracle(ctx, r.vm, rpm, "1.0", true)
		if err != nil {
			return err
		}
		version := "99.0"
		var restore func(context.Context) error
		if name == "wrong-signing-key-refused" {
			version = "2.0"
			restore, err = resourceWrongSigner(ctx, r.vm, rpm)
			if err != nil {
				return err
			}
		}
		runErr := r.assign(ctx, resourcePackageDesired(rpm, version, true), resourceCreatePolicy())
		if runErr == nil {
			s.Action, runErr = r.action(ctx, true)
		}
		if restore != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			runErr = errors.Join(runErr, restore(cleanup))
			cancel()
		}
		if runErr != nil {
			s.Failure = runErr.Error()
			return runErr
		}
		if s.Action.GetStartAuthorizedAt() != nil {
			return errors.New("invalid package source/version acquired native effect authority")
		}
		after, err := packageOracle(ctx, r.vm, rpm, "1.0", true)
		if err != nil {
			return err
		}
		if !bytes.Equal(before.Bytes, after.Bytes) {
			return errors.New("rejected package source/version changed native package state")
		}
		s.Native = []VMResourceNativeRecord{before, after}
		s.Passed = true
		s.FinishedAt = time.Now().UTC()
	}
	return nil
}

func exercisePackageDrift(ctx context.Context, r *resourceDispatch, rpm resourcePackaging, evidence *VMResourceKindEvidence) error {
	r.profile, r.resource, r.revision = uuid.NewString(), uuid.NewString(), ""
	desired := resourcePackageDesired(rpm, "1.0", true)
	if err := r.assign(ctx, desired, resourceCreatePolicy()); err != nil {
		return err
	}
	action, err := r.action(ctx, false)
	if err != nil {
		return err
	}
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: "external-pin-drift-release-refused", StartedAt: time.Now().UTC(), Action: action})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	path := "/etc/dnf/versionlock.toml"
	switch {
	case rpm.dnf4:
		path = dnf4VersionlockList
	case !rpm.rpm:
		digest := sha256.Sum256([]byte(desired.GetRef().GetCanonicalKey()))
		path = fmt.Sprintf("/etc/apt/preferences.d/lindm-%x", digest)
	}
	if err := lifecycleCommand(ctx, r.vm, "inject external native pin drift", "systemctl stop lindm-agent.service; printf '\\n# external-owner-edit\\n' >> "+path); err != nil {
		return err
	}
	before, err := packageOracle(ctx, r.vm, rpm, "1.0", true)
	if err != nil {
		return err
	}
	sourceHead := r.head
	clear, err := r.control.session.Admin.SetResourceAssignment(ctx, connect.NewRequest(&adminv1.SetResourceAssignmentRequest{RequestId: uuid.NewString(), DeviceId: r.device, ExpectedAssignmentId: proto.String(r.head), Clear: true, Reason: "external native package pin edit must block release"}))
	if err != nil {
		return err
	}
	r.head = clear.Msg.GetAssignment().GetAssignmentId()
	if err := lifecycleCommand(ctx, r.vm, "resume package release relay", "systemctl start lindm-agent.service"); err != nil {
		return err
	}
	s.Release, err = waitResourceReleaseConflict(ctx, r.control, r.device, sourceHead, desired.GetRef())
	if err != nil {
		s.Failure = err.Error()
		return err
	}
	after, err := packageOracle(ctx, r.vm, rpm, "1.0", true)
	if err != nil {
		return err
	}
	if !bytes.Equal(before.Bytes, after.Bytes) {
		return errors.New("external native package pin overwritten during release")
	}
	s.Native = []VMResourceNativeRecord{before, after}
	s.FinishedAt = time.Now().UTC()
	s.Passed = true
	return nil
}

// The safe maintainer-script witness blocks after entering a real transaction.
// Killing its fixed helper cgroup and the executor models an interrupted RUNNING
// effect. A fresh root session must retain terminal uncertainty, never replay it.
func exercisePackageInterruption(ctx context.Context, r *resourceDispatch, rpm resourcePackaging, evidence *VMResourceKindEvidence) error {
	r.profile, r.resource, r.revision = uuid.NewString(), uuid.NewString(), ""
	desired := resourcePackageDesired(rpm, "1.0", true)
	desired.GetNativePackage().Package.NativeName = "lindm-resource-crash"
	desired.Ref.CanonicalKey = strings.Replace(desired.Ref.CanonicalKey, resourcePackageName, "lindm-resource-crash", 1)
	if err := lifecycleCommand(ctx, r.vm, "arm safe native maintainer interruption", "test ! -e "+resourceFixtureRoot+"/interrupt.log; touch "+resourceFixtureRoot+"/interrupt"); err != nil {
		return err
	}
	if err := r.assign(ctx, desired, resourceCreatePolicy()); err != nil {
		return err
	}
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: "interrupted-running-no-replay", StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	waitCtx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	var action *adminv1.ServiceActionSummary
	notReached := func(err error) error {
		s.Native = append(s.Native, executorDiagnostics(ctx, r.vm))
		if state, err := r.vm.runResult(ctx, "sudo -n sh -c 'ls -lZ "+resourceFixtureRoot+"; cat "+resourceFixtureRoot+"/maintainer.log; systemctl --no-pager list-units --all \"lindm-*\"' 2>&1", nil, 64<<10, 30*time.Second); err == nil {
			s.Native = append(s.Native, resourceNativeRecord("failure-diagnostic-interrupt-state", state.Stdout))
		}
		return fmt.Errorf("native maintainer interruption point not reached (action %q): %w", action.GetActionId(), err)
	}
	for {
		state, err := r.control.dispatchState(waitCtx, r.device)
		if err != nil {
			return notReached(err)
		}
		if len(state.GetResources()) == 1 {
			action = state.GetResources()[0].GetLatestAction()
		}
		marker, err := r.vm.runResult(waitCtx, "sudo -n test -s "+resourceFixtureRoot+"/interrupt.log", nil, 1024, 10*time.Second)
		if err != nil {
			return notReached(err)
		}
		if marker.ExitCode == 0 && action.GetStartAuthorizedAt() != nil {
			break
		}
		if err := lifecycleDelay(waitCtx, 100*time.Millisecond); err != nil {
			return notReached(err)
		}
	}
	id, err := uuid.Parse(action.GetActionId())
	if err != nil {
		return err
	}
	if err := lifecycleCommand(ctx, r.vm, "interrupt real running package effect", "systemctl stop lindm-agent.service; for k in /sys/fs/cgroup/system.slice/lindm-package-*-apply.service/cgroup.kill; do echo 1 > \"$k\"; done; systemctl kill "+systemctlKillWhom+"=main --signal=KILL lindm-executor.service; systemctl start lindm-executor.service; systemctl start lindm-agent.service"); err != nil {
		return err
	}
	s.Action, err = r.action(ctx, true)
	if err != nil {
		s.Failure = err.Error()
		return err
	}
	if s.Action.GetActionId() != id.String() || s.Action.GetStatus().GetStartedAt() == nil {
		return errors.New("interrupted native action replaced or lost its effect boundary")
	}
	command := "test \"$(cat " + resourceFixtureRoot + "/interrupt.log)\" = entered; cat " + resourceFixtureRoot + "/interrupt.log; cat " + resourceFixtureRoot + "/maintainer.log; "
	if rpm.rpm {
		command += "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\\n' 'lindm-resource-*'"
	} else {
		command += "dpkg-query -W -f='${Package} ${Version} ${db:Status-Status}\\n' 'lindm-resource-*'"
	}
	before, err := resourceOracle(ctx, r.vm, "interrupted-native-transaction", command)
	if err != nil {
		return err
	}
	if err := lifecycleCommand(ctx, r.vm, "restart executor without replay authority", "systemctl restart lindm-executor.service lindm-agent.service"); err != nil {
		return err
	}
	if _, err := waitGuestExecutorReady(ctx, r.vm, agentv1.Lifecycle_LIFECYCLE_ENROLLED); err != nil {
		return err
	}
	// Exact terminal CLI lookup proves executor recovery did not mint a new run;
	// it does not claim that the interrupted package database is healthy.
	response := new(agentv1.GetResourceExecutionResponse)
	packages := &nativeGuestPackages{vm: r.vm}
	if err := vmServiceRPC(ctx, packages, "resource-status", id.String(), &agentv1.GetResourceExecutionRequest{ActionId: id.String()}, response); err != nil {
		return err
	}
	if !proto.Equal(response.GetStatus(), s.Action.GetStatus()) {
		return errors.New("executor restart changed terminal interrupted package history")
	}
	after, err := resourceOracle(ctx, r.vm, "interrupted-native-transaction-after-restart", command)
	if err != nil {
		return err
	}
	if !bytes.Equal(before.Bytes, after.Bytes) {
		return errors.New("interrupted native maintainer script replayed after restart")
	}
	s.Native = []VMResourceNativeRecord{before, after}
	s.FinishedAt = time.Now().UTC()
	s.Passed = true
	return nil
}
