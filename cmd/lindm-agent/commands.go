//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/actionprovider"
	"lindm/internal/agent/config"
	"lindm/internal/agent/enrollment"
	"lindm/internal/agent/executor"
	"lindm/internal/agent/journal"
	"lindm/internal/agent/localrpc"
	"lindm/internal/agent/transport"
)

func serveExecutor(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("executor accepts no arguments")
	}
	doc, err := config.Load(config.ExecutorConfigPath)
	if err != nil {
		return err
	}
	if actionConfig := doc.Proto.GetActionProvider(); actionConfig.GetRecoveryEnvironment() && actionConfig.GetProtectedStateDirectory() != doc.StateDirectory {
		return errors.New("recovery action state directory must be the actual executor journal directory")
	}
	// Pin before opening the journal: retained account ownership contains exact
	// shadow credentials even before the provider factory is constructed.
	if actionMemoryRequired(doc.Proto.GetActionProvider()) {
		if err := actionprovider.PinLiveRootMemory(); err != nil {
			return err
		}
	}
	return executor.Run(ctx, executor.Config{
		StateDirectory: doc.StateDirectory, RuntimeDirectory: doc.RuntimeDirectory,
		SocketName: doc.SocketName, NetworkUID: doc.NetworkUID, NetworkGID: doc.NetworkGID,
		RequireRoot: true,
		ActionProviderFactory: func(store *journal.Store) (executor.DeviceActionProvider, error) {
			return nativeActionProvider(doc.Proto.GetActionProvider(), store)
		},
		ActionProviderConfig: doc.Proto.GetActionProvider(),
		RecoveryBoot:         recoveryBootConfig(doc.Proto.GetRecoveryBoot()),
		Updates:              doc.Proto.GetUpdates(),
		// Effective providers: this document merged with the verified signed
		// capability policy, re-derived whenever the policy record changes.
		Local:                   doc,
		RemoteAssistance:        doc.Proto.GetRemoteAssistance(),
		SessionRuntimeDirectory: doc.SessionRuntimeDirectory,
	})
}

func serveNetwork(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("run accepts no arguments")
	}
	doc, err := config.Load(config.NetworkConfigPath)
	if err != nil {
		return err
	}
	return transport.Run(ctx, doc)
}

func bootstrapCommand(ctx context.Context, args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("bootstrap requires root")
	}
	flags := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	rootPath := flags.String("root", "", "authenticated execution-root document")
	bundlePath := flags.String("bundle", "", "DSSE-signed bootstrap bundle")
	grantPath := flags.String("grant", "", "protected grant file, or - for stdin")
	tokenPath := flags.String("provisioning-token-file", "", "root-only boot-delivered reusable provisioning token file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *rootPath == "" || *bundlePath == "" || (*grantPath == "") == (*tokenPath == "") || *tokenPath == "-" {
		return errors.New("bootstrap requires -root FILE -bundle FILE and exactly one of -grant FILE or -provisioning-token-file FILE")
	}
	root, err := readNoFollow(*rootPath, 64<<10, false)
	if err != nil {
		return fmt.Errorf("read execution root: %w", err)
	}
	bundle, err := readNoFollow(*bundlePath, 512<<10, false)
	if err != nil {
		return fmt.Errorf("read bootstrap bundle: %w", err)
	}
	if *tokenPath != "" {
		*grantPath = *tokenPath
	}
	grant, err := readGrant(*grantPath)
	if err != nil {
		return err
	}
	return finishEnrollment(ctx, &agentv1.PrepareBootstrapRequest{ExecutionRootJson: root, BootstrapEnvelope: bundle, PendingGrant: grant, ProvisioningToken: *tokenPath != ""})
}

func resumeCommand(ctx context.Context, args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("resume requires root")
	}
	flags := flag.NewFlagSet("resume", flag.ContinueOnError)
	wait := flags.Uint64("wait-seconds", 0, "bounded root-only approval wait, at most 86400 seconds")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("resume accepts only -wait-seconds SECONDS")
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(&agentv1.EnrollmentResumeOptions{}), protovalidate.WithDisableLazy())
	if err != nil {
		return err
	}
	if err := validator.Validate(&agentv1.EnrollmentResumeOptions{WaitSeconds: *wait}); err != nil {
		return errors.New("invalid enrollment resume wait")
	}
	if *wait == 0 {
		return finishEnrollment(ctx, &agentv1.PrepareBootstrapRequest{Resume: true})
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(*wait)*time.Second)
	defer cancel()
	for {
		err := finishEnrollment(ctx, &agentv1.PrepareBootstrapRequest{Resume: true})
		if err == nil {
			return nil
		}
		if !errors.Is(err, enrollment.ErrPendingApproval) && connect.CodeOf(err) != connect.CodeUnavailable && connect.CodeOf(err) != connect.CodeDeadlineExceeded {
			return err
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("enrollment resume wait ended without installation: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func finishEnrollment(ctx context.Context, request *agentv1.PrepareBootstrapRequest) error {
	doc, err := config.Load(config.ExecutorConfigPath)
	if err != nil {
		return err
	}
	client, cleanup, err := localrpc.Dial(doc.SocketPath)
	if err != nil {
		return err
	}
	defer func() { _ = cleanup() }()
	status, err := client.Status(ctx, connect.NewRequest(&agentv1.StatusRequest{}))
	if err != nil {
		return err
	}
	if status.Msg.GetLifecycle() == agentv1.Lifecycle_LIFECYCLE_ENROLLED {
		if !status.Msg.GetTlsUsable() {
			return errors.New("installed identity is not usable; explicit identity recovery is required")
		}
		return nil
	}
	prepared, err := client.PrepareBootstrap(ctx, connect.NewRequest(request))
	if err != nil {
		return err
	}
	enrolled, err := enrollment.Enroll(ctx, prepared.Msg)
	if errors.Is(err, enrollment.ErrPendingApproval) {
		if request.GetResume() {
			return enrollment.ErrPendingApproval
		}
		_, printErr := fmt.Println("Enrollment reserved; awaiting administrator approval. Run lindm-agent resume after approval.")
		return printErr
	}
	if err != nil {
		return fmt.Errorf("enrollment rejected: %w", err)
	}
	installed, err := client.InstallEnrollment(ctx, connect.NewRequest(&agentv1.InstallEnrollmentRequest{
		DeviceId: enrolled.GetDeviceId(), EnrollmentGeneration: enrolled.GetEnrollmentGeneration(), CertificatePem: enrolled.GetCertificatePem(),
	}))
	if err != nil {
		return err
	}
	_, err = fmt.Printf("Enrolled device %s generation %s.\nRenew after %s.\n", installed.Msg.GetDeviceId(), installed.Msg.GetEnrollmentGeneration(), installed.Msg.GetRenewAfter().AsTime().UTC().Format(time.RFC3339))
	return err
}

func statusCommand(ctx context.Context, args []string, output io.Writer) error {
	if len(args) != 0 {
		return errors.New("status accepts no arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("status requires root")
	}
	doc, err := config.Load(config.ExecutorConfigPath)
	if err != nil {
		return err
	}
	if reported, err := statusFromSocket(ctx, doc.SocketPath); err == nil {
		return writeStatus(output, combinedStatus(doc, reported))
	}
	reported, err := executor.Inspect(ctx, doc.StateDirectory)
	if errors.Is(err, executor.ErrBusy) {
		return errors.New("executor is running but its socket did not answer")
	}
	if err != nil {
		return err
	}
	return writeStatus(output, combinedStatus(doc, reported))
}

func statusFromSocket(ctx context.Context, socketPath string) (*agentv1.StatusResponse, error) {
	client, cleanup, err := localrpc.Dial(socketPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := client.Status(call, connect.NewRequest(&agentv1.StatusRequest{}))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func writeStatus(output io.Writer, status *agentv1.AgentStatus) error {
	data, err := (protojson.MarshalOptions{Indent: "  ", UseProtoNames: true}).Marshal(status)
	if err != nil {
		return err
	}
	_, err = output.Write(append(data, '\n'))
	return err
}

func combinedStatus(doc *config.Document, executorStatus *agentv1.StatusResponse) *agentv1.AgentStatus {
	result := &agentv1.AgentStatus{Executor: executorStatus}
	report, err := transport.ReadStatus(doc)
	switch {
	case errors.Is(err, os.ErrNotExist):
		result.TransportReportState = agentv1.TransportReportState_TRANSPORT_REPORT_STATE_NOT_RECORDED
	case err != nil:
		result.TransportReportState = agentv1.TransportReportState_TRANSPORT_REPORT_STATE_UNREADABLE
	case report.GetDeviceId() != "" && (report.GetDeploymentId() != executorStatus.GetDeploymentId() || report.GetDeviceId() != executorStatus.GetDeviceId() || report.GetEnrollmentGeneration() != executorStatus.GetEnrollmentGeneration()):
		result.TransportReportState = agentv1.TransportReportState_TRANSPORT_REPORT_STATE_IDENTITY_MISMATCH
	default:
		result.Transport = report
		result.TransportReportState = agentv1.TransportReportState_TRANSPORT_REPORT_STATE_RECORDED
	}
	return result
}
