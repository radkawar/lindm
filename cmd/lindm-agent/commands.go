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

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/enrollment"
	"lindm/internal/agent/executor"
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
	return executor.Run(ctx, executor.Config{
		StateDirectory: doc.StateDirectory, RuntimeDirectory: doc.RuntimeDirectory,
		SocketName: doc.SocketName, NetworkUID: doc.NetworkUID, NetworkGID: doc.NetworkGID,
		RequireRoot: true,
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
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *rootPath == "" || *bundlePath == "" || *grantPath == "" {
		return errors.New("bootstrap requires -root FILE -bundle FILE -grant FILE")
	}
	root, err := readNoFollow(*rootPath, 64<<10, false)
	if err != nil {
		return fmt.Errorf("read execution root: %w", err)
	}
	bundle, err := readNoFollow(*bundlePath, 512<<10, false)
	if err != nil {
		return fmt.Errorf("read bootstrap bundle: %w", err)
	}
	grant, err := readGrant(*grantPath)
	if err != nil {
		return err
	}
	return finishEnrollment(ctx, &agentv1.PrepareBootstrapRequest{ExecutionRootJson: root, BootstrapEnvelope: bundle, PendingGrant: grant})
}

func resumeCommand(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("resume accepts no arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("resume requires root")
	}
	return finishEnrollment(ctx, &agentv1.PrepareBootstrapRequest{Resume: true})
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
	prepared, err := client.PrepareBootstrap(ctx, connect.NewRequest(request))
	if err != nil {
		return err
	}
	enrolled, err := enrollment.Enroll(ctx, prepared.Msg)
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
