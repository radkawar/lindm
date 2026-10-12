//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/enrollment"
	"lindm/internal/agent/localrpc"
	"lindm/internal/pki"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

// runGuestProbe is a development-only guest helper, never a product command.
// Bootstrap material is accepted only on stdin; errors never echo RPC bodies.
func runGuestProbe(ctx context.Context, args []string, stdout, _ io.Writer) error {
	if len(args) == 1 && args[0] == "update-unpack" {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		return guestUpdateUnpack(ctx, stdout)
	}
	if len(args) == 2 && (args[0] == "nvme-identity" || args[0] == "nvme-identify") {
		ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		return guestNVMeIdentity(ctx, args[0] == "nvme-identify", args[1], stdout)
	}
	if len(args) == 2 && args[0] == "alpm-lock-boundary" {
		ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		return guestALPMLock(ctx, args[1], stdout)
	}
	if len(args) != 1 {
		return errors.New("guest requires a single probe operation without flags (bootstrap-interrupted, network-boundaries, executor-ready, connection-identity, connection-certificate, services, action-authorize-denied, live-erase-no-report, update-unpack, redhat-ready, redhat-register, redhat-identity, redhat-repositories, or redhat-unregister), or alpm-lock-boundary <signed-fixture-archive>")
	}
	if args[0] == "redhat-ready" || args[0] == "redhat-register" || args[0] == "redhat-unregister" || args[0] == "redhat-identity" || args[0] == "redhat-repositories" {
		return guestRedHat(ctx, args[0])
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	switch args[0] {
	case "bootstrap-interrupted":
		return guestBootstrapInterrupted(ctx, stdout)
	case "network-boundaries":
		return guestNetworkBoundaries(ctx, stdout)
	case "executor-ready":
		return guestExecutorReady(ctx, stdout)
	case "connection-identity":
		return guestConnectionIdentity(ctx, stdout)
	case "connection-certificate":
		return guestConnectionCertificate(ctx, stdout)
	case "services":
		return guestServices(ctx, stdout)
	case "action-authorize-denied":
		return guestActionAuthorizationDenied(ctx, stdout)
	case "live-erase-no-report":
		return guestLiveEraseWithoutReport(ctx, stdout)
	default:
		return errors.New("unknown guest probe")
	}
}

// guestExecutorReady waits only for an absent or not-yet-listening socket. A
// recovery hold is a valid RPC response, not an uninitialized endpoint; the
// caller must check the lifecycle it expects. Never fall back to offline Inspect
// or retry away peer-authentication, permissions, or other RPC failures.
func guestExecutorReady(ctx context.Context, output io.Writer) (err error) {
	if os.Geteuid() != 0 {
		return errors.New("executor readiness requires root")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	doc, err := config.Load(config.ExecutorConfigPath)
	if err != nil {
		return errors.New("cannot load protected executor configuration")
	}
	client, cleanup, err := localrpc.Dial(doc.SocketPath)
	if err != nil {
		return errors.New("cannot dial root executor")
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	request := connect.NewRequest(&agentv1.StatusRequest{})
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("executor RPC readiness deadline: %w", err)
		}
		call, cancelCall := context.WithTimeout(ctx, 5*time.Second)
		response, callErr := client.Status(call, request)
		cancelCall()
		if callErr == nil {
			return writeGuestEvidence(output, response.Msg)
		}
		var dialErr *net.OpError
		if !errors.As(callErr, &dialErr) || dialErr.Op != "dial" || dialErr.Net != "unix" ||
			(!errors.Is(dialErr, unix.ENOENT) && !errors.Is(dialErr, unix.ECONNREFUSED)) {
			return guestRPCFailure("executor readiness status", callErr)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("executor RPC readiness deadline: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func guestBootstrapInterrupted(ctx context.Context, output io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("interrupted bootstrap requires root")
	}
	deadline := time.Now().Add(30 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	// SSH/sudo can supply a blocking pipe or terminal. NewFile registers a
	// nonblocking descriptor with Go's poller so the one-shot probe can bound
	// its read without a stranded reader goroutine.
	fd, err := unix.FcntlInt(os.Stdin.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return errors.New("cannot duplicate bootstrap stdin")
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return errors.New("cannot prepare bounded bootstrap stdin")
	}
	input := os.NewFile(uintptr(fd), "bootstrap-stdin")
	defer func() { _ = input.Close() }()
	if err := input.SetReadDeadline(deadline); err != nil {
		info, statErr := input.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			return errors.New("bootstrap stdin must support a bounded read")
		}
	}
	data, err := io.ReadAll(io.LimitReader(input, (1<<20)+1))
	defer clear(data)
	if err != nil || len(data) == 0 || len(data) > 1<<20 {
		return errors.New("bootstrap stdin must contain at most 1 MiB of protobuf JSON")
	}
	request := &agentv1.PrepareBootstrapRequest{}
	defer func() {
		clear(request.ExecutionRootJson)
		clear(request.BootstrapEnvelope)
		proto.Reset(request)
	}()
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, request); err != nil {
		return errors.New("invalid bootstrap protobuf JSON")
	}
	if err := protovalidate.Validate(request); err != nil {
		return errors.New("invalid bootstrap request")
	}
	clear(data)
	doc, err := config.Load(config.ExecutorConfigPath)
	if err != nil {
		return errors.New("cannot load protected executor configuration")
	}
	client, cleanup, err := localrpc.Dial(doc.SocketPath)
	if err != nil {
		return errors.New("cannot dial root executor")
	}
	defer func() { _ = cleanup() }()
	prepared, err := client.PrepareBootstrap(ctx, connect.NewRequest(request))
	if err != nil {
		return guestRPCFailure("prepare bootstrap", err)
	}
	defer proto.Reset(prepared.Msg)
	request.PendingGrant = ""
	if err := protovalidate.Validate(prepared.Msg); err != nil {
		return errors.New("invalid prepared bootstrap response")
	}
	issued, err := enrollment.Enroll(ctx, prepared.Msg)
	if err != nil {
		return guestRPCFailure("public enrollment", err)
	}
	prepared.Msg.PendingGrant = ""
	defer proto.Reset(issued)
	cert, err := guestCertificate(issued.GetCertificatePem(), prepared.Msg.GetDeploymentId(), issued.GetDeviceId(), issued.GetEnrollmentGeneration())
	if err != nil {
		return err
	}
	block, rest := pem.Decode(prepared.Msg.GetCsrPem())
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("executor returned invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || !bytes.Equal(csr.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) {
		return errors.New("issued certificate does not bind executor CSR")
	}
	if issued.GetExpiresAt() == nil || issued.GetExpiresAt().CheckValid() != nil || !issued.GetExpiresAt().AsTime().Equal(cert.NotAfter) {
		return errors.New("issued certificate expiration differs from enrollment response")
	}
	fingerprint := sha256.Sum256(cert.Raw)
	// Intentionally omit InstallEnrollment. The normal packaged resume command
	// must retrieve the exact server issuance using the durable protected intent.
	return writeGuestEvidence(output, &labv1.InterruptedBootstrapEvidence{
		DeviceId: issued.GetDeviceId(), EnrollmentGeneration: issued.GetEnrollmentGeneration(),
		CertificateSha256: fingerprint[:], EnrollmentTransactionId: prepared.Msg.GetEnrollmentTransactionId(),
		CertificateNotAfter: issued.GetExpiresAt(),
	})
}

func guestNetworkBoundaries(ctx context.Context, output io.Writer) error {
	doc, err := config.Load(config.NetworkConfigPath)
	if err != nil {
		return errors.New("cannot load protected network configuration")
	}
	if os.Geteuid() == 0 || uint32(os.Geteuid()) != doc.NetworkUID || uint32(os.Getuid()) != doc.NetworkUID {
		return errors.New("network boundaries require the actual configured nonroot network UID")
	}
	client, cleanup, err := localrpc.Dial(doc.SocketPath)
	if err != nil {
		return errors.New("cannot dial root executor")
	}
	defer func() { _ = cleanup() }()
	before, err := client.GetConnection(ctx, connect.NewRequest(&agentv1.GetConnectionRequest{}))
	if err != nil {
		return guestRPCFailure("get connection before probes", err)
	}
	if err := guestConnection(before.Msg); err != nil {
		return err
	}
	evidence := &labv1.NetworkBoundaryEvidence{
		DeviceId: before.Msg.GetDeviceId(), EnrollmentGeneration: before.Msg.GetEnrollmentGeneration(),
		CertificateSha256: before.Msg.GetCertificateSha256(),
	}
	checks := []struct {
		boundary labv1.NetworkBoundary
		path     string
		kind     string
	}{
		{labv1.NetworkBoundary_NETWORK_BOUNDARY_EXECUTOR_STATE_READ_DENIED, doc.StateDirectory, "read-directory"},
		{labv1.NetworkBoundary_NETWORK_BOUNDARY_EXECUTOR_CONFIG_WRITE_DENIED, config.ExecutorConfigPath, "write-file"},
		{labv1.NetworkBoundary_NETWORK_BOUNDARY_NETWORK_CONFIG_WRITE_DENIED, config.NetworkConfigPath, "write-file"},
		{labv1.NetworkBoundary_NETWORK_BOUNDARY_CONFIG_PARENT_WRITE_DENIED, filepath.Dir(config.ExecutorConfigPath), "create-entry"},
		{labv1.NetworkBoundary_NETWORK_BOUNDARY_RUNTIME_DIRECTORY_WRITE_DENIED, doc.RuntimeDirectory, "create-entry"},
		{labv1.NetworkBoundary_NETWORK_BOUNDARY_RUNTIME_PARENT_WRITE_DENIED, filepath.Dir(doc.RuntimeDirectory), "create-entry"},
	}
	for _, check := range checks {
		if err := guestFilesystemDenied(check.path, check.kind); err != nil {
			return fmt.Errorf("%s: %w", check.boundary, err)
		}
		evidence.PassedBoundaries = append(evidence.PassedBoundaries, check.boundary)
	}
	bootstrap, err := client.PrepareBootstrap(ctx, connect.NewRequest(&agentv1.PrepareBootstrapRequest{Resume: true}))
	if bootstrap != nil {
		proto.Reset(bootstrap.Msg)
	}
	if bootstrap != nil || connect.CodeOf(err) != connect.CodePermissionDenied {
		return errors.New("network UID was not denied PrepareBootstrap")
	}
	evidence.PassedBoundaries = append(evidence.PassedBoundaries, labv1.NetworkBoundary_NETWORK_BOUNDARY_PREPARE_BOOTSTRAP_DENIED)
	install := &agentv1.InstallEnrollmentRequest{
		DeviceId: before.Msg.GetDeviceId(), EnrollmentGeneration: before.Msg.GetEnrollmentGeneration(),
		CertificatePem: before.Msg.GetCertificatePem(),
	}
	if err := protovalidate.Validate(install); err != nil {
		return errors.New("current identity cannot form a valid install request")
	}
	installed, err := client.InstallEnrollment(ctx, connect.NewRequest(install))
	if installed != nil || connect.CodeOf(err) != connect.CodePermissionDenied {
		return errors.New("network UID was not denied InstallEnrollment")
	}
	evidence.PassedBoundaries = append(evidence.PassedBoundaries, labv1.NetworkBoundary_NETWORK_BOUNDARY_INSTALL_ENROLLMENT_DENIED)

	// The server context has the correct CertificateVerify length but must
	// never be signed by the client-credential oracle, even for its real cert.
	wrongContext := append([]byte("                                                                TLS 1.3, server CertificateVerify\x00"), make([]byte, 32)...)
	sign := &agentv1.SignTLSClientMessageRequest{CertificateSha256: before.Msg.GetCertificateSha256(), Message: wrongContext}
	if err := protovalidate.Validate(sign); err != nil {
		return errors.New("TLS context probe does not satisfy request shape")
	}
	signed, err := client.SignTLSClientMessage(ctx, connect.NewRequest(sign))
	if signed != nil || !guestRejection(err, connect.CodePermissionDenied, "signing_rejected") {
		return errors.New("executor did not reject wrong TLS context without a signature")
	}
	evidence.PassedBoundaries = append(evidence.PassedBoundaries, labv1.NetworkBoundary_NETWORK_BOUNDARY_TLS_CONTEXT_REJECTED)

	renew := &agentv1.PrepareRenewalRequest{}
	if renew.ProtoReflect().Descriptor().Fields().Len() != 0 {
		return errors.New("PrepareRenewal schema changed; closed CSR probe requires review")
	}
	csr, err := guestCallerCSR()
	if err != nil {
		return err
	}
	// Field 1 is deliberately absent from the real generated empty request.
	// Connect's protobuf wire codec preserves it, exercising server-side closed
	// schema admission rather than merely a local JSON decoder rejection.
	unknown := protowire.AppendTag(nil, 1, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, csr)
	renew.ProtoReflect().SetUnknown(unknown)
	renewed, err := client.PrepareRenewal(ctx, connect.NewRequest(renew))
	if renewed != nil || !guestRejection(err, connect.CodeInvalidArgument, "invalid_request") {
		return errors.New("executor did not reject caller CSR at the closed renewal contract")
	}
	evidence.PassedBoundaries = append(evidence.PassedBoundaries, labv1.NetworkBoundary_NETWORK_BOUNDARY_CALLER_CSR_REJECTED)
	after, err := client.GetConnection(ctx, connect.NewRequest(&agentv1.GetConnectionRequest{}))
	if err != nil {
		return guestRPCFailure("get connection after probes", err)
	}
	if err := guestConnection(after.Msg); err != nil {
		return err
	}
	if after.Msg.GetDeploymentId() != before.Msg.GetDeploymentId() || after.Msg.GetDeviceId() != before.Msg.GetDeviceId() ||
		after.Msg.GetEnrollmentGeneration() != before.Msg.GetEnrollmentGeneration() || after.Msg.GetKeyId() != before.Msg.GetKeyId() ||
		!bytes.Equal(after.Msg.GetCertificateSha256(), before.Msg.GetCertificateSha256()) || !bytes.Equal(after.Msg.GetCertificatePem(), before.Msg.GetCertificatePem()) {
		return errors.New("executor public identity changed during boundary probes")
	}
	evidence.PassedBoundaries = append(evidence.PassedBoundaries, labv1.NetworkBoundary_NETWORK_BOUNDARY_IDENTITY_UNCHANGED)
	return writeGuestEvidence(output, evidence)
}

func guestFilesystemDenied(path, kind string) error {
	if kind == "create-entry" {
		file, err := os.CreateTemp(path, ".lindm-boundary-*")
		if errors.Is(err, os.ErrPermission) {
			return nil
		}
		if err != nil {
			return errors.New("filesystem probe did not observe a permission denial")
		}
		// No existing file is touched. Clean up only this O_EXCL-created entry
		// when a writable directory has exposed an actual packaging defect.
		closeErr := file.Close()
		removeErr := os.Remove(file.Name())
		return errors.Join(errors.New("network UID unexpectedly created a protected directory entry"), closeErr, removeErr)
	}
	flags := unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if kind == "read-directory" {
		flags |= unix.O_RDONLY | unix.O_DIRECTORY
	} else {
		// Opening for write without O_TRUNC or writes proves DAC protection
		// without damaging a configuration if that protection is missing.
		flags |= unix.O_WRONLY
	}
	fd, err := unix.Open(path, flags, 0)
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return nil
	}
	if err != nil {
		return errors.New("filesystem probe did not observe a permission denial")
	}
	return errors.Join(errors.New("network UID unexpectedly opened a protected path"), unix.Close(fd))
}

func guestCallerCSR() ([]byte, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("cannot generate caller CSR key")
	}
	defer clear(key)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, errors.New("cannot construct caller CSR")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func guestCertificate(encoded []byte, deployment, device, generation string) (*x509.Certificate, error) {
	var ids [3]uuid.UUID
	for i, text := range []string{deployment, device, generation} {
		id, err := uuid.Parse(text)
		if err != nil || id == uuid.Nil || id.String() != text {
			return nil, errors.New("noncanonical certificate identity")
		}
		ids[i] = id
	}
	if len(encoded) < 64 || len(encoded) > 16384 {
		return nil, errors.New("invalid certificate size")
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one public certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid public certificate")
	}
	if err := pki.CheckDeviceCertificate(cert, ids[0], ids[1], ids[2]); err != nil {
		return nil, errors.New("certificate identity binding rejected")
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		return nil, errors.New("certificate is not an Ed25519 credential")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, errors.New("certificate is not currently usable")
	}
	return cert, nil
}

func guestConnection(connection *agentv1.GetConnectionResponse) error {
	if connection == nil || connection.GetRenewalPending() || connection.GetRetrieval() != nil || connection.GetIdentityExpired() ||
		connection.GetCredentialKind() != agentv1.TLSCredentialKind_TLS_CREDENTIAL_KIND_ED25519 {
		return errors.New("connection must have usable enrolled identity and no pending renewal")
	}
	cert, err := guestCertificate(connection.GetCertificatePem(), connection.GetDeploymentId(), connection.GetDeviceId(), connection.GetEnrollmentGeneration())
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(cert.Raw)
	publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("certificate is not an Ed25519 credential")
	}
	keyID, err := trust.KeyID(publicKey)
	if err != nil || keyID != connection.GetKeyId() || !bytes.Equal(fingerprint[:], connection.GetCertificateSha256()) ||
		connection.GetCertificateNotAfter() == nil || connection.GetCertificateNotAfter().CheckValid() != nil || !cert.NotAfter.Equal(connection.GetCertificateNotAfter().AsTime()) {
		return errors.New("connection public credential binding rejected")
	}
	return nil
}

func guestRejection(err error, code connect.Code, reason string) bool {
	var rpcErr *connect.Error
	return errors.As(err, &rpcErr) && rpcErr.Code() == code && rpcreason.Get(rpcErr) == reason
}

func guestRPCFailure(operation string, err error) error {
	// Never propagate remote descriptions or validation text: bootstrap
	// requests and responses may contain grants or other protected material.
	// A Lindm-Reason is a fixed snake_case code; anything else is withheld.
	if reason := rpcreason.Get(err); guestReasonCode(reason) {
		return fmt.Errorf("%s failed (%s: %s)", operation, connect.CodeOf(err), reason)
	}
	return fmt.Errorf("%s failed (%s)", operation, connect.CodeOf(err))
}

func guestReasonCode(reason string) bool {
	if reason == "" || len(reason) > 64 {
		return false
	}
	for _, r := range reason {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func writeGuestEvidence(output io.Writer, evidence proto.Message) error {
	if err := protovalidate.Validate(evidence); err != nil {
		return errors.New("guest evidence did not satisfy its protobuf contract")
	}
	data, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(evidence)
	if err != nil {
		return errors.New("cannot encode guest evidence")
	}
	_, err = output.Write(append(data, '\n'))
	return err
}
