//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"os"

	"connectrpc.com/connect"

	agentv1 "lindm/gen/lindm/agent/v1"
	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/agent/config"
	"lindm/internal/agent/localrpc"
)

func guestConnectionIdentity(ctx context.Context, output io.Writer) (err error) {
	document, err := config.Load(config.NetworkConfigPath)
	if err != nil {
		return err
	}
	if uint32(os.Geteuid()) != document.NetworkUID {
		return errors.New("connection identity evidence requires the configured network UID")
	}
	client, cleanup, err := localrpc.Dial(document.SocketPath)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	response, err := client.GetConnection(ctx, connect.NewRequest(&agentv1.GetConnectionRequest{}))
	if err != nil {
		return guestRPCFailure("connection identity", err)
	}
	connection := response.Msg
	if err := guestConnection(connection); err != nil {
		return err
	}
	if roots := x509.NewCertPool(); !roots.AppendCertsFromPEM(connection.GetTransportCaPem()) {
		return errors.New("connection identity has no usable transport pins")
	}
	pins := sha256.Sum256(connection.GetTransportCaPem())
	return writeGuestEvidence(output, &labv1.ConnectionIdentityEvidence{
		DeploymentId: connection.GetDeploymentId(), DeviceId: connection.GetDeviceId(), EnrollmentGeneration: connection.GetEnrollmentGeneration(),
		EnrollmentOrigin: connection.GetEnrollmentOrigin(), DeviceOrigin: connection.GetDeviceOrigin(),
		TransportCaSha256: pins[:], CertificateSha256: connection.GetCertificateSha256(), KeyId: connection.GetKeyId(),
	})
}
