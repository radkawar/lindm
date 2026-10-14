// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
)

// A credential or either pinned origin-root change retires the old idle connections.
// Boot/session transitions alone do not require another TLS handshake.
type connectionCache struct {
	connection *agentv1.GetConnectionResponse
	servers    *connections
}

func (c *connectionCache) Get(executor agentv1connect.ExecutorServiceClient, connection *agentv1.GetConnectionResponse) (*connections, error) {
	previous := c.connection
	if previous != nil && previous.GetDeploymentId() == connection.GetDeploymentId() && previous.GetDeviceId() == connection.GetDeviceId() && previous.GetEnrollmentGeneration() == connection.GetEnrollmentGeneration() && previous.GetEnrollmentOrigin() == connection.GetEnrollmentOrigin() && previous.GetDeviceOrigin() == connection.GetDeviceOrigin() && previous.GetKeyId() == connection.GetKeyId() && previous.GetCredentialKind() == connection.GetCredentialKind() && (len(previous.GetCertificatePem()) == 0) == (len(connection.GetCertificatePem()) == 0) && bytes.Equal(previous.GetCertificateSha256(), connection.GetCertificateSha256()) && bytes.Equal(previous.GetTransportCaPem(), connection.GetTransportCaPem()) && bytes.Equal(previous.GetConsoleCaPem(), connection.GetConsoleCaPem()) {
		return c.servers, nil
	}
	servers, err := connectServers(executor, connection)
	if err != nil {
		return nil, err
	}
	c.Close()
	c.connection = connection
	c.servers = servers
	return servers, nil
}

func (c *connectionCache) Close() {
	if c.servers != nil {
		c.servers.Close()
	}
	c.connection = nil
	c.servers = nil
}
