// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localrpc

import (
	"context"
	"errors"
	"net"
	"net/http"

	"connectrpc.com/connect"

	"lindm/gen/lindm/agent/v1/agentv1connect"
)

// DialSession returns a SessionService client for the session-helper socket
// and a cleanup that closes idle connections. The caller must call cleanup.
// Like Dial, every connection checks SO_PEERCRED and refuses a server peer
// that is not UID 0 before any HTTP request bytes are written, so a socket
// planted by another user is never spoken to. Messages are bounded like the
// server side.
func DialSession(socketPath string) (agentv1connect.SessionServiceClient, func() error, error) {
	return dialSession(socketPath, requireRootSessionPeer)
}

func dialSession(socketPath string, authenticate func(net.Conn) error) (agentv1connect.SessionServiceClient, func() error, error) {
	if socketPath == "" || authenticate == nil {
		return nil, nil, errors.New("missing session socket")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, "unix", socketPath)
			if err != nil {
				return nil, err
			}
			if err := authenticate(conn); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		},
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
	}
	httpClient := &http.Client{Transport: transport}
	cleanup := func() error {
		httpClient.CloseIdleConnections()
		return nil
	}
	client := agentv1connect.NewSessionServiceClient(httpClient, SessionBaseURL,
		connect.WithReadMaxBytes(maxSessionMessageBytes),
		connect.WithSendMaxBytes(maxSessionMessageBytes),
	)
	return client, cleanup, nil
}

func requireRootSessionPeer(conn net.Conn) error {
	uid, err := peerCredential(conn)
	if err != nil {
		return err
	}
	if uid != 0 {
		return errors.New("session socket peer is not root")
	}
	return nil
}
