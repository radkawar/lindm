package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"

	"connectrpc.com/connect"

	"lindm/gen/lindm/recovery/v1/recoveryv1connect"
)

// NewRecoveryClient creates the separate one-action proof endpoint client. It
// pins server trust and deliberately has no device certificate, cookie jar,
// proxy, redirects or ordinary device/admin client. The caller closes idle
// connections after its single recovery execution.
func NewRecoveryClient(origin string, caPEM []byte) (recoveryv1connect.RecoveryServiceClient, func(), error) {
	if err := checkOrigin(origin); err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	if len(caPEM) == 0 || len(caPEM) > 65536 || !roots.AppendCertsFromPEM(caPEM) {
		return nil, nil, errors.New("invalid pinned recovery transport trust")
	}
	transport := newHTTPTransport(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	client := recoveryv1connect.NewRecoveryServiceClient(newHTTPClient(transport), origin, connect.WithReadMaxBytes(1<<20))
	return client, transport.CloseIdleConnections, nil
}
