// SPDX-License-Identifier: Apache-2.0

package vmlab

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"
)

// systemctl start does not establish that a Type=simple service is listening.
// Observe only the public readiness GET; no restore or management work is retried.
func waitDeployReadiness(ctx context.Context, origin string, trust *tls.Config) error {
	transport := &http.Transport{TLSClientConfig: trust}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/readyz", nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err == nil {
			if closeErr := response.Body.Close(); closeErr != nil {
				return closeErr
			}
			if response.StatusCode == http.StatusNoContent {
				return nil
			}
			if response.StatusCode != http.StatusServiceUnavailable {
				return fmt.Errorf("native readiness refused HTTP %d", response.StatusCode)
			}
		} else if !deployReadinessStarting(err) {
			return fmt.Errorf("native readiness TLS or transport refused: %w", err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("native readiness deadline: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func deployReadinessStarting(err error) bool {
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		return false
	}
	var network net.Error
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || (errors.As(err, &network) && network.Timeout())
}
