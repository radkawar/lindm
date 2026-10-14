// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
)

// startAgentUpdates is independent of device-session/plan compatibility: an old
// but enrolled agent must still obtain a verified update. It never needs a grant.
func startAgentUpdates(parent context.Context, executor agentv1connect.ExecutorServiceClient) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			delay, err := agentUpdateCycle(ctx, executor)
			if err != nil && ctx.Err() == nil {
				slog.Warn("agent update transport incomplete", "error", err)
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}

func agentUpdateCycle(parent context.Context, executor agentv1connect.ExecutorServiceClient) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(parent, 16*time.Minute)
	defer cancel()
	connection, err := rpc(ctx, executor.GetConnection, &agentv1.GetConnectionRequest{})
	if err != nil {
		return time.Minute, err
	}
	if connection.GetDeviceActionReportOnly() {
		return time.Minute, nil
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(connection.GetTransportCaPem()) {
		return time.Minute, errors.New("update transport has no protected TLS roots")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 16 << 10, DisableCompression: true}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("update repository redirect rejected") }}
	defer client.CloseIdleConnections()
	answer := &agentv1.ExchangeAgentUpdateRequest{}
	for {
		response, err := rpc(ctx, executor.ExchangeAgentUpdate, answer)
		if err != nil {
			return time.Minute, err
		}
		delay := time.Duration(response.GetPollIntervalSeconds()) * time.Second
		if delay < time.Second || delay > 24*time.Hour {
			delay = time.Minute
		}
		fetch := response.GetFetch()
		if fetch == nil {
			phase := response.GetStatus().GetPhase()
			if phase != "checking" && phase != "staged" && phase != "applying" && phase != "installing" {
				return delay, nil
			}
			answer = &agentv1.ExchangeAgentUpdateRequest{}
			continue
		}
		// A completed identity/session exchange is NOT permission to update after
		// live-root erasure. Recheck the protected gate before every network read.
		connection, err = rpc(ctx, executor.GetConnection, &agentv1.GetConnectionRequest{})
		if err != nil {
			return time.Minute, err
		}
		if connection.GetDeviceActionReportOnly() {
			return time.Minute, nil
		}
		answer = fetchAgentUpdateChunk(ctx, client, response.GetRepositoryUrl(), fetch)
	}
}

func fetchAgentUpdateChunk(ctx context.Context, client *http.Client, base string, fetch *agentv1.AgentUpdateFetch) *agentv1.ExchangeAgentUpdateRequest {
	answer := &agentv1.ExchangeAgentUpdateRequest{RequestId: fetch.GetRequestId(), Failed: true}
	if fetch.GetLimit() == 0 || fetch.GetLimit() > 256<<10 || fetch.GetOffset() > 1<<30 {
		return answer
	}
	relative := fetch.GetPath()
	if path.Clean(relative) != relative || strings.ContainsAny(relative, "\\?#%") || (!strings.HasPrefix(relative, "metadata/") && !strings.HasPrefix(relative, "targets/")) {
		return answer
	}
	parsed, err := url.Parse(strings.TrimRight(base, "/") + "/" + relative)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return answer
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return answer
	}
	end := fetch.GetOffset() + uint64(fetch.GetLimit()) - 1
	request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", fetch.GetOffset(), end))
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		return answer
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusNotFound {
		answer.Failed, answer.NotFound = false, true
		return answer
	}
	if response.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		if response.Header.Get("Content-Range") == fmt.Sprintf("bytes */%d", fetch.GetOffset()) {
			answer.Failed, answer.Eof = false, true
		}
		return answer
	}
	var expected uint64
	switch response.StatusCode {
	case http.StatusPartialContent:
		var first, last, total uint64
		if n, err := fmt.Sscanf(response.Header.Get("Content-Range"), "bytes %d-%d/%d", &first, &last, &total); err != nil || n != 3 || first != fetch.GetOffset() || last < first || last > end || total <= last || total > 1<<30 {
			return answer
		}
		expected = last - first + 1
		answer.Eof = last+1 == total
	case http.StatusOK:
		if fetch.GetOffset() != 0 || response.ContentLength < 0 || uint64(response.ContentLength) > uint64(fetch.GetLimit()) {
			return answer
		}
		expected = uint64(response.ContentLength)
		answer.Eof = true
	default:
		return answer
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(fetch.GetLimit())+1))
	if err != nil || uint64(len(data)) != expected {
		return answer
	}
	answer.Data, answer.Failed = data, false
	return answer
}
