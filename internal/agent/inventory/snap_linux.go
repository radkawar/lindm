//go:build linux

package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"time"
	"unicode/utf8"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const snapTimeout = 10 * time.Second

// collectSnap observes only the local system installation. Neither configuration
// nor inventory requests can choose a socket, URL, method, proxy or redirect.
// snapd permits this read without granting the network service new privileges.
func collectSnap(ctx context.Context) *inventoryv1.ApplicationDetails {
	dialer := &net.Dialer{Timeout: snapTimeout}
	return collectSnapWithDial(ctx, dialer.DialContext)
}

func collectSnapWithDial(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) *inventoryv1.ApplicationDetails {
	ctx, cancel := context.WithTimeout(ctx, snapTimeout)
	defer cancel()
	transport := &http.Transport{
		// This transport serves one request, so dialing shares its deadline
		// rather than the HTTP pool's detached connection context.
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx, "unix", "/run/snapd.socket")
		},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 16 << 10,
		ResponseHeaderTimeout:  snapTimeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/v2/snaps", nil)
	if err != nil {
		return &inventoryv1.ApplicationDetails{Status: invalid}
	}
	response, err := client.Do(request)
	if err != nil {
		return &inventoryv1.ApplicationDetails{Status: snapReadStatus(err)}
	}
	result := readSnapResponse(response)
	if err := response.Body.Close(); err != nil && result.Status == success {
		result = &inventoryv1.ApplicationDetails{Status: snapReadStatus(err)}
	}
	if ctx.Err() != nil {
		return &inventoryv1.ApplicationDetails{Status: statusFor(ctx.Err())}
	}
	return result
}

func snapReadStatus(err error) inventoryv1.CollectionStatus {
	var netErr net.Error
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return statusFor(context.DeadlineExceeded)
	case errors.As(err, &netErr) && netErr.Timeout():
		return statusFor(context.DeadlineExceeded)
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, fs.ErrPermission):
		return statusFor(err)
	default:
		return commandFailure
	}
}

func readSnapResponse(response *http.Response) *inventoryv1.ApplicationDetails {
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return &inventoryv1.ApplicationDetails{Status: statusFor(fs.ErrPermission)}
	case http.StatusNotFound:
		return &inventoryv1.ApplicationDetails{Status: unavailable}
	default:
		return &inventoryv1.ApplicationDetails{Status: commandFailure}
	}
	if response.ContentLength > maxDetailFile {
		return &inventoryv1.ApplicationDetails{Status: capacity}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxDetailFile+1))
	if len(data) > maxDetailFile {
		return &inventoryv1.ApplicationDetails{Status: capacity}
	}
	if err != nil {
		return &inventoryv1.ApplicationDetails{Status: snapReadStatus(err)}
	}
	return parseSnap(data)
}

func parseSnap(data []byte) *inventoryv1.ApplicationDetails {
	result := &inventoryv1.ApplicationDetails{Status: invalid}
	if len(data) > maxDetailFile {
		result.Status = capacity
		return result
	}
	var envelope struct {
		Type       string          `json:"type"`
		StatusCode int             `json:"status-code"`
		Status     string          `json:"status"`
		Result     json.RawMessage `json:"result"`
	}
	// Additional snapd metadata (sources, refresh times, publisher, etc.) is
	// extensible. Consumed fields remain typed; missing/null results are invalid.
	if err := json.Unmarshal(data, &envelope); err != nil {
		return result
	}
	if !utf8.Valid(data) {
		return result
	}
	if envelope.Type != "sync" || envelope.StatusCode != http.StatusOK || envelope.Status != "OK" {
		return result
	}
	decoder := json.NewDecoder(bytes.NewReader(envelope.Result))
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return result
	}
	seen := make(map[string]bool)
	for decoder.More() {
		if len(result.Applications) == 2048 {
			return &inventoryv1.ApplicationDetails{Status: capacity}
		}
		var snap struct {
			Name         string `json:"name"`
			Version      string `json:"version"`
			Architecture string `json:"architecture"`
		}
		if err := decoder.Decode(&snap); err != nil || len(snap.Name) > 512 || !packageName.MatchString(snap.Name) || seen[snap.Name] {
			return &inventoryv1.ApplicationDetails{Status: invalid}
		}
		seen[snap.Name] = true
		version, arch := observed(snap.Version, nil), observed(snap.Architecture, nil)
		if version.Status == invalid || arch.Status == invalid {
			return &inventoryv1.ApplicationDetails{Status: invalid}
		}
		result.Applications = append(result.Applications, &inventoryv1.Application{
			Name: snap.Name, Version: version, Architecture: arch, Scope: observed("system", nil),
		})
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
		return &inventoryv1.ApplicationDetails{Status: invalid}
	}
	result.Status = success
	return result
}
