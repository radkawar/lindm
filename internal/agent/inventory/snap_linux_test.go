// SPDX-License-Identifier: Apache-2.0

//go:build linux

package inventory

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"buf.build/go/protovalidate"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

func snapTestDial(t *testing.T, server *httptest.Server) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "unix" || address != "/run/snapd.socket" {
			t.Errorf("unexpected destination: %s %s", network, address)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > snapTimeout {
			t.Error("Snap read lacks bounded context")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
}

func TestSnapCapturedEmptyInstallation(t *testing.T) {
	fixture := detailFixture(t, "snap-ubuntu24-empty.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.RequestURI() != "/v2/snaps" || r.Host != "localhost" {
			t.Errorf("unexpected observation request: %s %s %s", r.Method, r.URL, r.Host)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(fixture); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	// Proxy configuration must never redirect this local observation.
	t.Setenv("HTTP_PROXY", "http://invalid.invalid:1")
	got := collectSnapWithDial(t.Context(), snapTestDial(t, server))
	if got.Status != success || len(got.Applications) != 0 {
		t.Fatalf("installed but empty Snap: %v", got)
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
}

func TestSnapTypedApplications(t *testing.T) {
	got := parseSnap([]byte(`{"type":"sync","status-code":200,"status":"OK","result":[{"name":"core22","version":"20260901","architecture":"amd64","revision":"123"},{"name":"app","version":"1.0"}]}`))
	if got.Status != success || len(got.Applications) != 2 {
		t.Fatalf("Snap applications: %v", got)
	}
	first := got.Applications[0]
	if first.Name != "core22" || first.Version.Value != "20260901" || first.Architecture.Value != "amd64" || first.Architecture.Status != success || first.Scope.Value != "system" {
		t.Fatalf("lost native fields: %v", first)
	}
	if got.Applications[1].Architecture.Status != unavailable {
		t.Fatalf("invented absent architecture: %v", got.Applications[1])
	}
	if err := protovalidate.Validate(got); err != nil {
		t.Fatal(err)
	}
}

func TestSnapRejectsMalformedOutput(t *testing.T) {
	for name, data := range map[string]string{
		"empty":              "",
		"null":               "null",
		"missing envelope":   `{}`,
		"missing result":     `{"type":"sync","status-code":200,"status":"OK"}`,
		"null result":        `{"type":"sync","status-code":200,"status":"OK","result":null}`,
		"object result":      `{"type":"sync","status-code":200,"status":"OK","result":{}}`,
		"wrong status type":  `{"type":"sync","status-code":"200","status":"OK","result":[]}`,
		"wrong status":       `{"type":"sync","status-code":500,"status":"OK","result":[]}`,
		"async response":     `{"type":"async","status-code":200,"status":"OK","result":[]}`,
		"wrong status text":  `{"type":"sync","status-code":200,"status":"failed","result":[]}`,
		"trailing data":      `{"type":"sync","status-code":200,"status":"OK","result":[]} {}`,
		"null item":          `{"type":"sync","status-code":200,"status":"OK","result":[null]}`,
		"missing name":       `{"type":"sync","status-code":200,"status":"OK","result":[{"version":"1"}]}`,
		"numeric version":    `{"type":"sync","status-code":200,"status":"OK","result":[{"name":"app","version":1}]}`,
		"array architecture": `{"type":"sync","status-code":200,"status":"OK","result":[{"name":"app","architecture":["amd64"]}]}`,
		"duplicate name":     `{"type":"sync","status-code":200,"status":"OK","result":[{"name":"app"},{"name":"app"}]}`,
		"bad field":          `{"type":"sync","status-code":200,"status":"OK","result":[{"name":"app","version":"bad\nvalue"}]}`,
		"bad UTF8":           "{\"type\":\"sync\",\"status-code\":200,\"status\":\"OK\",\"result\":[{\"name\":\"app\",\"version\":\"\xff\"}]}",
	} {
		t.Run(name, func(t *testing.T) {
			got := parseSnap([]byte(data))
			if got.Status != invalid || len(got.Applications) != 0 {
				t.Fatalf("malformed response published: %v", got)
			}
		})
	}
}

func TestSnapResponseBounds(t *testing.T) {
	for _, count := range []int{2048, 2049} {
		var data strings.Builder
		data.WriteString(`{"type":"sync","status-code":200,"status":"OK","result":[`)
		for i := range count {
			if i != 0 {
				data.WriteByte(',')
			}
			fmt.Fprintf(&data, `{"name":"app%d","version":"1"}`, i)
		}
		data.WriteString(`]}`)
		got := parseSnap([]byte(data.String()))
		if count == 2048 {
			if got.Status != success || len(got.Applications) != count {
				t.Fatalf("at list limit: %v", got)
			}
		} else if got.Status != capacity || len(got.Applications) != 0 {
			t.Fatalf("over list limit: %v", got)
		}
	}
	for _, length := range []int64{-1, maxDetailFile + 1} {
		got := readSnapResponse(&http.Response{StatusCode: http.StatusOK, ContentLength: length, Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", maxDetailFile+1)))})
		if got.Status != capacity || len(got.Applications) != 0 {
			t.Fatalf("oversized body length %d: %v", length, got)
		}
	}
}

func TestSnapNativeHTTPFailures(t *testing.T) {
	for _, tc := range []struct {
		code int
		want inventoryv1.CollectionStatus
	}{
		{http.StatusUnauthorized, statusFor(fs.ErrPermission)},
		{http.StatusForbidden, statusFor(fs.ErrPermission)},
		{http.StatusNotFound, unavailable},
		{http.StatusInternalServerError, commandFailure},
		{http.StatusServiceUnavailable, commandFailure},
		{http.StatusNoContent, commandFailure},
		{http.StatusFound, commandFailure},
	} {
		t.Run(http.StatusText(tc.code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v2/snaps" {
					t.Errorf("followed redirect: %s", r.URL)
				}
				w.Header().Set("Location", "http://localhost/not-allowed")
				w.WriteHeader(tc.code)
				if tc.code == http.StatusNoContent {
					return
				}
				if _, err := io.WriteString(w, `{"type":"error","status-code":500,"status":"Internal Server Error","result":{"message":"native failure"}}`); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			got := collectSnapWithDial(t.Context(), snapTestDial(t, server))
			if got.Status != tc.want || len(got.Applications) != 0 {
				t.Fatalf("native response %d: %v", tc.code, got)
			}
		})
	}
}

func TestSnapTransportFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want inventoryv1.CollectionStatus
	}{
		{"absent socket", fs.ErrNotExist, unavailable},
		{"denied socket", fs.ErrPermission, statusFor(fs.ErrPermission)},
		{"timeout", context.DeadlineExceeded, statusFor(context.DeadlineExceeded)},
		{"canceled", context.Canceled, statusFor(context.Canceled)},
		{"daemon refused", syscall.ECONNREFUSED, commandFailure},
		{"broken socket", syscall.ECONNRESET, commandFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := collectSnapWithDial(t.Context(), func(context.Context, string, string) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Net: "unix", Err: tc.err}
			})
			if got.Status != tc.want || len(got.Applications) != 0 {
				t.Fatalf("transport failure: %v", got)
			}
		})
	}
	got := readSnapResponse(&http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(applicationReadFailure{})})
	if got.Status != commandFailure || len(got.Applications) != 0 {
		t.Fatalf("truncated native body: %v", got)
	}
}

func TestSnapCancellationWhileReading(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(fmt.Sprint(body), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if body {
					if _, err := io.WriteString(w, `{"type":"sync",`); err != nil {
						t.Error(err)
					}
					if err := http.NewResponseController(w).Flush(); err != nil {
						t.Error(err)
					}
				}
				cancel()
				<-r.Context().Done()
			}))
			defer server.Close()
			got := collectSnapWithDial(ctx, snapTestDial(t, server))
			if got.Status != statusFor(context.Canceled) || len(got.Applications) != 0 {
				t.Fatalf("canceled native observation: %v", got)
			}
		})
	}
}

func TestFlatpakAbsentExecutable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent-flatpak")
	run := func(ctx context.Context, selected backend, consume func(io.Reader) inventoryv1.CollectionStatus) inventoryv1.CollectionStatus {
		if selected.path != "/usr/bin/flatpak" || strings.Join(selected.args, " ") != "list --system --app --columns=application,version,arch" {
			t.Fatalf("changed Flatpak scope: %+v", selected)
		}
		selected.path = missing
		return runNative(ctx, selected, consume)
	}
	got := collectFlatpak(t.Context(), run)
	if got.Status != unavailable || len(got.Applications) != 0 {
		t.Fatalf("missing Flatpak executable: %v", got)
	}
}

func TestSnapRejectsOversizedResponseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Native-Metadata", strings.Repeat("x", 17<<10))
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"type":"sync","status-code":200,"status":"OK","result":[]}`); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	got := collectSnapWithDial(t.Context(), snapTestDial(t, server))
	if got.Status != commandFailure || len(got.Applications) != 0 {
		t.Fatalf("oversized headers accepted: %v", got)
	}
}
