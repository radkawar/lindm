package devlab

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lindm/gen/lindm/admin/v1/adminv1connect"
)

func TestEntraOutageMeasurementRequiresProtectedDenial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/session" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		if _, err := w.Write([]byte(`{"code":"unavailable","message":"directory_unavailable"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	browser := &brokerBrowser{client: server.Client(), origin: server.URL, admin: adminv1connect.NewAdminServiceClient(server.Client(), server.URL)}
	mutation := time.Now().UTC()
	measured, err := measureEntraDenial(t.Context(), nil, browser, "graph-outage", mutation)
	if err != nil {
		t.Fatal(err)
	}
	if measured.Denied.Before(mutation) || measured.GraphVisible != mutation || measured.SessionHTTP != http.StatusServiceUnavailable || measured.EnforcementMilliseconds >= 60000 {
		t.Fatalf("invalid measurement: %+v", measured)
	}
}

func TestEntraOutageTransportFailureIsNotDenialEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	browser := &brokerBrowser{client: server.Client(), origin: server.URL, admin: adminv1connect.NewAdminServiceClient(server.Client(), server.URL)}
	server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	measured, err := measureEntraDenial(ctx, nil, browser, "graph-outage", time.Now())
	if err == nil || !measured.Denied.IsZero() {
		t.Fatalf("transport loss was treated as authorization evidence: %+v, %v", measured, err)
	}
}
