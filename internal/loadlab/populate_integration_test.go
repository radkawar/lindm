// SPDX-License-Identifier: Apache-2.0

//go:build integration && consolelab

package loadlab

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/gen/lindm/integrations/v1/integrationsv1connect"
	"lindm/internal/devlab"
	"lindm/internal/trust"
)

// This opt-in real-process lane requires the protected dev fixture plus a prebuilt
// lindmd with embedded web assets. It does not join the schema-only integration
// suite, which has neither a prebuilt executable nor development trust material.
func TestPopulateRetainsCallerFixtureAndDynamicBrowserOrigin(t *testing.T) {
	repository, binary := os.Getenv("LINDM_CONSOLE_REPOSITORY"), os.Getenv("LINDM_CONSOLE_LINDMD")
	if repository == "" || binary == "" {
		t.Fatal("set LINDM_CONSOLE_REPOSITORY and LINDM_CONSOLE_LINDMD for the real console lab regression")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	fixture, err := devlab.OpenLocalConsoleAuthorityFixture(ctx, repository, binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	})
	origin, err := url.Parse(fixture.ConsoleOrigin)
	if err != nil || origin.Hostname() != "localhost" || origin.Port() == "" || origin.Host != "localhost:"+strings.Split(fixture.AdminAddress, ":")[1] {
		t.Fatalf("browser origin does not bind actual listener: %q (%v)", fixture.ConsoleOrigin, err)
	}
	material, err := fixture.ReadAgentFixture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := trust.New()
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := authority.VerifyBootstrap(ctx, material.ExecutionRootJSON, material.BootstrapEnvelope, time.Now())
	if err != nil || bootstrap.Bundle.GetEnrollmentOrigin() != fixture.ConsoleOrigin {
		t.Fatalf("signed bootstrap lost the browser origin: %v", err)
	}
	roots := x509.NewCertPool()
	ca, err := os.ReadFile(filepath.Join(devlab.FixturePath(repository), "transport-ca.crt"))
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatalf("read fixture browser trust: %v", err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fixture.ConsoleOrigin+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || strings.Contains(response.Header.Get("Content-Security-Policy"), "localhost:18444") {
		t.Fatal("browser request failed or CSP retained the shared origin")
	}
	// Missing optional-service configuration used to route these POSTs to the
	// console fallback (405). They must instead reach the real session guard.
	for _, procedure := range []string{
		integrationsv1connect.IntegrationServiceListDestinationsProcedure,
		integrationsv1connect.IntegrationServiceListDeliveriesProcedure,
		integrationsv1connect.ReportServiceListReportArtifactsProcedure,
		integrationsv1connect.ReportServiceListReportSchedulesProcedure,
	} {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, fixture.ConsoleOrigin+procedure, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", fixture.ConsoleOrigin)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		if err := errors.Join(readErr, response.Body.Close()); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s did not reach the authenticated RPC route: HTTP %d", procedure, response.StatusCode)
		}
	}
	options := PopulateOptions{Devices: 3, Packages: 8, AssignmentPercent: 100, EnrollmentWorkers: 2}
	population, err := Populate(ctx, fixture, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(population.DeviceIDs) != 3 || population.CompletedAssignments != 3 {
		t.Fatalf("incomplete population: %+v", population)
	}
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatalf("Populate closed its caller's fixture: %v", err)
	}
	for _, id := range population.DeviceIDs {
		device, err := owner.Admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: id}))
		if err != nil || device.Msg.GetHost() == nil || device.Msg.GetCurrentSnapshot() == nil {
			t.Fatalf("missing populated host/snapshot: %v", err)
		}
		packages, err := owner.Admin.ListDevicePackages(ctx, connect.NewRequest(&adminv1.ListDevicePackagesRequest{DeviceId: id, PageSize: 20}))
		if err != nil || len(packages.Msg.GetPackages()) != 8 {
			t.Fatalf("missing populated packages: %v", err)
		}
	}
	if err := owner.Close(ctx); err != nil {
		t.Fatal(err)
	}
	enrollment, err := fixture.CreateConsoleEnrollment(ctx)
	if err != nil || enrollment.GetSecret() == "" {
		t.Fatalf("browser account cannot enroll after population: %v", err)
	}
	enrollment.Secret = ""
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := Populate(canceled, fixture, options); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled population did not terminate: %v", err)
	}
	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Populate(ctx, fixture, options); err == nil {
		t.Fatal("population outlived its fixture")
	}
}
