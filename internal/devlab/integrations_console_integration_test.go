// SPDX-License-Identifier: Apache-2.0

//go:build integration && consolelab

package devlab

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/gen/lindm/integrations/v1/integrationsv1connect"
	"lindm/internal/config"
	"lindm/internal/labexec"
	"lindm/internal/rpcreason"
)

// Exercise the persistent authorityDeviceActions path used by held demos, not
// the separate local-console fixture. Shared repository trust is read-only;
// only this short-path fixture's database, configuration and process are owned.
func TestPersistentConsoleIntegrationsConfiguredAndUnconfigured(t *testing.T) {
	repository, binary := os.Getenv("LINDM_CONSOLE_REPOSITORY"), os.Getenv("LINDM_CONSOLE_LINDMD")
	if repository == "" || binary == "" {
		t.Fatal("set LINDM_CONSOLE_REPOSITORY and LINDM_CONSOLE_LINDMD for the owned integrations console regression")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node is required for the real Chromium integrations journey")
	}
	script, err := filepath.Abs("../../web/acceptance/integrations-regression.mjs")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	root, err := os.MkdirTemp("", "l405-")
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "authority")
	var fixture *AuthorityFixture
	defer func() {
		if fixture != nil {
			if err := fixture.Close(); err != nil {
				t.Error(err)
			}
		}
		// Let the shared cluster's checkpoint work use the fixture drop budget.
		cleanup := context.WithoutCancel(t.Context())
		if err := DestroyPersistentFixture(cleanup, repository, state); err != nil {
			t.Errorf("destroy failed; owned private state retained at %s: %v", state, err)
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	}()
	fixture, err = OpenPersistentFixture(ctx, repository, binary, state, LoadAuthorityOptions{DatabaseStorage: "shared"})
	if err != nil {
		t.Fatal(err)
	}

	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(private, "evidence")
	if retained := os.Getenv("LINDM_CONSOLE_EVIDENCE"); retained != "" {
		if err := os.MkdirAll(retained, 0700); err != nil {
			t.Fatal(err)
		}
		evidence, err = os.MkdirTemp(retained, "integrations-")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("retained integrations browser evidence: %s", evidence)
	}
	var passwordBytes [32]byte
	if _, err := rand.Read(passwordBytes[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(passwordBytes[:])
	clear(passwordBytes[:])
	credentialPath := filepath.Join(private, "browser-credential.json")

	assertIntegrationsConsoleRPCs(t, ctx, fixture, true)
	enrollment, err := fixture.CreateConsoleEnrollment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runBrowser := func(state, secret string) {
		t.Helper()
		input := map[string]any{
			"origin": fixture.ConsoleOrigin, "username": "console-owner", "password": password,
			"state": state, "enrollmentSecret": secret, "credentialPath": credentialPath,
			"evidenceDirectory": evidence, "ignoreHTTPSErrors": true,
		}
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		inputPath := filepath.Join(private, state+".json")
		if err := os.WriteFile(inputPath, encoded, 0600); err != nil {
			clear(encoded)
			t.Fatal(err)
		}
		clear(encoded)
		defer os.Remove(inputPath)
		// Never capture/print browser exceptions or raw process output: they can
		// quote filled passwords. The driver writes a bounded, safe result file.
		if err := labexec.Run(ctx, labexec.Command{Path: node, Args: []string{script, inputPath}, Timeout: 2 * time.Minute}); err != nil {
			t.Fatalf("%s Chromium integrations journey failed (%v); private result: %s", state, err, filepath.Join(evidence, state+"-result.json"))
		}
		resultPath := filepath.Join(evidence, state+"-result.json")
		encoded, err = os.ReadFile(resultPath)
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			Passed bool `json:"passed"`
		}
		if err := json.Unmarshal(encoded, &result); err != nil || !result.Passed {
			t.Fatalf("%s Chromium journey did not record success; private result: %s", state, resultPath)
		}
	}
	runBrowser("configured", enrollment.GetSecret())
	enrollment.Secret = ""

	// This document is under the new owned persistent directory, never the
	// protected source repository or a shared/held owner's server.json.
	document, err := config.Load(fixture.configPath())
	if err != nil {
		t.Fatal(err)
	}
	if document.Proto.GetIntegrations() == nil {
		t.Fatal("persistent authorityDeviceActions fixture did not configure integrations")
	}
	document.Proto.Integrations = nil
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.writeConfig(encoded); err != nil {
		t.Fatal(err)
	}
	if err := fixture.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	assertIntegrationsConsoleRPCs(t, ctx, fixture, false)
	runBrowser("unconfigured", "")
}

func assertIntegrationsConsoleRPCs(t *testing.T, ctx context.Context, fixture *AuthorityFixture, configured bool) {
	t.Helper()
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := owner.Close(cleanup); err != nil {
			t.Error(err)
		}
	}()
	anonymous := *owner.client
	anonymous.Jar = nil
	reads := []struct {
		path     string
		request  proto.Message
		response proto.Message
	}{
		{integrationsv1connect.IntegrationServiceListDestinationsProcedure, &integrationsv1.ListDestinationsRequest{PageSize: 50}, new(integrationsv1.ListDestinationsResponse)},
		{integrationsv1connect.IntegrationServiceListDeliveriesProcedure, &integrationsv1.ListDeliveriesRequest{PageSize: 20, FailuresOnly: true}, new(integrationsv1.ListDeliveriesResponse)},
		{integrationsv1connect.IntegrationServiceSummarizeDeliveriesProcedure, new(integrationsv1.SummarizeDeliveriesRequest), new(integrationsv1.SummarizeDeliveriesResponse)},
		{integrationsv1connect.ReportServiceListReportSchedulesProcedure, &integrationsv1.ListReportSchedulesRequest{PageSize: 50}, new(integrationsv1.ListReportSchedulesResponse)},
		{integrationsv1connect.ReportServiceListReportArtifactsProcedure, &integrationsv1.ListReportArtifactsRequest{PageSize: 10}, new(integrationsv1.ListReportArtifactsResponse)},
	}
	for _, read := range reads {
		for _, authenticated := range []bool{true, false} {
			body, err := protojson.Marshal(read.request)
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, fixture.ConsoleOrigin+read.path, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Connect-Protocol-Version", "1")
			request.Header.Set("Origin", fixture.ConsoleOrigin)
			client := &anonymous
			if authenticated {
				request.Header.Set("X-CSRF-Token", owner.csrf)
				client = owner.client
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("%s authenticated=%t: %v", read.path, authenticated, err)
			}
			encoded, err := readFixtureResponse(response)
			closeErr := response.Body.Close()
			if err != nil || closeErr != nil {
				t.Fatalf("%s: read=%v close=%v", read.path, err, closeErr)
			}
			switch {
			case !authenticated:
				if response.StatusCode != http.StatusUnauthorized {
					t.Errorf("%s anonymous: HTTP %d, want session guard 401 (configured=%t)", read.path, response.StatusCode, configured)
					continue
				}
			case configured:
				if response.StatusCode != http.StatusOK {
					t.Errorf("%s configured: HTTP %d, want 200", read.path, response.StatusCode)
					continue
				}
				if err := protojson.Unmarshal(encoded, read.response); err != nil {
					t.Errorf("%s did not return its protobuf JSON response: %v", read.path, err)
					continue
				}
			default:
				var failure struct {
					Code string `json:"code"`
				}
				if err := json.Unmarshal(encoded, &failure); err != nil {
					t.Errorf("%s unconfigured: HTTP %d without Connect JSON error", read.path, response.StatusCode)
					continue
				}
				if response.StatusCode != http.StatusBadRequest || failure.Code != connect.CodeFailedPrecondition.String() || response.Header.Get(rpcreason.Header) != "integrations_unconfigured" {
					t.Errorf("%s unconfigured: HTTP %d code=%q reason=%q, want 400 failed_precondition integrations_unconfigured", read.path, response.StatusCode, failure.Code, response.Header.Get(rpcreason.Header))
				}
			}
		}
	}
	if t.Failed() {
		t.FailNow()
	}
}
