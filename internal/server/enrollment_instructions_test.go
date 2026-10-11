package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"buf.build/go/protovalidate"

	adminv1 "lindm/gen/lindm/admin/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
	"lindm/internal/platform"
)

func TestPublicBootstrapMaterial(t *testing.T) {
	bootstrap := &config.ExecutionBootstrap{
		RootJSON: []byte("{\"deploymentId\":\"public-root\"}\n"),
		Envelope: []byte("{\"payloadType\":\"application/vnd.lindm.bootstrap.v1+json\",\"payload\":\"exact-signed-bytes\",\"signatures\":[]}\n"),
	}
	mux := http.NewServeMux()
	mux.Handle("/bootstrap/", bootstrapMaterialHandler(bootstrap))
	for _, test := range []struct {
		name   string
		method string
		path   string
		status int
		body   []byte
	}{
		{name: "anonymous root", method: http.MethodGet, path: executionRootPath, status: http.StatusOK, body: bootstrap.RootJSON},
		{name: "anonymous exact envelope", method: http.MethodGet, path: bootstrapBundlePath, status: http.StatusOK, body: bootstrap.Envelope},
		{name: "head root", method: http.MethodHead, path: executionRootPath, status: http.StatusOK},
		{name: "head envelope", method: http.MethodHead, path: bootstrapBundlePath, status: http.StatusOK},
		{name: "post denied", method: http.MethodPost, path: bootstrapBundlePath, status: http.StatusMethodNotAllowed},
		{name: "put denied", method: http.MethodPut, path: executionRootPath, status: http.StatusMethodNotAllowed},
		{name: "delete denied", method: http.MethodDelete, path: bootstrapBundlePath, status: http.StatusMethodNotAllowed},
		{name: "directory denied", method: http.MethodGet, path: "/bootstrap/", status: http.StatusNotFound},
		{name: "private key denied", method: http.MethodGet, path: "/bootstrap/plan.key", status: http.StatusNotFound},
		{name: "unsigned bundle denied", method: http.MethodGet, path: "/bootstrap/bootstrap.json", status: http.StatusNotFound},
		{name: "nested path denied", method: http.MethodGet, path: executionRootPath + "/private", status: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "https://attacker.example"+test.path, nil)
			request.Header.Set("Forwarded", "host=attacker.example;proto=http")
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing public document response protections")
			}
			if test.status == http.StatusOK {
				if response.Body.String() != string(test.body) {
					t.Fatal("response changed the exact document or sent a HEAD body")
				}
				if response.Header().Get("Content-Type") != "application/json" || !strings.HasPrefix(response.Header().Get("Content-Disposition"), "attachment;") {
					t.Fatal("public material is not an explicit JSON download")
				}
				if test.method == http.MethodGet && response.Header().Get("Content-Length") != strconv.Itoa(len(test.body)) {
					t.Fatal("incorrect document length")
				}
			}
			if test.status == http.StatusMethodNotAllowed && response.Header().Get("Allow") != "GET, HEAD" {
				t.Fatal("endpoint advertised a writable method")
			}
		})
	}
}

func TestUnconfiguredBootstrapIsNotPublished(t *testing.T) {
	for _, path := range []string{executionRootPath, bootstrapBundlePath, "/bootstrap/"} {
		response := httptest.NewRecorder()
		bootstrapMaterialHandler(nil).ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("unconfigured %s status = %d", path, response.Code)
		}
	}
}

func TestEnrollmentInstructionsUseOnlyAuthoritativeConfiguration(t *testing.T) {
	fixture := newNativeFixture(t)
	fixture.apt(t, "arm64")
	fixture.rpm(t, "aarch64")
	fixture.arch(t)
	resources := fixture.resources()
	resources.Proto.AdminListener = &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18444}
	resources.Proto.DeviceListener = &configv1.ListenerConfig{Address: "0.0.0.0", Port: 18445}
	response := enrollmentInstructions(resources, loadNativeRepositories(t.Context(), resources))
	validator, err := protovalidate.New(protovalidate.WithMessages(&adminv1.GetEnrollmentInstructionsResponse{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(response); err != nil {
		t.Fatalf("invalid instruction projection: %v", err)
	}
	if response.GetEnrollmentOrigin() != resources.Proto.GetPublicUrl() || response.GetDeviceOrigin() != resources.Proto.GetDevicePublicUrl() || response.GetExecutionRootUrl() != "https://console.example/bootstrap/execution-root.json" || response.GetBootstrapBundleUrl() != "https://console.example/bootstrap/bootstrap.dsse.json" {
		t.Fatalf("instructions inferred or misjoined origins: %v", response)
	}
	if response.AptRepository.GetBaseUrl() != "https://console.example/repo/apt" || response.AptRepository.GetSigningKeyUrl() != "https://console.example/repo/apt/lindm-package-signing.asc" || response.AptRepository.GetSigningKeyFingerprint() != fixture.fingerprint || response.AptRepository.GetSuite() != "stable" || strings.Join(response.AptRepository.GetComponents(), " ") != "main" || response.DnfRepository.GetBaseUrl() != "https://console.example/repo/rpm" || response.ArchRepository.GetBaseUrl() != "https://console.example/repo/arch" {
		t.Fatal("instructions exposed a repository outside the configured server origin")
	}
	if response.GetExecutionRootSha256() != nativeTestDigest(resources.ExecutionBootstrap.RootJSON) || !response.GetReadiness().GetReady() {
		t.Fatal("execution root was not authenticated or published repositories were not ready")
	}
	if len(response.Platforms) != len(platform.Releases()) {
		t.Fatal("platform projection does not cover the authoritative registry")
	}
	for _, choice := range response.Platforms {
		release, ok := platform.Lookup(choice.Id)
		if !ok || choice.Label != release.Name || choice.OsId != release.ID {
			t.Fatalf("invented platform: %v", choice)
		}
		switch choice.Id {
		case "ubuntu-24.04", "fedora-44":
			if !choice.Readiness.Ready || strings.Join(choice.Architectures, ",") != "arm64" {
				t.Fatalf("arm64 publication not projected: %v", choice)
			}
		case "arch", "opensuse-tumbleweed":
			if !choice.Readiness.Ready {
				t.Fatalf("packaged native family incorrectly gated: %v", choice)
			}
		case "nixos":
			if choice.Readiness.Ready || choice.Readiness.Reason != "platform_installation_gated" {
				t.Fatalf("design-only family admitted: %v", choice)
			}
		}
	}
	resources.Proto.ReleaseRepository = nil
	resources.ReleaseRepositoryDirectory = ""
	resources.Proto.DevicePublicUrl = nil
	resources.ExecutionBootstrap = nil
	response = enrollmentInstructions(resources, loadNativeRepositories(t.Context(), resources))
	if response.DeviceOrigin != nil || response.ExecutionRootUrl != nil || response.BootstrapBundleUrl != nil || response.AptRepository != nil || response.DnfRepository != nil {
		t.Fatal("missing setup fabricated installation instructions")
	}
	if response.GetReadiness().GetReady() || response.GetReadiness().GetRemedy() == "" {
		t.Fatal("missing setup lacks an explicit remedy")
	}
	if response.GetGrantCommand() != "/usr/libexec/lindm/lindm-agent bootstrap -root /etc/lindm/execution-root.json -bundle /etc/lindm/bootstrap.dsse.json -grant /run/lindm-enrollment/grant" || response.GetProvisioningCommand() != "/usr/libexec/lindm/lindm-agent bootstrap -root /etc/lindm/execution-root.json -bundle /etc/lindm/bootstrap.dsse.json -provisioning-token-file /etc/lindm/provisioning-token" || response.GetResumeCommand() != "/usr/libexec/lindm/lindm-agent resume -wait-seconds 3600" {
		t.Fatal("missing or incorrect protected-file CLI templates")
	}
}

func TestEnrollmentReadinessDistinguishesFamilyAndArchitecture(t *testing.T) {
	f := newNativeFixture(t)
	f.apt(t, "arm64")
	resources := f.resources()
	response := enrollmentInstructions(resources, loadNativeRepositories(t.Context(), resources))
	if !response.GetReadiness().GetReady() {
		t.Fatal("ready APT family blocked by missing RPM publication")
	}
	for _, choice := range response.Platforms {
		switch choice.Id {
		case "fedora-44", "arch":
			if choice.GetReadiness().GetReason() != "native_repository_unavailable" {
				t.Fatalf("missing family not gated: %v", choice)
			}
		case "linuxmint-22.3":
			if choice.GetReadiness().GetReason() != "native_architecture_unavailable" {
				t.Fatalf("arm64-only publication incorrectly admits x86 derivative: %v", choice)
			}
		}
	}
	resources.EnrollmentTLSUnavailable = true
	response = enrollmentInstructions(resources, loadNativeRepositories(t.Context(), resources))
	if response.GetReadiness().GetReason() != "https_trust_unavailable" {
		t.Fatal("unverifiable HTTPS trust admitted")
	}
	for _, choice := range response.Platforms {
		if choice.GetReadiness().GetReady() {
			t.Fatal("platform bypassed global HTTPS trust gate")
		}
	}
}
