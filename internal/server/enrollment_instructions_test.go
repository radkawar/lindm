package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
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
	resources := &config.Resources{Proto: &configv1.ServerConfig{
		PublicUrl:       "https://console.example/",
		DevicePublicUrl: proto.String("https://devices.example:9443"),
		AdminListener:   &configv1.ListenerConfig{Address: "127.0.0.1", Port: 18444},
		DeviceListener:  &configv1.ListenerConfig{Address: "0.0.0.0", Port: 18445},
		EnrollmentInstructions: &configv1.EnrollmentInstructionsConfig{
			AptRepository: &configv1.EnrollmentAPTRepositoryConfig{BaseUrl: "https://packages.example/apt", SigningKeyUrl: "https://packages.example/apt.asc", SigningKeyFingerprint: strings.Repeat("A", 40), Suite: "stable", Components: []string{"main", "extra"}},
			DnfRepository: &configv1.EnrollmentDNFRepositoryConfig{BaseUrl: "https://packages.example/rpm", SigningKeyUrl: "https://packages.example/rpm.asc", SigningKeyFingerprint: strings.Repeat("B", 64)},
		},
	}, ExecutionBootstrap: &config.ExecutionBootstrap{RootJSON: []byte("root"), Envelope: []byte("envelope")}}
	response := enrollmentInstructions(resources)
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
	apt, dnf := resources.Proto.EnrollmentInstructions.AptRepository, resources.Proto.EnrollmentInstructions.DnfRepository
	if response.AptRepository.GetBaseUrl() != apt.GetBaseUrl() || response.AptRepository.GetSigningKeyUrl() != apt.GetSigningKeyUrl() || response.AptRepository.GetSigningKeyFingerprint() != apt.GetSigningKeyFingerprint() || response.AptRepository.GetSuite() != apt.GetSuite() || strings.Join(response.AptRepository.GetComponents(), " ") != "main extra" || response.DnfRepository.GetBaseUrl() != dnf.GetBaseUrl() || response.DnfRepository.GetSigningKeyUrl() != dnf.GetSigningKeyUrl() || response.DnfRepository.GetSigningKeyFingerprint() != dnf.GetSigningKeyFingerprint() {
		t.Fatal("instructions changed configured native repository metadata")
	}
	response.AptRepository.Components[0] = "changed"
	if apt.Components[0] != "main" {
		t.Fatal("response aliases mutable configuration")
	}
	resources.Proto.EnrollmentInstructions = nil
	resources.Proto.DevicePublicUrl = nil
	resources.ExecutionBootstrap = nil
	response = enrollmentInstructions(resources)
	if response.DeviceOrigin != nil || response.ExecutionRootUrl != nil || response.BootstrapBundleUrl != nil || response.AptRepository != nil || response.DnfRepository != nil {
		t.Fatal("missing setup fabricated installation instructions")
	}
	if response.GetGrantCommand() != "/usr/libexec/lindm/lindm-agent bootstrap -root /etc/lindm/execution-root.json -bundle /etc/lindm/bootstrap.dsse.json -grant /run/lindm-enrollment/grant" || response.GetProvisioningCommand() != "/usr/libexec/lindm/lindm-agent bootstrap -root /etc/lindm/execution-root.json -bundle /etc/lindm/bootstrap.dsse.json -provisioning-token-file /etc/lindm/provisioning-token" || response.GetResumeCommand() != "/usr/libexec/lindm/lindm-agent resume -wait-seconds 3600" {
		t.Fatal("missing or incorrect protected-file CLI templates")
	}
}
