package server

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/config"
)

const (
	executionRootPath   = "/bootstrap/execution-root.json"
	bootstrapBundlePath = "/bootstrap/bootstrap.dsse.json"
)

// enrollmentInstructions projects only configured public metadata. Native
// repositories are distinct from the TUF update repository and never inferred.
func enrollmentInstructions(resources *config.Resources) *adminv1.GetEnrollmentInstructionsResponse {
	cfg := resources.Proto
	response := &adminv1.GetEnrollmentInstructionsResponse{
		EnrollmentOrigin:    cfg.GetPublicUrl(),
		GrantCommand:        "/usr/libexec/lindm/lindm-agent bootstrap -root /etc/lindm/execution-root.json -bundle /etc/lindm/bootstrap.dsse.json -grant /run/lindm-enrollment/grant",
		ProvisioningCommand: "/usr/libexec/lindm/lindm-agent bootstrap -root /etc/lindm/execution-root.json -bundle /etc/lindm/bootstrap.dsse.json -provisioning-token-file /etc/lindm/provisioning-token",
		ResumeCommand:       "/usr/libexec/lindm/lindm-agent resume -wait-seconds 3600",
	}
	if cfg.DevicePublicUrl != nil {
		response.DeviceOrigin = proto.String(cfg.GetDevicePublicUrl())
	}
	if resources.ExecutionBootstrap != nil {
		origin := strings.TrimSuffix(cfg.GetPublicUrl(), "/")
		response.ExecutionRootUrl = proto.String(origin + executionRootPath)
		response.BootstrapBundleUrl = proto.String(origin + bootstrapBundlePath)
	}
	configured := cfg.GetEnrollmentInstructions()
	if apt := configured.GetAptRepository(); apt != nil {
		response.AptRepository = &adminv1.EnrollmentAPTRepository{
			BaseUrl: apt.GetBaseUrl(), SigningKeyUrl: apt.GetSigningKeyUrl(),
			SigningKeyFingerprint: apt.GetSigningKeyFingerprint(),
			Suite:                 apt.GetSuite(), Components: slices.Clone(apt.GetComponents()),
		}
	}
	if dnf := configured.GetDnfRepository(); dnf != nil {
		response.DnfRepository = &adminv1.EnrollmentDNFRepository{
			BaseUrl: dnf.GetBaseUrl(), SigningKeyUrl: dnf.GetSigningKeyUrl(),
			SigningKeyFingerprint: dnf.GetSigningKeyFingerprint(),
		}
	}
	return response
}

// bootstrapMaterialHandler serves only the two exact public documents already
// loaded and cryptographically verified during resource resolution. It cannot
// read arbitrary files, publish private keys or synthesize unsigned trust.
// Downloading an execution root does not authenticate it to a new installation.
func bootstrapMaterialHandler(bootstrap *config.ExecutionBootstrap) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if bootstrap == nil {
			http.NotFound(w, r)
			return
		}
		var document []byte
		var filename string
		switch r.URL.Path {
		case executionRootPath:
			document, filename = bootstrap.RootJSON, "execution-root.json"
		case bootstrapBundlePath:
			document, filename = bootstrap.Envelope, "bootstrap.dsse.json"
		default:
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(document)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(document)
		}
	})
}
