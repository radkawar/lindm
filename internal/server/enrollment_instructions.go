// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/config"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

const (
	executionRootPath   = "/bootstrap/execution-root.json"
	bootstrapBundlePath = "/bootstrap/bootstrap.dsse.json"
)

// enrollmentInstructions projects a verified publication snapshot and registry
// identities; no listener address, Host header or external repository is used.
func enrollmentInstructions(resources *config.Resources, native *nativeRepositories) *adminv1.GetEnrollmentInstructionsResponse {
	cfg := resources.Proto
	response := &adminv1.GetEnrollmentInstructionsResponse{
		EnrollmentOrigin:    cfg.GetPublicUrl(),
		GrantCommand:        "/usr/libexec/lindm/lindm-agent bootstrap -root /etc/lindm/execution-root.json -bundle /etc/lindm/bootstrap.dsse.json -grant /run/lindm-enrollment/grant",
		ProvisioningCommand: "/usr/libexec/lindm/lindm-agent bootstrap -root /etc/lindm/execution-root.json -bundle /etc/lindm/bootstrap.dsse.json -provisioning-token-file /etc/lindm/provisioning-token",
		ResumeCommand:       "/usr/libexec/lindm/lindm-agent resume -wait-seconds 3600",
		Readiness:           &adminv1.EnrollmentReadiness{Ready: true},
	}
	if cfg.DevicePublicUrl != nil {
		response.DeviceOrigin = proto.String(cfg.GetDevicePublicUrl())
	}
	if resources.ExecutionBootstrap != nil {
		origin := strings.TrimSuffix(cfg.GetPublicUrl(), "/")
		response.ExecutionRootUrl = proto.String(origin + executionRootPath)
		response.BootstrapBundleUrl = proto.String(origin + bootstrapBundlePath)
		digest := sha256.Sum256(resources.ExecutionBootstrap.RootJSON)
		response.ExecutionRootSha256 = proto.String(hex.EncodeToString(digest[:]))
	}
	if resources.EnrollmentTLSCAPEM != "" {
		response.TlsCaPem = proto.String(resources.EnrollmentTLSCAPEM)
		response.TlsCaSha256 = proto.String(resources.EnrollmentTLSCASHA256)
	}
	switch {
	case resources.ExecutionBootstrap == nil:
		response.Readiness = enrollmentNotReady("execution_bootstrap_missing", "Configure executionBootstrap with the authenticated execution root and signed bootstrap bundle, then restart lindmd.")
	case cfg.GetDevicePublicUrl() == "":
		response.Readiness = enrollmentNotReady("device_origin_missing", "Configure the device HTTPS public origin and restart lindmd.")
	case resources.EnrollmentTLSUnavailable:
		response.Readiness = enrollmentNotReady("https_trust_unavailable", "Provide the administrative HTTPS CA through adminCaFile, the administrative TLS chain or trustedCaFile, with a certificate covering publicUrl, then restart lindmd.")
	}
	origin := strings.TrimSuffix(cfg.GetPublicUrl(), "/")
	if native.apt.err == nil {
		response.AptRepository = &adminv1.EnrollmentAPTRepository{
			BaseUrl: origin + "/repo/apt", SigningKeyUrl: origin + "/repo/apt/" + nativePublicKey,
			SigningKeyFingerprint: native.apt.fingerprint,
			Suite:                 packaging.APTDistribution, Components: []string{packaging.APTComponent},
		}
	}
	if native.rpm.err == nil {
		response.DnfRepository = &adminv1.EnrollmentDNFRepository{
			BaseUrl: origin + "/repo/rpm", SigningKeyUrl: origin + "/repo/rpm/" + nativePublicKey,
			SigningKeyFingerprint: native.rpm.fingerprint,
		}
	}
	if native.arch.err == nil {
		response.ArchRepository = &adminv1.EnrollmentArchRepository{
			BaseUrl: origin + "/repo/arch", SigningKeyUrl: origin + "/repo/arch/" + nativePublicKey,
			SigningKeyFingerprint: native.arch.fingerprint, RepositoryName: "lindm",
		}
	}
	for _, release := range platform.Releases() {
		choice := &adminv1.EnrollmentPlatform{
			Id: release.Key, Label: release.Name, OsId: release.ID,
			VariantIds: slices.Clone(release.Variants),
			Readiness:  proto.CloneOf(response.Readiness),
		}
		for _, format := range release.Provisioning {
			choice.ProvisioningFormats = append(choice.ProvisioningFormats, string(format))
		}
		switch release.Version.Rule {
		case platform.VersionExact:
			choice.VersionRule, choice.VersionIds = "exact", []string{release.Version.Value}
		case platform.VersionMajor:
			choice.VersionRule, choice.VersionIds = "major", []string{release.Version.Value}
		case platform.VersionAbsent:
			choice.VersionRule = "absent"
		case platform.VersionSnapshot:
			choice.VersionRule = "snapshot"
		case platform.VersionAny:
			choice.VersionRule = "any"
		}
		var repository *nativeRepository
		switch release.Native().Packages.Backend {
		case platform.BackendAPT:
			choice.PackageFamily, repository = "apt", native.apt
		case platform.BackendDNF4, platform.BackendDNF5:
			choice.PackageFamily, repository = "dnf", native.rpm
		case platform.BackendZypper:
			choice.PackageFamily, repository = "zypper", native.rpm
		case platform.BackendPacman:
			choice.PackageFamily, repository = "pacman", native.arch
		default:
			choice.PackageFamily = string(release.Family)
		}
		supported := release.Supported(platform.Lifecycle)
		choice.Support = adminv1.EnrollmentPlatformSupport_ENROLLMENT_PLATFORM_SUPPORT_NOT_SUPPORTED
		if supported {
			choice.Support = adminv1.EnrollmentPlatformSupport_ENROLLMENT_PLATFORM_SUPPORT_SUPPORTED
		}
		if choice.Readiness.Ready {
			switch {
			case !supported:
				choice.Readiness = enrollmentNotReady("platform_installation_gated", release.GateReason(platform.Lifecycle)+". Select a registry platform with a supported native installation method.")
			case repository == nil:
				choice.Readiness = enrollmentNotReady("native_repository_unavailable", "Publish a signed native agent repository for this package family on lindmd.")
			case repository.err != nil:
				choice.Readiness = enrollmentNotReady("native_repository_unavailable", "The agent repository failed verification: "+repository.err.Error()+". Reinstall the signed lindmd release bundle or correct the custom publication, then restart lindmd.")
			}
		}
		if repository != nil && repository.err == nil {
			for _, arch := range release.Architectures {
				normalized := nativeArchitecture(arch)
				switch {
				case containsArchitecture(repository.architectures, normalized):
					choice.Architectures = append(choice.Architectures, normalized)
					appendEnrollmentPackages(choice, repository, normalized)
				case supported && normalized != "":
					choice.UnpublishedArchitectures = append(choice.UnpublishedArchitectures, normalized)
				}
			}
			if choice.Readiness.Ready && len(choice.Architectures) == 0 {
				choice.Readiness = enrollmentNotReady("native_architecture_unavailable", "The installed release has no signed agent package for this platform's architectures. Install a lindmd release that carries them, then restart lindmd.")
			}
		}
		response.Platforms = append(response.Platforms, choice)
	}
	if response.Readiness.Ready && response.AptRepository == nil && response.DnfRepository == nil && response.ArchRepository == nil {
		response.Readiness = enrollmentNotReady("native_repository_unavailable", "The installed signed agent repository is unavailable. Check each platform's verification result and reinstall the signed lindmd release bundle.")
	}
	return response
}

func enrollmentNotReady(reason, remedy string) *adminv1.EnrollmentReadiness {
	return &adminv1.EnrollmentReadiness{Reason: reason, Remedy: remedy}
}

func appendEnrollmentPackages(choice *adminv1.EnrollmentPlatform, repository *nativeRepository, arch string) {
	for _, version := range repository.versions[arch] {
		choice.AgentPackages = append(choice.AgentPackages, &adminv1.EnrollmentAgentPackage{Architecture: arch, Version: version})
	}
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
