// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package releasebuild produces and verifies locally reproducible release exports.
// It never installs packages, accesses ambient production keys, publishes TUF
// authority or claims a certified SLSA level. Both builders have independent
// source, npm trees, HOME, module and compiler caches; the host/toolchain is shared.
// Every OCI image includes an explicit independently pinned CA bundle; its real
// layer bytes are checked against both signed SBOM and provenance on export
// verification. Supply a maintained public-root bundle for public OIDC issuers.
// Production custody requires an independently SHA256-authenticated protobuf
// SigningTrustInventory covering execution, TLS, the complete TUF root and
// top-level targets metadata authenticated by that root's offline targets role.
// Every delegated public key remains excluded even when metadata has expired
// or the key is no longer referenced by an active delegated role.
// The inventory excludes actual public key material from attestation and native
// package signing; neither sidecar labels nor TUF/OpenPGP key-ID strings suffice.
// A reproducibility mismatch retains the private build trees and a bounded
// protobuf-JSON failure record containing both unsigned archives, executable
// and console-file digests plus source/tool versions. It never publishes a
// successful manifest. Normal cleanup handles readonly private Go module trees
// without following links or changing any shared cache permissions.
package releasebuild

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	releasev1 "lindm/gen/lindm/release/v1"
	"lindm/internal/packaging"
)

// Request is an in-process build invocation, not a serialized config schema.
type Request struct {
	Repository, Output, Version, Revision string
	SourceDateEpoch                       int64
	tools                                 buildToolchain
	PackageSigner                         packaging.SigningKey
	AttestationSigner                     AttestationKey
	OCICABundle, OCICASHA256              string
	Installer                             *InstallerInputs
	ServerNotice                          *releasev1.ServerReleaseNotice
}

// exportArtifact copies one built package, and an Arch package's detached
// package-signer signature, into the release export.
func exportArtifact(exported string, built builtArtifact) error {
	if err := copyNew(built.path, filepath.Join(exported, built.artifact.GetPath()), 0644); err != nil {
		return err
	}
	if built.nativeSignature == "" {
		return nil
	}
	return copyNew(built.nativeSignature, filepath.Join(exported, built.artifact.GetNativeSignaturePath()), 0644)
}

type builtArtifact struct {
	artifact *releasev1.ReleaseArtifact
	path     string
	sbom     []byte
	// nativeSignature is the Arch package's detached package-signer signature.
	nativeSignature string
}
type buildOutput struct {
	observation      *releasev1.BuildObservation
	artifacts        []builtArtifact
	packagePublicKey string
}

// Build captures bounded source once, makes two isolated clean builds of the
// complete matrix and publishes only after every unsigned archive agrees.
func Build(ctx context.Context, request Request) (manifest *releasev1.ReleaseManifest, err error) {
	return buildRelease(ctx, request, false)
}

// BuildDevelopmentAgentRepository builds and authenticates the complete native
// agent matrix twice before publishing a fixture-only ready repository bundle.
// Explicit development custody is required; it is never a production fallback.
func BuildDevelopmentAgentRepository(ctx context.Context, request Request) (*releasev1.ReleaseManifest, error) {
	if request.PackageSigner.Custody != packaging.CustodyDevelopment || request.AttestationSigner.Custody != "development" {
		return nil, errors.New("releasebuild: development repository requires development signers")
	}
	return buildRelease(ctx, request, true)
}

func buildRelease(ctx context.Context, request Request, agentOnly bool) (manifest *releasev1.ReleaseManifest, err error) {
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(request.Version) || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`).MatchString(request.Revision) || request.SourceDateEpoch <= 0 {
		return nil, errors.New("releasebuild: version, revision and positive source epoch are required")
	}
	if request.PackageSigner.Custody != packaging.Custody(request.AttestationSigner.Custody) {
		return nil, errors.New("releasebuild: package and attestation custody must agree")
	}
	if request.PackageSigner.PassphraseFD != nil && request.PackageSigner.PassphraseFile != "" {
		return nil, errors.New("releasebuild: package passphrase file and descriptor are mutually exclusive")
	}
	signer, err := loadSigner(request.AttestationSigner)
	if err != nil {
		return nil, err
	}
	defer signer.close()
	var caBundle []byte
	if !agentOnly {
		var caDigest string
		caBundle, caDigest, err = loadCABundle(request.OCICABundle, request.OCICASHA256)
		if err != nil {
			return nil, err
		}
		request.OCICASHA256 = caDigest
	}
	request.PackageSigner.RejectPublicKeySHA256 = append(append(append([]string{}, request.PackageSigner.RejectPublicKeySHA256...), signer.exclusions.spki...), signer.id)
	request.PackageSigner.RejectFingerprints = append(append([]string{}, request.PackageSigner.RejectFingerprints...), signer.exclusions.fingerprints...)
	request.PackageSigner.RejectPathPrefixes = append(append([]string{}, request.PackageSigner.RejectPathPrefixes...), signer.exclusions.homes...)
	output, err := filepath.Abs(request.Output)
	if err != nil {
		return nil, err
	}
	if request.Output == "" {
		return nil, errors.New("releasebuild: output required")
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("releasebuild: output must not exist")
	}
	work, ownedWork, err := createBuildWork()
	if err != nil {
		return nil, err
	}
	retainWork := false
	defer func() {
		if !retainWork {
			err = errors.Join(err, cleanupBuildWork(work, ownedWork))
		}
	}()
	trustedPublic := filepath.Join(work, "trusted-attestation.pub")
	if err := writeNew(trustedPublic, signer.public, 0644); err != nil {
		return nil, err
	}
	source, sourceDigest, err := captureBuildSource(ctx, work, request.Repository, caBundle)
	if err != nil {
		return nil, err
	}
	request.tools, err = resolveBuildToolchain(ctx, request.Repository, source)
	if err != nil {
		return nil, err
	}
	first, err := cleanBuild(ctx, work, "first", source, sourceDigest, request)
	if err != nil {
		return nil, err
	}
	second, err := cleanBuild(ctx, work, "second", source, sourceDigest, request)
	if err != nil {
		return nil, err
	}
	if err := compareBuilds(first, second); err != nil {
		retainWork, err = retainMismatch(ctx, work, ownedWork, filepath.Dir(output), first, second, err)
		return nil, err
	}
	// Native signing may vary between builds. Only after independently built
	// unsigned agent archives agree can either server consume canonical bytes.
	bundle := filepath.Join(work, "agent-repository")
	licenses := filepath.Join(work, "first", "source", "internal", "packaging", "assets")
	manifest, err = exportCanonicalAgentRepository(ctx, bundle, &request, signer, sourceDigest, first, second, licenses)
	if err != nil {
		return nil, err
	}
	exported := bundle
	if !agentOnly {
		for _, item := range []struct {
			label string
			build *buildOutput
		}{{"first", first}, {"second", second}} {
			if err := buildProducts(ctx, filepath.Join(work, item.label), request, item.build, []string{"lindmd", "lindmctl"}, bundle); err != nil {
				return nil, err
			}
		}
		if err := compareBuilds(first, second); err != nil {
			retainWork, err = retainMismatch(ctx, work, ownedWork, filepath.Dir(output), first, second, err)
			return nil, err
		}
		exported = filepath.Join(work, "export")
		if err := os.Mkdir(exported, 0700); err != nil {
			return nil, err
		}
		manifest, err = exportRelease(ctx, exported, request, signer, sourceDigest, first, second, bundle, licenses)
		if err != nil {
			return nil, err
		}
		if request.Installer != nil {
			if err := ExportInstaller(ctx, source, work, exported, request, *request.Installer); err != nil {
				return nil, err
			}
			if err := VerifyInstaller(ctx, exported, filepath.Join(exported, "attestation.pub"), signer.id); err != nil {
				return nil, err
			}
		}
	}
	if err := publishExport(ctx, exported, output, trustedPublic, signer.id, !agentOnly && request.Installer != nil); err != nil {
		return nil, err
	}
	return manifest, nil
}

func exportCanonicalAgentRepository(ctx context.Context, bundle string, request *Request, signer *releaseSigner, sourceDigest string, first, second *buildOutput, assetsDirectory string) (*releasev1.ReleaseManifest, error) {
	if err := os.Mkdir(bundle, 0700); err != nil {
		return nil, err
	}
	manifest, err := exportRelease(ctx, bundle, *request, signer, sourceDigest, first, second, "", assetsDirectory)
	if err != nil {
		return nil, err
	}
	if err := publishAgentRepositories(ctx, bundle, *request, manifest); err != nil {
		return nil, err
	}
	if err := normalizeAgentRepository(bundle); err != nil {
		return nil, err
	}
	if err := verifyRepositoryPayloads(bundle, manifest); err != nil {
		return nil, err
	}
	if _, err := Verify(ctx, bundle, filepath.Join(bundle, "attestation.pub"), signer.id); err != nil {
		return nil, err
	}
	return manifest, nil
}

// provenancePredicate is the SLSA v1 provenance for one artifact of the two
// clean builds. It claims local isolation only, never a trusted builder.
func provenancePredicate(request Request, artifact *releasev1.ReleaseArtifact, sourceDigest, caDigest, bundleDigest string, first, second *releasev1.BuildObservation) map[string]any {
	dependencies := []any{map[string]any{"uri": "urn:lindm:captured-source", "digest": map[string]string{"sha256": sourceDigest}}}
	if artifact.GetFormat() == "oci" {
		dependencies = append(dependencies, map[string]any{"uri": "urn:lindm:explicit-oci-ca-bundle", "digest": map[string]string{"sha256": caDigest}})
	}
	if artifact.GetProduct() == "lindmd" && bundleDigest != "" {
		dependencies = append(dependencies, map[string]any{"uri": "urn:lindm:canonical-agent-repository-after-unsigned-agreement", "digest": map[string]string{"sha256": bundleDigest}})
	}
	return map[string]any{
		"buildDefinition": map[string]any{
			"buildType":            "https://lindm.invalid/build/local-two-clean/v1",
			"externalParameters":   map[string]any{"version": request.Version, "revision": request.Revision, "sourceDateEpoch": request.SourceDateEpoch, "product": artifact.GetProduct(), "architecture": artifact.GetArchitecture(), "format": artifact.GetFormat()},
			"internalParameters":   map[string]any{"isolation": "separate source/home/npm/module/compiler-cache directories on one host; not a hermetic or independently trusted builder", "unsignedArchiveSha256": artifact.GetUnsignedSha256(), "secondUnsignedArchiveSha256": artifact.GetSecondUnsignedSha256()},
			"resolvedDependencies": dependencies,
		},
		"runDetails": map[string]any{
			"builder":  map[string]any{"id": "https://lindm.invalid/builders/local-release/v1", "version": first.GetToolVersions()},
			"metadata": map[string]string{"startedOn": first.GetStartedAt(), "finishedOn": second.GetFinishedAt()},
		},
	}
}

// writeAttestations writes the artifact's signed SBOM, provenance and release
// signature statements beside it in exported.
func writeAttestations(exported string, signer *releaseSigner, artifact *releasev1.ReleaseArtifact, bom any, provenance map[string]any, custody string) error {
	for _, item := range []struct {
		path, kind string
		predicate  any
	}{{artifact.GetSbomPath(), "https://cyclonedx.org/bom", bom}, {artifact.GetProvenancePath(), "https://slsa.dev/provenance/v1", provenance}, {artifact.GetSignaturePath(), "https://lindm.invalid/release/artifact/v1", map[string]string{"custody": custody, "keyId": signer.id}}} {
		envelope, err := signer.statement(artifact, item.kind, item.predicate)
		if err != nil {
			return err
		}
		if err := writeNew(filepath.Join(exported, item.path), envelope, 0644); err != nil {
			return err
		}
	}
	return nil
}

// writeSignedManifest validates the manifest, then writes release.json and its
// DSSE envelope.
func writeSignedManifest(exported string, signer *releaseSigner, manifest *releasev1.ReleaseManifest) error {
	if err := protovalidate.Validate(manifest); err != nil {
		return err
	}
	document, err := (protojson.MarshalOptions{Indent: "  ", UseProtoNames: true}).Marshal(manifest)
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(exported, "release.json"), document, 0644); err != nil {
		return err
	}
	envelope, err := signer.sign(document, manifestType)
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(exported, "release.json.dsse"), envelope, 0644)
}

func compareBuilds(first, second *buildOutput) error {
	if first.observation.GetSourceSha256() != second.observation.GetSourceSha256() || len(first.artifacts) != len(second.artifacts) {
		return errors.New("releasebuild: build inputs or matrix differ")
	}
	for _, artifact := range first.artifacts {
		sum := artifact.artifact.GetUnsignedSha256()
		if sum == "" || second.observation.GetUnsignedSha256()[artifact.artifact.GetPath()] != sum {
			return fmt.Errorf("releasebuild: unsigned archive differs: %s first=%s second=%s binary-first=%s binary-second=%s console-first=%s console-second=%s", artifact.artifact.GetPath(), sum, second.observation.GetUnsignedSha256()[artifact.artifact.GetPath()], first.observation.GetBinarySha256()[artifact.artifact.GetProduct()+"/"+artifact.artifact.GetArchitecture()], second.observation.GetBinarySha256()[artifact.artifact.GetProduct()+"/"+artifact.artifact.GetArchitecture()], first.observation.GetConsoleTreeSha256(), second.observation.GetConsoleTreeSha256())
		}
	}
	return nil
}

func cleanBuild(ctx context.Context, work, label, source, sourceDigest string, request Request) (*buildOutput, error) {
	root := filepath.Join(work, label)
	if err := os.Mkdir(root, 0700); err != nil {
		return nil, err
	}
	checkout := filepath.Join(root, "source")
	if err := copySource(source, checkout); err != nil {
		return nil, err
	}
	captured, err := treeDigest(checkout)
	if err != nil {
		return nil, err
	}
	if captured != sourceDigest {
		return nil, errors.New("releasebuild: copied source differs")
	}
	for _, dir := range []string{"home", "go-cache", "go-mod", "npm-cache", "bin", "packages"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			return nil, err
		}
	}
	environment := builderEnvironment(root, request.SourceDateEpoch, request.tools)
	observation := &releasev1.BuildObservation{SourceSha256: captured, StartedAt: time.Now().UTC().Format(time.RFC3339Nano), ToolVersions: map[string]string{}, UnsignedSha256: map[string]string{}, BinarySha256: map[string]string{}}
	if err := observeToolchain(ctx, checkout, environment, request.tools, observation); err != nil {
		return nil, err
	}
	result := &buildOutput{observation: observation}
	if err := bootstrapBuildSource(ctx, checkout, environment, request.tools); err != nil {
		return nil, err
	}
	if err := buildProducts(ctx, root, request, result, []string{"lindm-agent"}, ""); err != nil {
		return nil, err
	}
	return result, nil
}

func buildProducts(ctx context.Context, root string, request Request, result *buildOutput, products []string, bundle string) error {
	checkout := filepath.Join(root, "source")
	environment := builderEnvironment(root, request.SourceDateEpoch, request.tools)
	observation := result.observation
	var npmBOM []byte
	if bundle != "" {
		var err error
		observation.ConsoleTreeSha256, err = treeDigest(filepath.Join(checkout, "web", "dist"))
		if err != nil {
			return err
		}
		observation.ConsoleSha256, err = consoleDigests(filepath.Join(checkout, "web", "dist"))
		if err != nil {
			return err
		}
		npmBOM, err = runNPM(ctx, checkout, environment, request.tools, "sbom", "--sbom-format=cyclonedx")
		if err != nil {
			return err
		}
	}
	// Rebuild the packaging helper too: embedded lifecycle assets and package
	// generation code must come from each captured source, not the invoking lab.
	helper := filepath.Join(root, "bin", "lab")
	hostEnvironment := append(append([]string{}, environment...), "GOARCH="+runtime.GOARCH)
	if bundle == "" {
		if _, err := command(ctx, checkout, hostEnvironment, request.tools.goBinary, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", helper, "./cmd/lab"); err != nil {
			return err
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		env := append(append([]string{}, environment...), "GOARCH="+arch)
		for _, product := range products {
			binary := filepath.Join(root, "bin", product+"-"+arch)
			flags := "-buildid= -X lindm/internal/agent/buildinfo.Version=" + request.Version + " -X lindm/internal/agent/buildinfo.Revision=" + request.Revision
			if _, err := command(ctx, checkout, env, request.tools.goBinary, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags", flags, "-o", binary, "./cmd/"+product); err != nil {
				return err
			}
			binaryDigest, _, err := digestFile(binary)
			if err != nil {
				return err
			}
			observation.BinarySha256[product+"/"+arch] = binaryDigest
			bom, err := sbom(ctx, checkout, env, product, request.Version, arch, npmBOM, request.tools.goBinary)
			if err != nil {
				return err
			}
			packageDir := filepath.Join(root, "packages", product+"-"+arch)
			if err := os.Mkdir(packageDir, 0700); err != nil {
				return err
			}
			args := packageArgs(request, product, arch, binary, packageDir)
			if product == "lindmd" {
				args = append(args, "-agent-repository", bundle)
			}
			var files []*os.File
			if request.PackageSigner.PassphraseFD != nil {
				files = []*os.File{request.PackageSigner.PassphraseFD}
			}
			nativeJSON, err := commandWithFiles(ctx, checkout, hostEnvironment, files, helper, args...)
			if err != nil {
				return err
			}
			var native packaging.BuildResult
			if err := json.Unmarshal(nativeJSON, &native); err != nil {
				return err
			}
			result.packagePublicKey = native.PublicKey
			for _, item := range native.Artifacts {
				artifact := &releasev1.ReleaseArtifact{Path: filepath.Base(item.Path), Product: product, Architecture: arch, Format: string(item.Format), Sha256: item.SHA256, Size: item.Size, UnsignedSha256: item.UnsignedSHA256}
				if item.SignaturePath != "" {
					artifact.NativeSignaturePath = artifact.GetPath() + ".sig"
				}
				result.artifacts = append(result.artifacts, builtArtifact{artifact: artifact, path: item.Path, sbom: bom, nativeSignature: item.SignaturePath})
				observation.UnsignedSha256[artifact.GetPath()] = artifact.GetUnsignedSha256()
			}
			// The privileged split agent needs native systemd integration, not an OCI runtime.
			if product != "lindm-agent" {
				name := product + "_" + request.Version + "_" + arch + ".oci.tar"
				path := filepath.Join(packageDir, name)
				if err := buildOCI(binary, filepath.Join(checkout, capturedCAPath), path, product, arch, request.SourceDateEpoch, filepath.Join(checkout, "internal", "packaging", "assets"), bundleForProduct(product, bundle)); err != nil {
					return err
				}
				sum, size, err := digestFile(path)
				if err != nil {
					return err
				}
				ociBOM, err := withCABundleSBOM(bom, request.OCICASHA256)
				if err != nil {
					return err
				}
				artifact := &releasev1.ReleaseArtifact{Path: name, Product: product, Architecture: arch, Format: "oci", Sha256: sum, Size: size, UnsignedSha256: sum}
				result.artifacts = append(result.artifacts, builtArtifact{artifact: artifact, path: path, sbom: ociBOM})
				observation.UnsignedSha256[name] = sum
			}
		}
	}
	observation.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return nil
}

// builderEnvironment isolates one builder's HOME, Go and npm caches and pins
// the toolchain, target OS and source epoch.
func builderEnvironment(root string, sourceDateEpoch int64, tools buildToolchain) []string {
	return []string{
		"PATH=" + filepath.Dir(tools.goBinary) + string(os.PathListSeparator) + filepath.Dir(tools.nodeBinary) + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GOROOT=" + tools.goRoot,
		"HOME=" + filepath.Join(root, "home"),
		"GOCACHE=" + filepath.Join(root, "go-cache"),
		"GOMODCACHE=" + filepath.Join(root, "go-mod"),
		"GOPATH=" + filepath.Join(root, "home", "go"),
		"GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOOS=linux", "CGO_ENABLED=0",
		"SOURCE_DATE_EPOCH=" + fmt.Sprint(sourceDateEpoch),
		"npm_config_cache=" + filepath.Join(root, "npm-cache"),
		"npm_config_userconfig=" + filepath.Join(root, "home", "user.npmrc"),
		"npm_config_globalconfig=" + filepath.Join(root, "home", "global.npmrc"),
		"npm_config_audit=false", "npm_config_fund=false",
	}
}

// observeToolchain records the builder's tool versions and requires the Node and
// Go versions pinned by the captured source.
func observeToolchain(ctx context.Context, checkout string, environment []string, tools buildToolchain, observation *releasev1.BuildObservation) error {
	for _, tool := range []struct {
		name, path string
		args       []string
	}{
		{"go", tools.goBinary, []string{"version"}},
		{"node", tools.nodeBinary, []string{"--version"}},
		{"dpkg-deb", "dpkg-deb", []string{"--version"}},
		{"rpmbuild", "rpmbuild", []string{"--version"}},
	} {
		version, err := command(ctx, checkout, environment, tool.path, tool.args...)
		if err != nil {
			return err
		}
		observation.ToolVersions[tool.name] = strings.TrimSpace(string(version))
	}
	version, err := runNPM(ctx, checkout, environment, tools, "--version")
	if err != nil {
		return err
	}
	observation.ToolVersions["npm"] = strings.TrimSpace(string(version))
	return checkBuildToolVersions(tools, observation.ToolVersions["go"], observation.ToolVersions["node"])
}

// packageArgs is the captured packaging helper's command line for one product
// binary, carrying the package signer and every excluded key.
func packageArgs(request Request, product, arch, binary, packageDir string) []string {
	packageCommand, binaryFlag := "build", "-agent"
	switch product {
	case "lindmd":
		packageCommand, binaryFlag = "build-server", "-lindmd"
	case "lindmctl":
		packageCommand, binaryFlag = "build-cli", "-lindmctl"
	}
	args := []string{"packages", packageCommand, binaryFlag, binary, "-version", request.Version, "-arch", arch, "-output", packageDir, "-source-date-epoch", fmt.Sprint(request.SourceDateEpoch), "-signer-home", request.PackageSigner.Home, "-fingerprint", request.PackageSigner.Fingerprint}
	args = append(args, "-formats", strings.Join(nativeFormats(arch, product), ","))
	if request.PackageSigner.PassphraseFD != nil {
		args = append(args, "-passphrase-fd", "3")
	} else if request.PackageSigner.PassphraseFile != "" {
		args = append(args, "-passphrase-file", request.PackageSigner.PassphraseFile)
	}
	if request.PackageSigner.Custody == packaging.CustodyDevelopment {
		args = append(args, "-development-key")
	}
	for _, value := range request.PackageSigner.RejectPublicKeySHA256 {
		args = append(args, "-reject-spki-sha256", value)
	}
	for _, value := range request.PackageSigner.RejectFingerprints {
		args = append(args, "-reject-fingerprint", value)
	}
	for _, value := range request.PackageSigner.RejectPathPrefixes {
		args = append(args, "-reject-home-prefix", value)
	}
	return args
}

func syncDirectory(path string) (err error) {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return f.Sync()
}
