//go:build linux

package vmlab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"lindm/internal/packaging"
)

const updateInitialVersion = "0.1.0"
const updateNextVersion = "0.2.0"

// updatePackageFixture freezes all source bytes before building either side of
// the update. The host server and the guest packages therefore use one contract;
// the two package versions exercise the previous-minor compatibility window.
type updatePackageFixture struct {
	sourceSHA256 string
	serverBinary string
	server       *packaging.BuildResult
	builds       []*packaging.BuildResult
	first        packaging.Artifact
	second       packaging.Artifact
	apt          *packaging.APTRepository
	publicKey    string
	fingerprint  string
}

func buildUpdatePackages(ctx context.Context, repository, work, distribution, architecture string) (*updatePackageFixture, error) {
	var target string
	switch architecture {
	case "amd64", "x86_64":
		target = "amd64"
	case "arm64", "aarch64":
		target = "arm64"
	default:
		return nil, errors.New("update lane requires a supported guest architecture")
	}
	format := packaging.FormatDEB
	if distribution == "fedora" {
		format = packaging.FormatRPM
	} else if distribution != "ubuntu" {
		return nil, errors.New("update lane requires Ubuntu or Fedora")
	}
	fixture := new(updatePackageFixture)
	source := filepath.Join(work, "source")
	var err error
	fixture.sourceSHA256, err = snapshotServerSource(ctx, repository, source)
	if err != nil {
		return nil, err
	}
	signer, err := packaging.GenerateDevelopmentSigner(ctx, work)
	if err != nil {
		return nil, err
	}
	fixture.fingerprint = signer.Fingerprint
	for _, version := range []string{updateInitialVersion, updateNextVersion} {
		out := filepath.Join(work, "agent-"+version)
		if err := os.Mkdir(out, 0o700); err != nil {
			return nil, err
		}
		built, err := packaging.BuildSource(ctx, packaging.SourceRequest{Repository: source, Revision: "native-tuf-update-lab", BuildRequest: packaging.BuildRequest{Version: version, TargetArchitecture: target, OutputDir: out, Formats: []packaging.Format{format}, Signer: *signer}})
		if err != nil {
			return nil, err
		}
		if len(built.Artifacts) != 1 {
			return nil, errors.New("update build did not produce one native artifact")
		}
		fixture.builds = append(fixture.builds, built)
	}
	fixture.first, fixture.second = fixture.builds[0].Artifacts[0], fixture.builds[1].Artifacts[0]
	fixture.publicKey = fixture.builds[0].PublicKey
	if format == packaging.FormatDEB {
		out := filepath.Join(work, "apt")
		if err := os.Mkdir(out, 0o700); err != nil {
			return nil, err
		}
		fixture.apt, err = packaging.PublishAPT(ctx, packaging.APTRequest{OutputDir: out, DEBs: []string{fixture.first.Path, fixture.second.Path}, Signer: *signer})
		if err != nil {
			return nil, err
		}
		fixture.publicKey = fixture.apt.PublicKeyArmor
	}
	serverOut := filepath.Join(work, "server")
	if err := os.Mkdir(serverOut, 0o700); err != nil {
		return nil, err
	}
	fixture.server, err = packaging.BuildServerSource(ctx, packaging.SourceRequest{Repository: source, Revision: "native-tuf-update-lab", BuildRequest: packaging.BuildRequest{Version: updateNextVersion, TargetArchitecture: runtime.GOARCH, OutputDir: serverOut, Formats: []packaging.Format{packaging.FormatDEB}}})
	if err != nil {
		return nil, err
	}
	if len(fixture.server.Artifacts) != 1 {
		return nil, errors.New("update server build did not produce one artifact")
	}
	extracted := filepath.Join(serverOut, "extracted")
	// Extraction never installs on the host or executes package lifecycle scripts.
	if _, err := hostCommand(ctx, serverOut, "dpkg-deb", nil, "--extract", fixture.server.Artifacts[0].Path, extracted); err != nil {
		return nil, err
	}
	fixture.serverBinary = filepath.Join(extracted, "usr/bin/lindmd")
	digest, err := dispatchFileDigest(fixture.serverBinary)
	if err != nil || digest != fixture.server.BinarySHA256 {
		return nil, fmt.Errorf("update server extraction differs from verified package: %w", errors.Join(err, errors.New("server payload digest mismatch")))
	}
	return fixture, nil
}
