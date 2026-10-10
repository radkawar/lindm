package main

import (
	"context"
	"errors"
	"io"

	"lindm/internal/releaseupdate"
)

func runRelease(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("release requires build, attestation-keygen, verify or repository")
	}
	switch args[0] {
	case "build":
		return runReleaseBuild(ctx, args[1:], stdout, stderr)
	case "attestation-keygen":
		return runReleaseAttestationKeygen(args[1:], stdout, stderr)
	case "verify":
		return runReleaseVerify(ctx, args[1:], stdout, stderr)
	case "repository":
		return releaseupdate.RunCLI(ctx, args[1:], stdout, stderr)
	default:
		return errors.New("unknown release command: use build, attestation-keygen, verify or repository")
	}
}
