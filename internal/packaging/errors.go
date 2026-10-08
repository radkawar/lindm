//go:build linux

package packaging

import "errors"

var (
	// ErrUnsafePath rejects replaceable, relative, or non-canonical inputs.
	ErrUnsafePath = errors.New("unsafe packaging path")
	// ErrArchitecture rejects a binary that is not a supported Linux ELF.
	ErrArchitecture = errors.New("agent binary architecture rejected")
	// ErrVersion rejects a binary whose executed version does not match.
	ErrVersion = errors.New("agent binary version rejected")
	// ErrToolMissing means a required native tool is not in /usr/bin or /bin.
	ErrToolMissing = errors.New("required packaging tool is not installed")
	// ErrRepositoryTool means createrepo_c was not run and no repodata exists.
	ErrRepositoryTool = errors.New("createrepo_c is required to build an RPM repository and is not installed; repodata was not generated or verified")
	// ErrSigner rejects a key that is not an explicit package-signing key.
	ErrSigner = errors.New("package signing key rejected")
	// ErrSignerBusy means another operation owns this package-signing home.
	ErrSignerBusy = errors.New("package signing home is busy")
	// ErrArtifact means a built package failed its own digest or signature check.
	ErrArtifact = errors.New("package artifact verification failed")
)
