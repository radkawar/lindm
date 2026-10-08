//go:build linux

package packaging

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

// SourceRequest builds the actual agent from a checkout before native packaging.
// Go's normal module/build caches remain available for the inner development loop;
// the module graph is read-only and compilation intermediates are private.
type SourceRequest struct {
	Repository string
	Revision   string
	BuildRequest
}

var revisionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

// BuildSource is the maintained lab source-to-artifact path. It does not assert
// release reproducibility, clean source, or production signing-key custody.
func BuildSource(ctx context.Context, request SourceRequest) (*BuildResult, error) {
	version, err := parseVersion(request.Version)
	if err != nil {
		return nil, err
	}
	if !revisionPattern.MatchString(request.Revision) {
		return nil, fmt.Errorf("%w: invalid source revision label", ErrVersion)
	}
	if request.AgentBinary != "" {
		return nil, fmt.Errorf("%w: source and prebuilt agent are mutually exclusive", ErrArtifact)
	}
	root, err := filepath.Abs(request.Repository)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: repository is not a directory", ErrUnsafePath)
	}
	output, err := openPrivate(request.OutputDir)
	if err != nil {
		return nil, err
	}
	if err := output.Close(); err != nil {
		return nil, err
	}
	work, cleanup, err := privateWork(request.OutputDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()
	compiler, err := exec.LookPath("go")
	if err != nil {
		return nil, err
	}
	binary := filepath.Join(work, "lindm-agent")
	flags := "-X lindm/internal/agent/buildinfo.Version=" + version + " -X lindm/internal/agent/buildinfo.Revision=" + request.Revision
	_, _, err = runTool(ctx, work, toolCmd{Path: compiler, Args: []string{"build", "-mod=readonly", "-trimpath", "-ldflags", flags, "-o", binary, "./cmd/lindm-agent"}, Dir: root, ExtraEnv: append(os.Environ(), "CGO_ENABLED=0"), Timeout: 5 * time.Minute})
	if err != nil {
		return nil, fmt.Errorf("compile versioned agent: %w", err)
	}
	request.AgentBinary = binary
	return Build(ctx, request.BuildRequest)
}
