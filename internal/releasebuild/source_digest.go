// SPDX-License-Identifier: Apache-2.0

//go:build linux

package releasebuild

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
)

// SourceDigest hashes the exact bounded source selected by the release capture,
// without copying it or compiling anything. Cache consumers must compare the
// resulting build's source digest again before publishing a new cache entry.
func SourceDigest(ctx context.Context, repository string) (string, error) {
	paths, err := sourcePaths(ctx, repository)
	if err != nil {
		return "", err
	}
	return digestPaths(ctx, repository, paths)
}

// agentInputFiles are captured-source files outside the agent's Go package
// closure that still decide the development agent repository: the module graph,
// the Go and Node toolchain pins the build enforces, and the `lab packages`
// helper's entry point and subcommand, which the build recompiles from the
// captured source to generate and sign the native packages.
var agentInputFiles = []string{"go.mod", "go.sum", ".node-version", ".tool-versions", "mise.toml", ".mise.toml", "cmd/lab/main.go", "cmd/lab/packages.go"}

// agentInputPackages are the Go packages whose dependency closure, for every
// built and host architecture, is compiled into the agent or drives its
// packaging, signing and release manifest.
var agentInputPackages = []string{"./cmd/lindm-agent", "./internal/packaging", "./internal/releasebuild"}

// AgentInputDigest is a conservative cache key for BuildDevelopmentAgentRepository:
// the same bounded, captured files as SourceDigest, restricted to the directory
// trees of every in-module package the agent, packaging and release build code
// depend on (whole trees, so embedded assets, tests and nested packages count),
// plus agentInputFiles and the caller's extra captured paths. Console, server,
// documentation and other lab changes keep the key. The resulting build still
// records the full SourceDigest of the tree it was built from.
func AgentInputDigest(ctx context.Context, repository string, extra ...string) (string, error) {
	paths, err := sourcePaths(ctx, repository)
	if err != nil {
		return "", err
	}
	directories, err := agentInputDirectories(ctx, repository)
	if err != nil {
		return "", err
	}
	files := slices.Concat(agentInputFiles, extra)
	selected := slices.DeleteFunc(paths, func(name string) bool {
		if slices.Contains(files, name) {
			return false
		}
		for _, directory := range directories {
			// A dependency at the module root covers the whole tree.
			if directory == "." || strings.HasPrefix(name, directory+"/") {
				return false
			}
		}
		return true
	})
	return digestPaths(ctx, repository, selected)
}

// agentInputDirectories lists repository-relative directories of the in-module
// Go dependencies of agentInputPackages for linux on each built architecture
// and the host. Out-of-module dependencies are pinned by go.sum and the Go
// toolchain version in go.mod.
func agentInputDirectories(ctx context.Context, repository string) ([]string, error) {
	root, err := filepath.Abs(repository)
	if err != nil {
		return nil, err
	}
	if root, err = filepath.EvalSymlinks(root); err != nil {
		return nil, err
	}
	environment := []string{"GOOS=linux", "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=-mod=readonly"}
	for _, key := range []string{"HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "MISE_DATA_DIR", "MISE_CONFIG_DIR", "GOPATH", "GOMODCACHE", "GOCACHE", "GOPROXY", "GOPRIVATE", "GONOSUMDB", "GONOPROXY", "GOTOOLCHAIN"} {
		if value, ok := os.LookupEnv(key); ok {
			environment = append(environment, key+"="+value)
		}
	}
	var directories []string
	for _, architecture := range slices.Compact(slices.Sorted(slices.Values([]string{"amd64", "arm64", runtime.GOARCH}))) {
		listed, err := command(ctx, repository, append(slices.Clone(environment), "GOARCH="+architecture), "go", slices.Concat([]string{"list", "-deps", "-f", "{{.Dir}}"}, agentInputPackages)...)
		if err != nil {
			return nil, fmt.Errorf("releasebuild: list agent input packages: %w", err)
		}
		for _, directory := range strings.Split(strings.TrimSpace(string(listed)), "\n") {
			if directory == "" {
				continue
			}
			// Compare resolved paths so a symlinked checkout cannot silently drop
			// in-module packages from the key.
			resolved, err := filepath.EvalSymlinks(directory)
			if err != nil {
				return nil, err
			}
			relative, err := filepath.Rel(root, resolved)
			if err != nil {
				return nil, err
			}
			if relative != "." && !filepath.IsLocal(relative) {
				continue // module cache or GOROOT: pinned by go.sum and go.mod
			}
			directories = append(directories, filepath.ToSlash(relative))
		}
	}
	if len(directories) == 0 {
		return nil, errors.New("releasebuild: agent input packages resolved outside the repository")
	}
	slices.Sort(directories)
	return slices.Compact(directories), nil
}

func digestPaths(ctx context.Context, repository string, paths []string) (string, error) {
	root, err := os.OpenRoot(repository)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	hash := sha256.New()
	var total int64
	for _, name := range paths {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		info, err := root.Lstat(name)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("releasebuild: source %s is not regular", name)
		}
		total += info.Size()
		if total > 512<<20 || info.Size() > 64<<20 {
			return "", errors.New("releasebuild: source exceeds bound")
		}
		sum, size, err := sourceFileDigest(root, name, info.Size())
		if err != nil {
			return "", err
		}
		if _, err := fmt.Fprintf(hash, "%s\x00%o\x00%d\x00%s\n", name, info.Mode().Perm()&0755, size, sum); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func sourceFileDigest(root *os.Root, name string, size int64) (sum string, count int64, err error) {
	file, err := root.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	count, err = io.Copy(hash, io.LimitReader(file, size+1))
	if err != nil {
		return "", 0, err
	}
	if count != size {
		return "", 0, errors.New("releasebuild: source changed while hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), count, nil
}

func sourcePaths(ctx context.Context, repository string) ([]string, error) {
	listed, err := command(ctx, repository, nil, "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	paths := strings.Split(strings.TrimSuffix(string(listed), "\x00"), "\x00")
	if len(paths) > 100000 {
		return nil, errors.New("releasebuild: source file count exceeds bound")
	}
	removed, err := command(ctx, repository, nil, "git", "ls-files", "--deleted", "-z")
	if err != nil {
		return nil, fmt.Errorf("releasebuild: list source deletions: %w", err)
	}
	var removedPaths map[string]struct{}
	if len(removed) > 0 {
		names := strings.Split(strings.TrimSuffix(string(removed), "\x00"), "\x00")
		if len(names) > 100000 {
			return nil, errors.New("releasebuild: source deletion count exceeds bound")
		}
		removedPaths = make(map[string]struct{}, len(names))
		for _, name := range names {
			removedPaths[name] = struct{}{}
		}
	}
	// Match filepath.WalkDir's component ordering, not flat path ordering.
	sort.Slice(paths, func(i, j int) bool { return sourcePathLess(paths[i], paths[j]) })
	kept := paths[:0]
	previous := ""
	for _, name := range paths {
		if name == previous {
			continue
		}
		previous = name
		if !filepath.IsLocal(name) {
			return nil, errors.New("releasebuild: invalid source path")
		}
		// Cached entries include unstaged deletions. Later disappearance still fails
		// the digest/capture filesystem checks rather than becoming a silent omission.
		if _, removed := removedPaths[name]; removed {
			continue
		}
		ignored := false
		for _, prefix := range []string{".git/", ".cache/", ".tools/", "artifacts/", "node_modules/", "web/dist/"} {
			if strings.HasPrefix(name, prefix) {
				ignored = true
				break
			}
		}
		if !ignored {
			kept = append(kept, name)
		}
	}
	return kept, nil
}

func sourcePathLess(a, b string) bool {
	for {
		partA, restA, moreA := strings.Cut(a, "/")
		partB, restB, moreB := strings.Cut(b, "/")
		if partA != partB {
			return partA < partB
		}
		if !moreA || !moreB {
			return !moreA && moreB
		}
		a, b = restA, restB
	}
}
