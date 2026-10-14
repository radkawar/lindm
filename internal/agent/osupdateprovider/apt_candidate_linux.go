// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdateprovider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"lindm/internal/resource"
)

// maxAPTParts bounds the mirrored apt.conf.d listing.
const maxAPTParts = 1024

// aptCandidateTree is a private copy of the APT configuration-part directory
// in which the owned override already has its candidate bytes. Every other
// entry is a symlink to the real part, so APT applies its own file-name and
// ordering rules exactly as it will after the effect.
type aptCandidateTree struct {
	root, parts, config string
}

// buildAPTCandidateTree creates the tree under scratch (an executor-private
// directory). APT reads APT_CONFIG first, then the Dir::Etc::parts directory
// it names, then Dir::Etc::main (/etc/apt/apt.conf) last.
func buildAPTCandidateTree(scratch, partsDir string, candidate []byte) (_ *aptCandidateTree, err error) {
	root, err := os.MkdirTemp(scratch, ".os-update-apt-")
	if err != nil {
		return nil, err
	}
	tree := &aptCandidateTree{root: root, parts: filepath.Join(root, "apt.conf.d"), config: filepath.Join(root, "apt.conf")}
	defer func() {
		if err != nil {
			err = errors.Join(err, tree.Close())
		}
	}()
	if strings.ContainsAny(tree.parts, "\"\n\\") {
		return nil, ErrUnsupported
	}
	if err := os.Mkdir(tree.parts, 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(partsDir)
	if err != nil {
		return nil, err
	}
	if len(entries) > maxAPTParts {
		return nil, fmt.Errorf("%w: too many APT configuration parts", ErrConflict)
	}
	owned := filepath.Base(resource.OSUpdateAPTPeriodPath)
	for _, entry := range entries {
		if entry.Name() == owned || entry.IsDir() {
			continue
		}
		if err := os.Symlink(filepath.Join(partsDir, entry.Name()), filepath.Join(tree.parts, entry.Name())); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(tree.parts, owned), candidate, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(tree.config, []byte("Dir::Etc::parts \""+tree.parts+"/\";\n"), 0600); err != nil {
		return nil, err
	}
	return tree, nil
}

func (t *aptCandidateTree) Close() error { return os.RemoveAll(t.root) }

// aptCandidatePeriodic predicts APT::Periodic::Unattended-Upgrade after the
// owned override is installed, before any native effect.
func aptCandidatePeriodic(ctx context.Context, scratch string, candidate []byte) (value string, err error) {
	tree, err := buildAPTCandidateTree(scratch, filepath.Dir(resource.OSUpdateAPTPeriodPath), candidate)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, tree.Close()) }()
	output, err := runNativeEnv(ctx, []string{"APT_CONFIG=" + tree.config}, "/usr/bin/apt-config", "shell", "Value", "APT::Periodic::Unattended-Upgrade")
	if err != nil {
		return "", err
	}
	return parseAPTShell(output)
}
