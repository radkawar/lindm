// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/custody"
)

// alpmPolicyInputs binds every Include expansion, including its path set. A new
// glob match or any included-byte change invalidates preparation. The top-level
// owned block is removed by the caller; external bytes remain authoritative.
func alpmPolicyInputs(root []byte) ([32]byte, error) {
	h := sha256.New()
	count, size := 0, len(root)
	var visit func(string, []byte, int) error
	visit = func(path string, data []byte, depth int) error {
		count++
		if depth > 16 || count > 256 || size > 4<<20 {
			return errors.New("packageprovider: ALPM include capacity")
		}
		_, _ = fmt.Fprintf(h, "%d:%s:%d:", len(path), path, len(data)) // hash.Hash writes cannot fail.
		_, _ = h.Write(data)
		for line := range strings.SplitSeq(string(data), "\n") {
			text, _, _ := strings.Cut(line, "#")
			key, value, ok := strings.Cut(text, "=")
			if !ok || strings.TrimSpace(key) != "Include" {
				continue
			}
			pattern := strings.TrimSpace(value)
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join("/", pattern) // native probe cwd is /
			}
			paths, err := filepath.Glob(pattern)
			if err != nil || len(paths) == 0 {
				return errors.New("packageprovider: unresolved ALPM Include")
			}
			for _, included := range paths {
				contents, err := custody.ReadRoot(included, 1<<20, false)
				if err != nil {
					return err
				}
				size += len(contents)
				if err := visit(included, contents, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(pacmanConfigPath, root, 0); err != nil {
		return [32]byte{}, err
	}
	return [32]byte(h.Sum(nil)), nil
}

func checkALPMHolds(policy string, selection alpmSelection, remove bool) error {
	for line := range strings.SplitSeq(policy, "\n") {
		key, values, _ := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		var candidates []string
		switch key {
		case "IgnorePkg":
			candidates = []string{selection.record.GetPackage().GetNativeName()}
		case "IgnoreGroup":
			candidates = selection.groups
		case "HoldPkg":
			if remove {
				candidates = []string{selection.record.GetPackage().GetNativeName()}
			}
		}
		for _, pattern := range strings.Fields(values) {
			for _, candidate := range candidates {
				// Reject simple holds early. Bracket classes, escapes and slash
				// matching use libc fnmatch, not Go's pathname grammar, in the
				// retained native transaction before the effect permit.
				if strings.ContainsAny(pattern, "[\\/") || strings.Contains(candidate, "/") {
					continue
				}
				matched, err := filepath.Match(pattern, candidate)
				if err != nil || matched {
					return errors.New("packageprovider: externally owned ALPM package/group hold")
				}
			}
		}
	}
	return nil
}

func (p *Provider) checkALPMPolicy(ctx context.Context, directory string, d *resourcev1.NativePackageDesired) error {
	policy, inputs, err := p.alpmPolicy(ctx, directory, d)
	if err != nil {
		return err
	}
	prepared, err := custody.ReadRoot(filepath.Join(directory, "cache", "alpm-policy"), maxPin, false)
	if err != nil {
		return err
	}
	if !bytes.Equal(prepared, []byte(hex.EncodeToString(inputs[:])+"\n"+policy)) {
		return ErrConflict
	}
	return nil
}
