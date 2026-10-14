// SPDX-License-Identifier: Apache-2.0

//go:build linux

package fileprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/nativeexec"
	"lindm/internal/platform"
)

// ModuleBlocklistPath is reserved for the closed, non-secret module template.
const ModuleBlocklistPath = "/etc/modprobe.d/99-lindm-blocklist.conf"

func moduleTemplate(d *resourcev1.ManagedFileDesired) *resourcev1.ManagedFileDesired {
	if d.GetKernelModuleBlocklist() == nil {
		return d
	}
	result := proto.CloneOf(d)
	result.KernelModuleBlocklist = nil
	modules := slices.Clone(d.GetKernelModuleBlocklist().GetModules())
	slices.Sort(modules)
	var text strings.Builder
	text.WriteString("# Managed by lindm. Active and built-in modules are never unloaded.\n")
	for _, name := range modules {
		fmt.Fprintf(&text, "blacklist %s\ninstall %s /bin/false\n", name, name)
	}
	result.Content = []byte(text.String())
	result.Mode, result.Uid, result.Gid = proto.Uint32(0644), proto.Uint32(0), proto.Uint32(0)
	return result
}

func moduleTooling(product *resourcev1.PlatformProduct) (platform.ModuleBlocklistTooling, error) {
	tools := platform.Of(product).ModuleBlocklist
	if tools.Rebuild == "" || tools.Modprobe == "" {
		return tools, fmt.Errorf("%w: kernel module blocklist tooling unqualified", ErrUnsupported)
	}
	for _, path := range []string{tools.Modprobe, tools.Rebuild} {
		info, err := os.Stat(path)
		if err != nil {
			return tools, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return tools, ErrUnsupported
		}
	}
	return tools, nil
}

func observeModules(ctx context.Context, d *resourcev1.ManagedFileDesired, product *resourcev1.PlatformProduct, kernel string) (*resourcev1.KernelModuleBlocklistObservation, error) {
	tools, err := moduleTooling(product)
	if err != nil {
		return nil, err
	}
	loaded, err := boundedModuleFile("/proc/modules", 4<<20)
	if err != nil {
		return nil, err
	}
	builtins, err := boundedModuleFile(filepath.Join("/lib/modules", kernel, "modules.builtin"), 4<<20)
	if err != nil {
		return nil, err
	}
	config, err := nativeexec.Run(ctx, nativeexec.Command{Path: tools.Modprobe, Args: []string{"--showconfig"}, Timeout: 10 * time.Second, StdoutLimit: 4 << 20, StderrLimit: 32768})
	if err != nil {
		return nil, err
	}
	names := d.GetKernelModuleBlocklist().GetModules()
	result := &resourcev1.KernelModuleBlocklistObservation{Modules: make([]*resourcev1.KernelModuleObservation, 0, len(names))}
	byName := make(map[string]*resourcev1.KernelModuleObservation, len(names))
	for _, name := range names {
		module := &resourcev1.KernelModuleObservation{Name: name}
		result.Modules = append(result.Modules, module)
		byName[name] = module
	}
	for line := range strings.SplitSeq(string(loaded), "\n") {
		name, _, _ := strings.Cut(line, " ")
		if module := byName[name]; module != nil {
			module.Loaded = true
		}
	}
	for line := range strings.SplitSeq(string(builtins), "\n") {
		name := strings.ReplaceAll(strings.TrimSuffix(filepath.Base(line), ".ko"), "-", "_")
		if module := byName[name]; module != nil {
			module.BuiltIn = true
		}
	}
	for line := range strings.SplitSeq(string(config.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "blacklist" {
			continue
		}
		if module := byName[strings.ReplaceAll(fields[1], "-", "_")]; module != nil {
			module.ModprobeBlocked = true
		}
	}
	for _, module := range result.Modules {
		if !module.ModprobeBlocked {
			continue
		}
		deps, depErr := nativeexec.Run(ctx, nativeexec.Command{Path: tools.Modprobe, Args: []string{"--show-depends", "--", module.Name}, Timeout: 10 * time.Second, StdoutLimit: 32768, StderrLimit: 32768})
		module.ModprobeBlocked = depErr == nil && moduleInstallCommandsBlocked(deps.Stdout)
	}
	entries, err := os.ReadDir("/lib/modules")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.ContainsAny(name, "/\x00\r\n") {
			return nil, ErrUnsupported
		}
		path := fmt.Sprintf(tools.InitramfsPattern, name)
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		if len(result.Initramfs) >= 32 {
			return nil, ErrUnsupported
		}
		image, content, err := initramfsBlocklist(path)
		if err != nil {
			return nil, fmt.Errorf("observe initramfs %s: %w", name, err)
		}
		result.Initramfs = append(result.Initramfs, &resourcev1.ModuleInitramfsObservation{KernelRelease: name, Path: path, Sha256: image, BlocklistSha256: content})
	}
	if len(result.Initramfs) == 0 {
		return nil, fmt.Errorf("%w: no installed initramfs", ErrUnsupported)
	}
	return result, nil
}

// kmod prints one line per module/dependency. A blocked dependency may therefore
// repeat the same false command; any insmod/builtin/other install remains drift.
func moduleInstallCommandsBlocked(output []byte) bool {
	output = bytes.TrimSpace(output)
	if len(output) == 0 {
		return false
	}
	for line := range bytes.SplitSeq(output, []byte{'\n'}) {
		if !bytes.Equal(bytes.TrimSpace(line), []byte("install /bin/false")) {
			return false
		}
	}
	return true
}

func boundedModuleFile(path string, limit int64) (data []byte, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = ErrUnsupported
	}
	return data, err
}

func initramfsMatches(observation *resourcev1.KernelModuleBlocklistObservation, target *agentv1.ResourceOwnershipSnapshot) bool {
	if observation == nil || len(observation.GetInitramfs()) == 0 {
		return false
	}
	var want []byte
	if target.GetObservation().GetManagedFile().GetExists() {
		digest := sha256.Sum256(target.GetManagedFileContent())
		want = digest[:]
	}
	for _, image := range observation.GetInitramfs() {
		if !bytes.Equal(image.GetBlocklistSha256(), want) {
			return false
		}
	}
	return true
}

// moduleFileImage removes non-file evidence only at the nativefile boundary.
// Module and archive preconditions are checked separately before effect admission.
func moduleFileImage(source *agentv1.ResourceOwnershipSnapshot) *agentv1.ResourceOwnershipSnapshot {
	if source.GetObservation().GetManagedFile().GetKernelModuleBlocklist() == nil {
		return source
	}
	result := proto.CloneOf(source)
	result.Observation.GetManagedFile().KernelModuleBlocklist = nil
	result.ModuleInitramfsRebuildSucceeded = nil
	return result
}

func moduleRebuildFailed(snapshot *agentv1.ResourceOwnershipSnapshot) bool {
	return snapshot != nil && snapshot.ModuleInitramfsRebuildSucceeded != nil && !snapshot.GetModuleInitramfsRebuildSucceeded()
}
