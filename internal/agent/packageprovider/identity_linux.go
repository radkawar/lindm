// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// architectureIndependent is each package database's spelling of a package
// that installs unchanged on every architecture.
func architectureIndependent(ecosystem resourcev1.PackageEcosystem) string {
	switch ecosystem {
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB:
		return "all"
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM:
		return "noarch"
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM:
		return "any"
	default:
		return ""
	}
}

// resolveNativeArchitecture asks the native package tool, never uname, which
// package architecture this device installs by default: dpkg's and rpm's
// spellings differ from the kernel's and from each other. ALPM has no such
// query outside pacman.conf, so the approved sources' single Architecture is
// it; sources that disagree leave it unresolved and neutral packages refused.
func (p *Provider) resolveNativeArchitecture(ctx context.Context) error {
	var architecture string
	switch p.ecosystem {
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_DEB, resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM:
		executable, args := "/usr/bin/dpkg", []string{"--print-architecture"}
		if p.ecosystem == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM {
			executable, args = "/usr/bin/rpm", []string{"--eval", "%{_arch}"}
		}
		result, err := p.run(ctx, executable, args, "/", nil)
		if err != nil {
			return fmt.Errorf("resolve native package architecture: %w", err)
		}
		output := string(result.stdout)
		architecture = strings.TrimSuffix(output, "\n")
		if len(result.stderr) != 0 || architecture == "" || strings.ContainsAny(architecture, "\n%") || architecture+"\n" != output {
			return errors.New("packageprovider: invalid native package architecture")
		}
	case resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM:
		for _, source := range p.config.Native.GetSources() {
			repository := source.GetRepository().GetAlpm()
			if repository == nil {
				continue
			}
			if architecture != "" && architecture != repository.GetArchitecture() {
				p.native = ""
				return nil
			}
			architecture = repository.GetArchitecture()
		}
		if architecture == "" || architecture == architectureIndependent(p.ecosystem) {
			p.native = ""
			return nil
		}
	default:
		return ErrUnsupported
	}
	if architecture == architectureIndependent(p.ecosystem) {
		return errors.New("packageprovider: native package architecture is architecture-independent")
	}
	if err := validateMessage(&resourcev1.PackageIdentity{Ecosystem: p.ecosystem, NativeName: "native", Architecture: architecture}); err != nil {
		return fmt.Errorf("packageprovider: invalid native package architecture: %w", err)
	}
	p.native = architecture
	return nil
}

// nativeTarget is the identity the native tools are asked for. A pinned
// package is itself. A package that follows the device's architecture is its
// one installed native or architecture-independent record; when neither is
// installed it stays a bare name, which every native solver resolves to its
// own architecture (requests then admits only a native or independent pick).
// The result is always a fresh message.
func (p *Provider) nativeTarget(db *database, identity *resourcev1.PackageIdentity) (*resourcev1.PackageIdentity, error) {
	if identity.GetArchitecture() != "" {
		return proto.CloneOf(identity), nil
	}
	if p.native == "" {
		return nil, fmt.Errorf("%w: native package architecture unresolved", ErrUnsupported)
	}
	var found *resourcev1.PackageIdentity
	for _, architecture := range []string{p.native, architectureIndependent(identity.GetEcosystem())} {
		candidate := &resourcev1.PackageIdentity{Ecosystem: identity.GetEcosystem(), NativeName: identity.GetNativeName(), Architecture: architecture}
		if db.records[packageKey(candidate)] == nil {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: %s is installed both for %s and architecture-independent", ErrConflict, identity.GetNativeName(), p.native)
		}
		found = candidate
	}
	if found == nil {
		return proto.CloneOf(identity), nil
	}
	return found, nil
}

// resolveIdentity is the concrete identity native evidence names: the native
// target, or the device's own architecture for a package not installed yet.
func (p *Provider) resolveIdentity(db *database, identity *resourcev1.PackageIdentity) (*resourcev1.PackageIdentity, error) {
	target, err := p.nativeTarget(db, identity)
	if err != nil || target.GetArchitecture() != "" {
		return target, err
	}
	target.Architecture = p.native
	return target, nil
}

// requests reports whether a native identity is the desired package itself:
// the pinned identity exactly, or for a package that follows the device's
// architecture the same name at the native or architecture-independent one.
func (p *Provider) requests(desired, candidate *resourcev1.PackageIdentity) bool {
	if desired.GetArchitecture() != "" {
		return proto.Equal(desired, candidate)
	}
	return p.native != "" && candidate.GetEcosystem() == desired.GetEcosystem() && candidate.GetNativeName() == desired.GetNativeName() &&
		(candidate.GetArchitecture() == p.native || candidate.GetArchitecture() == architectureIndependent(desired.GetEcosystem()))
}

// nativeSpec spells a native target for APT (`name:arch`) or for RPM tools
// (`name.arch`); a bare name leaves the choice to the native solver.
func nativeSpec(target *resourcev1.PackageIdentity, separator string) string {
	if target.GetArchitecture() == "" {
		return target.GetNativeName()
	}
	return target.GetNativeName() + separator + target.GetArchitecture()
}
