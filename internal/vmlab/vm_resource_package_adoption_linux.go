//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// packageAdoptionScenarios run where the agent proves an installed package's
// provenance against the approved source (APT and DNF5).
var packageAdoptionScenarios = []string{"modified-installation-unverified", "installed-package-adoption-required", "approved-package-adoption", "adopted-release-retains-package"}

func packageAdoptionSupported(rpm resourcePackaging) bool {
	return !rpm.dnf4 && !rpm.pacman && !rpm.zypper
}

// exercisePackageAdoption installs the signed fixture's v1 outside lindm, as an
// image ships a package. A modified installation stays unverified even under
// approved adoption; the unmodified one needs approved adoption, which pins it
// without a package transaction; release removes only the pin. The package is
// then removed outside lindm so later scenarios start from absence. The lab
// server must list APPROVED_ADOPTION for NATIVE_PACKAGE to dispatch it.
func exercisePackageAdoption(ctx context.Context, r *resourceDispatch, rpm resourcePackaging, evidence *VMResourceKindEvidence) error {
	if !packageAdoptionSupported(rpm) {
		return nil
	}
	r.profile, r.resource, r.revision = uuid.NewString(), uuid.NewString(), ""
	desired := resourcePackageDesired(rpm, "1.0", true)
	program := "/usr/bin/" + resourcePackageName
	install := "dpkg -i " + resourceFixtureRoot + "/repo/" + resourcePackageName + "-1.0.deb"
	remove := "dpkg -r " + resourcePackageName
	query := "dpkg-query -W -f='${Package} ${Version} ${Architecture} ${db:Status-Status}\\n' " + resourcePackageName + "; test \"$(dpkg-query -W -f='${Version}' " + resourcePackageName + ")\" = 1.0-1; "
	verify := "test -z \"$(dpkg --verify " + resourcePackageName + ")\"; printf 'verified\\n'; "
	unpinned := fmt.Sprintf("test ! -e /etc/apt/preferences.d/lindm-%x; ", sha256.Sum256([]byte(desired.GetRef().GetCanonicalKey())))
	if rpm.rpm {
		install = "rpm -i " + resourceFixtureRoot + "/repo/" + resourcePackageName + "-1.0-1." + rpm.nativeArch() + ".rpm"
		remove = "rpm -e " + resourcePackageName
		query = "rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH} %{SHA256HEADER}\\n' " + resourcePackageName + "; test \"$(rpm -q --qf '%{VERSION}' " + resourcePackageName + ")\" = 1.0; "
		verify = "rpm -V " + resourcePackageName + "; printf 'verified\\n'; "
		unpinned = "python3 -c " + nativeQuote("import os, tomllib; p='/etc/dnf/versionlock.toml'; d=tomllib.load(open(p,'rb')) if os.path.exists(p) else {}; assert not [e for e in d.get('packages', []) if e['name']=='"+resourcePackageName+"']") + "; "
	}
	unpinned += "printf 'unpinned\\n'; "
	maintainer := "cat " + resourceFixtureRoot + "/maintainer.log"
	baselineCommand := query + verify + unpinned + maintainer
	if err := lifecycleCommand(ctx, r.vm, "install signed fixture v1 outside lindm", install); err != nil {
		return err
	}
	baseline, err := resourceOracle(ctx, r.vm, "unmanaged-installation", baselineCommand)
	if err != nil {
		return err
	}
	adoption := &resourcev1.OwnershipPolicy{Mode: resourcev1.OwnershipMode_OWNERSHIP_MODE_APPROVED_ADOPTION, Release: resourcev1.ReleaseBehavior_RELEASE_BEHAVIOR_RESTORE_OWNED}
	// refused runs one row that must fail preparation with the given detail
	// and leave the installation exactly as before.
	refused := func(name string, ownership *resourcev1.OwnershipPolicy, detail, command string) error {
		evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: name, StartedAt: time.Now().UTC()})
		s := &evidence.Scenarios[len(evidence.Scenarios)-1]
		before, err := resourceOracle(ctx, r.vm, name+"-before", command)
		if err != nil {
			return err
		}
		if err := r.assign(ctx, desired, ownership); err != nil {
			s.Failure = err.Error()
			return err
		}
		if s.Action, err = r.action(ctx, true); err != nil {
			s.Failure = err.Error()
			return err
		}
		if s.Action.GetStartAuthorizedAt() != nil || s.Action.GetStatus().GetPreparationOutcome().GetDetail() != detail {
			s.Failure = fmt.Sprintf("want unstarted refusal %s, got %s", detail, s.Action)
			return errors.New(s.Failure)
		}
		after, err := resourceOracle(ctx, r.vm, name+"-after", command)
		if err != nil {
			return err
		}
		if !bytes.Equal(before.Bytes, after.Bytes) {
			return errors.New("refused package acquisition changed the installation")
		}
		s.Native = []VMResourceNativeRecord{before, after}
		s.Passed = true
		s.FinishedAt = time.Now().UTC()
		return nil
	}
	if err := lifecycleCommand(ctx, r.vm, "modify an installed package file outside its package", "cp -p "+program+" "+resourceFixtureRoot+"/proof.orig; printf '# modified outside its package\\n' >> "+program); err != nil {
		return err
	}
	if err := refused("modified-installation-unverified", adoption, "existing_package_unverified", "sha256sum "+program+"; "+query+unpinned+maintainer); err != nil {
		return err
	}
	if err := lifecycleCommand(ctx, r.vm, "restore the packaged file", "cp -p "+resourceFixtureRoot+"/proof.orig "+program+"; rm "+resourceFixtureRoot+"/proof.orig"); err != nil {
		return err
	}
	if err := refused("installed-package-adoption-required", resourceCreatePolicy(), "existing_package", baselineCommand); err != nil {
		return err
	}
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: "approved-package-adoption", StartedAt: time.Now().UTC()})
	s := &evidence.Scenarios[len(evidence.Scenarios)-1]
	scripts, err := resourceOracle(ctx, r.vm, "maintainer-scripts-before-adoption", maintainer)
	if err != nil {
		return err
	}
	if err := r.assign(ctx, desired, adoption); err != nil {
		s.Failure = err.Error()
		return err
	}
	if s.Action, err = r.action(ctx, false); err != nil {
		s.Failure = err.Error()
		s.Native = append(s.Native, executorDiagnostics(ctx, r.vm))
		return err
	}
	if s.Action.GetStartAuthorizedAt() == nil || !s.Action.GetStatus().GetVerification().GetNativePackage().GetApprovedSourceMatches() {
		s.Failure = "approved adoption converged without its owned pin or approved source"
		return errors.New(s.Failure)
	}
	adopted, err := packageOracle(ctx, r.vm, rpm, "1.0", true)
	if err != nil {
		s.Failure = err.Error()
		return err
	}
	unchanged, err := resourceOracle(ctx, r.vm, "maintainer-scripts-after-adoption", maintainer)
	if err != nil {
		return err
	}
	if !bytes.Equal(scripts.Bytes, unchanged.Bytes) {
		s.Failure = "approved adoption ran a package transaction"
		return errors.New(s.Failure)
	}
	s.Native = []VMResourceNativeRecord{baseline, scripts, adopted, unchanged}
	s.Passed = true
	s.FinishedAt = time.Now().UTC()
	evidence.Scenarios = append(evidence.Scenarios, VMResourceScenario{Name: "adopted-release-retains-package", StartedAt: time.Now().UTC()})
	s = &evidence.Scenarios[len(evidence.Scenarios)-1]
	if s.Release, err = r.release(ctx, desired.GetRef(), false); err != nil {
		s.Failure = err.Error()
		return err
	}
	restored, err := resourceOracle(ctx, r.vm, "restored-unmanaged-installation", baselineCommand)
	if err != nil {
		s.Failure = err.Error()
		return err
	}
	if !bytes.Equal(restored.Bytes, baseline.Bytes) {
		s.Failure = "adopted package release changed the installation, its files or left its pin"
		return errors.New(s.Failure)
	}
	s.Native = []VMResourceNativeRecord{baseline, restored}
	s.Passed = true
	s.FinishedAt = time.Now().UTC()
	return lifecycleCommand(ctx, r.vm, "remove the adopted fixture outside lindm", remove)
}
