package platform

import (
	"fmt"
	"slices"
)

// RepositorySnapshotRecipe contains vendor trust and explicit native-solver
// inputs. Signed metadata and the guest's complete installed package inventory
// supply the dependency graph; this list is not itself a closure.
type RepositorySnapshotRecipe struct {
	Signer               string
	Sources              map[string]string
	Packages             []string
	ArchitecturePackages map[string][]string
	// SnapshotPackages binds exact native selectors to VERSION_ID and architecture.
	// An unrecorded snapshot has no complete installer recipe.
	SnapshotPackages map[string]map[string][]string
	// DesktopTaboo names, per VERSION_ID and architecture, packages a desktop
	// golden must not select because the signed closure omits them.
	DesktopTaboo map[string]map[string][]string
}

// RepositorySnapshotInputs includes the maintained lane recipes as well as
// explicit baseline/resource/password inputs. Sorting fixes the solver input
// order and makes the exact input set part of the content address.
func RepositorySnapshotInputs(distribution, version, architecture string) ([]string, error) {
	recipe := RepositorySnapshotRecipes[distribution]
	pinned := recipe.SnapshotPackages[version][architecture]
	if len(pinned) == 0 {
		return nil, fmt.Errorf("no exact snapshot package recipe for %s %s %s", distribution, version, architecture)
	}
	inputs := slices.Clone(recipe.Packages)
	inputs = append(inputs, recipe.ArchitecturePackages[architecture]...)
	inputs = append(inputs, pinned...)
	release := ForManifest(distribution, version)
	inputs = append(inputs, release.Lab.ResourcePackages...)
	inputs = append(inputs, release.Lab.InstallerPackages...)
	inputs = append(inputs, release.Lab.TPM.Packages...)
	inputs = append(inputs, release.Lab.Guest.Actions...)
	inputs = append(inputs, release.Lab.Guest.OwnedBoot...)
	inputs = append(inputs, release.Lab.Guest.MeasuredBoot...)
	inputs = append(inputs, release.Lab.Session.Capture...)
	for _, packages := range release.Lab.Session.Desktops {
		inputs = append(inputs, packages...)
	}
	slices.Sort(inputs)
	return slices.Compact(inputs), nil
}
