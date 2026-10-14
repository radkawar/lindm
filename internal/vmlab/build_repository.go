// SPDX-License-Identifier: Apache-2.0

package vmlab

// VMBuildRepository selects compilation inputs without rebinding the development
// fixture. An omitted override preserves the lane's existing repository default.
func VMBuildRepository(fixtureRepository, buildRepository string) string {
	if buildRepository != "" {
		return buildRepository
	}
	return fixtureRepository
}
