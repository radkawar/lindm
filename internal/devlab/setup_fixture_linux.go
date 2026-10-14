// SPDX-License-Identifier: Apache-2.0

package devlab

import "context"

// OpenSetupEnrollmentConsoleAuthorityFixture leaves a fresh LOCAL installation
// uninitialized so the real review browser owns its password/passkey ceremony.
// Its signed repository is published before start; no owner/account SQL bypass
// or authentication response interception substitutes for browser completion.
// The caller keeps the returned capability only in its protected runner config.
func OpenSetupEnrollmentConsoleAuthorityFixture(ctx context.Context, repository, sourceRepository, binary string, architectures []string) (*AuthorityFixture, string, error) {
	var code string
	fixture, err := openAuthorityFixtureWithOptions(ctx, repository, binary, authorityLocalConsole, LoadAuthorityOptions{
		NativeEnrollmentArchitectures: architectures, NativeEnrollmentSourceRepository: sourceRepository, stockEnrollment: true, setupCodeOut: &code,
	})
	if err != nil {
		return nil, "", err
	}
	return fixture, code, nil
}

// OpenSetupMissingArtifactConsoleAuthorityFixture preserves genuinely absent
// publication while leaving owner initialization to the real review browser.
func OpenSetupMissingArtifactConsoleAuthorityFixture(ctx context.Context, repository, binary string) (*AuthorityFixture, string, error) {
	var code string
	fixture, err := openAuthorityFixtureWithOptions(ctx, repository, binary, authorityLocalConsole, LoadAuthorityOptions{
		missingEnrollmentArtifact: true, setupCodeOut: &code,
	})
	if err != nil {
		return nil, "", err
	}
	return fixture, code, nil
}
