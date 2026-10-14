// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serviceprovider

import "context"

// DefinitionFingerprint hashes the ordered native fragment/drop-in graph using
// the same protected descriptor custody as service observations. It authorizes
// neither writes nor execution and rejects unbound legacy include directives.
func DefinitionFingerprint(ctx context.Context, fragment string, dropIns []string) ([]byte, error) {
	return definitionHash(ctx, fragment, dropIns)
}
