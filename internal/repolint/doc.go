// SPDX-License-Identifier: Apache-2.0

// Package repolint holds repository-wide convention tests that belong to no
// single package, such as requiring a package doc comment everywhere under
// internal/. It has no runtime code. Lints that guard one package's API stay
// in that package, as rpcreason and platform do.
package repolint
