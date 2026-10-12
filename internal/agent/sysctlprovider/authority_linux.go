//go:build linux

package sysctlprovider

// AuthorityKey reports whether the provider refuses key as protected kernel
// authority or a one-shot command, whatever its configuration lists.
func AuthorityKey(key string) bool { return authorityKey(key) }
