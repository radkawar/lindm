// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
)

// POSIX ACL fixtures. The managed file desired state has no ACL dimension and
// the provider can preserve only user.* and security.selinux xattrs, so it
// fails closed instead of discarding or rewriting ACLs.
const (
	resourceACLFile = resourceFileRoot + "/acl-adopted"
	resourceACLDir  = resourceFileRoot + "/acl-inherit"
)

const resourceACLFixtureScript = `set -eu
if ! command -v setfacl >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y acl; else dnf install -y acl; fi
fi
test ! -e ` + resourceACLFile + `
test ! -e ` + resourceACLDir + `
printf 'acl-baseline\n' > ` + resourceACLFile + `
chmod 0640 ` + resourceACLFile + `
setfacl -m u:65534:r ` + resourceACLFile + `
mkdir -m 0755 ` + resourceACLDir + `
setfacl -d -m u:65534:r ` + resourceACLDir + `
if command -v restorecon >/dev/null 2>&1; then restorecon -RF ` + resourceACLFile + ` ` + resourceACLDir + `; fi
`

// aclOracle binds both fixtures' ACLs (getfacl), content, mode, ownership,
// inode change times and the inheriting directory's entries.
func aclOracle(ctx context.Context, vm *guestVM) (VMResourceNativeRecord, error) {
	command := "getfacl -n --absolute-names " + resourceACLFile + " | grep -Fx 'user:65534:r--'; getfacl -n --absolute-names " + resourceACLDir + " | grep -Fx 'default:user:65534:r--'; " +
		"getfacl -n --absolute-names " + resourceACLFile + " " + resourceACLDir + "; stat -c '%n %a %u %g %s %Y %Z' " + resourceACLFile + " " + resourceACLDir + "; sha256sum " + resourceACLFile + "; " +
		"test -z \"$(ls -A " + resourceACLDir + ")\"; printf 'inheriting-directory-empty\\n'; if test -e /sys/fs/selinux/enforce; then test \"$(getenforce)\" = Enforcing; getenforce; fi"
	return resourceOracle(ctx, vm, "native-posix-acl-getfacl", command)
}

// exerciseResourceFileACLs proves the documented refusal: a file carrying a
// foreign access ACL cannot be adopted, and a file cannot be created where a
// default ACL would be inherited. Neither the refusal nor the clear changes
// the file, its ACL or the directory.
func exerciseResourceFileACLs(ctx context.Context, r *resourceDispatch, evidence *VMResourceKindEvidence) error {
	if err := lifecycleCommand(ctx, r.vm, "construct foreign POSIX ACL fixtures", resourceACLFixtureScript); err != nil {
		return err
	}
	r.fresh()
	if err := resourceRefusalStep(ctx, r, evidence, "foreign-acl-adoption-refused", resourceFileDesired("acl-adopted", "managed\n"), resourceAdoptionPolicy(), withVM(r.vm, aclOracle)); err != nil {
		return err
	}
	r.fresh()
	return resourceRefusalStep(ctx, r, evidence, "inherited-default-acl-create-refused", resourceFileDesired("acl-inherit/created", "managed\n"), resourceCreatePolicy(), withVM(r.vm, aclOracle))
}
