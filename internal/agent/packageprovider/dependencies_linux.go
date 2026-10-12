//go:build linux

package packageprovider

import (
	"context"
	"fmt"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
)

// packageRef is the resource ref naming a package identity: `<eco>/<name>`
// for a package that follows the device's architecture, else
// `<eco>/<name>/<arch>`.
func packageRef(identity *resourcev1.PackageIdentity) *resourcev1.ResourceRef {
	ecosystem := "deb"
	if identity.GetEcosystem() == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_RPM {
		ecosystem = "rpm"
	} else if identity.GetEcosystem() == resourcev1.PackageEcosystem_PACKAGE_ECOSYSTEM_ALPM {
		ecosystem = "alpm"
	}
	key := ecosystem + "/" + identity.GetNativeName()
	if identity.GetArchitecture() != "" {
		key += "/" + identity.GetArchitecture()
	}
	return &resourcev1.ResourceRef{Kind: resourcev1.ResourceKind_RESOURCE_KIND_NATIVE_PACKAGE, CanonicalKey: key}
}

// dependencyOwnership refuses a transaction that would change a package
// another resource owns, whether that resource pins the dependency's
// architecture or follows the native one the dependency was resolved to.
func (p *Provider) dependencyOwnership(ctx context.Context, manifest *resourcev1.PackageTransactionManifest) error {
	for _, entry := range manifest.GetEntries() {
		if entry.GetDirectRequest() {
			continue
		}
		owners := []*resourcev1.ResourceRef{packageRef(entry.GetPackage())}
		if neutral := (&resourcev1.PackageIdentity{Ecosystem: entry.GetPackage().GetEcosystem(), NativeName: entry.GetPackage().GetNativeName()}); p.requests(neutral, entry.GetPackage()) {
			owners = append(owners, packageRef(neutral))
		}
		for _, owner := range owners {
			ledger, err := p.ledger(ctx, owner)
			if err != nil {
				return err
			}
			if ledger != nil && ledger.GetState() != agentv1.ResourceOwnershipState_RESOURCE_OWNERSHIP_STATE_RELEASED {
				return fmt.Errorf("%w: dependency %s has independent ownership", ErrConflict, packageKey(entry.GetPackage()))
			}
		}
	}
	return nil
}
func dependencyClaims(manifest *resourcev1.PackageTransactionManifest) []*resourcev1.ResourceClaim {
	var claims []*resourcev1.ResourceClaim
	for _, entry := range manifest.GetEntries() {
		if entry.GetDirectRequest() {
			continue
		}
		claims = append(claims,
			&resourcev1.ResourceClaim{Domain: resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, Key: packageRef(entry.GetPackage()).GetCanonicalKey(), Mode: resourcev1.ClaimMode_CLAIM_MODE_REQUIRED},
			&resourcev1.ResourceClaim{Domain: resourcev1.ClaimDomain_CLAIM_DOMAIN_PACKAGE, Key: "native-name/" + entry.GetPackage().GetNativeName(), Mode: resourcev1.ClaimMode_CLAIM_MODE_REQUIRED},
		)
	}
	return claims
}
