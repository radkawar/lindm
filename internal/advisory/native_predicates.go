package advisory

import (
	"context"
	"slices"
	"strings"

	"github.com/google/uuid"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/advisory/advisorydb"
	"lindm/internal/advisory/feed"
)

type nativePredicateResult struct {
	applies bool
	reason  string
}

// Native conditions read the same immutable package snapshot as candidates.
// Cache booleans by exact predicate, not package rows or cross-device state.
func nativeApplicability(ctx context.Context, q *advisorydb.Queries, snapshot uuid.UUID, record *advisoryv1.Advisory, cache map[string]nativePredicateResult) (nativePredicateResult, error) {
	if len(cache) >= 4096 {
		clear(cache)
	}
	if name := record.GetPrerequisitePackage(); name != "" {
		key := "product\x00" + name + "\x00" + record.GetPrerequisiteMinVersion()
		result, ok := cache[key]
		if !ok {
			rows, err := q.AdvisoryNativeInstances(ctx, advisorydb.AdvisoryNativeInstancesParams{SnapshotID: snapshot, Name: name})
			if err != nil {
				return result, err
			}
			result = nativeProductPredicate(rows, record.GetPrerequisiteMinVersion())
			cache[key] = result
		}
		if !result.applies {
			return result, nil
		}
	}
	if !record.GetAllInstalledInstances() {
		return nativePredicateResult{applies: true}, nil
	}
	key := "all\x00" + record.GetPackageName() + "\x00" + record.GetFixedVersion() + "\x00" + strings.Join(record.GetInstanceArchitectures(), "\x00")
	if result, ok := cache[key]; ok {
		return result, nil
	}
	rows, err := q.AdvisoryNativeInstances(ctx, advisorydb.AdvisoryNativeInstancesParams{SnapshotID: snapshot, Name: record.GetPackageName()})
	if err != nil {
		return nativePredicateResult{}, err
	}
	result := nativeAllPredicate(rows, record)
	cache[key] = result
	return result, nil
}

func nativeProductPredicate(rows []advisorydb.AdvisoryNativeInstancesRow, minimum string) nativePredicateResult {
	result := nativePredicateResult{reason: "native_product_predicate_unsatisfied"}
	if len(rows) == 0 || len(rows) > 1024 {
		return result
	}
	for _, row := range rows {
		if row.Manager != "rpm" {
			continue
		}
		n, err := feed.Compare("rpm", row.Version, minimum)
		if err == nil && n >= 0 {
			return nativePredicateResult{applies: true}
		}
	}
	return result
}

func nativeAllPredicate(rows []advisorydb.AdvisoryNativeInstancesRow, record *advisoryv1.Advisory) nativePredicateResult {
	if len(rows) == 0 || len(rows) > 1024 {
		return nativePredicateResult{reason: "native_package_instances_unavailable"}
	}
	for _, row := range rows {
		if row.Manager != "rpm" || row.Architecture == "" {
			return nativePredicateResult{reason: "native_package_instances_unavailable"}
		}
		if arches := record.GetInstanceArchitectures(); len(arches) != 0 && !slices.Contains(arches, row.Architecture) {
			return nativePredicateResult{}
		}
		n, err := feed.Compare("rpm", row.Version, record.GetFixedVersion())
		if err != nil {
			return nativePredicateResult{reason: "package_version_unrecognized"}
		}
		if n >= 0 {
			return nativePredicateResult{}
		}
	}
	return nativePredicateResult{applies: true}
}
