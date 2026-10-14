// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"slices"

	"github.com/google/uuid"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
	"lindm/internal/device/devicedb"
)

// HostValueKind identifies one searchable value derived from host evidence.
type HostValueKind int16

// Kinds stored in host_inventory_values.
const (
	HostValueLocalUser HostValueKind = 1
	HostValueShell     HostValueKind = 2
	HostValueFlatpak   HostValueKind = 3
	HostValueSnap      HostValueKind = 4
)

// recordHostValues keeps host_inventory_values equal to the values in the
// generation's latest accepted host observation, as GetDevice shows it: a kind
// whose collection failed, or historical evidence without native details, has
// no values rather than older ones presented as current.
func recordHostValues(ctx context.Context, q *devicedb.Queries, generation uuid.UUID, details *inventoryv1.NativeDetails) error {
	success := inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS
	// Non-nil even when empty: an empty set clears the kind.
	collected := map[HostValueKind][]string{HostValueLocalUser: {}, HostValueShell: {}, HostValueFlatpak: {}, HostValueSnap: {}}
	if users := details.GetLocalUsers(); users.GetStatus() == success {
		for _, user := range users.GetUsers() {
			collected[HostValueLocalUser] = append(collected[HostValueLocalUser], user.GetName())
			collected[HostValueShell] = append(collected[HostValueShell], user.GetShell())
		}
	}
	for kind, apps := range map[HostValueKind]*inventoryv1.ApplicationDetails{HostValueFlatpak: details.GetFlatpak(), HostValueSnap: details.GetSnap()} {
		if apps.GetStatus() != success {
			continue
		}
		for _, app := range apps.GetApplications() {
			collected[kind] = append(collected[kind], app.GetName())
		}
	}
	for kind, values := range collected {
		values = slices.DeleteFunc(values, func(value string) bool { return value == "" })
		slices.Sort(values)
		values = slices.Compact(values)
		if err := q.DeleteStaleHostInventoryValues(ctx, devicedb.DeleteStaleHostInventoryValuesParams{GenerationID: generation, Kind: int16(kind), Values: values}); err != nil {
			return err
		}
		if err := q.InsertHostInventoryValues(ctx, devicedb.InsertHostInventoryValuesParams{GenerationID: generation, Kind: int16(kind), Values: values}); err != nil {
			return err
		}
	}
	return nil
}
