// SPDX-License-Identifier: Apache-2.0

import { createFileRoute } from "@tanstack/react-router";
import { useProfileHeadLabel, useTargetRefLabel } from "@/app/target-names";
import { RolloutsView } from "@/features/targeting/rollouts";
import { canPermission } from "@/lib/permissions";
import { DevicePicker } from "@/features/devices/picker";
import { GroupPicker } from "@/features/groups/picker";
import { ProfileRevisionPicker } from "@/features/profiles/picker";
import { TargetPickerProvider } from "@/features/targeting/pickers";
import { canonicalUuid } from "@/lib/ids";

export const Route = createFileRoute("/_authenticated/rollouts")({
  // Profile handoffs carry the exact published version, never a moving latest version.
  validateSearch: (
    search: Record<string, unknown>,
  ): {
    device?: string;
    create?: true;
    profile?: string;
    revision?: string;
  } => {
    const result: { device?: string; create?: true; profile?: string; revision?: string } = {};
    if (search.create === true) result.create = true;
    for (const key of ["device", "profile", "revision"] as const) {
      if (search[key] === undefined) continue;
      const value = typeof search[key] === "string" ? canonicalUuid(search[key]) : null;
      if (!value) throw new Error(`Choose a valid ${key} from the console.`);
      result[key] = value;
    }
    if (!!result.profile !== !!result.revision)
      throw new Error("Choose a saved profile version from Profiles.");
    return result;
  },
  beforeLoad: ({ context }) => {
    if (!canPermission(context.principal, "resources.assign"))
      throw new Error("You do not have rollout-management permission.");
  },
  component: RolloutsPage,
});

function RolloutsPage() {
  const { device, create, profile, revision } = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <TargetPickerProvider
      pickers={{
        devicePicker: DevicePicker,
        groupPicker: GroupPicker,
        profileRevisionPicker: ProfileRevisionPicker,
      }}
      names={{ useTargetLabel: useTargetRefLabel, useProfileVersionLabel: useProfileHeadLabel }}
    >
      <RolloutsView
        initialDevice={device}
        initialProfile={profile}
        initialRevision={revision}
        creating={create === true}
        onCreatingChange={(next) =>
          void navigate({
            search: (previous) => ({ device: previous.device, ...(next ? { create: true } : {}) }),
            replace: true,
          })
        }
      />
    </TargetPickerProvider>
  );
}
