// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import type { TargetRef } from "../../gen/lindm/policy/v1/targeting_pb";
import { deviceQueryOptions } from "@/features/devices/queries";
import { deviceGroupQueryOptions } from "@/features/groups/view";
import { profilesQueryOptions } from "@/features/profiles/queries";
import { useDynamicGroupLabel } from "@/features/targeting/pickers";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";

// Display names for targeting identities, composed into the rollouts and
// approvals routes. An empty id disables the lookup.
function useDeviceLabel(id: string) {
  const query = useQuery({ ...deviceQueryOptions(useAuthLifetime(), id), enabled: !!id });
  if (query.data?.device)
    return { text: query.data.device.hostname.trim() || "Unnamed device", ready: true };
  if (query.isPending) return { text: "Loading name…", ready: false };
  return { text: "Device name unavailable", ready: false };
}

function useGroupLabel(id: string) {
  const query = useQuery({ ...deviceGroupQueryOptions(useAuthLifetime(), id), enabled: !!id });
  if (query.data) return { text: query.data.name || "Unnamed group", ready: true };
  if (query.isPending) return { text: "Loading name…", ready: false };
  if (query.error) return { text: "Group name unavailable", ready: false };
  return { text: "Removed device group", ready: false };
}

// The target's display name, or why it is unavailable. Every lookup runs
// unconditionally and is disabled unless the target names its kind.
export function useTargetRefLabel(target?: TargetRef) {
  const value = target?.target.value ?? "";
  const kind = target?.target.case;
  const device = useDeviceLabel(kind === "deviceId" ? value : "");
  const group = useGroupLabel(kind === "staticGroupId" ? value : "");
  const dynamic = useDynamicGroupLabel(kind === "dynamicGroupId" ? value : "");
  if (!value) return { text: "no target", ready: false };
  return kind === "deviceId" ? device : kind === "dynamicGroupId" ? dynamic : group;
}

// A profile version's name from the first page of profiles' latest versions,
// for the rare record whose response carries no server label. It never reads
// each profile's version history: that fan-out overloads the server's
// admission limit on large catalogs (hundreds of parallel reads).
export function useProfileHeadLabel(id: string) {
  const query = useQuery({ ...profilesQueryOptions(useAuthLifetime(), 100, ""), enabled: !!id });
  const profile = query.data?.profiles.find((item) => item.revisionId === id);
  if (!id) return { text: "No profile version", short: "", ready: false };
  if (profile) {
    const name = profile.name || "Unnamed profile";
    return {
      text: `${name}, version ${profile.revisionNumber.toString()}`,
      short: `${name} v${profile.revisionNumber.toString()}`,
      ready: true,
    };
  }
  if (query.isPending) return { text: "Loading profile name…", short: "", ready: false };
  return { text: "An earlier profile version", short: "", ready: false };
}
