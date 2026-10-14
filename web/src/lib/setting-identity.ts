// SPDX-License-Identifier: Apache-2.0

import type { InterfaceSelector } from "../../gen/lindm/resource/v1/common_pb";
import { ResourceKind, type ResourceRef } from "../../gen/lindm/resource/v1/identity_pb";
import type { FirewallZoneDesired } from "../../gen/lindm/resource/v1/network_pb";
import type { ResourceDesiredState } from "../../gen/lindm/resource/v1/resource_pb";

export const UNNAMED_ZONE = "Unnamed zone";

function interfaceLabel(selector: InterfaceSelector): string {
  return (
    selector.ifname ||
    (selector.identity.case === "permanentMac"
      ? selector.identity.value
      : selector.identity.case === "hardwareId"
        ? "a matched network adapter"
        : "an unidentified network adapter")
  );
}

function shortList(items: string[]): string {
  return items.length <= 3
    ? items.join(", ")
    : `${items.slice(0, 3).join(", ")} and ${items.length - 3} more`;
}

// Firewall zones carry no name, only a generated UUID. Describe one by what it
// binds to (the device applies an unbound zone to all traffic); the UUID
// belongs in Details only.
export function firewallZoneLabel(zone: FirewallZoneDesired): string {
  const interfaces = zone.interfaces.map(interfaceLabel);
  const networks = zone.sourceNetworks.map(
    (network) => `${network.networkAddress}/${network.prefixLength}`,
  );
  if (interfaces.length === 0 && networks.length === 0) return `${UNNAMED_ZONE} on all interfaces`;
  return [
    UNNAMED_ZONE,
    interfaces.length ? `on ${shortList(interfaces)}` : "",
    networks.length ? `for ${shortList(networks)}` : "",
  ]
    .filter(Boolean)
    .join(" ");
}

// The primary text for one managed setting: its administrator-facing identity,
// never a generated UUID. Undefined when nothing identifies it.
export function settingTitle(
  ref: ResourceRef | undefined,
  desired?: ResourceDesiredState,
): string | undefined {
  if (desired?.state.case === "firewallZone") return firewallZoneLabel(desired.state.value);
  if ((ref ?? desired?.ref)?.kind === ResourceKind.FIREWALL_ZONE) return UNNAMED_ZONE;
  return (ref ?? desired?.ref)?.canonicalKey || undefined;
}

// Copyable identity for Details when the title hides it (a firewall zone UUID).
export function settingTechnicalIds(ref: ResourceRef | undefined) {
  return ref?.kind === ResourceKind.FIREWALL_ZONE
    ? [{ label: "Zone ID", value: ref.canonicalKey }]
    : [];
}
