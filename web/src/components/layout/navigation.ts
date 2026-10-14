// SPDX-License-Identifier: Apache-2.0

import {
  BlocksIcon,
  ClipboardCheckIcon,
  FileClockIcon,
  KeyRoundIcon,
  LayoutDashboardIcon,
  LayersIcon,
  LockKeyholeIcon,
  MonitorIcon,
  RocketIcon,
  SettingsIcon,
  ShieldAlertIcon,
  ShieldUserIcon,
  UsersIcon,
  UserRoundCogIcon,
} from "lucide-react";
import type { SessionPrincipal } from "../../../gen/lindm/auth/v1/auth_pb";
import { canPermission, canUseApprovals } from "@/lib/permissions";

// `access` lists the server grants a page needs; any one suffices. Pages over
// global resources (catalogs, enrollment, audit, accounts) need the grant without
// a device scope, so a scoped role never sees a page that only refuses it.
type Access = readonly { readonly permission: string; readonly unrestricted?: true }[];

export const navigation = [
  {
    to: "/dashboard",
    label: "Dashboard",
    icon: LayoutDashboardIcon,
    access: [{ permission: "fleet.read" }],
    group: "Fleet",
  },
  {
    to: "/devices",
    label: "Devices",
    icon: MonitorIcon,
    access: [{ permission: "fleet.read" }],
    group: "Fleet",
  },
  {
    to: "/profiles",
    label: "Profiles",
    icon: LayersIcon,
    access: [{ permission: "fleet.read", unrestricted: true }],
    group: "Changes",
  },
  {
    to: "/rollouts",
    label: "Rollouts",
    icon: RocketIcon,
    access: [{ permission: "resources.assign" }],
    group: "Changes",
  },
  {
    to: "/enrollment",
    label: "Enrollment",
    icon: KeyRoundIcon,
    access: [{ permission: "enrollment.manage", unrestricted: true }],
    group: "Fleet",
  },
  {
    to: "/advisories",
    label: "Advisories",
    icon: ShieldAlertIcon,
    access: [{ permission: "fleet.read" }],
    group: "Security",
  },
  {
    to: "/secrets",
    label: "Secrets",
    icon: LockKeyholeIcon,
    access: [{ permission: "secrets.manage" }],
    group: "Security",
  },
  {
    to: "/approvals",
    label: "Approvals",
    icon: ClipboardCheckIcon,
    access: "approvals",
    group: "Changes",
  },
  {
    to: "/audit",
    label: "Audit log",
    icon: FileClockIcon,
    access: [{ permission: "audit.read", unrestricted: true }],
    group: "Security",
  },
  {
    to: "/accounts",
    label: "Accounts",
    icon: UserRoundCogIcon,
    access: [{ permission: "accounts.manage", unrestricted: true }],
    group: "Admin",
  },
  {
    to: "/authorization",
    label: "Authorization",
    icon: ShieldUserIcon,
    access: [{ permission: "accounts.manage", unrestricted: true }],
    group: "Admin",
  },
  {
    to: "/groups",
    label: "Groups",
    icon: UsersIcon,
    access: [
      { permission: "accounts.manage", unrestricted: true },
      { permission: "inventory.manage", unrestricted: true },
    ],
    group: "Admin",
  },
  {
    to: "/integrations",
    label: "Integrations",
    icon: BlocksIcon,
    access: [{ permission: "integrations.manage", unrestricted: true }],
    group: "Admin",
  },
  {
    to: "/settings",
    label: "Settings",
    icon: SettingsIcon,
    access: [
      { permission: "enrollment.manage", unrestricted: true },
      { permission: "inventory.manage", unrestricted: true },
      { permission: "execution_trust.manage", unrestricted: true },
      { permission: "integrations.manage", unrestricted: true },
    ],
    group: "Settings",
  },
] as const satisfies readonly {
  to: string;
  label: string;
  icon: typeof LayoutDashboardIcon;
  group: "Fleet" | "Security" | "Changes" | "Admin" | "Settings";
  access: Access | "approvals";
}[];

export type NavigationArea = (typeof navigation)[number]["group"];

export const navigationAreas = [
  { label: "Fleet", icon: MonitorIcon },
  { label: "Security", icon: ShieldAlertIcon },
  { label: "Changes", icon: RocketIcon },
  { label: "Admin", icon: UsersIcon },
  { label: "Settings", icon: SettingsIcon },
] as const;

// Related links reuse the same authorized destinations as the rail and palette.
export const relatedNavigation: Record<NavigationArea, readonly string[]> = {
  Fleet: ["/rollouts", "/advisories", "/groups"],
  Security: ["/approvals", "/devices"],
  Changes: ["/devices", "/advisories", "/audit"],
  Admin: ["/enrollment", "/settings"],
  Settings: ["/enrollment", "/authorization", "/integrations"],
};

// The shell and the command palette share this one decision.
export function visibleNavigation(principal: SessionPrincipal) {
  return navigation.filter((item) => {
    const access: Access | "approvals" = item.access;
    return access === "approvals"
      ? canUseApprovals(principal)
      : access.some(({ permission, unrestricted }) =>
          canPermission(principal, permission, unrestricted),
        );
  });
}
