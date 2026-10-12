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
    group: "Fleet",
  },
  {
    to: "/rollouts",
    label: "Rollouts",
    icon: RocketIcon,
    access: [{ permission: "resources.assign" }],
    group: "Fleet",
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
    group: "Security",
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
    group: "Administration",
  },
  {
    to: "/authorization",
    label: "Authorization",
    icon: ShieldUserIcon,
    access: [{ permission: "accounts.manage", unrestricted: true }],
    group: "Administration",
  },
  {
    to: "/groups",
    label: "Groups",
    icon: UsersIcon,
    access: [
      { permission: "accounts.manage", unrestricted: true },
      { permission: "inventory.manage", unrestricted: true },
    ],
    group: "Administration",
  },
  {
    to: "/integrations",
    label: "Integrations",
    icon: BlocksIcon,
    access: [{ permission: "integrations.manage", unrestricted: true }],
    group: "Administration",
  },
  {
    to: "/settings",
    label: "Settings",
    icon: SettingsIcon,
    access: [
      { permission: "enrollment.manage", unrestricted: true },
      { permission: "inventory.manage", unrestricted: true },
      { permission: "execution_trust.manage", unrestricted: true },
    ],
    group: "Administration",
  },
] as const satisfies readonly {
  to: string;
  label: string;
  icon: typeof LayoutDashboardIcon;
  group: "Fleet" | "Security" | "Administration";
  access: Access | "approvals";
}[];

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
