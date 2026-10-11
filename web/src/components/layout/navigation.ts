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
  UsersIcon,
  UserRoundCogIcon,
} from "lucide-react";
import type { SessionPrincipal } from "../../../gen/lindm/auth/v1/auth_pb";
import { canPermission } from "@/lib/permissions";

export const navigation = [
  {
    to: "/dashboard",
    label: "Dashboard",
    icon: LayoutDashboardIcon,
    permission: "fleet.read",
    group: "Fleet",
  },
  {
    to: "/devices",
    label: "Devices",
    icon: MonitorIcon,
    permission: "fleet.read",
    group: "Fleet",
  },
  {
    to: "/profiles",
    label: "Profiles",
    icon: LayersIcon,
    permission: "fleet.read",
    group: "Fleet",
  },
  {
    to: "/rollouts",
    label: "Rollouts",
    icon: RocketIcon,
    permission: "resources.assign",
    group: "Fleet",
  },
  {
    to: "/enrollment",
    label: "Enrollment",
    icon: KeyRoundIcon,
    permission: "enrollment.manage",
    group: "Fleet",
  },
  {
    to: "/advisories",
    label: "Advisories",
    icon: ShieldAlertIcon,
    permission: "fleet.read",
    group: "Security",
  },
  {
    to: "/secrets",
    label: "Secrets",
    icon: LockKeyholeIcon,
    permission: "secrets.manage",
    group: "Security",
  },
  {
    to: "/approvals",
    label: "Approvals",
    icon: ClipboardCheckIcon,
    permission: "device.revoke",
    group: "Security",
  },
  {
    to: "/audit",
    label: "Audit log",
    icon: FileClockIcon,
    permission: "audit.read",
    group: "Security",
  },
  {
    to: "/accounts",
    label: "Accounts",
    icon: UserRoundCogIcon,
    permission: "accounts.manage",
    group: "Administration",
  },
  {
    to: "/authorization",
    label: "Authorization",
    icon: LockKeyholeIcon,
    permission: "accounts.manage",
    group: "Administration",
  },
  {
    to: "/groups",
    label: "Groups",
    icon: UsersIcon,
    permission: "accounts.manage",
    group: "Administration",
  },
  {
    to: "/integrations",
    label: "Integrations",
    icon: BlocksIcon,
    permission: "integrations.manage",
    group: "Administration",
  },
  {
    to: "/settings",
    label: "Settings",
    icon: SettingsIcon,
    permission: "enrollment.manage",
    group: "Administration",
  },
] as const;

export function visibleNavigation(principal: SessionPrincipal) {
  return navigation.filter(
    (item) =>
      canPermission(
        principal,
        item.permission,
        item.to === "/groups" ||
          item.to === "/integrations" ||
          item.to === "/authorization" ||
          item.to === "/accounts",
      ) ||
      (item.to === "/groups" && canPermission(principal, "inventory.manage", true)) ||
      (item.to === "/approvals" &&
        [
          "approvals.manage",
          "resources.assign",
          "execution_trust.manage",
          "destructive.execute",
          "recovery_keys.read",
          "remote_execution.run",
          "scripts.run",
          "secrets.reveal",
        ].some((permission) => canPermission(principal, permission))),
  );
}
