import {
  BlocksIcon,
  ClipboardCheckIcon,
  FileClockIcon,
  KeyRoundIcon,
  LayoutDashboardIcon,
  LayersIcon,
  MonitorIcon,
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
    group: "Workspace",
  },
  {
    to: "/devices",
    label: "Devices",
    icon: MonitorIcon,
    permission: "fleet.read",
    group: "Workspace",
  },
  {
    to: "/profiles",
    label: "Profiles",
    icon: LayersIcon,
    permission: "fleet.read",
    group: "Workspace",
  },
  {
    to: "/rollouts",
    label: "Rollouts",
    icon: LayersIcon,
    permission: "resources.assign",
    group: "Workspace",
  },
  {
    to: "/enrollment",
    label: "Enrollment",
    icon: KeyRoundIcon,
    permission: "enrollment.manage",
    group: "Workspace",
  },
  {
    to: "/advisories",
    label: "Advisories",
    icon: ShieldAlertIcon,
    permission: "fleet.read",
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
] as const;

export function visibleNavigation(principal: SessionPrincipal) {
  return navigation.filter(
    (item) =>
      canPermission(
        principal,
        item.permission,
        item.to === "/groups" || item.to === "/integrations",
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
        ].some((permission) => canPermission(principal, permission))),
  );
}
