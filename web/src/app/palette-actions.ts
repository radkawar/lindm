import type { UseNavigateResult } from "@tanstack/react-router";
import type { LucideIcon } from "lucide-react";
import {
  EraserIcon,
  HeadsetIcon,
  KeyRoundIcon,
  LayersIcon,
  LockKeyholeIcon,
  RefreshCwIcon,
  RocketIcon,
  RotateCcwIcon,
  UserRoundPlusIcon,
  UsersIcon,
} from "lucide-react";
import type { SessionPrincipal } from "../../gen/lindm/auth/v1/auth_pb";
import { ASSISTANCE_VIEW_PERMISSION } from "@/features/assistance/display";
import { actionPermissions } from "@/features/devices/action-display";
import { canPermission } from "@/lib/permissions";

type Navigate = UseNavigateResult<string>;

// A palette command that opens the page or dialog where the job is done. Each
// entry mirrors the permission its destination checks, so the palette never
// offers a command the page would refuse.
export type PaletteAction = {
  id: string;
  label: string;
  keywords: string[];
  icon: LucideIcon;
  allowed: (principal: SessionPrincipal) => boolean;
  open: (navigate: Navigate) => Promise<void>;
};

// A command on one device: the palette asks for the device, then opens the
// device's own review or dialog. Nothing is requested from the palette itself.
export type PaletteDeviceAction = {
  id: string;
  label: string;
  // Shown while the palette asks for the device.
  prompt: string;
  keywords: string[];
  icon: LucideIcon;
  allowed: (principal: SessionPrincipal) => boolean;
  open: (navigate: Navigate, deviceId: string) => Promise<void>;
};

export const paletteActions: PaletteAction[] = [
  {
    id: "enrollment-code",
    label: "Create enrollment code",
    keywords: ["one-time code", "enroll a device", "add device"],
    icon: KeyRoundIcon,
    allowed: (principal) => canPermission(principal, "enrollment.manage", true),
    open: (navigate) => navigate({ to: "/enrollment", search: { create: "code" } }),
  },
  {
    id: "provisioning-token",
    label: "Create provisioning token",
    keywords: ["automatic enrollment", "cloud-init", "kickstart", "autoinstall"],
    icon: KeyRoundIcon,
    allowed: (principal) => canPermission(principal, "enrollment.manage", true),
    open: (navigate) => navigate({ to: "/enrollment", search: { create: "token" } }),
  },
  {
    id: "rollout",
    label: "New rollout",
    keywords: ["assign profile", "deploy"],
    icon: RocketIcon,
    allowed: (principal) => canPermission(principal, "resources.assign", true),
    open: (navigate) => navigate({ to: "/rollouts", search: { create: true } }),
  },
  {
    id: "profile",
    label: "New profile",
    keywords: ["create profile", "settings"],
    icon: LayersIcon,
    allowed: (principal) => canPermission(principal, "profiles.manage", true),
    open: (navigate) => navigate({ to: "/profiles/new" }),
  },
  {
    id: "secret",
    label: "Create secret",
    keywords: ["new secret", "password", "credential"],
    icon: LockKeyholeIcon,
    allowed: (principal) => canPermission(principal, "secrets.manage", true),
    open: (navigate) => navigate({ to: "/secrets", search: { create: true } }),
  },
  {
    id: "group",
    label: "New group",
    keywords: ["create group", "device group"],
    icon: UsersIcon,
    allowed: (principal) => canPermission(principal, "accounts.manage", true),
    open: (navigate) => navigate({ to: "/groups", search: { create: true } }),
  },
  {
    id: "account",
    label: "Create account",
    keywords: ["new account", "administrator", "user"],
    icon: UserRoundPlusIcon,
    allowed: (principal) => canPermission(principal, "accounts.manage", true),
    open: (navigate) => navigate({ to: "/accounts", search: { create: true } }),
  },
];

// Choosing a device needs the device list.
function canChooseDevice(principal: SessionPrincipal, permission: string) {
  return canPermission(principal, "fleet.read") && canPermission(principal, permission);
}

export const paletteDeviceActions: PaletteDeviceAction[] = [
  {
    id: "wipe",
    label: "Wipe device…",
    prompt: "Choose the device to wipe",
    keywords: ["wipe encrypted storage", "erase", "crypto erase", "retire"],
    icon: EraserIcon,
    allowed: (principal) => canChooseDevice(principal, actionPermissions.cryptoErase),
    open: (navigate, deviceId) =>
      navigate({
        to: "/devices/$deviceId/actions/new/$kind",
        params: { deviceId, kind: "cryptoErase" },
        search: { luksUuid: "" },
      }),
  },
  {
    id: "restart",
    label: "Restart device…",
    prompt: "Choose the device to restart",
    keywords: ["reboot"],
    icon: RotateCcwIcon,
    allowed: (principal) => canChooseDevice(principal, actionPermissions.restart),
    open: (navigate, deviceId) =>
      navigate({
        to: "/devices/$deviceId",
        params: { deviceId },
        search: { action: "restart" },
      }),
  },
  {
    id: "refresh-inventory",
    label: "Refresh inventory…",
    prompt: "Choose the device whose inventory to refresh",
    keywords: ["request inventory", "update inventory"],
    icon: RefreshCwIcon,
    allowed: (principal) => canChooseDevice(principal, actionPermissions.refreshInventory),
    open: (navigate, deviceId) =>
      navigate({
        to: "/devices/$deviceId",
        params: { deviceId },
        search: { action: "refreshInventory" },
      }),
  },
  {
    id: "assistance",
    label: "Request remote assistance…",
    prompt: "Choose the device that needs assistance",
    keywords: ["remote support", "screen sharing", "help"],
    icon: HeadsetIcon,
    allowed: (principal) => canChooseDevice(principal, ASSISTANCE_VIEW_PERMISSION),
    open: (navigate, deviceId) =>
      navigate({
        to: "/devices/$deviceId",
        params: { deviceId },
        search: { tab: "assistance" },
      }),
  },
];
