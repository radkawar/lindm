import { useNavigate } from "@tanstack/react-router";
import { ChevronDown } from "lucide-react";
import { useRef, useState, type ReactNode, type RefObject } from "react";
import type { Device } from "../../../gen/lindm/admin/v1/admin_pb";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { DeviceActionForm } from "./action-form";
import { actionLabels, actionPermissions, type DeviceActionKind } from "./action-display";
import { DeviceRevocationImpact } from "./view";

export const simpleActionKinds: DeviceActionKind[] = [
  "restart",
  "shutdown",
  "refreshInventory",
  "patchNow",
  "lockSessions",
  "releaseLock",
  "quarantine",
  "releaseQuarantine",
];
export const complexActionKinds = ["cryptoErase", "sanitize", "escrowRotate", "tpm2Bind"] as const;
export type ComplexActionKind = (typeof complexActionKinds)[number];

// Entries follow the caller's permissions on this device (GetDevice
// caller_permissions); with none left there is no Actions button, never an empty menu.
// The open action dialog lives in the URL (?action=restart), so the command palette can open it.
export function DeviceActionMenu({
  device,
  permissions,
  revoke,
  action,
  onActionChange,
}: {
  device: Device;
  permissions: readonly string[];
  revoke?: ReactNode;
  action: DeviceActionKind | null;
  onActionChange: (action: DeviceActionKind | null) => void;
}) {
  const navigate = useNavigate();
  const trigger = useRef<HTMLButtonElement>(null);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const simple = simpleActionKinds.filter((value) =>
    permissions.includes(actionPermissions[value]),
  );
  const kind = action && simple.includes(action) ? action : null;
  const complex = complexActionKinds.filter((value) =>
    permissions.includes(actionPermissions[value]),
  );
  const canRevoke = !!revoke && permissions.includes("device.revoke");
  if (!simple.length && !complex.length && !canRevoke) return null;
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger render={<Button ref={trigger} variant="outline" />}>
          Actions <ChevronDown aria-hidden="true" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="min-w-56">
          {simple.map((value) => (
            <DropdownMenuItem
              key={value}
              aria-haspopup="dialog"
              onClick={() => onActionChange(value)}
            >
              {actionLabels[value]}
            </DropdownMenuItem>
          ))}
          {simple.length && complex.length ? <DropdownMenuSeparator /> : null}
          {complex.map((value) => (
            <DropdownMenuItem
              key={value}
              onClick={() =>
                void navigate({
                  to: "/devices/$deviceId/actions/new/$kind",
                  params: { deviceId: device.id, kind: value },
                  search: { luksUuid: "" },
                })
              }
            >
              {actionLabels[value]}
            </DropdownMenuItem>
          ))}
          {canRevoke ? (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                variant="destructive"
                aria-haspopup="dialog"
                onClick={() => setRevokeOpen(true)}
              >
                Revoke device
              </DropdownMenuItem>
            </>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
      <DeviceActionDialog
        deviceId={device.id}
        deviceName={device.hostname.trim() || "Unnamed device"}
        kind={kind}
        finalFocus={trigger}
        onClose={() => onActionChange(null)}
      />
      <Dialog open={revokeOpen} onOpenChange={setRevokeOpen}>
        <DialogContent
          data-review-destructive="revoke-device"
          finalFocus={trigger}
          className="max-h-[90svh] overflow-y-auto sm:max-w-lg"
        >
          <DialogHeader>
            <DialogTitle>Revoke {device.hostname.trim() || "Unnamed device"}</DialogTitle>
            <DialogDescription>
              Review the access change before requesting approval.
            </DialogDescription>
          </DialogHeader>
          <DeviceRevocationImpact device={device} />
          {revoke}
        </DialogContent>
      </Dialog>
    </>
  );
}

// One simple action form in a dialog; on success opens the created action's page.
export function DeviceActionDialog({
  deviceId,
  deviceName,
  kind,
  finalFocus,
  onClose,
}: {
  deviceId: string;
  deviceName: string;
  kind: DeviceActionKind | null;
  finalFocus?: RefObject<HTMLElement | null>;
  onClose: () => void;
}) {
  const navigate = useNavigate();
  return (
    <Dialog
      open={kind !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      {kind ? (
        <DialogContent
          finalFocus={finalFocus}
          className="max-h-[90svh] overflow-y-auto sm:max-w-xl"
        >
          <DialogHeader>
            <DialogTitle>{actionLabels[kind]}</DialogTitle>
            <DialogDescription>
              {kind === "releaseLock"
                ? `Restores the local accounts lindm locked on ${deviceName}. Users must unlock their screens. Review the action before you send it.`
                : kind === "releaseQuarantine"
                  ? `Restores normal network access on ${deviceName} at its next check-in. Review the action before you send it.`
                  : deviceName}
            </DialogDescription>
          </DialogHeader>
          <DeviceActionForm
            key={kind}
            deviceId={deviceId}
            mode="actions"
            kind={kind}
            onCreated={(actionId) => {
              onClose();
              void navigate({
                to: "/devices/$deviceId/actions/$actionId",
                params: { deviceId, actionId },
              });
            }}
          />
        </DialogContent>
      ) : null}
    </Dialog>
  );
}
