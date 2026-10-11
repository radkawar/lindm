import { useNavigate } from "@tanstack/react-router";
import { ChevronDown } from "lucide-react";
import { useRef, useState, type ReactNode } from "react";
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
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { DeviceActionForm } from "./action-form";
import { actionLabels, actionPermissions, type DeviceActionKind } from "./action-display";

const simpleKinds: DeviceActionKind[] = [
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

export function DeviceActionMenu({ device, revoke }: { device: Device; revoke?: ReactNode }) {
  const principal = usePrincipal();
  const navigate = useNavigate();
  const trigger = useRef<HTMLButtonElement>(null);
  const [kind, setKind] = useState<DeviceActionKind | null>(null);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [revokeVisited, setRevokeVisited] = useState(false);
  const simple = simpleKinds.filter(
    (value) =>
      canPermission(principal, actionPermissions[value]) &&
      (value !== "refreshInventory" || canPermission(principal, "fleet.read")),
  );
  const complex = complexActionKinds.filter((value) =>
    canPermission(principal, actionPermissions[value]),
  );
  const canRevoke = !!revoke && canPermission(principal, "device.revoke");
  if (!simple.length && !complex.length && !canRevoke) return null;
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger render={<Button ref={trigger} variant="outline" />}>
          Actions <ChevronDown aria-hidden="true" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="min-w-56">
          {simple.map((value) => (
            <DropdownMenuItem key={value} aria-haspopup="dialog" onClick={() => setKind(value)}>
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
                onClick={() => {
                  setRevokeVisited(true);
                  setRevokeOpen(true);
                }}
              >
                Revoke device
              </DropdownMenuItem>
            </>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
      <Dialog
        open={kind !== null}
        onOpenChange={(open) => {
          if (!open) setKind(null);
        }}
      >
        {kind ? (
          <DialogContent finalFocus={trigger} className="max-h-[90svh] overflow-y-auto sm:max-w-xl">
            <DialogHeader>
              <DialogTitle>{actionLabels[kind]}</DialogTitle>
              <DialogDescription>{device.hostname.trim() || "Unnamed device"}</DialogDescription>
            </DialogHeader>
            <DeviceActionForm
              key={kind}
              deviceId={device.id}
              mode="actions"
              kind={kind}
              onCreated={(actionId) => {
                setKind(null);
                void navigate({
                  to: "/devices/$deviceId/actions/$actionId",
                  params: { deviceId: device.id, actionId },
                });
              }}
            />
          </DialogContent>
        ) : null}
      </Dialog>
      <Dialog open={revokeOpen} onOpenChange={setRevokeOpen}>
        {revokeVisited ? (
          <DialogContent
            keepMounted
            finalFocus={trigger}
            className="max-h-[90svh] overflow-y-auto sm:max-w-lg"
          >
            <DialogHeader>
              <DialogTitle>Revoke {device.hostname.trim() || "Unnamed device"}</DialogTitle>
              <DialogDescription>
                Another admin must approve before this device is removed from lindm.
              </DialogDescription>
            </DialogHeader>
            {revoke}
          </DialogContent>
        ) : null}
      </Dialog>
    </>
  );
}
