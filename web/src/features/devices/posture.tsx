import { useQuery } from "@tanstack/react-query";
import { useRef, useState, type ReactNode } from "react";
import type { Device } from "../../../gen/lindm/admin/v1/admin_pb";
import type { PatchStatusObservation } from "../../../gen/lindm/agent/v1/os_update_pb";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/ui/status-badge";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { formatTimestamp, freshnessLabel } from "@/lib/time";
import { deviceEncryptionQueryOptions } from "./action-queries";
import { DeviceRestrictions } from "./actions";
import { actionPermissions } from "./action-display";
import { DeviceActionDialog } from "./action-menu";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { ObservedTime } from "./observations";

export type PostureTab = "encryption" | "inventory" | "findings" | "resources" | "actions";

function Age({ value }: { value: Timestamp | undefined }) {
  const formatted = formatTimestamp(value);
  return formatted.date ? (
    <time dateTime={formatted.utc} title={`${formatted.local} · ${formatted.utc}`}>
      {freshnessLabel(formatted.date, new Date())}
    </time>
  ) : (
    <span>at an unrecorded time</span>
  );
}

function PostureRow({
  id,
  label,
  link,
  onOpen,
  children,
}: {
  id: string;
  label: string;
  link: string;
  onOpen: () => void;
  children: ReactNode;
}) {
  return (
    <div
      data-posture-row={id}
      className="grid gap-1 py-3 sm:grid-cols-[11rem_minmax(0,1fr)_auto] sm:items-center sm:gap-4"
    >
      <dt className="text-sm font-medium">{label}</dt>
      <dd className="min-w-0 text-sm">{children}</dd>
      <dd>
        <Button variant="link" className="h-auto px-0" onClick={onOpen}>
          {link}
        </Button>
      </dd>
    </div>
  );
}

function EncryptionState({
  deviceId,
  rootEncryption,
}: {
  deviceId: string;
  rootEncryption: string;
}) {
  const lifetime = useAuthLifetime();
  const custody = useQuery(deviceEncryptionQueryOptions(lifetime, deviceId));
  const encrypted = ["luks", "dm-crypt", "inherited-dm-crypt"].includes(rootEncryption);
  if (rootEncryption === "none")
    return (
      <span className="flex flex-wrap items-center gap-2">
        <StatusBadge status="warning">Not encrypted</StatusBadge>
        The root disk is not encrypted, so no recovery key applies.
      </span>
    );
  if (!encrypted)
    return (
      <span className="flex flex-wrap items-center gap-2">
        <StatusBadge status="neutral">Unknown</StatusBadge>
        The device hasn&apos;t reported root disk encryption.
      </span>
    );
  const escrow = custody.error ? undefined : custody.data?.escrow;
  return (
    <span className="flex flex-wrap items-center gap-2">
      <StatusBadge status={escrow ? "success" : "warning"}>
        {escrow ? "Recoverable" : "No recovery key"}
      </StatusBadge>
      {custody.isPending ? (
        "Root disk encrypted. Checking the recovery key…"
      ) : custody.error ? (
        "Root disk encrypted. Recovery key status unavailable."
      ) : escrow ? (
        <span>
          Root disk encrypted, recovery key escrowed <Age value={escrow.storedAt} />.
        </span>
      ) : (
        "Root disk encryption is active. The server has no recovery key."
      )}
    </span>
  );
}

function UpdateState({ status }: { status: PatchStatusObservation | undefined }) {
  if (!status?.available)
    return (
      <span className="flex flex-wrap items-center gap-2">
        <StatusBadge status="neutral">Unknown</StatusBadge>
        {status
          ? "The device couldn't compute its pending updates."
          : "The latest inventory has no update status."}
      </span>
    );
  const security = status.pendingSecurityUpdates;
  const pending = status.pendingUpdates;
  const parts = [
    pending === 0
      ? "No updates pending"
      : `${pending.toLocaleString()} ${pending === 1 ? "update" : "updates"} pending, ${
          security ? `${security.toLocaleString()} security` : "none are security updates"
        }`,
  ];
  if (status.rebootRequired) parts.push("restart required");
  return (
    <span className="flex flex-wrap items-center gap-2">
      <StatusBadge
        status={security ? "destructive" : status.rebootRequired || pending ? "warning" : "success"}
      >
        {security
          ? "Security updates pending"
          : pending
            ? "Updates pending"
            : status.rebootRequired
              ? "Restart required"
              : "Up to date"}
      </StatusBadge>
      {parts.join(" · ")}
    </span>
  );
}

// First Overview section: is this machine safe and managed? Each row opens its tab.
export function DevicePosture({
  device,
  rootEncryption,
  patchStatus,
  inventoryReceivedAt,
  findings,
  compliance,
  onOpen,
}: {
  device: Device;
  rootEncryption: string;
  patchStatus: PatchStatusObservation | undefined;
  inventoryReceivedAt: Timestamp | undefined;
  findings: ReactNode;
  compliance: ReactNode;
  onOpen: (tab: PostureTab) => void;
}) {
  const principal = usePrincipal();
  const [refreshing, setRefreshing] = useState(false);
  const refreshButton = useRef<HTMLButtonElement>(null);
  return (
    <section aria-labelledby={`posture-${device.id}`} data-device-posture className="grid gap-1">
      <h2 id={`posture-${device.id}`} className="text-base font-semibold">
        Security posture
      </h2>
      <dl className="divide-y border-y">
        <PostureRow
          id="encryption"
          label="Encryption"
          link="Open Encryption"
          onOpen={() => onOpen("encryption")}
        >
          <EncryptionState deviceId={device.id} rootEncryption={rootEncryption} />
        </PostureRow>
        <PostureRow
          id="updates"
          label="Updates"
          link="Open Inventory"
          onOpen={() => onOpen("inventory")}
        >
          <UpdateState status={patchStatus} />
          {!patchStatus?.available &&
          canPermission(principal, actionPermissions.refreshInventory) ? (
            <>
              <Button
                ref={refreshButton}
                variant="outline"
                size="sm"
                className="mt-2"
                aria-haspopup="dialog"
                onClick={() => setRefreshing(true)}
              >
                Request fresh inventory
              </Button>
              <DeviceActionDialog
                deviceId={device.id}
                deviceName={device.hostname.trim() || "Unnamed device"}
                kind={refreshing ? "refreshInventory" : null}
                finalFocus={refreshButton}
                onClose={() => setRefreshing(false)}
              />
            </>
          ) : null}
        </PostureRow>
        <PostureRow
          id="findings"
          label="Findings"
          link="Open Findings"
          onOpen={() => onOpen("findings")}
        >
          {findings}
        </PostureRow>
        <PostureRow
          id="compliance"
          label="Profile compliance"
          link="Open Services"
          onOpen={() => onOpen("resources")}
        >
          {compliance}
        </PostureRow>
        <PostureRow
          id="restrictions"
          label="Restrictions"
          link="Open Actions"
          onOpen={() => onOpen("actions")}
        >
          <DeviceRestrictions
            deviceId={device.id}
            deviceName={device.hostname.trim() || "Unnamed device"}
          />
        </PostureRow>
        <PostureRow
          id="contact"
          label="Last contact"
          link="Open Inventory"
          onOpen={() => onOpen("inventory")}
        >
          <span>
            <ObservedTime value={device.lastSeenAt} server relative />
            {inventoryReceivedAt ? (
              <>
                {" "}
                · inventory received <Age value={inventoryReceivedAt} />
              </>
            ) : (
              " · no inventory received yet"
            )}
          </span>
        </PostureRow>
      </dl>
    </section>
  );
}
