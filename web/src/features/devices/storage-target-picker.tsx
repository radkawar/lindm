// SPDX-License-Identifier: Apache-2.0

import { toJsonString } from "@bufbuild/protobuf";
import { useEffect, useId, useState, type ReactNode } from "react";
import type { ListDeviceStorageTargetsResponse } from "../../../gen/lindm/admin/v1/device_actions_pb";
import {
  NvmeIdentityBasis,
  NVMeSanitizeScopeSchema,
  StorageTargetSchema,
  type NVMeSanitizeScope,
  type StorageTarget,
} from "../../../gen/lindm/agent/v1/device_actions_pb";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { StorageTargetView, type DeviceActionKind } from "./action-display";
import { Fact, ObservedTime } from "./observations";
import { formatBytes } from "@/lib/bytes";

export type ObservedStorageSelection = {
  target: StorageTarget;
  nvmeScope?: NVMeSanitizeScope;
  name: string;
  model: string;
  encryption: string;
  // In use: backs the running root file system or is mounted. A wipe of such a
  // volume can only run while the device is running, then powers it off.
  inUse: boolean;
};

const unavailableMessages: Record<string, string> = {
  device_action_inventory_unavailable: "No storage reported yet. Refresh inventory.",
  device_action_inventory_stale: "Storage info is too old. Refresh inventory first.",
  device_action_storage_unavailable: "No storage reported yet. Refresh inventory.",
  device_action_storage_identity_unavailable:
    "This action has no eligible disk yet. Refresh inventory.",
  device_action_tpm2_unavailable: "No TPM 2.0 reported. Refresh inventory.",
  device_action_tpm2_binding_unsupported:
    "This OS release cannot bind the disk to the TPM. TPM binding needs systemd 252 or newer.",
};

// Completes "Storage info from 12 min ago is too old …" per action.
const staleUses: Partial<Record<DeviceActionKind, string>> = {
  cryptoErase: "for a wipe",
  sanitize: "for a wipe",
  escrowRotate: "for a key rotation",
  tpm2Bind: "for TPM binding",
};

export function observedStorageSelections(
  targets: ListDeviceStorageTargetsResponse | undefined,
  kind: DeviceActionKind,
): readonly { key: string; selection: ObservedStorageSelection }[] {
  if (
    !targets?.fresh ||
    targets.unavailableReason ||
    !["cryptoErase", "sanitize", "escrowRotate", "tpm2Bind"].includes(kind)
  )
    return [];

  const selections = new Map<string, ObservedStorageSelection>();
  for (const entry of targets.targets) {
    if (!entry.target) continue;
    const key = JSON.stringify([
      toJsonString(StorageTargetSchema, entry.target),
      entry.nvme ? toJsonString(NVMeSanitizeScopeSchema, entry.nvme) : null,
    ]);
    selections.set(key, {
      target: entry.target,
      nvmeScope: entry.nvme,
      name: entry.name,
      model: entry.model,
      encryption: entry.encryption,
      inUse: entry.rootBacking || entry.mountpoint !== "",
    });
  }
  return Array.from(selections, ([key, selection]) => ({ key, selection }));
}

export function ObservedStorageTargetPicker({
  targets,
  kind,
  selectedKey,
  onSelect,
  onRefresh,
  refreshNote,
  refreshStatus,
  disabled = false,
}: {
  targets: ListDeviceStorageTargetsResponse | undefined;
  kind: DeviceActionKind;
  selectedKey: string;
  onSelect: (key: string, selection: ObservedStorageSelection) => void;
  onRefresh: () => void;
  // Shown above Refresh inventory, e.g. why the last refresh didn't complete.
  refreshNote?: ReactNode;
  // Replaces Refresh inventory while a requested refresh is still pending.
  refreshStatus?: ReactNode;
  disabled?: boolean;
}) {
  const id = useId();
  const entries = observedStorageSelections(targets, kind);
  const selected = entries.find((entry) => entry.key === selectedKey);
  // The server gates on receipt time (five minutes); show its age, kept current.
  const staleSince = targets && !targets.fresh ? targets.receivedAt : undefined;
  const stale = staleSince !== undefined;
  const [, setTick] = useState(0);
  useEffect(() => {
    if (!stale) return;
    const timer = window.setInterval(() => setTick((tick) => tick + 1), 30_000);
    return () => window.clearInterval(timer);
  }, [stale]);
  const unavailable = targets?.unavailableReason
    ? (unavailableMessages[targets.unavailableReason] ??
      "The console cannot select storage now. Refresh inventory.")
    : targets && !targets.fresh
      ? unavailableMessages.device_action_inventory_stale
      : targets?.targets.length
        ? unavailableMessages.device_action_storage_identity_unavailable
        : "No storage reported yet. Refresh inventory.";

  return (
    <section className="grid min-w-0 gap-3" aria-label="Observed storage target">
      <Label htmlFor={id}>Target</Label>
      {entries.length ? (
        <>
          <SelectField
            id={id}
            value={selected?.key ?? ""}
            disabled={disabled}
            aria-describedby={`${id}-help`}
            options={[
              { value: "", label: "Select observed storage", disabled: true },
              ...entries.map(({ key, selection }) => ({
                value: key,
                label: `${selection.name || "Name not reported"} · ${formatBytes(selection.target.sizeBytes)} · ${selection.model || "Model not reported"} · ${selection.encryption || "Encryption not reported"}`,
              })),
            ]}
            onValueChange={(key) => {
              const entry = entries.find((candidate) => candidate.key === key);
              if (entry) onSelect(key, entry.selection);
            }}
          />
          <p id={`${id}-help`} className="text-sm text-muted-foreground">
            This list shows only eligible disks for this action.
          </p>
          {selectedKey && !selected ? (
            <p role="status" className="text-sm text-muted-foreground">
              The device no longer reports this disk. Select another disk.
            </p>
          ) : null}
          {selected ? <ObservedStorageIdentity selection={selected.selection} /> : null}
        </>
      ) : staleSince ? (
        <div className="grid gap-1">
          <p role="status" className="text-sm text-warning">
            Storage info from <ObservedTime value={staleSince} relative server /> is too old{" "}
            {staleUses[kind] ?? "for this action"}
          </p>
          <p className="text-sm text-muted-foreground">
            Disk actions need storage info received in the last 5 minutes.
          </p>
        </div>
      ) : (
        <p role="status" className="text-sm text-muted-foreground">
          {unavailable}
        </p>
      )}
      {refreshStatus ?? (
        <>
          {refreshNote}
          <div>
            <Button
              type="button"
              variant="outline"
              aria-haspopup="dialog"
              disabled={disabled}
              onClick={onRefresh}
            >
              Refresh inventory
            </Button>
          </div>
        </>
      )}
    </section>
  );
}

function ObservedStorageIdentity({ selection }: { selection: ObservedStorageSelection }) {
  const scope = selection.nvmeScope;
  const identity = scope?.identity;
  return (
    <details className="rounded-md border p-3 text-sm">
      <summary className="cursor-pointer font-medium">Exact observed identity (read-only)</summary>
      <div className="mt-3 grid gap-3 break-all">
        <StorageTargetView target={selection.target} />
        {scope ? (
          <dl className="grid gap-2 sm:grid-cols-2">
            <Fact label="NVMe identity basis">
              {identity?.basis === NvmeIdentityBasis.NAMESPACE_NID
                ? "Namespace NID (NGUID/EUI-64)"
                : identity?.basis === NvmeIdentityBasis.CONTROLLER_SERIAL_NSID
                  ? "Controller serial + namespace ID"
                  : "Not reported"}
            </Fact>
            <Fact label="NVMe namespace ID">{scope.namespaceId}</Fact>
            <Fact label="Scope">
              {scope.controllerWide
                ? "Entire controller: all namespaces"
                : "Selected namespace only"}
            </Fact>
            {identity ? (
              <>
                <Fact label="Vendor ID (VID, decimal)">{identity.vendorId}</Fact>
                <Fact label="Subsystem vendor ID (SSVID, decimal)">
                  {identity.subsystemVendorId}
                </Fact>
                <Fact label="Controller serial">{identity.controllerSerial || "Not reported"}</Fact>
                <Fact label="Controller model">{identity.controllerModel || "Not reported"}</Fact>
                <Fact label="Controller firmware">
                  {identity.controllerFirmware || "Not reported"}
                </Fact>
                <Fact label="Namespace size">{formatBytes(identity.namespaceSizeBytes)}</Fact>
                <Fact label="LBA data size shift (LBADS)">{identity.lbaDataSizeShift}</Fact>
              </>
            ) : null}
          </dl>
        ) : null}
      </div>
    </details>
  );
}
