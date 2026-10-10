import { toJsonString } from "@bufbuild/protobuf";
import { useId } from "react";
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
import { Fact } from "./observations";

export type ObservedStorageSelection = {
  target: StorageTarget;
  nvmeScope?: NVMeSanitizeScope;
  name: string;
  model: string;
  encryption: string;
};

const unavailableMessages: Record<string, string> = {
  device_action_inventory_unavailable:
    "No storage observed yet. Ask the device to refresh inventory.",
  device_action_inventory_stale:
    "The storage observation is stale. Ask the device to refresh inventory before selecting a target.",
  device_action_storage_unavailable:
    "No storage observed yet. Ask the device to refresh inventory.",
  device_action_storage_identity_unavailable:
    "No eligible storage target has a complete observed identity. Ask the device to refresh inventory.",
  device_action_tpm2_unavailable:
    "TPM 2.0 is not available in the current observation. Ask the device to refresh inventory.",
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
  disabled = false,
}: {
  targets: ListDeviceStorageTargetsResponse | undefined;
  kind: DeviceActionKind;
  selectedKey: string;
  onSelect: (key: string, selection: ObservedStorageSelection) => void;
  onRefresh: () => void;
  disabled?: boolean;
}) {
  const id = useId();
  const entries = observedStorageSelections(targets, kind);
  const selected = entries.find((entry) => entry.key === selectedKey);
  const unavailable = targets?.unavailableReason
    ? (unavailableMessages[targets.unavailableReason] ??
      "Storage selection is unavailable. Ask the device to refresh inventory.")
    : targets && !targets.fresh
      ? unavailableMessages.device_action_inventory_stale
      : targets?.targets.length
        ? unavailableMessages.device_action_storage_identity_unavailable
        : "No storage observed yet. Ask the device to refresh inventory.";

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
                label: `${selection.name || "Name not reported"} · ${selection.target.sizeBytes.toLocaleString()} bytes · ${selection.model || "Model not reported"} · ${selection.encryption || "Encryption not reported"}`,
              })),
            ]}
            onValueChange={(key) => {
              const entry = entries.find((candidate) => candidate.key === key);
              if (entry) onSelect(key, entry.selection);
            }}
          />
          <p id={`${id}-help`} className="text-sm text-muted-foreground">
            Only eligible targets from the device&apos;s current inventory can be selected. Identity
            is read-only and is checked again before the action runs.
          </p>
          {selectedKey && !selected ? (
            <p role="status" className="text-sm text-muted-foreground">
              The selected identity is no longer available. Select a current observed target.
            </p>
          ) : null}
          {selected ? <ObservedStorageIdentity selection={selected.selection} /> : null}
        </>
      ) : (
        <p role="status" className="text-sm text-muted-foreground">
          {unavailable}
        </p>
      )}
      <div>
        <Button type="button" variant="outline" disabled={disabled} onClick={onRefresh}>
          Refresh inventory
        </Button>
      </div>
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
                  ? "Controller serial + namespace ID (namespace identifiers absent or rejected by kernel)"
                  : "Not reported"}
            </Fact>
            <Fact label="Exact NVMe namespace ID">{scope.namespaceId}</Fact>
            <Fact label="Observed command scope">
              {scope.controllerWide
                ? "Entire controller: all qualified namespaces affected"
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
                <Fact label="Namespace size (bytes)">{identity.namespaceSizeBytes.toString()}</Fact>
                <Fact label="LBA format index">{identity.lbaFormat}</Fact>
                <Fact label="LBA data size shift (LBADS)">{identity.lbaDataSizeShift}</Fact>
              </>
            ) : null}
          </dl>
        ) : null}
      </div>
    </details>
  );
}
