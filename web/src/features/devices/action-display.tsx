// SPDX-License-Identifier: Apache-2.0

import {
  CryptoEraseMode,
  DeviceActionState,
  NvmeIdentityBasis,
  RecoveryBootMode,
  SanitizeMethod,
  StorageIdentityBasis,
  type DeviceActionSpec,
  type DeviceActionVerification,
  type StorageTarget,
} from "../../../gen/lindm/agent/v1/device_actions_pb";
import { OSUpdateRebootMode, UpdateSelection } from "../../../gen/lindm/resource/v1/software_pb";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { exactBytes, formatBytes } from "@/lib/bytes";
import { Fact } from "./observations";

export type DeviceActionKind = NonNullable<DeviceActionSpec["action"]["case"]>;
export const actionLabels: Record<DeviceActionKind, string> = {
  escrowRotate: "Rotate escrow recovery key",
  tpm2Bind: "Bind TPM 2.0 unlock",
  lockSessions: "Lock sessions and local accounts",
  releaseLock: "Undo account lock",
  quarantine: "Quarantine network",
  releaseQuarantine: "Release quarantine",
  cryptoErase: "Wipe encrypted storage",
  sanitize: "Sanitize offline unencrypted disk",
  restart: "Restart device",
  shutdown: "Shut down device",
  refreshInventory: "Refresh inventory",
  localAdminPasswordRotate: "Rotate managed local-admin password",
  patchNow: "Patch now",
};
export const actionPermissions: Record<DeviceActionKind, string> = {
  escrowRotate: "encryption.manage",
  tpm2Bind: "encryption.manage",
  lockSessions: "actions.lock",
  releaseLock: "actions.release-lock",
  quarantine: "actions.quarantine",
  releaseQuarantine: "actions.quarantine",
  cryptoErase: "destructive.execute",
  sanitize: "destructive.execute",
  restart: "remote_execution.run",
  shutdown: "remote_execution.run",
  refreshInventory: "inventory.manage",
  localAdminPasswordRotate: "secrets.manage",
  patchNow: "remote_execution.run",
};
export const actionStateLabels: Record<DeviceActionState, string> = {
  [DeviceActionState.UNSPECIFIED]: "No result yet",
  [DeviceActionState.PREPARED]: "Prepared, not started",
  [DeviceActionState.QUEUED]: "Queued",
  [DeviceActionState.RUNNING]: "Running",
  [DeviceActionState.SUCCEEDED]: "Completed",
  [DeviceActionState.FAILED]: "Failed",
  [DeviceActionState.OUTCOME_UNKNOWN]: "Outcome unknown, don't retry",
  [DeviceActionState.EXPIRED]: "Expired",
  [DeviceActionState.AWAITING_ESCROW]: "Waiting for recovery key backup",
  [DeviceActionState.RETIRING_ESCROW]: "Removing old recovery key",
};

export const sanitizeMethodLabels: Record<SanitizeMethod, string> = {
  [SanitizeMethod.UNSPECIFIED]: "Not supported",
  [SanitizeMethod.OVERWRITE]: "Overwrite (hard drives)",
  [SanitizeMethod.DISCARD]: "Discard and verify zeros (SSDs)",
  [SanitizeMethod.NVME_FORMAT_USER_DATA]: "NVMe format: wipe user data",
  [SanitizeMethod.NVME_FORMAT_CRYPTO_ERASE]: "NVMe format: wipe encryption keys",
  [SanitizeMethod.NVME_SANITIZE_BLOCK_ERASE]: "NVMe sanitize: wipe blocks",
  [SanitizeMethod.NVME_SANITIZE_CRYPTO_ERASE]: "NVMe sanitize: wipe encryption keys",
};
export const sanitizeMethods = [
  SanitizeMethod.OVERWRITE,
  SanitizeMethod.DISCARD,
  SanitizeMethod.NVME_FORMAT_USER_DATA,
  SanitizeMethod.NVME_FORMAT_CRYPTO_ERASE,
  SanitizeMethod.NVME_SANITIZE_BLOCK_ERASE,
  SanitizeMethod.NVME_SANITIZE_CRYPTO_ERASE,
];

export function StorageTargetView({
  target,
  technicalDetails = true,
}: {
  target: StorageTarget | undefined;
  technicalDetails?: boolean;
}) {
  if (!target) return <p>No storage target reported.</p>;
  return (
    <div className="grid gap-2">
      <StorageTargetFacts target={target} />
      {technicalDetails ? <TechnicalDetails items={storageTargetDetailItems(target)} /> : null}
    </div>
  );
}

// Primary target facts without their Details, for screens that merge diagnostics.
export function StorageTargetFacts({ target }: { target: StorageTarget }) {
  return (
    <dl className="grid gap-2 text-sm sm:grid-cols-2">
      <Fact label="Target">{target.luksUuid ? "Encrypted volume" : "Unencrypted disk"}</Fact>
      <Fact label="Size">{formatBytes(target.sizeBytes)}</Fact>
      {target.identityBasis === StorageIdentityBasis.SERIAL_GPT_LUKS ? (
        <Fact label="Backing disk size">{formatBytes(target.diskSizeBytes)}</Fact>
      ) : null}
    </dl>
  );
}

export function storageTargetDetailItems(target: StorageTarget) {
  return [
    {
      label: "Identity basis",
      value:
        target.identityBasis === StorageIdentityBasis.WWN_SERIAL
          ? "WWN + serial"
          : target.identityBasis === StorageIdentityBasis.SERIAL_GPT_LUKS
            ? "Disk serial + GPT + LUKS"
            : "Not supported",
    },
    { label: "Exact size", value: exactBytes(target.sizeBytes) },
    ...(target.identityBasis === StorageIdentityBasis.SERIAL_GPT_LUKS
      ? [{ label: "Exact backing disk size", value: exactBytes(target.diskSizeBytes) }]
      : []),
    { label: "LUKS UUID", value: target.luksUuid },
    { label: "WWN", value: target.wwn },
    { label: "Serial", value: target.serial },
    ...(target.identityBasis === StorageIdentityBasis.SERIAL_GPT_LUKS
      ? [{ label: "GPT disk GUID", value: target.gptDiskGuid }]
      : []),
  ];
}

// Every Details item DeviceActionSpecView shows, for screens that render one
// merged disclosure with `technicalDetails={false}`.
export function deviceActionDetailItems(spec: DeviceActionSpec | undefined) {
  const action = spec?.action;
  const target = (value: StorageTarget | undefined, prefix = "") =>
    value
      ? storageTargetDetailItems(value).map((item) => ({ ...item, label: prefix + item.label }))
      : [];
  switch (action?.case) {
    case "escrowRotate":
      return [
        ...target(action.value.target),
        { label: "Escrow key ID", value: action.value.escrowKeyId },
      ];
    case "tpm2Bind":
      return target(action.value.target);
    case "cryptoErase":
      return action.value.mode === CryptoEraseMode.LIVE_ROOT_HEADER
        ? action.value.targets.flatMap((value, index) =>
            target(value, action.value.targets.length > 1 ? `Volume ${index + 1}: ` : ""),
          )
        : target(action.value.target);
    case "sanitize":
      return [
        ...target(action.value.target),
        ...(action.value.nvmeScope?.identity
          ? [
              {
                label: "Exact namespace size",
                value: exactBytes(action.value.nvmeScope.identity.namespaceSizeBytes),
              },
            ]
          : []),
      ];
    case "localAdminPasswordRotate":
      return [{ label: "Escrow key ID", value: action.value.escrowKeyId }];
    case "releaseLock":
      return [{ label: "Lock action ID", value: action.value.lockActionId }];
    case "releaseQuarantine":
      return [{ label: "Quarantine action ID", value: action.value.quarantineActionId }];
    default:
      return [];
  }
}

export function DeviceActionSpecView({
  spec,
  technicalDetails = true,
}: {
  spec: DeviceActionSpec | undefined;
  technicalDetails?: boolean;
}) {
  if (!spec?.action.case) return <p>No action specification.</p>;
  const action = spec.action;
  return (
    <div className="grid gap-2">
      <p className="font-medium">{actionLabels[action.case]}</p>
      {action.case === "escrowRotate" ||
      action.case === "tpm2Bind" ||
      action.case === "sanitize" ? (
        <StorageTargetView target={action.value.target} technicalDetails={technicalDetails} />
      ) : null}
      {action.case === "cryptoErase" ? (
        <div className="grid gap-3">
          <p>
            Mode:{" "}
            {action.value.mode === CryptoEraseMode.LIVE_ROOT_HEADER
              ? "Wipe while running, then power off"
              : action.value.mode === CryptoEraseMode.OFFLINE
                ? "Wipe a volume that isn't in use"
                : "Not supported"}
          </p>
          {action.value.mode === CryptoEraseMode.LIVE_ROOT_HEADER ? (
            action.value.targets.map((target) => (
              <div key={target.luksUuid} className="rounded-md border p-3">
                <StorageTargetView target={target} technicalDetails={technicalDetails} />
              </div>
            ))
          ) : (
            <StorageTargetView target={action.value.target} technicalDetails={technicalDetails} />
          )}
        </div>
      ) : null}
      {action.case === "escrowRotate" ? (
        <dl className="grid gap-2 text-sm">
          <Fact label="Remove old recovery key">
            {action.value.retireKeyslot ?? "No, keep old keys"}
          </Fact>
        </dl>
      ) : null}
      {technicalDetails && action.case === "escrowRotate" ? (
        <TechnicalDetails items={[{ label: "Escrow key ID", value: action.value.escrowKeyId }]} />
      ) : null}
      {action.case === "tpm2Bind" ? <p>PCR policy: {action.value.pcrs.join(", ")}</p> : null}
      {action.case === "restart" || action.case === "shutdown" ? (
        <dl className="grid gap-2 text-sm">
          <Fact label="Delay (seconds)">{action.value.delaySeconds ?? "Not specified"}</Fact>
          <Fact label="User notification">{action.value.message || "None"}</Fact>
          <Fact label="Confirmed when">
            {action.case === "restart"
              ? "The device reports a new boot."
              : "The device stops reporting. The server cannot confirm power-off."}
          </Fact>
        </dl>
      ) : null}
      {action.case === "refreshInventory" ? (
        <p>Collect a fresh inventory from this device.</p>
      ) : null}
      {action.case === "patchNow" ? (
        <dl className="grid gap-2 text-sm">
          <Fact label="Updates">
            {action.value.selection === UpdateSelection.ALL
              ? "All updates"
              : action.value.selection === UpdateSelection.SECURITY
                ? "Security updates"
                : "Unsupported / unspecified"}
          </Fact>
          <Fact label="Reboot">
            {action.value.rebootPolicy?.mode === OSUpdateRebootMode.OS_UPDATE_REBOOT_MODE_SCHEDULED
              ? `Scheduled within ${action.value.rebootPolicy.maxDelayMinutes} minutes when required`
              : action.value.rebootPolicy?.mode === OSUpdateRebootMode.OS_UPDATE_REBOOT_MODE_NEVER
                ? "Never: report reboot-required only"
                : "Unsupported / unspecified"}
          </Fact>
          {action.value.rebootPolicy?.notice ? (
            <Fact label="User notice">{action.value.rebootPolicy.notice}</Fact>
          ) : null}
          <Fact label="Completion evidence">
            The action confirms only that the native update run started. Installed updates and the
            run result appear in Patch status.
          </Fact>
        </dl>
      ) : null}
      {action.case === "localAdminPasswordRotate" ? (
        <>
          <dl className="grid gap-2 text-sm">
            <Fact label="Account">{action.value.accountName}</Fact>
          </dl>
          {technicalDetails ? (
            <TechnicalDetails
              items={[{ label: "Escrow key ID", value: action.value.escrowKeyId }]}
            />
          ) : null}
        </>
      ) : null}
      {action.case === "lockSessions" ? (
        <dl className="grid gap-2 text-sm">
          <Fact label="Terminate interactive sessions">
            {action.value.terminateSessions ? "Yes: users can lose unsaved work" : "No: lock only"}
          </Fact>
          <Fact label="Block local sign-in">
            {action.value.allHumanAccounts
              ? "All eligible local human accounts"
              : action.value.usernames.join(", ") || "None: session lock only"}
          </Fact>
          <Fact label="Never locked">Root and the device&apos;s protected accounts</Fact>
        </dl>
      ) : null}
      {action.case === "releaseLock" ? (
        <>
          <p>Restores accounts locked by lindm. Screen locks stay in place.</p>
          {technicalDetails ? (
            <TechnicalDetails
              items={[{ label: "Lock action ID", value: action.value.lockActionId }]}
            />
          ) : null}
        </>
      ) : null}
      {action.case === "quarantine" ? (
        <p>Management IPs still allowed: {action.value.managementEndpoints.join(", ")}</p>
      ) : null}
      {action.case === "releaseQuarantine" ? (
        <>
          <p>Removes the network restrictions added by quarantine.</p>
          {technicalDetails ? (
            <TechnicalDetails
              items={[{ label: "Quarantine action ID", value: action.value.quarantineActionId }]}
            />
          ) : null}
        </>
      ) : null}
      {action.case === "sanitize" ? (
        <p>Method: {sanitizeMethodLabels[action.value.method]}</p>
      ) : null}
      {action.case === "sanitize" && action.value.nvmeScope ? (
        <dl className="grid gap-2 text-sm">
          <Fact label="NVMe identity">
            <strong>
              {action.value.nvmeScope.identity?.basis === NvmeIdentityBasis.NAMESPACE_NID
                ? "Namespace NID (NGUID/EUI-64)"
                : action.value.nvmeScope.identity?.basis ===
                    NvmeIdentityBasis.CONTROLLER_SERIAL_NSID
                  ? "Controller serial + namespace ID"
                  : "Not specified"}
            </strong>
          </Fact>
          {action.value.nvmeScope.identity ? (
            <>
              <Fact label="Vendor ID (VID, decimal)">
                {action.value.nvmeScope.identity.vendorId}
              </Fact>
              <Fact label="Subsystem vendor ID (SSVID, decimal)">
                {action.value.nvmeScope.identity.subsystemVendorId}
              </Fact>
              <Fact label="Controller serial">
                {action.value.nvmeScope.identity.controllerSerial}
              </Fact>
              <Fact label="Controller model">
                {action.value.nvmeScope.identity.controllerModel}
              </Fact>
              <Fact label="Controller firmware">
                {action.value.nvmeScope.identity.controllerFirmware}
              </Fact>
              <Fact label="Namespace size">
                {formatBytes(action.value.nvmeScope.identity.namespaceSizeBytes)}
              </Fact>
              <Fact label="LBA data size shift (LBADS)">
                {action.value.nvmeScope.identity.lbaDataSizeShift}
              </Fact>
            </>
          ) : null}
          <Fact label="NVMe namespace ID">{action.value.nvmeScope.namespaceId}</Fact>
          <Fact label="Scope">
            {action.value.nvmeScope.controllerWide
              ? "Entire controller: wipes all namespaces"
              : "Selected namespace only"}
          </Fact>
        </dl>
      ) : null}
      {technicalDetails && action.case === "sanitize" && action.value.nvmeScope?.identity ? (
        <TechnicalDetails
          items={[
            {
              label: "Exact namespace size",
              value: exactBytes(action.value.nvmeScope.identity.namespaceSizeBytes),
            },
          ]}
        />
      ) : null}
      {action.case === "sanitize" ? (
        action.value.recovery ? (
          <dl className="grid gap-2 text-sm">
            <Fact label="Mode">Boot into lindm recovery on this device</Fact>
            <Fact label="Boot method">
              {RecoveryBootMode[action.value.recovery.bootMode] ?? "Unsupported"}
            </Fact>
            <Fact label="Recovery image SHA-256">
              <span className="break-all font-mono">
                {Array.from(action.value.recovery.imageSha256, (byte) =>
                  byte.toString(16).padStart(2, "0"),
                ).join("")}
              </span>
            </Fact>
            <Fact label="Recovery media SHA-256">
              <span className="break-all font-mono">
                {Array.from(action.value.recovery.mediaSha256, (byte) =>
                  byte.toString(16).padStart(2, "0"),
                ).join("")}
              </span>
            </Fact>
          </dl>
        ) : (
          <p>Mode: device is already in recovery.</p>
        )
      ) : null}
    </div>
  );
}

export function CryptoEraseVerificationView({
  verification,
}: {
  verification: DeviceActionVerification | undefined;
}) {
  if (!verification?.cryptoEraseResults.length) return null;
  return (
    <div className="grid gap-3">
      <h4 className="font-semibold">Wipe results per volume</h4>
      {verification.cryptoEraseResults.map((result) => (
        <div key={result.target?.luksUuid} className="grid gap-2 rounded-md border p-3">
          <StorageTargetView target={result.target} />
          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            <Fact label="Header extent">{formatBytes(result.headerBytes)}</Fact>
            <Fact label="LUKS wipe">
              <StatusBadge status={result.nativeLuksErase ? "success" : "warning"}>
                {result.nativeLuksErase ? "Confirmed" : "Not confirmed"}
              </StatusBadge>
            </Fact>
            <Fact label="Zeros verified">
              <StatusBadge status={result.rawZeroVerified ? "success" : "warning"}>
                {result.rawZeroVerified ? "Confirmed" : "Not confirmed"}
              </StatusBadge>
            </Fact>
            <Fact label="LUKS metadata absent">
              <StatusBadge status={result.metadataAbsent ? "success" : "warning"}>
                {result.metadataAbsent ? "Confirmed" : "Not confirmed"}
              </StatusBadge>
            </Fact>
            <Fact label="Evidence">{result.evidence || "Not reported"}</Fact>
          </dl>
        </div>
      ))}
      <p className="text-sm text-muted-foreground">
        The wipe keeps server recovery keys and backups. Power-off clears keys from memory.
      </p>
    </div>
  );
}

export function NativeSanitizeVerificationView({
  verification,
}: {
  verification: DeviceActionVerification | undefined;
}) {
  const native = verification?.nvmeSanitize;
  if (!native) return null;
  const scope = native.observedScope;
  return (
    <div className="grid gap-3 rounded-md border p-3">
      <h4 className="font-semibold">NVMe sanitize results</h4>
      <dl className="grid gap-2 text-sm sm:grid-cols-2">
        <Fact label="Command completed">
          <StatusBadge status={native.nativeCommandCompleted ? "success" : "warning"}>
            {native.nativeCommandCompleted ? "Confirmed" : "Not confirmed"}
          </StatusBadge>
        </Fact>
        <Fact label="Controller serial / model">
          {scope ? `${scope.controllerSerial} / ${scope.controllerModel}` : "Not reported"}
        </Fact>
        <Fact label="Controller firmware">{scope?.controllerFirmware || "Not reported"}</Fact>
        <Fact label="Target namespace">{scope?.scope?.namespaceId ?? "Not reported"}</Fact>
        <Fact label="Command scope">
          {scope?.scope
            ? scope.scope.controllerWide
              ? "Controller-wide"
              : "Namespace only"
            : "Not reported"}
        </Fact>
        <Fact label="Allocated namespace IDs">
          {scope?.allocatedNamespaceIds.join(", ") || "Not reported"}
        </Fact>
        <Fact label="Sanitize status / progress">
          {native.sanitizeStatus} / {native.sanitizeProgress}
        </Fact>
        <Fact label="Verification samples read">{native.samplesRead}</Fact>
        <Fact label="Sample SHA-256">
          <span className="break-all font-mono">
            {Array.from(native.sampleSha256, (byte) => byte.toString(16).padStart(2, "0")).join(
              "",
            ) || "Not reported"}
          </span>
        </Fact>
      </dl>
      <p className="text-sm text-muted-foreground">
        Reported by the drive and checked by sampling. This isn&apos;t a physical-media certificate.
      </p>
    </div>
  );
}
