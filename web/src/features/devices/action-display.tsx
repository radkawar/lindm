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
  [SanitizeMethod.NVME_FORMAT_USER_DATA]: "NVMe format: user-data erase",
  [SanitizeMethod.NVME_FORMAT_CRYPTO_ERASE]: "NVMe format: cryptographic erase",
  [SanitizeMethod.NVME_SANITIZE_BLOCK_ERASE]: "NVMe sanitize: block erase",
  [SanitizeMethod.NVME_SANITIZE_CRYPTO_ERASE]: "NVMe sanitize: cryptographic erase",
};
export const sanitizeMethods = [
  SanitizeMethod.OVERWRITE,
  SanitizeMethod.DISCARD,
  SanitizeMethod.NVME_FORMAT_USER_DATA,
  SanitizeMethod.NVME_FORMAT_CRYPTO_ERASE,
  SanitizeMethod.NVME_SANITIZE_BLOCK_ERASE,
  SanitizeMethod.NVME_SANITIZE_CRYPTO_ERASE,
];

export function StorageTargetView({ target }: { target: StorageTarget | undefined }) {
  if (!target) return <p>No storage target reported.</p>;
  return (
    <dl className="grid gap-2 text-sm sm:grid-cols-2">
      <Fact label="Identity basis">
        {target.identityBasis === StorageIdentityBasis.WWN_SERIAL
          ? "WWN + serial"
          : target.identityBasis === StorageIdentityBasis.SERIAL_GPT_LUKS
            ? "Disk serial + GPT + LUKS"
            : "Not supported"}
      </Fact>
      <Fact label="LUKS UUID">{target.luksUuid || "Unencrypted target"}</Fact>
      <Fact label="WWN">{target.wwn || "Not reported"}</Fact>
      <Fact label="Serial">{target.serial || "Not reported"}</Fact>
      <Fact label="Exact size (bytes)">{target.sizeBytes.toString()}</Fact>
      {target.identityBasis === StorageIdentityBasis.SERIAL_GPT_LUKS ? (
        <>
          <Fact label="GPT disk GUID">{target.gptDiskGuid || "Not reported"}</Fact>
          <Fact label="Backing disk size (bytes)">{target.diskSizeBytes.toString()}</Fact>
        </>
      ) : null}
    </dl>
  );
}

export function DeviceActionSpecView({ spec }: { spec: DeviceActionSpec | undefined }) {
  if (!spec?.action.case) return <p>No action specification.</p>;
  const action = spec.action;
  return (
    <div className="grid gap-2">
      <p className="font-medium">{actionLabels[action.case]}</p>
      {action.case === "escrowRotate" ||
      action.case === "tpm2Bind" ||
      action.case === "sanitize" ? (
        <StorageTargetView target={action.value.target} />
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
                <StorageTargetView target={target} />
              </div>
            ))
          ) : (
            <StorageTargetView target={action.value.target} />
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
      {action.case === "escrowRotate" ? (
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
              : "Can't be confirmed. The device stops reporting."}
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
          <TechnicalDetails items={[{ label: "Escrow key ID", value: action.value.escrowKeyId }]} />
        </>
      ) : null}
      {action.case === "lockSessions" ? (
        <dl className="grid gap-2 text-sm">
          <Fact label="Terminate interactive sessions">
            {action.value.terminateSessions ? "Yes: unsaved work may be lost" : "No: lock only"}
          </Fact>
          <Fact label="Disable local login">
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
          <TechnicalDetails
            items={[{ label: "Lock action ID", value: action.value.lockActionId }]}
          />
        </>
      ) : null}
      {action.case === "quarantine" ? (
        <p>Management IPs still allowed: {action.value.managementEndpoints.join(", ")}</p>
      ) : null}
      {action.case === "releaseQuarantine" ? (
        <>
          <p>Removes the network restrictions added by quarantine.</p>
          <TechnicalDetails
            items={[{ label: "Quarantine action ID", value: action.value.quarantineActionId }]}
          />
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
              <Fact label="Namespace size (bytes)">
                {action.value.nvmeScope.identity.namespaceSizeBytes.toString()}
              </Fact>
              <Fact label="LBA format index">{action.value.nvmeScope.identity.lbaFormat}</Fact>
              <Fact label="LBA data size shift (LBADS)">
                {action.value.nvmeScope.identity.lbaDataSizeShift}
              </Fact>
            </>
          ) : null}
          <Fact label="NVMe namespace ID">{action.value.nvmeScope.namespaceId}</Fact>
          <Fact label="Scope">
            {action.value.nvmeScope.controllerWide
              ? "Entire controller: all namespaces are erased"
              : "Selected namespace only"}
          </Fact>
        </dl>
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
            <Fact label="Header extent (bytes)">{result.headerBytes.toString()}</Fact>
            <Fact label="LUKS erase">
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
        Server recovery keys and backups are kept. Keys in memory are cleared at power-off.
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
