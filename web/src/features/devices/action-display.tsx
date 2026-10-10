import {
  CryptoEraseMode,
  DeviceActionState,
  NvmeIdentityBasis,
  RecoveryBootMode,
  SanitizeMethod,
  type DeviceActionSpec,
  type DeviceActionVerification,
  type StorageTarget,
} from "../../../gen/lindm/agent/v1/device_actions_pb";
import { StatusBadge } from "@/components/ui/status-badge";
import { Fact } from "./observations";

export type DeviceActionKind = NonNullable<DeviceActionSpec["action"]["case"]>;
export const actionLabels: Record<DeviceActionKind, string> = {
  escrowRotate: "Rotate escrow recovery key",
  tpm2Bind: "Bind TPM 2.0 unlock",
  lockSessions: "Lock sessions and local accounts",
  releaseLock: "Release owned account lock",
  quarantine: "Quarantine network",
  releaseQuarantine: "Release quarantine",
  cryptoErase: "Wipe encrypted storage",
  sanitize: "Sanitize offline unencrypted disk",
  restart: "Restart device",
  shutdown: "Shut down device",
  refreshInventory: "Refresh inventory",
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
};
export const actionStateLabels: Record<DeviceActionState, string> = {
  [DeviceActionState.UNSPECIFIED]: "No protected result",
  [DeviceActionState.PREPARED]: "Prepared, not started",
  [DeviceActionState.QUEUED]: "Start accepted, not completed",
  [DeviceActionState.RUNNING]: "Running, outcome not yet known",
  [DeviceActionState.SUCCEEDED]: "Verified by device",
  [DeviceActionState.FAILED]: "Failed",
  [DeviceActionState.OUTCOME_UNKNOWN]: "Outcome unknown, do not repeat effects",
  [DeviceActionState.EXPIRED]: "Expired",
  [DeviceActionState.AWAITING_ESCROW]: "Awaiting durable escrow receipt / local credential",
  [DeviceActionState.RETIRING_ESCROW]: "Retiring old managed slot, outcome not yet known",
};

export const sanitizeMethodLabels: Record<SanitizeMethod, string> = {
  [SanitizeMethod.UNSPECIFIED]: "Unsupported / unspecified",
  [SanitizeMethod.OVERWRITE]: "Overwrite rotational media with sampling",
  [SanitizeMethod.DISCARD]: "Qualified zero-after-discard with sampling",
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
      <Fact label="LUKS UUID">{target.luksUuid || "Unencrypted target"}</Fact>
      <Fact label="WWN">{target.wwn || "Not reported"}</Fact>
      <Fact label="Serial">{target.serial || "Not reported"}</Fact>
      <Fact label="Exact size (bytes)">{target.sizeBytes.toString()}</Fact>
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
            Execution mode:{" "}
            {action.value.mode === CryptoEraseMode.LIVE_ROOT_HEADER
              ? "Live-root header erasure: complete frozen volume set; unconditional power-off"
              : action.value.mode === CryptoEraseMode.OFFLINE
                ? "Offline exact-volume erasure"
                : "Unsupported / unspecified mode"}
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
          <Fact label="Escrow public-key ID">
            <span className="break-all font-mono">{action.value.escrowKeyId}</span>
          </Fact>
          <Fact label="Retire old lindm-owned slot">
            {action.value.retireKeyslot ?? "None: preserve old slots"}
          </Fact>
        </dl>
      ) : null}
      {action.case === "tpm2Bind" ? <p>PCR policy: {action.value.pcrs.join(", ")}</p> : null}
      {action.case === "restart" || action.case === "shutdown" ? (
        <dl className="grid gap-2 text-sm">
          <Fact label="Delay (seconds)">{action.value.delaySeconds ?? "Not specified"}</Fact>
          <Fact label="User notification">{action.value.message || "None"}</Fact>
          <Fact label="Completion evidence">
            {action.case === "restart"
              ? "A new boot must be observed before restart is confirmed."
              : "Native acceptance does not prove power-off. Loss of contact remains an unknown outcome."}
          </Fact>
        </dl>
      ) : null}
      {action.case === "refreshInventory" ? (
        <p>
          Collect and publish a new full inventory snapshot. Collection alone is not completion.
        </p>
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
          <Fact label="Protected accounts">
            Root and the device&apos;s root-owned protected-account list are always excluded.
          </Fact>
        </dl>
      ) : null}
      {action.case === "releaseLock" ? (
        <p className="break-all">
          Original lock action: {action.value.lockActionId}. Restore only matching owned local
          account state; preserve administrator changes. This never unlocks a screen.
        </p>
      ) : null}
      {action.case === "quarantine" ? (
        <p>Retain management IPs: {action.value.managementEndpoints.join(", ")}</p>
      ) : null}
      {action.case === "releaseQuarantine" ? (
        <p className="break-all">Original quarantine action: {action.value.quarantineActionId}</p>
      ) : null}
      {action.case === "sanitize" ? (
        <p>Method: {sanitizeMethodLabels[action.value.method]}</p>
      ) : null}
      {action.case === "sanitize" && action.value.nvmeScope ? (
        <dl className="grid gap-2 text-sm">
          <Fact label="Approved NVMe identity basis">
            <strong>
              {action.value.nvmeScope.identity?.basis === NvmeIdentityBasis.NAMESPACE_NID
                ? "Namespace NID (NGUID/EUI-64)"
                : action.value.nvmeScope.identity?.basis ===
                    NvmeIdentityBasis.CONTROLLER_SERIAL_NSID
                  ? "Controller serial + namespace ID (namespace identifiers absent or rejected by kernel)"
                  : "Not specified"}
            </strong>
          </Fact>
          {action.value.nvmeScope.identity ? (
            <>
              <Fact label="Approved vendor ID (VID, decimal)">
                {action.value.nvmeScope.identity.vendorId}
              </Fact>
              <Fact label="Approved subsystem vendor ID (SSVID, decimal)">
                {action.value.nvmeScope.identity.subsystemVendorId}
              </Fact>
              <Fact label="Approved controller serial">
                {action.value.nvmeScope.identity.controllerSerial}
              </Fact>
              <Fact label="Approved controller model">
                {action.value.nvmeScope.identity.controllerModel}
              </Fact>
              <Fact label="Approved controller firmware">
                {action.value.nvmeScope.identity.controllerFirmware}
              </Fact>
              <Fact label="Approved namespace size (bytes)">
                {action.value.nvmeScope.identity.namespaceSizeBytes.toString()}
              </Fact>
              <Fact label="Approved LBA format index">
                {action.value.nvmeScope.identity.lbaFormat}
              </Fact>
              <Fact label="Approved LBA data size shift (LBADS)">
                {action.value.nvmeScope.identity.lbaDataSizeShift}
              </Fact>
            </>
          ) : null}
          <Fact label="Exact NVMe namespace ID">{action.value.nvmeScope.namespaceId}</Fact>
          <Fact label="Approved command scope">
            {action.value.nvmeScope.controllerWide
              ? "Entire controller: all qualified namespaces affected"
              : "Selected namespace only"}
          </Fact>
        </dl>
      ) : null}
      {action.case === "sanitize" ? (
        action.value.recovery ? (
          <dl className="grid gap-2 text-sm">
            <Fact label="Execution mode">Original-device signed recovery handoff</Fact>
            <Fact label="Boot method">
              {RecoveryBootMode[action.value.recovery.bootMode] ?? "Unsupported"}
            </Fact>
            <Fact label="Exact signed recovery image SHA-256">
              <span className="break-all font-mono">
                {Array.from(action.value.recovery.imageSha256, (byte) =>
                  byte.toString(16).padStart(2, "0"),
                ).join("")}
              </span>
            </Fact>
            <Fact label="Frozen target media SHA-256">
              <span className="break-all font-mono">
                {Array.from(action.value.recovery.mediaSha256, (byte) =>
                  byte.toString(16).padStart(2, "0"),
                ).join("")}
              </span>
            </Fact>
          </dl>
        ) : (
          <p>Execution mode: already in qualified offline recovery.</p>
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
      <h4 className="font-semibold">Per-volume header-erasure evidence</h4>
      {verification.cryptoEraseResults.map((result) => (
        <div key={result.target?.luksUuid} className="grid gap-2 rounded-md border p-3">
          <StorageTargetView target={result.target} />
          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            <Fact label="Header extent (bytes)">{result.headerBytes.toString()}</Fact>
            <Fact label="Native luksErase">
              <StatusBadge status={result.nativeLuksErase ? "success" : "warning"}>
                {result.nativeLuksErase ? "Confirmed" : "Not confirmed"}
              </StatusBadge>
            </Fact>
            <Fact label="Raw zero verification">
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
        Completion requires accepted, nonce-bound results for every selected volume. Erasing local
        headers leaves server escrow and backups intact; active volume keys remain until power-off.
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
      <h4 className="font-semibold">Native NVMe sanitation evidence</h4>
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
        Controller-reported completion and sampled reads are bounded native evidence, not
        independent physical-media certification.
      </p>
    </div>
  );
}
