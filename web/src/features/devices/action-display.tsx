import {
  CryptoEraseMode,
  DeviceActionState,
  RecoveryBootMode,
  SanitizeMethod,
  type DeviceActionSpec,
  type DeviceActionVerification,
  type StorageTarget,
} from "../../../gen/lindm/agent/v1/device_actions_pb";
import { Fact } from "./observations";

export type DeviceActionKind = NonNullable<DeviceActionSpec["action"]["case"]>;
export const actionLabels: Record<DeviceActionKind, string> = {
  escrowRotate: "Rotate escrow recovery key",
  tpm2Bind: "Bind TPM 2.0 unlock",
  lockSessions: "Lock sessions and local accounts",
  releaseLock: "Release owned account lock",
  quarantine: "Quarantine network",
  releaseQuarantine: "Release quarantine",
  cryptoErase: "Crypto erase",
  sanitize: "Sanitize offline unencrypted disk",
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
};
export const actionStateLabels: Record<DeviceActionState, string> = {
  [DeviceActionState.UNSPECIFIED]: "No protected result",
  [DeviceActionState.PREPARED]: "Prepared — not started",
  [DeviceActionState.QUEUED]: "Start accepted — not completed",
  [DeviceActionState.RUNNING]: "Running — outcome not yet known",
  [DeviceActionState.SUCCEEDED]: "Verified by device",
  [DeviceActionState.FAILED]: "Failed",
  [DeviceActionState.OUTCOME_UNKNOWN]: "OUTCOME UNKNOWN — do not repeat effects",
  [DeviceActionState.EXPIRED]: "Expired",
  [DeviceActionState.AWAITING_ESCROW]: "Awaiting durable escrow receipt / local credential",
  [DeviceActionState.RETIRING_ESCROW]: "Retiring old managed slot — outcome not yet known",
};

export const sanitizeMethodLabels: Record<SanitizeMethod, string> = {
  [SanitizeMethod.UNSPECIFIED]: "Unsupported / unspecified",
  [SanitizeMethod.OVERWRITE]: "Overwrite rotational media with sampling",
  [SanitizeMethod.DISCARD]: "Qualified zero-after-discard with sampling",
  [SanitizeMethod.NVME_FORMAT_USER_DATA]: "NVMe Format — user-data erase",
  [SanitizeMethod.NVME_FORMAT_CRYPTO_ERASE]: "NVMe Format — cryptographic erase",
  [SanitizeMethod.NVME_SANITIZE_BLOCK_ERASE]: "NVMe Sanitize — block erase",
  [SanitizeMethod.NVME_SANITIZE_CRYPTO_ERASE]: "NVMe Sanitize — cryptographic erase",
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
              ? "Live-root header erasure — complete frozen volume set; unconditional power-off"
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
            {action.value.retireKeyslot ?? "None — preserve old slots"}
          </Fact>
        </dl>
      ) : null}
      {action.case === "tpm2Bind" ? <p>PCR policy: {action.value.pcrs.join(", ")}</p> : null}
      {action.case === "lockSessions" ? (
        <dl className="grid gap-2 text-sm">
          <Fact label="Terminate interactive sessions">
            {action.value.terminateSessions ? "Yes — unsaved work may be lost" : "No — lock only"}
          </Fact>
          <Fact label="Disable local login">
            {action.value.allHumanAccounts
              ? "All eligible local human accounts"
              : action.value.usernames.join(", ") || "None — session lock only"}
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
          <Fact label="Exact NVMe namespace ID">{action.value.nvmeScope.namespaceId}</Fact>
          <Fact label="Approved command scope">
            {action.value.nvmeScope.controllerWide
              ? "Controller-wide — all qualified namespaces affected"
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
              {result.nativeLuksErase ? "Confirmed" : "Not confirmed"}
            </Fact>
            <Fact label="Raw zero verification">
              {result.rawZeroVerified ? "Confirmed" : "Not confirmed"}
            </Fact>
            <Fact label="LUKS metadata absent">
              {result.metadataAbsent ? "Confirmed" : "Not confirmed"}
            </Fact>
            <Fact label="Evidence">{result.evidence || "Not reported"}</Fact>
          </dl>
        </div>
      ))}
      <p className="text-sm text-muted-foreground">
        Only server-accepted, nonce-bound proof for every frozen member can establish aggregate
        completion. Local header destruction does not delete server escrow, backups, or active
        volume keys before power-off.
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
          {native.nativeCommandCompleted ? "Confirmed" : "Not confirmed"}
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
