import { create, toBinary } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useRef, useState } from "react";
import { toast } from "sonner";
import { CreateDeviceActionRequestSchema } from "../../../gen/lindm/admin/v1/device_actions_pb";
import { ApprovalState } from "../../../gen/lindm/admin/v1/approvals_pb";
import {
  CryptoEraseActionSchema,
  CryptoEraseMode,
  DeviceActionSpecSchema,
  EscrowRotateActionSchema,
  LockSessionsActionSchema,
  NVMeSanitizeScopeSchema,
  QuarantineActionSchema,
  RecoveryBootMode,
  RecoveryBootSpecSchema,
  ReleaseLockActionSchema,
  ReleaseQuarantineActionSchema,
  SanitizeActionSchema,
  SanitizeMethod,
  StorageTargetSchema,
  TPM2BindActionSchema,
  type StorageTarget,
} from "../../../gen/lindm/agent/v1/device_actions_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import {
  setDeviceActionAttempt,
  useDeviceActionAttempt,
  type DeviceActionAttempt,
} from "./action-attempt";
import {
  actionLabels,
  actionPermissions,
  DeviceActionSpecView,
  sanitizeMethodLabels,
  sanitizeMethods,
  StorageTargetView,
  type DeviceActionKind,
} from "./action-display";
import { deviceActionsQueryOptions, deviceEncryptionQueryOptions } from "./action-queries";
import { deviceQueryOptions } from "./queries";
import { validateInventory } from "./validation";

const encryptionKinds: DeviceActionKind[] = ["escrowRotate", "tpm2Bind"];
const imperativeKinds: DeviceActionKind[] = [
  "lockSessions",
  "releaseLock",
  "quarantine",
  "releaseQuarantine",
  "cryptoErase",
  "sanitize",
];
const approvalLabels: Record<ApprovalState, string> = {
  [ApprovalState.UNSPECIFIED]: "Unknown",
  [ApprovalState.PENDING]: "Pending independent approval",
  [ApprovalState.APPROVED]: "Approved — fresh authority will still be checked at start",
  [ApprovalState.REJECTED]: "Rejected",
  [ApprovalState.CONSUMED]: "Consumed",
  [ApprovalState.EXPIRED]: "Expired",
};

export function DeviceActionForm({
  deviceId,
  mode,
  selectedLuksUuid = "",
}: {
  deviceId: string;
  mode: "encryption" | "actions";
  selectedLuksUuid?: string;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const availableKinds = (mode === "encryption" ? encryptionKinds : imperativeKinds).filter(
    (value) => canPermission(principal, actionPermissions[value]),
  );
  const queryClient = useQueryClient();
  const detail = useQuery(deviceQueryOptions(lifetime, deviceId));
  const encryption = useQuery(deviceEncryptionQueryOptions(lifetime, deviceId, selectedLuksUuid));
  const actions = useQuery(deviceActionsQueryOptions(lifetime, deviceId, ""));
  const attemptKey = `${deviceId}:${mode}`;
  const attempt = useDeviceActionAttempt(attemptKey);
  const [kind, setKind] = useState<DeviceActionKind>(
    availableKinds[0] ?? (mode === "encryption" ? "escrowRotate" : "lockSessions"),
  );
  const [luksUuid, setLuksUuid] = useState(selectedLuksUuid);
  const [wwn, setWwn] = useState("");
  const [serial, setSerial] = useState("");
  const [size, setSize] = useState("");
  const [retireSlot, setRetireSlot] = useState("");
  const [pcrs, setPcrs] = useState("");
  const [endpoints, setEndpoints] = useState("");
  const [quarantineId, setQuarantineId] = useState("");
  const [lockId, setLockId] = useState("");
  const [terminateSessions, setTerminateSessions] = useState(false);
  const [accountSelection, setAccountSelection] = useState("none");
  const [usernames, setUsernames] = useState("");
  const [method, setMethod] = useState(SanitizeMethod.OVERWRITE);
  const [nvmeNamespaceId, setNvmeNamespaceId] = useState("");
  const [nvmeControllerWide, setNvmeControllerWide] = useState(false);
  const [eraseMode, setEraseMode] = useState(CryptoEraseMode.OFFLINE);
  const [liveTargets, setLiveTargets] = useState<StorageTarget[]>([]);
  const [recoveryHandoff, setRecoveryHandoff] = useState(false);
  const [recoveryBootMode, setRecoveryBootMode] = useState(RecoveryBootMode.UKI);
  const [recoveryImageSha256, setRecoveryImageSha256] = useState("");
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const storage =
    kind === "escrowRotate" || kind === "tpm2Bind" || kind === "cryptoErase" || kind === "sanitize";
  const liveErase = kind === "cryptoErase" && eraseMode === CryptoEraseMode.LIVE_ROOT_HEADER;
  const destructive = kind === "cryptoErase" || kind === "sanitize";
  const frozen = attempt !== null;
  const observed = !encryption.error ? encryption.data?.observation : undefined;
  const ready =
    !detail.error &&
    !!detail.data?.device?.enrollmentGeneration &&
    canPermission(principal, actionPermissions[kind]);
  const currentLockId = !actions.error ? actions.data?.lockActionId : undefined;
  const prefix = `action-${mode}-${deviceId}`;

  function addLiveTarget() {
    if (inFlight.current || frozen) return;
    setError("");
    try {
      const target = create(StorageTargetSchema, {
        luksUuid: luksUuid.trim(),
        wwn: wwn.trim(),
        serial: serial.trim(),
        sizeBytes: BigInt(size),
      });
      if (!target.wwn || !target.serial)
        throw new Error("Both exact WWN and serial are required for every member.");
      const targets = [...liveTargets, target];
      validateInventory(
        CryptoEraseActionSchema,
        create(CryptoEraseActionSchema, { mode: CryptoEraseMode.LIVE_ROOT_HEADER, targets }),
      );
      setLiveTargets(targets);
      setLuksUuid("");
      setWwn("");
      setSerial("");
      setSize("");
    } catch (error) {
      setError(toRpcFailure(error).message);
    }
  }

  async function freeze() {
    if (inFlight.current || frozen || !ready) return;
    inFlight.current = true;
    setBusy(true);
    setError("");
    try {
      if (destructive && confirmation !== deviceId)
        throw new Error("Type the exact device ID to acknowledge irreversible effects.");
      const target =
        storage && !liveErase
          ? create(StorageTargetSchema, {
              luksUuid: kind === "sanitize" ? "" : luksUuid.trim(),
              wwn: wwn.trim(),
              serial: serial.trim(),
              sizeBytes: BigInt(size),
            })
          : undefined;
      if (target && (!target.wwn || !target.serial))
        throw new Error("Both the exact WWN and serial are required by the native provider.");
      const spec = create(DeviceActionSpecSchema);
      switch (kind) {
        case "escrowRotate":
          if (
            encryption.error ||
            !encryption.data?.escrowKeyId ||
            !encryption.data.escrowPublicKey.length
          )
            throw new Error("Server escrow custody is unavailable; rotation cannot be prepared.");
          spec.action = {
            case: kind,
            value: create(EscrowRotateActionSchema, {
              target,
              escrowKeyId: encryption.data.escrowKeyId,
              escrowPublicKey: encryption.data.escrowPublicKey,
              retireKeyslot: retireSlot === "" ? undefined : Number(retireSlot),
            }),
          };
          break;
        case "tpm2Bind":
          spec.action = {
            case: kind,
            value: create(TPM2BindActionSchema, {
              target,
              pcrs: pcrs
                .split(/[\s,]+/)
                .filter(Boolean)
                .map(Number),
            }),
          };
          break;
        case "lockSessions":
          if (accountSelection === "explicit" && !usernames.split(/[\s,]+/).some(Boolean))
            throw new Error("Enter at least one explicit local username.");
          spec.action = {
            case: kind,
            value: create(LockSessionsActionSchema, {
              terminateSessions,
              allHumanAccounts: accountSelection === "all",
              usernames:
                accountSelection === "explicit" ? usernames.split(/[\s,]+/).filter(Boolean) : [],
            }),
          };
          break;
        case "releaseLock":
          if (!lockId || lockId !== currentLockId)
            throw new Error("Select the current original lock action; refresh if it changed.");
          spec.action = {
            case: kind,
            value: create(ReleaseLockActionSchema, { lockActionId: lockId }),
          };
          break;
        case "quarantine":
          spec.action = {
            case: kind,
            value: create(QuarantineActionSchema, {
              managementEndpoints: endpoints.split(/[\s,]+/).filter(Boolean),
            }),
          };
          break;
        case "releaseQuarantine":
          spec.action = {
            case: kind,
            value: create(ReleaseQuarantineActionSchema, {
              quarantineActionId: quarantineId.trim(),
            }),
          };
          break;
        case "cryptoErase":
          spec.action = {
            case: kind,
            value: create(CryptoEraseActionSchema, {
              mode: eraseMode,
              target,
              targets: liveErase ? liveTargets : [],
            }),
          };
          break;
        case "sanitize": {
          let recovery;
          if (recoveryHandoff && target) {
            const hex = recoveryImageSha256.trim();
            if (!/^(?:[0-9a-fA-F]{2})+$/.test(hex))
              throw new Error("Enter the configured recovery image SHA-256 as hexadecimal bytes.");
            const imageSha256 = Uint8Array.from(hex.match(/../g)!, (byte) =>
              Number.parseInt(byte, 16),
            );
            const mediaSha256 = new Uint8Array(
              await crypto.subtle.digest("SHA-256", toBinary(StorageTargetSchema, target)),
            );
            recovery = create(RecoveryBootSpecSchema, {
              imageSha256,
              mediaSha256,
              bootMode: recoveryBootMode,
            });
          }
          const nvmeScope =
            method >= SanitizeMethod.NVME_FORMAT_USER_DATA
              ? create(NVMeSanitizeScopeSchema, {
                  namespaceId: Number(nvmeNamespaceId),
                  controllerWide: nvmeControllerWide,
                })
              : undefined;
          spec.action = {
            case: kind,
            value: create(SanitizeActionSchema, { target, method, recovery, nvmeScope }),
          };
          break;
        }
      }
      const payload = create(CreateDeviceActionRequestSchema, {
        requestId: newRequestId(),
        deviceId,
        enrollmentGeneration: detail.data!.device!.enrollmentGeneration,
        spec,
        expiresAt: timestampFromDate(new Date(Date.now() + 10 * 60_000)),
        reason: reason.trim(),
      });
      validateInventory(CreateDeviceActionRequestSchema, payload);
      const digest = await crypto.subtle.digest("SHA-256", toBinary(DeviceActionSpecSchema, spec));
      lifetime.signal.throwIfAborted();
      const specSha256 = Array.from(new Uint8Array(digest), (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join("");
      setDeviceActionAttempt(lifetime, attemptKey, {
        payload,
        specSha256,
        status: "frozen",
        failure: null,
        approvalId: "",
        approvalAmbiguous: false,
      });
    } catch (error) {
      if (!lifetime.signal.aborted) setError(toRpcFailure(error).message);
    } finally {
      inFlight.current = false;
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  async function send(captured: DeviceActionAttempt) {
    if (inFlight.current || captured.status === "inflight" || captured.status === "accepted")
      return;
    const payload =
      captured.payload.approvalId || !captured.approvalId
        ? captured.payload
        : create(CreateDeviceActionRequestSchema, {
            ...captured.payload,
            approvalId: captured.approvalId,
          });
    const next = { ...captured, payload };
    if (
      !setDeviceActionAttempt(lifetime, attemptKey, { ...next, status: "inflight", failure: null })
    )
      return;
    inFlight.current = true;
    setBusy(true);
    setError("");
    try {
      const response = await adminClient.createDeviceAction(payload, {
        signal: lifetime.signal,
        timeoutMs: 30_000,
      });
      lifetime.signal.throwIfAborted();
      if (!response.action?.actionId)
        throw new Error("The server did not return an action receipt.");
      setDeviceActionAttempt(lifetime, attemptKey, { ...next, status: "accepted", failure: null });
      toast.success("Device action request accepted", {
        description: "Acceptance is not proof of execution. Review protected outcomes in History.",
      });
      await queryClient.invalidateQueries({
        queryKey: ["device-actions", lifetime.generation, deviceId],
      });
    } catch (error) {
      const failure = toRpcFailure(error);
      setDeviceActionAttempt(lifetime, attemptKey, {
        ...next,
        status: failure.ambiguous ? "ambiguous" : "rejected",
        failure,
      });
      if (!lifetime.signal.aborted) {
        toast.error(
          failure.ambiguous ? "Action submission outcome unknown" : "Action not accepted",
          {
            description: "Review the inline result and frozen request before continuing.",
          },
        );
      }
    } finally {
      inFlight.current = false;
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  async function approval() {
    if (
      !attempt ||
      inFlight.current ||
      attempt.status === "ambiguous" ||
      attempt.status === "accepted"
    )
      return;
    inFlight.current = true;
    setBusy(true);
    setError("");
    try {
      const response = await adminClient.createApproval(
        { lifetimeSeconds: 600, payload: { case: "createDeviceAction", value: attempt.payload } },
        { signal: lifetime.signal, timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      if (!response.approval?.id) throw new Error("No approval receipt returned.");
      setDeviceActionAttempt(lifetime, attemptKey, {
        ...attempt,
        approvalId: response.approval.id,
        approvalState: response.approval.state,
        approvalAmbiguous: false,
      });
      toast.success("Device action approval receipt received", {
        description:
          "Review the recorded approval state. This receipt does not prove native execution.",
      });
      await queryClient.invalidateQueries({ queryKey: ["approvals", lifetime.generation] });
    } catch (error) {
      const failure = toRpcFailure(error);
      setDeviceActionAttempt(lifetime, attemptKey, {
        ...attempt,
        approvalAmbiguous: failure.ambiguous,
      });
      if (!lifetime.signal.aborted) {
        setError(failure.message);
        toast.error(
          failure.ambiguous ? "Approval delivery unknown" : "Action approval request failed",
          {
            description: "Review the inline result and frozen request before continuing.",
          },
        );
      }
    } finally {
      inFlight.current = false;
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  return (
    <div className="grid gap-3 rounded-md border p-4">
      <h3 className="font-semibold">
        {mode === "encryption" ? "Prepare encryption action" : "Prepare imperative action"}
      </h3>
      <p className="text-sm text-muted-foreground">
        Preparation freezes the exact target, enrollment generation, expiry and typed payload. It
        does not execute anything. The root executor checks capabilities and a fresh,
        at-most-30-second start grant; no offline destructive queue exists.
      </p>
      <Alert>
        <AlertTitle>Capability and privilege gates remain enforced</AlertTitle>
        <AlertDescription>
          {observed
            ? `Last spec-specific preflight: ${observed.supported ? "supported for that recorded action only" : "unsupported"}${observed.reason ? ` — ${observed.reason}` : ""}. `
            : "No protected preflight observation is available. "}
          Supported platform inventory is not execution authorization. Every action requires the
          root-local allowlist and exact native preflight. Unsupported actions fail closed, not
          silently disappear.
        </AlertDescription>
      </Alert>
      {!frozen ? (
        <form
          className="grid gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            void freeze();
          }}
        >
          <Label htmlFor={`${prefix}-kind`}>Action</Label>
          <SelectField
            id={`${prefix}-kind`}
            value={kind}
            disabled={busy}
            onValueChange={(value) => {
              const selected = availableKinds.find((candidate) => candidate === value);
              if (selected) setKind(selected);
            }}
            options={availableKinds.map((value) => ({
              value,
              label: actionLabels[value],
            }))}
          />
          {kind === "cryptoErase" ? (
            <>
              <Label htmlFor={`${prefix}-erase-mode`}>Crypto erase execution mode</Label>
              <SelectField
                id={`${prefix}-erase-mode`}
                value={eraseMode}
                disabled={busy}
                onValueChange={(value) =>
                  setEraseMode(
                    Number(value) === CryptoEraseMode.LIVE_ROOT_HEADER
                      ? CryptoEraseMode.LIVE_ROOT_HEADER
                      : CryptoEraseMode.OFFLINE,
                  )
                }
                options={[
                  {
                    value: CryptoEraseMode.OFFLINE,
                    label: "Offline — one qualified volume, off-target journal",
                  },
                  {
                    value: CryptoEraseMode.LIVE_ROOT_HEADER,
                    label: "Live root — complete frozen encrypted-volume set, forced power-off",
                  },
                ]}
              />
            </>
          ) : null}
          {storage ? (
            <fieldset className="grid gap-3 rounded-md border p-3" disabled={busy}>
              <legend>
                {liveErase
                  ? "Add every encrypted volume to the aggregate"
                  : "Exact stable target — never a device path"}
              </legend>
              {observed?.target ? (
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    const target = observed.target!;
                    setLuksUuid(target.luksUuid);
                    setWwn(target.wwn);
                    setSerial(target.serial);
                    setSize(target.sizeBytes.toString());
                  }}
                >
                  Use last observed identity (verify before freezing)
                </Button>
              ) : null}
              {kind !== "sanitize" ? (
                <>
                  <Label htmlFor={`${prefix}-uuid`}>LUKS UUID</Label>
                  <Input
                    id={`${prefix}-uuid`}
                    required={!liveErase}
                    value={luksUuid}
                    onChange={(event) => setLuksUuid(event.target.value)}
                  />
                </>
              ) : null}
              <Label htmlFor={`${prefix}-wwn`}>WWN</Label>
              <Input
                id={`${prefix}-wwn`}
                required={!liveErase}
                value={wwn}
                onChange={(event) => setWwn(event.target.value)}
              />
              <Label htmlFor={`${prefix}-serial`}>Serial</Label>
              <Input
                id={`${prefix}-serial`}
                required={!liveErase}
                value={serial}
                onChange={(event) => setSerial(event.target.value)}
              />
              <Label htmlFor={`${prefix}-size`}>Exact size in bytes</Label>
              <Input
                id={`${prefix}-size`}
                required={!liveErase}
                inputMode="numeric"
                value={size}
                onChange={(event) => setSize(event.target.value)}
              />
              {liveErase ? (
                <Button type="button" variant="outline" onClick={addLiveTarget}>
                  Add exact volume to frozen target set
                </Button>
              ) : null}
            </fieldset>
          ) : null}
          {liveErase ? (
            <div className="grid gap-3">
              <p className="text-sm">
                This set must exactly match every locally configured encrypted target and every
                server-escrowed volume, including the actual root backing device. Missing, duplicate
                or extra targets fail closed. Every member requires the local crypto-erase allowlist
                plus explicit live-root permission.
              </p>
              {liveTargets.map((target) => (
                <div key={target.luksUuid} className="grid gap-2 rounded-md border p-3">
                  <StorageTargetView target={target} />
                  <Button
                    type="button"
                    variant="outline"
                    disabled={busy}
                    onClick={() =>
                      setLiveTargets((targets) =>
                        targets.filter((entry) => entry.luksUuid !== target.luksUuid),
                      )
                    }
                  >
                    Remove volume from draft
                  </Button>
                </div>
              ))}
            </div>
          ) : null}
          {kind === "escrowRotate" ? (
            <>
              <p className="text-sm">
                A new high-entropy recovery key is encrypted to server escrow. Old managed-slot
                retirement requires a durable signed custody receipt; independent owner slots are
                never retired. Root-local one-shot credentials must be supplied on the device (or a
                qualified TPM token used); do not enter owner credentials in this console.
              </p>
              <Label htmlFor={`${prefix}-slot`}>Old lindm-owned slot to retire (optional)</Label>
              <Input
                id={`${prefix}-slot`}
                inputMode="numeric"
                value={retireSlot}
                onChange={(event) => setRetireSlot(event.target.value)}
              />
            </>
          ) : null}
          {kind === "tpm2Bind" ? (
            <>
              <p className="text-sm">
                Requires qualified TPM 2.0 tooling, explicit PCR policy, exact LUKS identity, and a
                root-local one-shot credential. Binding is not proof of Secure Boot enforcement.
              </p>
              <Label htmlFor={`${prefix}-pcrs`}>PCR indices (comma separated)</Label>
              <Input
                id={`${prefix}-pcrs`}
                required
                value={pcrs}
                onChange={(event) => setPcrs(event.target.value)}
              />
            </>
          ) : null}
          {kind === "lockSessions" ? (
            <Dialog>
              <DialogTrigger render={<Button type="button" variant="outline" />}>
                Configure session and account lock…
              </DialogTrigger>
              <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-xl">
                <DialogHeader>
                  <DialogTitle>Lock sessions and local accounts</DialogTitle>
                  <DialogDescription>
                    Select the exact local restrictions. Closing saves this draft only; freeze and
                    review the signed action payload before submission.
                  </DialogDescription>
                </DialogHeader>
                <fieldset className="grid gap-3 rounded-md border p-3" disabled={busy}>
                  <legend>Session and account restrictions</legend>
                  <Label htmlFor={`${prefix}-termination`}>Interactive sessions</Label>
                  <SelectField
                    id={`${prefix}-termination`}
                    value={terminateSessions ? "terminate" : "lock"}
                    onValueChange={(value) => setTerminateSessions(value === "terminate")}
                    options={[
                      { value: "lock", label: "Lock supported sessions" },
                      {
                        value: "terminate",
                        label: "Lock and terminate sessions — unsaved work may be lost",
                      },
                    ]}
                  />
                  <Label htmlFor={`${prefix}-accounts`}>Disable local account login</Label>
                  <SelectField
                    id={`${prefix}-accounts`}
                    value={accountSelection}
                    onValueChange={setAccountSelection}
                    options={[
                      { value: "none", label: "None — session lock only" },
                      { value: "explicit", label: "Explicit local usernames" },
                      { value: "all", label: "All eligible local human accounts" },
                    ]}
                  />
                  {accountSelection === "explicit" ? (
                    <>
                      <Label htmlFor={`${prefix}-usernames`}>Local usernames (one per line)</Label>
                      <Textarea
                        id={`${prefix}-usernames`}
                        required
                        value={usernames}
                        onChange={(event) => setUsernames(event.target.value)}
                      />
                    </>
                  ) : null}
                  <Alert variant="destructive">
                    <AlertTitle>Protected accounts and local policy</AlertTitle>
                    <AlertDescription>
                      Root and the device&apos;s root-owned protected-account list cannot be
                      disabled. All-human selection uses local passwd, login.defs UID limits and
                      interactive shells, not directory accounts. Account locking requires a
                      separate root-local opt-in. No account or data is deleted. Termination can
                      lose unsaved work. A session lock is not boot lock or proof of physical
                      control. Release never unlocks a screen.
                    </AlertDescription>
                  </Alert>
                  {currentLockId ? (
                    <p className="text-destructive">
                      Release original lock {currentLockId} before another lock.
                    </p>
                  ) : null}
                </fieldset>
                <DialogFooter showCloseButton />
              </DialogContent>
            </Dialog>
          ) : null}
          {kind === "releaseLock" ? (
            <Dialog>
              <DialogTrigger render={<Button type="button" variant="outline" />}>
                Select original lock to release…
              </DialogTrigger>
              <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-xl">
                <DialogHeader>
                  <DialogTitle>Release owned account lock</DialogTitle>
                  <DialogDescription>
                    Choose the original lock. This is a separately authorized inverse action, never
                    an automatic retry or a screen unlock.
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-2">
                  <Label htmlFor={`${prefix}-original-lock`}>Original lock action</Label>
                  <SelectField
                    id={`${prefix}-original-lock`}
                    value={lockId}
                    disabled={busy || !currentLockId}
                    onValueChange={setLockId}
                    options={[
                      { value: "", label: "Select the original lock" },
                      ...(currentLockId ? [{ value: currentLockId, label: currentLockId }] : []),
                    ]}
                  />
                  <p className="text-sm">
                    Only accounts owned by this exact lock are restored, and only if their shadow
                    state still matches the recorded expected state. Administrator changes remain
                    untouched. Screen locks remain in place. Unknown results never trigger an
                    automatic retry.
                  </p>
                  {!currentLockId ? (
                    <p>No current original lock is available. Refresh action history.</p>
                  ) : null}
                </div>
                <DialogFooter showCloseButton />
              </DialogContent>
            </Dialog>
          ) : null}
          {kind === "quarantine" ? (
            <>
              <p className="text-sm">
                Only locally pinned numeric management IPs may remain reachable. Root-local policy
                bounds quarantine duration; unsupported firewall ownership is rejected.
              </p>
              <Label htmlFor={`${prefix}-endpoints`}>Retained management IPs (one per line)</Label>
              <Textarea
                id={`${prefix}-endpoints`}
                required
                value={endpoints}
                onChange={(event) => setEndpoints(event.target.value)}
              />
            </>
          ) : null}
          {kind === "releaseQuarantine" ? (
            <>
              <Label htmlFor={`${prefix}-quarantine`}>Original quarantine action ID</Label>
              <Input
                id={`${prefix}-quarantine`}
                required
                value={quarantineId}
                onChange={(event) => setQuarantineId(event.target.value)}
              />
            </>
          ) : null}
          {kind === "sanitize" ? (
            <>
              <Label htmlFor={`${prefix}-method`}>Qualified method</Label>
              <SelectField
                id={`${prefix}-method`}
                value={method}
                disabled={busy}
                onValueChange={(value) => {
                  const selected = sanitizeMethods.find((method) => method === Number(value));
                  if (selected !== undefined) setMethod(selected);
                }}
                options={sanitizeMethods.map((value) => ({
                  value,
                  label: sanitizeMethodLabels[value],
                }))}
              />
            </>
          ) : null}
          {kind === "sanitize" && method >= SanitizeMethod.NVME_FORMAT_USER_DATA ? (
            <fieldset className="grid gap-2 rounded-md border p-3" disabled={busy}>
              <legend>Exact native NVMe scope</legend>
              <Label htmlFor={`${prefix}-nvme-namespace`}>Namespace ID</Label>
              <Input
                id={`${prefix}-nvme-namespace`}
                required
                inputMode="numeric"
                value={nvmeNamespaceId}
                onChange={(event) => setNvmeNamespaceId(event.target.value)}
              />
              <Label htmlFor={`${prefix}-nvme-scope`}>Explicitly approved effect scope</Label>
              <SelectField
                id={`${prefix}-nvme-scope`}
                value={nvmeControllerWide ? "controller" : "namespace"}
                disabled={busy}
                onValueChange={(value) => setNvmeControllerWide(value === "controller")}
                options={[
                  { value: "namespace", label: "Selected namespace only" },
                  {
                    value: "controller",
                    label: "Entire controller — all qualified allocated namespaces",
                  },
                ]}
              />
              <p className="text-sm text-destructive">
                Controller-wide native commands may destroy every namespace, not just the named
                device. The root must verify controller capabilities, exact namespace inventory and
                safe mount/swap scope before any command. Unsupported or inconsistent scope is
                rejected; no generic discard substitute is used.
              </p>
            </fieldset>
          ) : null}
          {kind === "sanitize" ? (
            <div className="grid gap-2">
              <Label htmlFor={`${prefix}-sanitize-mode`}>Sanitize execution mode</Label>
              <select
                id={`${prefix}-sanitize-mode`}
                className="rounded-md border bg-background p-2"
                value={recoveryHandoff ? "recovery" : "offline"}
                disabled={busy}
                onChange={(event) => setRecoveryHandoff(event.target.value === "recovery")}
              >
                <option value="offline">Already in qualified offline recovery</option>
                <option value="recovery">Original-device signed recovery handoff</option>
              </select>
              {recoveryHandoff ? (
                <>
                  <p className="text-sm">
                    The original enrolled device must prepare a root-owned handoff, register its
                    signed proof, consume a fresh BOOT-purpose grant, and boot the exact locally
                    authorized recovery image. After reboot, a new recovery challenge and start
                    grant are required before sanitation. The scoped credential is not a start
                    grant; it never exposes its private key to transport.
                  </p>
                  <Label htmlFor={`${prefix}-recovery-image`}>
                    Configured signed recovery image SHA-256
                  </Label>
                  <Input
                    id={`${prefix}-recovery-image`}
                    required
                    value={recoveryImageSha256}
                    onChange={(event) => setRecoveryImageSha256(event.target.value)}
                  />
                  <Label htmlFor={`${prefix}-recovery-boot`}>Locally authorized boot method</Label>
                  <select
                    id={`${prefix}-recovery-boot`}
                    className="rounded-md border bg-background p-2"
                    value={recoveryBootMode}
                    onChange={(event) =>
                      setRecoveryBootMode(
                        Number(event.target.value) === RecoveryBootMode.KEXEC
                          ? RecoveryBootMode.KEXEC
                          : RecoveryBootMode.UKI,
                      )
                    }
                  >
                    <option value={RecoveryBootMode.UKI}>Signed UKI</option>
                    <option value={RecoveryBootMode.KEXEC}>Qualified signed kexec</option>
                  </select>
                  <p className="text-sm">
                    The exact target media digest is derived from the frozen UUID/WWN/serial/size
                    specification. Unsupported boot, signature, media, TPM or journal placement
                    fails closed; no external-operator fallback is inferred.
                  </p>
                </>
              ) : null}
            </div>
          ) : null}
          {destructive ? (
            <Alert variant="destructive">
              <AlertTitle>Irreversible — independent approval required</AlertTitle>
              <AlertDescription>
                <p>
                  {liveErase
                    ? "LIVE ROOT HEADER ERASURE: all approved local LUKS headers, keyslots and tokens are destroyed. Mounted volume keys remain in memory until unconditional forced power-off within 120 seconds of consumption, even if result delivery fails. The final nonce-bound aggregate proof is memory-only, not a durable journal result. "
                    : recoveryHandoff && kind === "sanitize"
                      ? "ORIGINAL-DEVICE RECOVERY HANDOFF: reboot is itself authorized by a fresh signed BOOT grant. Sanitation occurs only after a new recovery-boot challenge and grant verify the exact approved media and image, never on the running root filesystem. "
                      : "Only qualified offline targets in a dedicated recovery environment with an off-target journal may proceed; the offline mode never erases the live root filesystem. "}
                  Crypto erase does not destroy independent recovery material, server escrow or
                  header backups. Sanitize requires unencrypted storage; sampling is not a physical
                  SSD secure-erasure claim. Missing proof or remote loss remains OUTCOME UNKNOWN.
                </p>
                <Label htmlFor={`${prefix}-confirm`}>Type device ID {deviceId}</Label>
                <Input
                  id={`${prefix}-confirm`}
                  required
                  value={confirmation}
                  onChange={(event) => setConfirmation(event.target.value)}
                />
              </AlertDescription>
            </Alert>
          ) : null}
          <Label htmlFor={`${prefix}-reason`}>Audit reason</Label>
          <Textarea
            id={`${prefix}-reason`}
            required
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
          {!ready ? (
            <p className="text-destructive">
              Current device generation or action permission is unavailable; refresh device access.
            </p>
          ) : null}
          <Button type="submit" disabled={busy || !ready}>
            Freeze for review (no execution)
          </Button>
        </form>
      ) : (
        <div className="grid gap-3">
          <dl className="grid gap-2 break-all text-sm">
            <dt>Request ID</dt>
            <dd className="font-mono">{attempt.payload.requestId}</dd>
            <dt>Device / frozen generation</dt>
            <dd className="font-mono">
              {attempt.payload.deviceId} / {attempt.payload.enrollmentGeneration}
            </dd>
            <dt>Intent expires</dt>
            <dd>{formatTimestamp(attempt.payload.expiresAt).local}</dd>
            <dt>Specification SHA-256</dt>
            <dd className="font-mono">{attempt.specSha256}</dd>
            <dt>Audit reason</dt>
            <dd>{attempt.payload.reason}</dd>
          </dl>
          <DeviceActionSpecView spec={attempt.payload.spec} />
          <p>
            Submission:{" "}
            {attempt.status === "accepted"
              ? "Accepted by server — not proof of execution or success. See protected results in the History tab."
              : attempt.status}
          </p>
          <p>
            Approval:{" "}
            {attempt.approvalState === undefined
              ? "No approval receipt"
              : approvalLabels[attempt.approvalState]}
            {attempt.approvalId ? ` (${attempt.approvalId})` : ""}.{" "}
            <Link to="/approvals" className="underline">
              Open approvals
            </Link>
          </p>
          {attempt.approvalAmbiguous ? (
            <p className="text-destructive">
              Approval delivery unknown. Retry the exact approval request; do not prepare another
              payload.
            </p>
          ) : null}
          {attempt.failure ? (
            <Alert variant="destructive">
              <AlertTitle>
                {attempt.status === "ambiguous" ? "Submission outcome unknown" : "Action rejected"}
              </AlertTitle>
              <AlertDescription>
                {attempt.failure.message}
                {attempt.status === "ambiguous"
                  ? " Retry this exact request only. Do not create another action."
                  : ""}
              </AlertDescription>
            </Alert>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Button
              disabled={
                busy ||
                attempt.status === "accepted" ||
                attempt.status === "inflight" ||
                attempt.approvalAmbiguous
              }
              onClick={() => void send(attempt)}
            >
              {attempt.status === "ambiguous" ? "Retry exact submission" : "Submit frozen action"}
            </Button>
            <Button
              variant="outline"
              disabled={
                busy ||
                attempt.status === "ambiguous" ||
                attempt.status === "inflight" ||
                attempt.status === "accepted"
              }
              onClick={() => void approval()}
            >
              {attempt.approvalId
                ? "Refresh exact approval state"
                : attempt.approvalAmbiguous
                  ? "Retry exact approval request"
                  : "Request independent approval"}
            </Button>
            <Button
              variant="outline"
              disabled={
                busy ||
                attempt.status === "ambiguous" ||
                attempt.status === "inflight" ||
                attempt.approvalAmbiguous
              }
              onClick={() => {
                setDeviceActionAttempt(lifetime, attemptKey, null);
                setConfirmation("");
                setError("");
              }}
            >
              Prepare a different action
            </Button>
          </div>
          <p className="text-sm text-muted-foreground">
            Approval state is the last observed receipt, never cached authority. Start rechecks both
            distinct humans, authorization versions, generation, exact specification and expiry.
            Unknown device outcomes must not be treated as safe to repeat.
          </p>
        </div>
      )}
      {error ? (
        <p role="alert" className="text-destructive">
          {error}
        </p>
      ) : null}
    </div>
  );
}
