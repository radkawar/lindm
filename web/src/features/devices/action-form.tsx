import { create, equals, toBinary } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { queryOptions, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
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
  RefreshInventoryActionSchema,
  ReleaseLockActionSchema,
  ReleaseQuarantineActionSchema,
  RestartActionSchema,
  SanitizeActionSchema,
  SanitizeMethod,
  ShutdownActionSchema,
  StorageTargetSchema,
  TPM2BindActionSchema,
} from "../../../gen/lindm/agent/v1/device_actions_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { StatusBadge } from "@/components/ui/status-badge";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { RpcError } from "@/components/ui/rpc-error";
import { Skeleton } from "@/components/ui/skeleton";
import { RecoveryReadinessView } from "./recovery-readiness";
import { recoveryReadinessMessage } from "@/lib/errors";
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
import {
  ObservedStorageTargetPicker,
  observedStorageSelections,
  type ObservedStorageSelection,
} from "./storage-target-picker";

const encryptionKinds: DeviceActionKind[] = ["escrowRotate", "tpm2Bind"];
const storageActionKinds: Partial<Record<DeviceActionKind, string>> = {
  escrowRotate: "escrow_rotate",
  tpm2Bind: "tpm2_bind",
  cryptoErase: "crypto_erase",
  sanitize: "sanitize",
};
const imperativeKinds: DeviceActionKind[] = [
  "lockSessions",
  "releaseLock",
  "quarantine",
  "releaseQuarantine",
  "cryptoErase",
  "sanitize",
  "restart",
  "shutdown",
  "refreshInventory",
];
const approvalLabels: Record<ApprovalState, string> = {
  [ApprovalState.UNSPECIFIED]: "Unknown",
  [ApprovalState.PENDING]: "Pending independent approval",
  [ApprovalState.APPROVED]: "Approved",
  [ApprovalState.REJECTED]: "Rejected",
  [ApprovalState.CONSUMED]: "Consumed",
  [ApprovalState.EXPIRED]: "Expired",
};

const actionSummaries: Record<DeviceActionKind, string> = {
  escrowRotate: "Create a new recovery key in server escrow for the exact encrypted volume.",
  tpm2Bind: "Bind TPM 2.0 unlock to the exact encrypted volume and PCR policy.",
  lockSessions: "Lock interactive sessions and optionally restrict local account login.",
  releaseLock: "Restore account state owned by the original lock. Screen locks remain in place.",
  quarantine: "Restrict network access while retaining the approved management IPs.",
  releaseQuarantine: "Remove the network restrictions owned by the original quarantine.",
  cryptoErase:
    "Destroy the selected LUKS headers and keyslots. Independent recovery copies remain.",
  sanitize: "Erase the exact unencrypted storage target using the selected qualified method.",
  restart: "Request a device restart. Completion requires evidence of a new boot.",
  shutdown: "Request device shutdown. Native acceptance does not prove power-off.",
  refreshInventory: "Collect and publish a new full inventory snapshot from this device.",
};

export function DeviceActionForm({
  deviceId,
  mode,
  selectedLuksUuid = "",
  kind: selectedKind,
  onCreated,
}: {
  deviceId: string;
  mode: "encryption" | "actions";
  selectedLuksUuid?: string;
  kind?: DeviceActionKind;
  onCreated?: (actionId: string) => void;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const availableKinds = (mode === "encryption" ? encryptionKinds : imperativeKinds).filter(
    (value) =>
      canPermission(principal, actionPermissions[value]) &&
      (value !== "refreshInventory" || canPermission(principal, "fleet.read")),
  );
  const queryClient = useQueryClient();
  const detail = useQuery(deviceQueryOptions(lifetime, deviceId));
  const actions = useQuery(deviceActionsQueryOptions(lifetime, deviceId, ""));
  const attemptKey = `${deviceId}:${selectedKind ?? mode}`;
  const attempt = useDeviceActionAttempt(attemptKey);
  const [draftKind, setKind] = useState<DeviceActionKind>(
    selectedKind ?? availableKinds[0] ?? (mode === "encryption" ? "escrowRotate" : "lockSessions"),
  );
  const kind = attempt?.payload.spec?.action.case ?? selectedKind ?? draftKind;
  const [selectedTarget, setSelectedTarget] = useState<{
    key: string;
    selection: ObservedStorageSelection;
  } | null>(null);
  const [refreshOpen, setRefreshOpen] = useState(false);
  const [retireSlot, setRetireSlot] = useState("");
  const [pcrs, setPcrs] = useState("");
  const [endpoints, setEndpoints] = useState("");
  const [quarantineId, setQuarantineId] = useState("");
  const [lockId, setLockId] = useState("");
  const [terminateSessions, setTerminateSessions] = useState(false);
  const [accountSelection, setAccountSelection] = useState("none");
  const [usernames, setUsernames] = useState("");
  const [powerDelay, setPowerDelay] = useState("");
  const [powerMessage, setPowerMessage] = useState("");
  const [method, setMethod] = useState(SanitizeMethod.OVERWRITE);
  const [nvmeControllerWide, setNvmeControllerWide] = useState(false);
  const [eraseMode, setEraseMode] = useState(CryptoEraseMode.OFFLINE);
  const [liveTargets, setLiveTargets] = useState<
    { key: string; selection: ObservedStorageSelection }[]
  >([]);
  const [recoveryHandoff, setRecoveryHandoff] = useState(false);
  const [recoveryBootMode, setRecoveryBootMode] = useState(RecoveryBootMode.UKI);
  const [recoveryImageSha256, setRecoveryImageSha256] = useState("");
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");
  const [rpcFailure, setRpcFailure] = useState<RpcFailure | null>(null);
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const storage =
    kind === "escrowRotate" || kind === "tpm2Bind" || kind === "cryptoErase" || kind === "sanitize";
  const encryption = useQuery({
    ...deviceEncryptionQueryOptions(
      lifetime,
      deviceId,
      selectedTarget?.selection.target.luksUuid || selectedLuksUuid,
    ),
    enabled: storage,
  });
  const liveErase = kind === "cryptoErase" && eraseMode === CryptoEraseMode.LIVE_ROOT_HEADER;
  const destructive = kind === "cryptoErase" || kind === "sanitize";
  const frozen = attempt !== null;
  const observed = !encryption.error ? encryption.data?.observation : undefined;
  const ready =
    !detail.error &&
    !!detail.data?.device?.enrollmentGeneration &&
    canPermission(principal, actionPermissions[kind]) &&
    (kind !== "refreshInventory" || canPermission(principal, "fleet.read"));
  const currentLockId = !actions.error ? actions.data?.lockActionId : undefined;
  const prefix = `action-${selectedKind ?? mode}-${deviceId}`;
  const confirmationName = detail.data?.device?.hostname || deviceId;
  const frozenSpec = attempt?.payload.spec?.action;
  const frozenRecovery = frozenSpec?.case === "sanitize" ? frozenSpec.value.recovery : undefined;
  const needsRecovery = frozen ? !!frozenRecovery : kind === "sanitize" && recoveryHandoff;
  const recoveryHash = frozenRecovery
    ? Array.from(frozenRecovery.imageSha256, (byte) => byte.toString(16).padStart(2, "0")).join("")
    : recoveryImageSha256.trim().toLowerCase();
  const recoveryDigest = needsRecovery && /^[a-f0-9]{64}$/.test(recoveryHash) ? recoveryHash : "";
  const storageQuery = queryOptions({
    queryKey: [
      "device-storage-targets",
      lifetime.generation,
      deviceId,
      kind,
      recoveryDigest,
    ] as const,
    meta: { authGeneration: lifetime.generation },
    retry: false,
    refetchInterval: 10_000,
    queryFn: async ({ signal }) => {
      const result = await adminClient.listDeviceStorageTargets(
        {
          deviceId,
          actionKind: storageActionKinds[kind] ?? "",
          recoveryImageSha256: recoveryDigest
            ? Uint8Array.from(recoveryDigest.match(/../g)!, (byte) => Number.parseInt(byte, 16))
            : undefined,
        },
        { signal: AbortSignal.any([signal, lifetime.signal]) },
      );
      lifetime.signal.throwIfAborted();
      return result;
    },
  });
  const storageTargets = useQuery({ ...storageQuery, enabled: storage });
  const eligibleTargets =
    !storageTargets.error &&
    storageTargets.data?.enrollmentGeneration === detail.data?.device?.enrollmentGeneration
      ? storageTargets.data
      : undefined;
  const recoveryReady = !storageTargets.error && eligibleTargets?.recoveryReadiness?.ready === true;
  const selectableTargets = observedStorageSelections(eligibleTargets, kind);

  function isStillObserved(
    entry: { key: string; selection: ObservedStorageSelection },
    entries = selectableTargets,
  ) {
    const current = entries.find((candidate) => candidate.key === entry.key)?.selection;
    return (
      !!current &&
      equals(StorageTargetSchema, current.target, entry.selection.target) &&
      (current.nvmeScope && entry.selection.nvmeScope
        ? equals(NVMeSanitizeScopeSchema, current.nvmeScope, entry.selection.nvmeScope)
        : current.nvmeScope === entry.selection.nvmeScope)
    );
  }

  const currentSelection =
    selectedTarget && isStillObserved(selectedTarget) ? selectedTarget.selection : undefined;

  function addLiveTarget() {
    if (inFlight.current || frozen || !currentSelection) return;
    setError("");
    if (
      liveTargets.some(
        (entry) => entry.selection.target.luksUuid === currentSelection.target.luksUuid,
      )
    ) {
      setError("This observed volume is already in the aggregate.");
      return;
    }
    setLiveTargets([...liveTargets, { key: selectedTarget!.key, selection: currentSelection }]);
  }

  async function freeze() {
    if (inFlight.current || frozen || !ready) return;
    inFlight.current = true;
    setBusy(true);
    setError("");
    setRpcFailure(null);
    try {
      if (needsRecovery && !recoveryDigest)
        throw new Error("Enter the signed recovery image SHA-256 as 64 hexadecimal characters.");
      if (needsRecovery && !recoveryReady)
        throw new Error(recoveryReadinessMessage(eligibleTargets?.recoveryReadiness?.reason || ""));
      if (storage && confirmation !== confirmationName)
        throw new Error(`Type ${confirmationName} exactly to confirm this storage action.`);
      if (storage && !currentSelection)
        throw new Error("Select a currently observed storage target before review.");
      if (
        liveErase &&
        (!liveTargets.length || !liveTargets.every((entry) => isStillObserved(entry)))
      )
        throw new Error("Every aggregate volume must still match an eligible observed target.");
      if (
        liveErase &&
        new Set(liveTargets.map((entry) => entry.selection.target.luksUuid)).size !==
          liveTargets.length
      )
        throw new Error("The aggregate must contain each observed volume exactly once.");
      const target = storage && !liveErase ? currentSelection!.target : undefined;
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
              targets: liveErase ? liveTargets.map((entry) => entry.selection.target) : [],
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
            method >= SanitizeMethod.NVME_FORMAT_USER_DATA && currentSelection?.nvmeScope
              ? create(NVMeSanitizeScopeSchema, {
                  ...currentSelection.nvmeScope,
                  controllerWide: nvmeControllerWide,
                })
              : undefined;
          if (method >= SanitizeMethod.NVME_FORMAT_USER_DATA) {
            if (!nvmeScope)
              throw new Error(
                "This target has no complete observed native NVMe identity. Refresh inventory before selecting this method.",
              );
            validateInventory(NVMeSanitizeScopeSchema, nvmeScope);
          }
          spec.action = {
            case: kind,
            value: create(SanitizeActionSchema, { target, method, recovery, nvmeScope }),
          };
          break;
        }
        case "restart":
          spec.action = {
            case: kind,
            value: create(RestartActionSchema, {
              delaySeconds: powerDelay.trim() === "" ? undefined : Number(powerDelay),
              message: powerMessage.trim() || undefined,
            }),
          };
          break;
        case "shutdown":
          spec.action = {
            case: kind,
            value: create(ShutdownActionSchema, {
              delaySeconds: powerDelay.trim() === "" ? undefined : Number(powerDelay),
              message: powerMessage.trim() || undefined,
            }),
          };
          break;
        case "refreshInventory":
          spec.action = { case: kind, value: create(RefreshInventoryActionSchema) };
          break;
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
      if (storage) {
        const latest = queryClient.getQueryData(storageQuery.queryKey);
        const latestEntries = observedStorageSelections(
          queryClient.getQueryState(storageQuery.queryKey)?.status !== "error" &&
            latest?.enrollmentGeneration === payload.enrollmentGeneration
            ? latest
            : undefined,
          kind,
        );
        const capturedTargets = liveErase ? liveTargets : selectedTarget ? [selectedTarget] : [];
        if (
          !capturedTargets.length ||
          !capturedTargets.every((entry) => isStillObserved(entry, latestEntries))
        )
          throw new Error(
            "The observed storage identity changed during preparation. Select the current target and review again.",
          );
        if (needsRecovery && !latest?.recoveryReadiness?.ready)
          throw new Error(recoveryReadinessMessage(latest?.recoveryReadiness?.reason || ""));
      }
      setDeviceActionAttempt(lifetime, attemptKey, {
        payload,
        specSha256,
        status: "frozen",
        failure: null,
        approvalId: "",
        approvalAmbiguous: false,
      });
    } catch (error) {
      if (!lifetime.signal.aborted)
        setError(error instanceof Error ? error.message : "Check the action inputs.");
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
    setRpcFailure(null);
    let createdActionId = "";
    try {
      const response = await adminClient.createDeviceAction(payload, {
        signal: lifetime.signal,
        timeoutMs: 30_000,
      });
      lifetime.signal.throwIfAborted();
      if (!response.action?.actionId)
        throw new Error("The server did not return an action receipt.");
      setDeviceActionAttempt(lifetime, attemptKey, {
        ...next,
        status: "accepted",
        failure: null,
        actionId: response.action.actionId,
      });
      toast.success("Device action request accepted", {
        description: "Acceptance is not proof of execution. Review the action status.",
      });
      void queryClient.invalidateQueries({
        queryKey: ["device-actions", lifetime.generation, deviceId],
      });
      createdActionId = response.action.actionId;
    } catch (error) {
      const failure = toRpcFailure(error);
      setDeviceActionAttempt(lifetime, attemptKey, {
        ...next,
        status: failure.ambiguous ? "ambiguous" : "rejected",
        failure,
      });
      if (!lifetime.signal.aborted) {
        const feedback = classifyRpcFailure(failure);
        toast[feedback.tone === "destructive" ? "error" : "warning"](feedback.title, {
          description: "Review the inline result and frozen request before continuing.",
        });
      }
    } finally {
      inFlight.current = false;
      if (!lifetime.signal.aborted) setBusy(false);
    }
    if (createdActionId && mounted.current && !lifetime.signal.aborted)
      onCreated?.(createdActionId);
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
    setRpcFailure(null);
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
        setRpcFailure(failure);
        const feedback = classifyRpcFailure(failure);
        toast[feedback.tone === "destructive" ? "error" : "warning"](feedback.title, {
          description: "Review the inline result and frozen request before continuing.",
        });
      }
    } finally {
      inFlight.current = false;
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  return (
    <div className="grid gap-4">
      {!frozen ? (
        <form
          className="grid gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            void freeze();
          }}
        >
          {!selectedKind ? (
            <>
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
            </>
          ) : null}
          {kind === "restart" || kind === "shutdown" ? (
            <>
              <Label htmlFor={`${prefix}-power-delay`}>Delay in seconds (optional)</Label>
              <Input
                id={`${prefix}-power-delay`}
                inputMode="numeric"
                value={powerDelay}
                onChange={(event) => setPowerDelay(event.target.value)}
              />
              <Label htmlFor={`${prefix}-power-message`}>User notification (optional)</Label>
              <Input
                id={`${prefix}-power-message`}
                value={powerMessage}
                onChange={(event) => setPowerMessage(event.target.value)}
              />
            </>
          ) : null}
          {storage && storageTargets.isPending ? (
            <div role="status" className="grid gap-2">
              <p className="text-sm text-muted-foreground">Loading observed storage…</p>
              <Skeleton className="h-24 w-full" />
            </div>
          ) : null}
          {storage && storageTargets.isSuccess && !eligibleTargets && !detail.error ? (
            <p role="status" className="text-sm text-warning">
              Device enrollment changed. Refresh this page before choosing storage.
            </p>
          ) : null}
          {storage && eligibleTargets ? (
            <ObservedStorageTargetPicker
              targets={eligibleTargets}
              kind={kind}
              selectedKey={selectedTarget?.key ?? ""}
              onSelect={(key, selection) => {
                setSelectedTarget({ key, selection });
                setNvmeControllerWide(false);
                setConfirmation("");
                setError("");
              }}
              onRefresh={() => setRefreshOpen(true)}
              disabled={busy}
            />
          ) : null}
          {kind === "sanitize" && eligibleTargets && !currentSelection ? (
            <details className="grid gap-3">
              <summary className="w-fit cursor-pointer text-sm font-medium">
                Recovery handoff readiness
              </summary>
              <div className="mt-3">
                <RecoveryReadinessView readiness={eligibleTargets.recoveryReadiness} />
              </div>
            </details>
          ) : null}
          {!storage || currentSelection ? (
            <>
              {kind === "cryptoErase" ? (
                <>
                  <Label htmlFor={`${prefix}-erase-mode`}>Wipe execution mode</Label>
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
                        label: "Offline: one qualified volume, off-target journal",
                      },
                      {
                        value: CryptoEraseMode.LIVE_ROOT_HEADER,
                        label: "Live root: complete encrypted-volume set, forced power-off",
                      },
                    ]}
                  />
                </>
              ) : null}
              {liveErase ? (
                <div className="grid gap-3">
                  <Button type="button" variant="outline" disabled={busy} onClick={addLiveTarget}>
                    Add selected volume to aggregate
                  </Button>
                  {liveTargets.map((entry) => (
                    <div key={entry.key} className="grid gap-2 rounded-md border p-3">
                      <p className="text-sm">
                        {entry.selection.name} · {entry.selection.model} ·{" "}
                        {entry.selection.encryption}
                      </p>
                      <StorageTargetView target={entry.selection.target} />
                      {!isStillObserved(entry) ? (
                        <p className="text-sm text-warning">
                          This volume no longer matches the current inventory. Remove it and select
                          an observed volume.
                        </p>
                      ) : null}
                      <Button
                        type="button"
                        variant="outline"
                        disabled={busy}
                        onClick={() =>
                          setLiveTargets((targets) =>
                            targets.filter((target) => target.key !== entry.key),
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
                  <Label htmlFor={`${prefix}-slot`}>
                    Old lindm-owned slot to retire (optional)
                  </Label>
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
                        label: "Lock and terminate sessions",
                      },
                    ]}
                  />
                  <Label htmlFor={`${prefix}-accounts`}>Disable local account login</Label>
                  <SelectField
                    id={`${prefix}-accounts`}
                    value={accountSelection}
                    onValueChange={setAccountSelection}
                    options={[
                      { value: "none", label: "None: session lock only" },
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
                  {currentLockId ? (
                    <p className="text-warning">
                      Release original lock {currentLockId} before another lock.
                    </p>
                  ) : null}
                </fieldset>
              ) : null}
              {kind === "releaseLock" ? (
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
                  {!currentLockId ? <p>No current original lock is available.</p> : null}
                </div>
              ) : null}
              {kind === "quarantine" ? (
                <>
                  <Label htmlFor={`${prefix}-endpoints`}>
                    Retained management IPs (one per line)
                  </Label>
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
                currentSelection?.nvmeScope ? (
                  <div className="grid gap-2">
                    <Label htmlFor={`${prefix}-nvme-scope`}>Approved effect scope</Label>
                    <SelectField
                      id={`${prefix}-nvme-scope`}
                      value={nvmeControllerWide ? "controller" : "namespace"}
                      disabled={busy}
                      onValueChange={(value) => setNvmeControllerWide(value === "controller")}
                      options={[
                        { value: "namespace", label: "Selected namespace only" },
                        {
                          value: "controller",
                          label: "Entire controller: all qualified namespaces",
                        },
                      ]}
                    />
                    <p className="text-sm text-muted-foreground">
                      The exact observed native identity is included automatically.
                      {nvmeControllerWide
                        ? " This authorizes erasure across the entire controller, not only the selected namespace."
                        : " Methods requiring controller-wide effects are rejected unless that scope is explicitly approved."}
                    </p>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    Native NVMe identity is not available for this target. Refresh inventory before
                    choosing a native NVMe method.
                  </p>
                )
              ) : null}
              {kind === "sanitize" ? (
                <div className="grid gap-2">
                  <Label htmlFor={`${prefix}-sanitize-mode`}>Sanitize execution mode</Label>
                  <SelectField
                    id={`${prefix}-sanitize-mode`}
                    value={recoveryHandoff ? "recovery" : "offline"}
                    disabled={busy}
                    onValueChange={(value) => setRecoveryHandoff(value === "recovery")}
                    options={[
                      { value: "offline", label: "Already in qualified offline recovery" },
                      { value: "recovery", label: "Original-device signed recovery handoff" },
                    ]}
                  />
                  {recoveryHandoff ? (
                    <>
                      <Label htmlFor={`${prefix}-recovery-image`}>
                        Configured signed recovery image SHA-256
                      </Label>
                      <Input
                        id={`${prefix}-recovery-image`}
                        required
                        value={recoveryImageSha256}
                        onChange={(event) => setRecoveryImageSha256(event.target.value)}
                      />
                      <Label htmlFor={`${prefix}-recovery-boot`}>
                        Locally authorized boot method
                      </Label>
                      <SelectField
                        id={`${prefix}-recovery-boot`}
                        value={recoveryBootMode}
                        disabled={busy}
                        onValueChange={(value) =>
                          setRecoveryBootMode(
                            Number(value) === RecoveryBootMode.KEXEC
                              ? RecoveryBootMode.KEXEC
                              : RecoveryBootMode.UKI,
                          )
                        }
                        options={[
                          { value: RecoveryBootMode.UKI, label: "Signed UKI" },
                          { value: RecoveryBootMode.KEXEC, label: "Qualified signed kexec" },
                        ]}
                      />
                      <RecoveryReadinessView readiness={eligibleTargets?.recoveryReadiness} />
                    </>
                  ) : null}
                </div>
              ) : null}
              <p className="text-sm">{actionSummaries[kind]}</p>
              {liveErase ? (
                <p className="text-sm">
                  Every selected volume loses its LUKS headers, keyslots and tokens. The device then
                  forces power-off within 120 seconds. Include the complete required
                  encrypted-volume set.
                </p>
              ) : null}
              <details className="text-sm text-muted-foreground">
                <summary className="cursor-pointer">Details</summary>
                <div className="mt-3 grid gap-3">
                  <p>
                    Preparation freezes the target, enrollment generation, expiry and signed
                    payload. Every action requires the root-local allowlist, exact native preflight
                    and a fresh start grant valid for at most 30 seconds. There is no offline
                    destructive queue. Platform inventory is not execution authorization.
                  </p>
                  <p>
                    {observed
                      ? `Last preflight: ${observed.supported ? "supported for that recorded action only" : "unsupported"}${observed.reason ? `: ${observed.reason}` : ""}.`
                      : "No protected preflight observation is available."}
                  </p>
                  <p>
                    Approval receipts are not cached authority. Start rechecks both distinct humans,
                    authorization versions, generation, exact specification and expiry. Unknown
                    outcomes must not be treated as safe to repeat.
                  </p>
                  {kind === "lockSessions" || kind === "releaseLock" ? (
                    <p>
                      Root and locally protected accounts are excluded. All-human selection uses
                      local passwd, login.defs UID limits and interactive shells, not directory
                      accounts. Account locking requires a separate local opt-in. No accounts or
                      data are deleted. Session locking is not boot locking or proof of physical
                      control. Release restores only matching owned shadow state, preserves
                      administrator changes and never unlocks a screen.
                    </p>
                  ) : null}
                  {kind === "escrowRotate" ? (
                    <p>
                      A new high-entropy key is encrypted to server escrow. Retiring an old managed
                      slot requires a durable signed custody receipt; independent owner slots are
                      preserved. Supply one-shot credentials locally on the device, or use a
                      qualified TPM token. Never enter owner credentials in this console.
                    </p>
                  ) : null}
                  {kind === "tpm2Bind" ? (
                    <p>
                      Binding requires qualified TPM 2.0 tooling, an explicit PCR policy, exact LUKS
                      identity and a root-local one-shot credential. It does not prove Secure Boot
                      enforcement.
                    </p>
                  ) : null}
                  {kind === "quarantine" ? (
                    <p>
                      Only locally pinned numeric management IPs can remain reachable. Local policy
                      bounds duration and rejects unsupported firewall ownership.
                    </p>
                  ) : null}
                  {kind === "cryptoErase" ? (
                    <p>
                      Offline erasure requires qualified recovery and an off-target journal.
                      Live-root erasure must include every configured and server-escrowed encrypted
                      volume, including root, with explicit local permission for every member. It
                      destroys headers, keyslots and tokens, then forces power-off within 120
                      seconds of consumption even if delivery fails. Mounted keys remain in memory
                      until power-off. Its final aggregate proof is memory-only. Neither mode
                      destroys independent recovery material, server escrow or header backups.
                    </p>
                  ) : null}
                  {kind === "sanitize" ? (
                    <p>
                      Sanitation requires unencrypted media in qualified offline recovery with an
                      off-target journal. Controller-wide commands can affect every namespace. The
                      root verifies the approved identity basis, controller capabilities, namespace
                      inventory and mount/swap safety without downgrading identity or substituting
                      generic discard. Sampling is not physical SSD secure-erasure certification.
                      Signed recovery handoff requires the original device&apos;s proof and fresh
                      boot grant, then a new recovery challenge and start grant. Its scoped
                      credential is not a start grant and its private key never reaches transport.
                      The media digest binds the exact target. Unsupported image, boot, signature,
                      media, TPM or journal placement fails closed.
                    </p>
                  ) : null}
                </div>
              </details>
              <p className="text-sm text-muted-foreground">
                {destructive
                  ? "Independent approval is required before execution."
                  : "Request any required approval at review."}{" "}
                Review does not send the action.
              </p>
              {storage ? (
                <div className="grid gap-2">
                  <Label htmlFor={`${prefix}-confirm`}>
                    Type {detail.data?.device?.hostname ? "hostname" : "device ID"}{" "}
                    {confirmationName} to confirm
                  </Label>
                  <Input
                    id={`${prefix}-confirm`}
                    required
                    value={confirmation}
                    onChange={(event) => setConfirmation(event.target.value)}
                  />
                </div>
              ) : null}
              <Label htmlFor={`${prefix}-reason`}>Audit reason</Label>
              <Textarea
                id={`${prefix}-reason`}
                required
                value={reason}
                onChange={(event) => setReason(event.target.value)}
              />
              {!ready ? (
                <p className="text-warning">
                  Current device generation and action permission are required before review.
                </p>
              ) : null}
              <Button
                type="submit"
                disabled={
                  busy ||
                  !ready ||
                  (needsRecovery && !recoveryReady) ||
                  (storage && confirmation !== confirmationName) ||
                  (liveErase &&
                    (!liveTargets.length ||
                      !liveTargets.every((entry) => isStillObserved(entry)))) ||
                  (kind === "sanitize" &&
                    method >= SanitizeMethod.NVME_FORMAT_USER_DATA &&
                    !currentSelection?.nvmeScope)
                }
              >
                Review action
              </Button>
            </>
          ) : null}
        </form>
      ) : (
        <div className="grid gap-3">
          {selectedKind && attempt.payload.spec?.action.case !== selectedKind ? (
            <p className="text-sm text-warning">
              A previous action is frozen for this device. Resolve that exact request before
              preparing another.
            </p>
          ) : null}
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
          {needsRecovery ? (
            <RecoveryReadinessView readiness={eligibleTargets?.recoveryReadiness} />
          ) : null}
          <div className="flex items-center gap-2 text-sm">
            Submission:
            <StatusBadge
              status={
                attempt.status === "ambiguous"
                  ? "warning"
                  : attempt.status === "rejected"
                    ? attempt.failure
                      ? classifyRpcFailure(attempt.failure).tone
                      : "destructive"
                    : "info"
              }
            >
              {
                {
                  frozen: "Ready for review",
                  inflight: "Submitting",
                  ambiguous: "Outcome unknown",
                  rejected: "Not accepted",
                  accepted: "Accepted, execution not confirmed",
                }[attempt.status]
              }
            </StatusBadge>
          </div>
          {attempt.actionId ? (
            <Link
              to="/devices/$deviceId/actions/$actionId"
              params={{ deviceId, actionId: attempt.actionId }}
              className="text-sm underline"
            >
              View action status
            </Link>
          ) : null}
          <p>
            Approval:{" "}
            <StatusBadge
              status={
                attempt.approvalState === ApprovalState.APPROVED
                  ? "success"
                  : attempt.approvalState === ApprovalState.REJECTED
                    ? "destructive"
                    : attempt.approvalState === ApprovalState.PENDING
                      ? "warning"
                      : "neutral"
              }
            >
              {attempt.approvalState === undefined
                ? "No approval receipt"
                : approvalLabels[attempt.approvalState]}
            </StatusBadge>
            {attempt.approvalId ? ` (${attempt.approvalId})` : ""}.{" "}
            <Link to="/approvals" className="underline">
              Open approvals
            </Link>
          </p>
          {attempt.approvalAmbiguous ? (
            <p className="text-warning">
              Approval delivery unknown. Retry the exact approval request; do not prepare another
              payload.
            </p>
          ) : null}
          {attempt.failure ? (
            <RpcError failure={attempt.failure}>
              {attempt.status === "ambiguous" ? (
                <p>Retry this exact request only. Do not create another action.</p>
              ) : null}
            </RpcError>
          ) : null}
          {attempt.status !== "accepted" ? (
            <Alert
              variant={
                attempt.payload.spec?.action.case === "cryptoErase" ||
                attempt.payload.spec?.action.case === "sanitize"
                  ? "destructive"
                  : "default"
              }
            >
              <AlertTitle>Confirm submission</AlertTitle>
              <AlertDescription>
                {attempt.payload.spec?.action.case === "cryptoErase"
                  ? attempt.payload.spec.action.value.mode === CryptoEraseMode.LIVE_ROOT_HEADER
                    ? "Irreversible header erasure with forced power-off. Independent approval is required."
                    : "Irreversible header erasure. Independent approval is required."
                  : attempt.payload.spec?.action.case === "sanitize"
                    ? attempt.payload.spec.action.value.nvmeScope?.controllerWide
                      ? "Irreversible erasure affects the entire controller. Independent approval is required."
                      : "Irreversible storage erasure. Independent approval is required."
                    : attempt.payload.spec?.action.case === "lockSessions" &&
                        attempt.payload.spec.action.value.terminateSessions
                      ? "Terminating sessions can lose unsaved work."
                      : attempt.payload.spec?.action.case === "restart" ||
                          attempt.payload.spec?.action.case === "shutdown"
                        ? "This interrupts device use and can lose unsaved work."
                        : "Submit only after reviewing the exact target and effects above."}
              </AlertDescription>
            </Alert>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Button
              disabled={
                busy ||
                (needsRecovery && !recoveryReady && attempt.status !== "ambiguous") ||
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
                (needsRecovery &&
                  !recoveryReady &&
                  !attempt.approvalId &&
                  !attempt.approvalAmbiguous) ||
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
                setRpcFailure(null);
              }}
            >
              Edit action
            </Button>
          </div>
        </div>
      )}
      {storage ? (
        <Dialog open={refreshOpen} onOpenChange={setRefreshOpen}>
          {refreshOpen ? (
            <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-xl">
              <DialogHeader>
                <DialogTitle>Refresh inventory</DialogTitle>
                <DialogDescription>
                  Ask {confirmationName} to collect and publish a fresh inventory snapshot.
                </DialogDescription>
              </DialogHeader>
              <DeviceActionForm
                deviceId={deviceId}
                mode="actions"
                kind="refreshInventory"
                onCreated={() => setRefreshOpen(false)}
              />
            </DialogContent>
          ) : null}
        </Dialog>
      ) : null}
      {error ? (
        <p role="alert" className="text-sm text-warning">
          {error}
        </p>
      ) : null}
      {rpcFailure ? <RpcError failure={rpcFailure} /> : null}
      {detail.error ? <RpcError failure={toRpcFailure(detail.error)} /> : null}
      {storage && encryption.error ? <RpcError failure={toRpcFailure(encryption.error)} /> : null}
      {storage && storageTargets.error ? (
        <RpcError failure={toRpcFailure(storageTargets.error)}>
          <Button
            variant="outline"
            disabled={storageTargets.isFetching}
            onClick={() => void storageTargets.refetch()}
          >
            Retry storage lookup
          </Button>
        </RpcError>
      ) : null}
      {(kind === "releaseLock" || kind === "lockSessions") && actions.error ? (
        <RpcError failure={toRpcFailure(actions.error)} />
      ) : null}
    </div>
  );
}
