import { create, equals, toBinary } from "@bufbuild/protobuf";
import { timestampDate, timestampFromDate } from "@bufbuild/protobuf/wkt";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import {
  CreateDeviceActionRequestSchema,
  type DeviceAction,
} from "../../../gen/lindm/admin/v1/device_actions_pb";
import { ApprovalState } from "../../../gen/lindm/admin/v1/approvals_pb";
import {
  CryptoEraseActionSchema,
  CryptoEraseMode,
  DeviceActionSpecSchema,
  DeviceActionState,
  EscrowRotateActionSchema,
  LockSessionsActionSchema,
  NVMeSanitizeScopeSchema,
  QuarantineActionSchema,
  PatchNowActionSchema,
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
import {
  OSUpdateRebootMode,
  OSUpdateRebootPolicySchema,
  UpdateSelection,
} from "../../../gen/lindm/resource/v1/software_pb";
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
import { SearchPicker, type PickerOption, type PickerProps } from "@/components/ui/search-picker";
import { StatusBadge } from "@/components/ui/status-badge";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { classifyRpcFailure, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
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
import {
  deviceActionQueryOptions,
  deviceActionsQueryOptions,
  deviceEncryptionQueryOptions,
  deviceStorageTargetsQueryOptions,
} from "./action-queries";
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
  "patchNow",
];
const approvalLabels: Record<ApprovalState, string> = {
  [ApprovalState.UNSPECIFIED]: "Unknown",
  [ApprovalState.PENDING]: "Waiting for approval",
  [ApprovalState.APPROVED]: "Approved",
  [ApprovalState.REJECTED]: "Rejected",
  [ApprovalState.CONSUMED]: "Used",
  [ApprovalState.EXPIRED]: "Expired",
};

const actionSummaries: Record<DeviceActionKind, string> = {
  escrowRotate: "Create a new recovery key for this encrypted volume and store it on the server.",
  tpm2Bind: "Unlock this encrypted volume automatically with the device's TPM.",
  lockSessions: "Lock user sessions and optionally block local logins.",
  releaseLock: "Restore accounts locked by lindm. Screen locks stay in place.",
  quarantine: "Cut network access except for the management IPs you allow.",
  releaseQuarantine: "Remove the network restrictions added by quarantine.",
  cryptoErase: "Destroy the encryption keys on this volume. Recovery keys on the server are kept.",
  sanitize: "Permanently erase this unencrypted disk.",
  restart: "Restart the device.",
  shutdown: "Shut down the device.",
  refreshInventory: "Collect a fresh inventory from this device.",
  localAdminPasswordRotate: "Set a new password for the managed local admin account.",
  patchNow: "Install OS updates now. Results appear in Patch status.",
};

// Where a requested inventory refresh stands as of its last poll. Polling stops
// at a terminal state, a server close, or a minute past the request's expiry
// (at most 10 minutes after it was sent), so waiting is always bounded.
function refreshOutcome(action: DeviceAction | undefined, polledAt: number) {
  const state = action?.status?.state;
  if (state === DeviceActionState.SUCCEEDED) return "succeeded";
  if (state === DeviceActionState.FAILED) return "failed";
  if (state === DeviceActionState.OUTCOME_UNKNOWN) return "unknown";
  if (state === DeviceActionState.EXPIRED || action?.closedReason) return "expired";
  const expiresAt = action?.expiresAt ? timestampDate(action.expiresAt).getTime() : NaN;
  if (polledAt > expiresAt + 60_000) return action?.status ? "unknown" : "expired";
  return "waiting";
}

function QuarantineActionPicker({ deviceId, ...props }: PickerProps & { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const [selected, setSelected] = useState<PickerOption>();
  const query = useQuery(deviceActionsQueryOptions(lifetime, deviceId, pageToken));
  const options: PickerOption[] = query.error
    ? []
    : (query.data?.actions
        .filter((action) => action.spec?.action.case === "quarantine")
        .map((action) => ({
          value: action.actionId,
          label: `Quarantine requested ${formatTimestamp(action.createdAt).local}`,
          description: `Expires ${formatTimestamp(action.expiresAt).local}`,
        })) ?? []);
  if (selected?.value === props.value && !options.some((option) => option.value === props.value)) {
    options.unshift(selected);
  }
  return (
    <SearchPicker
      {...props}
      disabled={props.disabled || query.isPending || !!query.error}
      options={options}
      onChange={(value) => {
        setSelected(options.find((option) => option.value === value));
        props.onChange(value);
      }}
      note="Searches this page of actions. Use Next page for older actions."
    >
      {query.isPending ? <p role="status">Loading quarantine actions…</p> : null}
      {query.error ? (
        <RpcError failure={toRpcFailure(query.error)} title="Couldn't load quarantine actions" />
      ) : null}
      {!query.isPending && !query.error && !options.length ? (
        <p className="text-sm text-muted-foreground">No quarantine actions on this page.</p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant="outline"
          disabled={props.disabled || query.isFetching || !pageToken}
          onClick={() => setPageToken("")}
        >
          First page
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={
            props.disabled || query.isFetching || !!query.error || !query.data?.nextPageToken
          }
          onClick={() => setPageToken(query.data!.nextPageToken)}
        >
          Next page
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={props.disabled || query.isFetching}
          onClick={() => void query.refetch()}
        >
          Refresh actions
        </Button>
      </div>
    </SearchPicker>
  );
}

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
  const [refreshActionId, setRefreshActionId] = useState("");
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
  const [patchSelection, setPatchSelection] = useState(UpdateSelection.SECURITY);
  const [patchRebootMode, setPatchRebootMode] = useState(
    OSUpdateRebootMode.OS_UPDATE_REBOOT_MODE_NEVER,
  );
  const [patchRebootDelay, setPatchRebootDelay] = useState("60");
  const [patchRebootNotice, setPatchRebootNotice] = useState("");
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
  // A refresh requested from this form: follow it, then reload storage as soon as
  // the device reports success so the target list appears without a reload.
  const refreshAction = useQuery({
    ...deviceActionQueryOptions(lifetime, deviceId, refreshActionId),
    enabled: storage && refreshActionId !== "",
    refetchInterval: (query) =>
      query.state.status !== "error" &&
      refreshOutcome(query.state.data, query.state.dataUpdatedAt) === "waiting"
        ? 3_000
        : false,
  });
  const refreshResult =
    !storage || !refreshActionId
      ? undefined
      : refreshAction.error
        ? "error"
        : refreshOutcome(refreshAction.data, refreshAction.dataUpdatedAt);
  const refreshSucceeded = refreshResult === "succeeded";
  useEffect(() => {
    if (!refreshSucceeded) return;
    void queryClient.invalidateQueries({
      queryKey: ["device-storage-targets", lifetime.generation, deviceId],
    });
  }, [refreshSucceeded, queryClient, lifetime.generation, deviceId]);
  const destructive = kind === "cryptoErase" || kind === "sanitize";
  const frozen = attempt !== null;
  const ready =
    !detail.error &&
    !!detail.data?.device?.enrollmentGeneration &&
    canPermission(principal, actionPermissions[kind]) &&
    (kind !== "refreshInventory" || canPermission(principal, "fleet.read"));
  const currentLockId = !actions.error ? actions.data?.lockActionId : undefined;
  // A device has at most one account lock; pin the one shown when the form opened
  // so a lock replaced before sending is refused rather than silently followed.
  if (kind === "releaseLock" && currentLockId && !lockId) setLockId(currentLockId);
  const prefix = `action-${selectedKind ?? mode}-${deviceId}`;
  const confirmationName = detail.data?.device?.hostname || deviceId;
  const frozenSpec = attempt?.payload.spec?.action;
  const frozenRecovery = frozenSpec?.case === "sanitize" ? frozenSpec.value.recovery : undefined;
  const needsRecovery = frozen ? !!frozenRecovery : kind === "sanitize" && recoveryHandoff;
  const recoveryHash = frozenRecovery
    ? Array.from(frozenRecovery.imageSha256, (byte) => byte.toString(16).padStart(2, "0")).join("")
    : recoveryImageSha256.trim().toLowerCase();
  const recoveryDigest = needsRecovery && /^[a-f0-9]{64}$/.test(recoveryHash) ? recoveryHash : "";
  const storageQuery = deviceStorageTargetsQueryOptions(
    lifetime,
    deviceId,
    storageActionKinds[kind] ?? "",
    recoveryDigest,
  );
  const storageTargets = useQuery({
    ...storageQuery,
    enabled: storage,
    refetchInterval: (query) =>
      refreshResult === "waiting" && !query.state.data?.fresh ? 3_000 : 10_000,
  });
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

  // What still blocks review, named inline instead of a disabled button. Empty
  // required text fields are reported by native form validation instead.
  const missing = (
    storage && !currentSelection
      ? [
          storageTargets.error
            ? "storage info (retry loading it below)"
            : !eligibleTargets
              ? ""
              : selectableTargets.length
                ? "a target"
                : eligibleTargets.fresh
                  ? "a disk this action can use"
                  : "current storage info, then a target",
        ]
      : [
          needsRecovery && !recoveryReady ? "a ready recovery image" : "",
          storage && confirmation !== confirmationName ? "the typed hostname confirmation" : "",
          liveErase && !liveTargets.length ? "volumes added to the list" : "",
          liveErase && liveTargets.some((entry) => !isStillObserved(entry))
            ? "removal of volumes the device no longer reports"
            : "",
          kind === "sanitize" &&
          method >= SanitizeMethod.NVME_FORMAT_USER_DATA &&
          !currentSelection?.nvmeScope
            ? "NVMe details for this disk"
            : "",
        ]
  ).filter(Boolean);
  if (
    !canPermission(principal, actionPermissions[kind]) ||
    (kind === "refreshInventory" && !canPermission(principal, "fleet.read"))
  )
    missing.unshift("permission for this action");
  else if (!detail.isPending && !ready) missing.unshift("an enrolled device");

  function addLiveTarget() {
    if (inFlight.current || frozen || !currentSelection) return;
    setError("");
    if (
      liveTargets.some(
        (entry) => entry.selection.target.luksUuid === currentSelection.target.luksUuid,
      )
    ) {
      setError("This volume is already in the list.");
      return;
    }
    setLiveTargets([...liveTargets, { key: selectedTarget!.key, selection: currentSelection }]);
  }

  async function freeze() {
    if (inFlight.current || frozen) return;
    if (!ready || missing.length) {
      setError(
        missing.length
          ? `Missing before review: ${missing.join("; ")}.`
          : "The device is still loading. Try again in a moment.",
      );
      return;
    }
    inFlight.current = true;
    setBusy(true);
    setError("");
    setRpcFailure(null);
    try {
      if (needsRecovery && !recoveryDigest)
        throw new Error("Enter the recovery image SHA-256 (64 hexadecimal characters).");
      if (needsRecovery && !recoveryReady)
        throw new Error(recoveryReadinessMessage(eligibleTargets?.recoveryReadiness?.reason || ""));
      if (storage && confirmation !== confirmationName)
        throw new Error(`Type ${confirmationName} exactly to confirm.`);
      if (storage && !currentSelection) throw new Error("Select a storage target.");
      if (
        liveErase &&
        (!liveTargets.length || !liveTargets.every((entry) => isStillObserved(entry)))
      )
        throw new Error("A volume in the list is no longer available. Refresh and try again.");
      if (
        liveErase &&
        new Set(liveTargets.map((entry) => entry.selection.target.luksUuid)).size !==
          liveTargets.length
      )
        throw new Error("Each volume can only be listed once.");
      const target = storage && !liveErase ? currentSelection!.target : undefined;
      const spec = create(DeviceActionSpecSchema);
      switch (kind) {
        case "escrowRotate":
          if (
            encryption.error ||
            !encryption.data?.escrowKeyId ||
            !encryption.data.escrowPublicKey.length
          )
            throw new Error("The server recovery key isn't set up, so you can't rotate yet.");
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
            throw new Error("Enter at least one local username.");
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
            throw new Error("The account lock changed. Refresh and try again.");
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
              throw new Error("Enter the recovery image SHA-256 in hexadecimal.");
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
                "This disk's NVMe details are incomplete. Refresh inventory, then try again.",
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
        case "patchNow": {
          const scheduled = patchRebootMode === OSUpdateRebootMode.OS_UPDATE_REBOOT_MODE_SCHEDULED;
          const delay = Number(patchRebootDelay.trim());
          if (scheduled && (!Number.isInteger(delay) || delay < 5 || delay > 10080))
            throw new Error("Enter a reboot delay between 5 and 10080 minutes.");
          spec.action = {
            case: kind,
            value: create(PatchNowActionSchema, {
              selection: patchSelection,
              rebootPolicy: create(OSUpdateRebootPolicySchema, {
                mode: patchRebootMode,
                maxDelayMinutes: scheduled ? delay : 0,
                notice: scheduled ? patchRebootNotice.trim() : "",
              }),
            }),
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
          throw new Error("The storage on this device changed. Select the target again.");
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
        setError(error instanceof Error ? error.message : "Check the action details.");
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
      if (!response.action?.actionId) throw new Error("The server didn't confirm the action.");
      setDeviceActionAttempt(lifetime, attemptKey, {
        ...next,
        status: "accepted",
        failure: null,
        actionId: response.action.actionId,
      });
      toast.success("Action sent to device");
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
        toast[feedback.tone === "destructive" ? "error" : "warning"](feedback.title);
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
      if (!response.approval?.id)
        throw new Error("The server didn't confirm the approval request.");
      setDeviceActionAttempt(lifetime, attemptKey, {
        ...attempt,
        approvalId: response.approval.id,
        approvalState: response.approval.state,
        approvalAmbiguous: false,
      });
      toast.success("Approval requested", {
        description: "Another admin must approve before you can send this action.",
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
        toast[feedback.tone === "destructive" ? "error" : "warning"](feedback.title);
      }
    } finally {
      inFlight.current = false;
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  const deviceName = detail.data?.device?.hostname.trim() || "The device";
  const refreshLink = refreshActionId ? (
    <Link
      to="/devices/$deviceId/actions/$actionId"
      params={{ deviceId, actionId: refreshActionId }}
      className="underline"
    >
      View request
    </Link>
  ) : null;
  const refreshStatus =
    refreshResult === "waiting" || (refreshSucceeded && storageTargets.isFetching) ? (
      <p role="status" className="text-sm text-muted-foreground">
        Inventory refresh requested. Waiting for {deviceName} to report its storage; targets appear
        here when it does. {refreshLink}
      </p>
    ) : refreshResult === "error" ? (
      <RpcError failure={toRpcFailure(refreshAction.error)} title="Couldn't check the refresh">
        <Button
          type="button"
          variant="outline"
          disabled={refreshAction.isFetching}
          onClick={() => void refreshAction.refetch()}
        >
          Check again
        </Button>
      </RpcError>
    ) : undefined;
  const refreshNote =
    refreshResult === "failed" ? (
      <p className="text-sm text-warning">
        The device reported that the last refresh failed. {refreshLink}
      </p>
    ) : refreshResult === "expired" ? (
      <p className="text-sm text-warning">
        {deviceName} didn&apos;t start the last refresh before it expired. Check that it&apos;s
        online, then request it again. {refreshLink}
      </p>
    ) : refreshResult === "unknown" ? (
      <p className="text-sm text-warning">
        The outcome of the last refresh is unknown. Check the request before asking again.{" "}
        {refreshLink}
      </p>
    ) : undefined;

  return (
    <div className="grid gap-4">
      {!frozen ? (
        <>
          {!selectedKind ? (
            <div className="grid gap-3">
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
            </div>
          ) : null}
          {storage && storageTargets.isPending ? (
            <div role="status" className="grid gap-2">
              <p className="text-sm text-muted-foreground">Loading storage…</p>
              <Skeleton className="h-24 w-full" />
            </div>
          ) : null}
          {storage && storageTargets.isSuccess && !eligibleTargets && !detail.error ? (
            <p role="status" className="text-sm text-warning">
              This device was re-enrolled. Refresh the page before choosing storage.
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
              refreshNote={refreshNote}
              refreshStatus={refreshStatus}
              disabled={busy}
            />
          ) : null}
          {kind === "sanitize" && eligibleTargets && !currentSelection ? (
            <div className="mt-3">
              <RecoveryReadinessView readiness={eligibleTargets.recoveryReadiness} />
            </div>
          ) : null}
          {!storage || currentSelection ? (
            <form
              className="grid gap-3"
              onSubmit={(event) => {
                event.preventDefault();
                void freeze();
              }}
            >
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
              {kind === "patchNow" ? (
                <>
                  <Label htmlFor={`${prefix}-patch-selection`}>Updates to install</Label>
                  <SelectField
                    id={`${prefix}-patch-selection`}
                    value={patchSelection}
                    disabled={busy}
                    onValueChange={(value) =>
                      setPatchSelection(
                        Number(value) === UpdateSelection.ALL
                          ? UpdateSelection.ALL
                          : UpdateSelection.SECURITY,
                      )
                    }
                    options={[
                      { value: UpdateSelection.SECURITY, label: "Security updates" },
                      { value: UpdateSelection.ALL, label: "All updates" },
                    ]}
                  />
                  <Label htmlFor={`${prefix}-patch-reboot`}>Reboot after updates</Label>
                  <SelectField
                    id={`${prefix}-patch-reboot`}
                    value={patchRebootMode}
                    disabled={busy}
                    onValueChange={(value) =>
                      setPatchRebootMode(
                        Number(value) === OSUpdateRebootMode.OS_UPDATE_REBOOT_MODE_SCHEDULED
                          ? OSUpdateRebootMode.OS_UPDATE_REBOOT_MODE_SCHEDULED
                          : OSUpdateRebootMode.OS_UPDATE_REBOOT_MODE_NEVER,
                      )
                    }
                    options={[
                      {
                        value: OSUpdateRebootMode.OS_UPDATE_REBOOT_MODE_NEVER,
                        label: "Never: only report that a reboot is required",
                      },
                      {
                        value: OSUpdateRebootMode.OS_UPDATE_REBOOT_MODE_SCHEDULED,
                        label: "Schedule a reboot when one is required",
                      },
                    ]}
                  />
                  {patchRebootMode === OSUpdateRebootMode.OS_UPDATE_REBOOT_MODE_SCHEDULED ? (
                    <>
                      <Label htmlFor={`${prefix}-patch-delay`}>
                        Reboot delay in minutes, 5 to 10080
                      </Label>
                      <Input
                        id={`${prefix}-patch-delay`}
                        inputMode="numeric"
                        value={patchRebootDelay}
                        onChange={(event) => setPatchRebootDelay(event.target.value)}
                      />
                      <Label htmlFor={`${prefix}-patch-notice`}>User notice (optional)</Label>
                      <Input
                        id={`${prefix}-patch-notice`}
                        maxLength={256}
                        value={patchRebootNotice}
                        onChange={(event) => setPatchRebootNotice(event.target.value)}
                      />
                    </>
                  ) : null}
                  <p className="text-sm text-muted-foreground">
                    This action only starts the device&apos;s native update run. Its result,
                    installed updates and any pending reboot appear in Patch status on this device.
                  </p>
                </>
              ) : null}
              {kind === "cryptoErase" ? (
                <>
                  <Label htmlFor={`${prefix}-erase-mode`}>Wipe mode</Label>
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
                        label: "Offline: one volume that isn't in use",
                      },
                      {
                        value: CryptoEraseMode.LIVE_ROOT_HEADER,
                        label: "While running: all encrypted volumes, then power off",
                      },
                    ]}
                  />
                </>
              ) : null}
              {liveErase ? (
                <div className="grid gap-3">
                  <Button type="button" variant="outline" disabled={busy} onClick={addLiveTarget}>
                    Add selected volume
                  </Button>
                  {liveTargets.map((entry) => (
                    <div key={entry.key} className="grid gap-2 rounded-md border p-3">
                      <p className="text-sm">
                        <code className="font-mono">{entry.selection.name}</code> ·{" "}
                        {entry.selection.model} · {entry.selection.encryption}
                      </p>
                      <StorageTargetView target={entry.selection.target} />
                      {!isStillObserved(entry) ? (
                        <p className="text-sm text-warning">
                          This volume is no longer reported by the device. Remove it and pick
                          another.
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
                        Remove volume
                      </Button>
                    </div>
                  ))}
                </div>
              ) : null}
              {kind === "escrowRotate" ? (
                <>
                  <Label htmlFor={`${prefix}-slot`}>Old key slot to remove (optional)</Label>
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
                  <legend>What to lock</legend>
                  <Label htmlFor={`${prefix}-termination`}>User sessions</Label>
                  <SelectField
                    id={`${prefix}-termination`}
                    value={terminateSessions ? "terminate" : "lock"}
                    onValueChange={(value) => setTerminateSessions(value === "terminate")}
                    options={[
                      { value: "lock", label: "Lock sessions" },
                      {
                        value: "terminate",
                        label: "Lock and sign out sessions",
                      },
                    ]}
                  />
                  <Label htmlFor={`${prefix}-accounts`}>Block local logins</Label>
                  <SelectField
                    id={`${prefix}-accounts`}
                    value={accountSelection}
                    onValueChange={setAccountSelection}
                    options={[
                      { value: "none", label: "None, lock sessions only" },
                      { value: "explicit", label: "Specific usernames" },
                      { value: "all", label: "All local user accounts" },
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
                    <p className="text-warning">Undo the current account lock first.</p>
                  ) : null}
                </fieldset>
              ) : null}
              {kind === "releaseLock" ? (
                <p className="text-sm">
                  {currentLockId
                    ? "Undoes the account lock currently on this device."
                    : "This device has no account lock to undo."}
                </p>
              ) : null}
              {kind === "quarantine" ? (
                <>
                  <Label htmlFor={`${prefix}-endpoints`}>
                    Management IPs to keep reachable (one per line)
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
                <QuarantineActionPicker
                  deviceId={deviceId}
                  label="Quarantine to undo"
                  value={quarantineId}
                  onChange={setQuarantineId}
                  disabled={busy || frozen}
                />
              ) : null}
              {kind === "sanitize" ? (
                <>
                  <Label htmlFor={`${prefix}-method`}>Method</Label>
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
                    <Label htmlFor={`${prefix}-nvme-scope`}>What to erase</Label>
                    <SelectField
                      id={`${prefix}-nvme-scope`}
                      value={nvmeControllerWide ? "controller" : "namespace"}
                      disabled={busy}
                      onValueChange={(value) => setNvmeControllerWide(value === "controller")}
                      options={[
                        { value: "namespace", label: "Selected namespace only" },
                        {
                          value: "controller",
                          label: "Entire controller: all namespaces",
                        },
                      ]}
                    />
                    {nvmeControllerWide ? (
                      <p className="text-sm text-warning">
                        Every namespace on this controller will be erased.
                      </p>
                    ) : null}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    NVMe details aren&apos;t available for this disk. Refresh inventory, then try
                    again.
                  </p>
                )
              ) : null}
              {kind === "sanitize" ? (
                <div className="grid gap-2">
                  <Label htmlFor={`${prefix}-sanitize-mode`}>Mode</Label>
                  <SelectField
                    id={`${prefix}-sanitize-mode`}
                    value={recoveryHandoff ? "recovery" : "offline"}
                    disabled={busy}
                    onValueChange={(value) => setRecoveryHandoff(value === "recovery")}
                    options={[
                      { value: "offline", label: "Device is already in recovery" },
                      { value: "recovery", label: "Boot into lindm recovery first" },
                    ]}
                  />
                  {recoveryHandoff ? (
                    <>
                      <Label htmlFor={`${prefix}-recovery-image`}>Recovery image SHA-256</Label>
                      <Input
                        id={`${prefix}-recovery-image`}
                        required
                        value={recoveryImageSha256}
                        onChange={(event) => setRecoveryImageSha256(event.target.value)}
                      />
                      <Label htmlFor={`${prefix}-recovery-boot`}>Boot method</Label>
                      <SelectField
                        id={`${prefix}-recovery-boot`}
                        value={recoveryBootMode}
                        disabled={busy}
                        onValueChange={(value) =>
                          setRecoveryBootMode(
                            Number(value) === RecoveryBootMode.KEXEC
                              ? RecoveryBootMode.KEXEC
                              : Number(value) === RecoveryBootMode.MEASURED_GRUB
                                ? RecoveryBootMode.MEASURED_GRUB
                                : RecoveryBootMode.UKI,
                          )
                        }
                        options={[
                          { value: RecoveryBootMode.UKI, label: "Signed UKI" },
                          { value: RecoveryBootMode.KEXEC, label: "Signed kexec" },
                          {
                            value: RecoveryBootMode.MEASURED_GRUB,
                            label: "Vendor kernel + TPM-attested initramfs (stock shim+GRUB)",
                          },
                        ]}
                      />
                      <RecoveryReadinessView readiness={eligibleTargets?.recoveryReadiness} />
                    </>
                  ) : null}
                </div>
              ) : null}
              <p className="text-sm">{actionSummaries[kind]}</p>
              {liveErase ? (
                <p className="text-sm text-warning">
                  Every selected volume is wiped and the device powers off within 2 minutes. Include
                  all encrypted volumes.
                </p>
              ) : null}
              <p className="text-sm text-muted-foreground">
                {destructive
                  ? "Another admin must approve before this runs."
                  : "You'll review the action before it's sent."}
              </p>
              {storage ? (
                <div className="grid gap-2">
                  <Label htmlFor={`${prefix}-confirm`}>
                    Type {detail.data?.device?.hostname ? "hostname " : ""}
                    <code className="font-mono">{confirmationName}</code> to confirm
                  </Label>
                  <Input
                    id={`${prefix}-confirm`}
                    required
                    value={confirmation}
                    onChange={(event) => setConfirmation(event.target.value)}
                  />
                </div>
              ) : null}
              <Label htmlFor={`${prefix}-reason`}>Reason</Label>
              <Textarea
                id={`${prefix}-reason`}
                required
                value={reason}
                onChange={(event) => setReason(event.target.value)}
              />
              {missing.length ? (
                <p id={`${prefix}-missing`} className="text-sm text-muted-foreground">
                  Missing before review: {missing.join("; ")}.
                </p>
              ) : null}
              <Button
                type="submit"
                className="w-fit"
                disabled={busy}
                aria-describedby={missing.length ? `${prefix}-missing` : undefined}
              >
                Review action
              </Button>
            </form>
          ) : missing.length ? (
            <p className="text-sm text-muted-foreground">
              Missing before review: {missing.join("; ")}.
            </p>
          ) : null}
        </>
      ) : (
        <div className="grid gap-3">
          {selectedKind && attempt.payload.spec?.action.case !== selectedKind ? (
            <p className="text-sm text-warning">
              Another action for this device is still waiting. Send or discard it first.
            </p>
          ) : null}
          <dl className="grid gap-2 text-sm">
            <dt className="text-muted-foreground">Expires</dt>
            <dd>{formatTimestamp(attempt.payload.expiresAt).local}</dd>
            <dt className="text-muted-foreground">Reason</dt>
            <dd>{attempt.payload.reason}</dd>
          </dl>
          <DeviceActionSpecView spec={attempt.payload.spec} />
          {needsRecovery ? (
            <RecoveryReadinessView readiness={eligibleTargets?.recoveryReadiness} />
          ) : null}
          <div className="flex items-center gap-2 text-sm">
            Status:
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
                  frozen: "Ready to send",
                  inflight: "Sending",
                  ambiguous: "Outcome unknown",
                  rejected: "Not accepted",
                  accepted: "Sent",
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
              View action
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
                ? "Not requested"
                : approvalLabels[attempt.approvalState]}
            </StatusBadge>{" "}
            <Link to="/approvals" className="underline">
              Open approvals
            </Link>
          </p>
          {attempt.approvalAmbiguous ? (
            <p className="text-warning">
              We couldn&apos;t confirm the approval request. Retry it before changing anything.
            </p>
          ) : null}
          {attempt.failure ? (
            <RpcError failure={attempt.failure}>
              {attempt.status === "ambiguous" ? (
                <p>Retry sending. Don&apos;t create a new action.</p>
              ) : null}
            </RpcError>
          ) : null}
          <TechnicalDetails
            items={[
              { label: "Request ID", value: attempt.payload.requestId },
              { label: "Device ID", value: attempt.payload.deviceId },
              {
                label: "Enrollment generation",
                value: String(attempt.payload.enrollmentGeneration),
              },
              { label: "Specification SHA-256", value: attempt.specSha256 },
              { label: "Approval ID", value: attempt.approvalId },
            ]}
          />
          {attempt.status !== "accepted" ? (
            <Alert
              variant={
                attempt.payload.spec?.action.case === "cryptoErase" ||
                attempt.payload.spec?.action.case === "sanitize"
                  ? "destructive"
                  : "default"
              }
            >
              <AlertTitle>Before you send</AlertTitle>
              <AlertDescription>
                {attempt.payload.spec?.action.case === "cryptoErase"
                  ? attempt.payload.spec.action.value.mode === CryptoEraseMode.LIVE_ROOT_HEADER
                    ? "This permanently wipes the volumes and powers off the device. Another admin must approve."
                    : "This permanently wipes the volume. Another admin must approve."
                  : attempt.payload.spec?.action.case === "sanitize"
                    ? attempt.payload.spec.action.value.nvmeScope?.controllerWide
                      ? "This permanently erases every namespace on the controller. Another admin must approve."
                      : "This permanently erases the disk. Another admin must approve."
                    : attempt.payload.spec?.action.case === "lockSessions" &&
                        attempt.payload.spec.action.value.terminateSessions
                      ? "Signing out sessions can lose unsaved work."
                      : attempt.payload.spec?.action.case === "restart" ||
                          attempt.payload.spec?.action.case === "shutdown"
                        ? "Users can lose unsaved work."
                        : attempt.payload.spec?.action.case === "patchNow"
                          ? "Updates can restart services and, with a reboot policy, the device."
                          : attempt.payload.spec?.action.case === "releaseLock"
                            ? "This re-enables the local accounts lindm locked on this device, so their users can sign in again."
                            : attempt.payload.spec?.action.case === "releaseQuarantine"
                              ? "This removes the network quarantine on this device."
                              : "Check the details above before sending."}
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
              {attempt.status === "ambiguous" ? "Retry sending" : "Send action"}
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
                ? "Refresh approval status"
                : attempt.approvalAmbiguous
                  ? "Retry approval request"
                  : "Request approval"}
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
                  Ask {detail.data?.device?.hostname.trim() || "Unnamed device"} to send a fresh
                  inventory.
                </DialogDescription>
              </DialogHeader>
              <DeviceActionForm
                deviceId={deviceId}
                mode="actions"
                kind="refreshInventory"
                onCreated={(actionId) => {
                  setRefreshOpen(false);
                  // Followed here from now on; the next request starts a new form.
                  setDeviceActionAttempt(lifetime, `${deviceId}:refreshInventory`, null);
                  setRefreshActionId(actionId);
                }}
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
            Retry
          </Button>
        </RpcError>
      ) : null}
      {(kind === "releaseLock" || kind === "lockSessions") && actions.error ? (
        <RpcError failure={toRpcFailure(actions.error)} />
      ) : null}
    </div>
  );
}
