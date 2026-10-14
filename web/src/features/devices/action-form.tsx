// SPDX-License-Identifier: Apache-2.0

import { create, equals, getOption, toBinary, type DescField } from "@bufbuild/protobuf";
import { timestampDate, timestampFromDate } from "@bufbuild/protobuf/wkt";
import { field as validationRules } from "@bufbuild/protovalidate/gen/buf/validate/validate_pb.js";
import { Code } from "@connectrpc/connect";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useEffectEvent, useRef, useState } from "react";
import { toast } from "sonner";
import {
  CreateDeviceActionRequestSchema,
  DeviceActionKind as ListedActionKind,
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
import { X } from "lucide-react";
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
import {
  SearchPicker,
  pickerFooter,
  type PickerOption,
  type PickerProps,
} from "@/components/ui/search-picker";
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
import { formatTimestamp, freshnessLabel } from "@/lib/time";
import {
  setDeviceActionAttempt,
  updateDeviceActionAttempt,
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
import { ObservedClock } from "./observations";
import {
  formErrorMessage,
  requestProblem,
  validateRequest,
  type FieldError,
} from "@/lib/validation";
import { LocalUserPicker } from "./local-users";
import {
  ObservedStorageTargetPicker,
  observedStorageSelections,
  type ObservedStorageSelection,
} from "./storage-target-picker";
import { formatBytes } from "@/lib/bytes";

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
  [ApprovalState.WITHDRAWN]: "Withdrawn",
};

// Power delays are bounded by the protos (logind schedules at most an hour ahead);
// the form states the same range rather than restating a number of its own.
function powerDelayMax(field: DescField): number {
  const rule = getOption(field, validationRules).type;
  if (rule.case !== "uint32" || rule.value.lessThan.case !== "lte")
    throw new Error("Missing bounded power delay constraint");
  return rule.value.lessThan.value;
}
const restartDelayMax = powerDelayMax(RestartActionSchema.field.delaySeconds);
const shutdownDelayMax = powerDelayMax(ShutdownActionSchema.field.delaySeconds);
const ENDPOINT_HINT = "Enter one IP address per line, such as 192.0.2.10 or 2001:db8::10.";
// Server refusals that fresh inventory repairs.
const inventoryBlockers: Record<string, true> = {
  device_action_inventory_stale: true,
  device_action_inventory_unavailable: true,
};

const actionSummaries: Record<DeviceActionKind, string> = {
  escrowRotate: "Create a new recovery key for this encrypted volume. Store the key on the server.",
  tpm2Bind: "Unlock this encrypted volume automatically with the device's TPM.",
  lockSessions: "Lock user sessions. Select whether to block local sign-in.",
  releaseLock: "Restore accounts locked by lindm. Screen locks stay in place.",
  quarantine: "Cut network access except for the management IPs you allow.",
  releaseQuarantine: "Remove the network restrictions added by quarantine.",
  cryptoErase: "Destroy the encryption keys on this volume. The server keeps recovery keys.",
  sanitize: "Permanently wipe this unencrypted disk.",
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

const QUARANTINES = [ListedActionKind.QUARANTINE];

// The server lists only this device's quarantines, newest first, so an older one
// is a More choices away rather than hidden behind other actions. Each choice
// names what stayed reachable and who asked when.
function QuarantineActionPicker({ deviceId, ...props }: PickerProps & { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const query = useQuery(deviceActionsQueryOptions(lifetime, deviceId, pageToken, QUARANTINES));
  const options: PickerOption[] = query.error
    ? []
    : (query.data?.actions.flatMap((action) =>
        action.spec?.action.case === "quarantine"
          ? [
              {
                value: action.actionId,
                label: `Network cut off except ${action.spec.action.value.managementEndpoints.join(", ")}`,
                description: [
                  `Requested ${formatTimestamp(action.createdAt).local}`,
                  action.actorDisplayName ? `by ${action.actorDisplayName}` : "",
                  `expires ${formatTimestamp(action.expiresAt).local}`,
                ]
                  .filter(Boolean)
                  .join(" "),
              },
            ]
          : [],
      ) ?? []);
  const nextPageToken = query.data?.nextPageToken ?? "";
  return (
    <SearchPicker
      {...props}
      options={options}
      note="Quarantines on this device, newest first, 25 at a time."
      footer={pickerFooter({
        loading: query.isPending,
        error: query.error,
        onRetry: () => void query.refetch(),
        empty:
          query.isSuccess && options.length === 0
            ? "No administrator has requested network quarantine on this device."
            : undefined,
        fetching: query.isFetching,
        onFirst: pageToken ? () => setPageToken("") : undefined,
        onMore: nextPageToken ? () => setPageToken(nextPageToken) : undefined,
      })}
    />
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
  const [pcrs, setPcrs] = useState<number[]>([]);
  const [endpoints, setEndpoints] = useState("");
  const [quarantineId, setQuarantineId] = useState("");
  const [lockId, setLockId] = useState("");
  const [terminateSessions, setTerminateSessions] = useState(false);
  const [accountSelection, setAccountSelection] = useState("none");
  const [usernames, setUsernames] = useState<string[]>([]);
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
  const [fieldErrors, setFieldErrors] = useState<readonly FieldError[]>([]);
  const [refreshFailure, setRefreshFailure] = useState<RpcFailure | null>(null);
  const [sendWhenReady, setSendWhenReady] = useState(false);
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
  // A refresh requested from this form: follow it, then reload storage and rerun
  // the review's server checks as soon as the device reports success.
  const refreshAction = useQuery({
    ...deviceActionQueryOptions(lifetime, deviceId, refreshActionId),
    enabled: refreshActionId !== "",
    refetchInterval: (query) =>
      query.state.status !== "error" &&
      refreshOutcome(query.state.data, query.state.dataUpdatedAt) === "waiting"
        ? 3_000
        : false,
  });
  const refreshResult = !refreshActionId
    ? undefined
    : refreshAction.error
      ? "error"
      : refreshOutcome(refreshAction.data, refreshAction.dataUpdatedAt);
  const refreshSucceeded = refreshResult === "succeeded";
  const recheckAfterRefresh = useEffectEvent(async () => {
    if (attempt?.status !== "frozen" && attempt?.status !== "rejected") return;
    const checked = await checkPreflight(attempt);
    // "Refresh inventory and send when ready": the same reviewed (and, when
    // required, approved) request goes out only once the server's checks pass.
    if (
      sendWhenReady &&
      checked?.status === "frozen" &&
      checked.preflight.state === "checked" &&
      !checked.preflight.result.blockedReason
    ) {
      setSendWhenReady(false);
      void send(checked);
    }
  });
  useEffect(() => {
    if (!refreshSucceeded) return;
    void queryClient.invalidateQueries({
      queryKey: ["device-storage-targets", lifetime.generation, deviceId],
    });
    void recheckAfterRefresh();
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
  // The mode follows the target: a volume in use can only be wiped while the
  // device runs, so offline mode is never offered for it.
  const effectiveEraseMode = currentSelection?.inUse ? CryptoEraseMode.LIVE_ROOT_HEADER : eraseMode;
  const liveErase =
    kind === "cryptoErase" && effectiveEraseMode === CryptoEraseMode.LIVE_ROOT_HEADER;
  // A wipe or disk erase always needs another admin's approval (server policy),
  // so requesting it is the next step until it is granted.
  const approvalFirst =
    (frozenSpec?.case === "cryptoErase" || frozenSpec?.case === "sanitize") &&
    attempt?.approvalState !== ApprovalState.APPROVED &&
    attempt?.status !== "ambiguous" &&
    attempt?.status !== "accepted";
  // The frozen targets by device path and size, matched against reported storage.
  const reviewVolumes = (
    frozenSpec?.case === "cryptoErase"
      ? frozenSpec.value.mode === CryptoEraseMode.LIVE_ROOT_HEADER
        ? frozenSpec.value.targets
        : frozenSpec.value.target
          ? [frozenSpec.value.target]
          : []
      : frozenSpec?.case === "sanitize" && frozenSpec.value.target
        ? [frozenSpec.value.target]
        : []
  ).map((target, index) => {
    const name = eligibleTargets?.targets.find(
      (entry) => entry.target && equals(StorageTargetSchema, entry.target, target),
    )?.name;
    return { key: index, path: name ? `/dev/${name}` : "", sizeBytes: target.sizeBytes };
  });

  const power = kind === "restart" || kind === "shutdown";
  const delayMax = kind === "shutdown" ? shutdownDelayMax : restartDelayMax;
  const delayText = powerDelay.trim();
  const delayError = !power
    ? ""
    : delayText !== "" && !(/^\d+$/.test(delayText) && Number(delayText) <= delayMax)
      ? `Enter a whole number of seconds from 0 to ${delayMax}.`
      : (fieldErrors.find((entry) => entry.field === "delay_seconds")?.message ?? "");
  // The schema names the refused entry by position; show the value the admin typed.
  const endpointList = endpoints.split(/[\s,]+/).filter(Boolean);
  const badEndpoints = fieldErrors.flatMap((entry) => {
    const index = /^spec\.quarantine\.management_endpoints\[(\d+)\]$/.exec(entry.path)?.[1];
    return index === undefined ? [] : [endpointList[Number(index)] ?? ""];
  });
  const endpointError =
    kind !== "quarantine"
      ? ""
      : badEndpoints.length > 0
        ? `Not an IP address: ${badEndpoints.join(", ")}. ${ENDPOINT_HINT}`
        : (fieldErrors.find((entry) => entry.field === "management_endpoints")?.message ?? "");

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
          delayError ? `a delay from 0 to ${delayMax} seconds` : "",
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
        throw new Error("A listed volume is no longer available. Refresh inventory. Try again.");
      if (
        liveErase &&
        new Set(liveTargets.map((entry) => entry.selection.target.luksUuid)).size !==
          liveTargets.length
      )
        throw new Error("Select each volume only once.");
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
              pcrs: [...pcrs].sort((a, b) => a - b),
            }),
          };
          break;
        case "lockSessions":
          if (accountSelection === "explicit" && usernames.length === 0)
            throw new Error("Choose at least one local account.");
          spec.action = {
            case: kind,
            value: create(LockSessionsActionSchema, {
              terminateSessions,
              allHumanAccounts: accountSelection === "all",
              usernames: accountSelection === "explicit" ? usernames : [],
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
              mode: effectiveEraseMode,
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
                "This disk's NVMe details are incomplete. Refresh inventory. Try again.",
              );
            validateRequest(NVMeSanitizeScopeSchema, nvmeScope);
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
      validateRequest(CreateDeviceActionRequestSchema, payload, {
        "spec.quarantine.management_endpoints": ENDPOINT_HINT,
      });
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
      const next: DeviceActionAttempt = {
        payload,
        specSha256,
        status: "frozen",
        failure: null,
        approvalId: "",
        approvalAmbiguous: false,
        preflight: { state: "checking" },
      };
      if (setDeviceActionAttempt(lifetime, attemptKey, next)) void checkPreflight(next);
    } catch (error) {
      if (!lifetime.signal.aborted) {
        setFieldErrors(requestProblem(error)?.fields ?? []);
        setError(formErrorMessage(error, "Check the action details."));
      }
    } finally {
      inFlight.current = false;
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  // Runs the server's create-time checks for the reviewed request, so a refusal
  // such as stale inventory appears with its remedy before Send, not after.
  async function checkPreflight(captured: DeviceActionAttempt) {
    const { payload } = captured;
    updateDeviceActionAttempt(lifetime, attemptKey, payload, (current) => ({
      ...current,
      preflight: { state: "checking" },
    }));
    try {
      const result = await adminClient.preflightDeviceAction(
        {
          deviceId: payload.deviceId,
          enrollmentGeneration: payload.enrollmentGeneration,
          spec: payload.spec,
        },
        { signal: lifetime.signal, timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      return updateDeviceActionAttempt(lifetime, attemptKey, payload, (current) =>
        // A server-precondition refusal the checks now pass can be sent again
        // with the same request ID; any other refusal still needs Edit action.
        current.status === "rejected" &&
        current.failure?.code === Code.FailedPrecondition &&
        !result.blockedReason
          ? { ...current, status: "frozen", failure: null, preflight: { state: "checked", result } }
          : { ...current, preflight: { state: "checked", result } },
      );
    } catch (error) {
      if (lifetime.signal.aborted) return null;
      return updateDeviceActionAttempt(lifetime, attemptKey, payload, (current) => ({
        ...current,
        preflight: { state: "failed", failure: toRpcFailure(error) },
      }));
    }
  }

  // Asks the device for fresh inventory under the reviewed action's reason; the
  // review's checks run again when the device reports it.
  async function requestInventory(captured: DeviceActionAttempt) {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setRefreshFailure(null);
    try {
      const response = await adminClient.createDeviceAction(
        create(CreateDeviceActionRequestSchema, {
          requestId: newRequestId(),
          deviceId,
          enrollmentGeneration: captured.payload.enrollmentGeneration,
          spec: create(DeviceActionSpecSchema, {
            action: { case: "refreshInventory", value: create(RefreshInventoryActionSchema) },
          }),
          expiresAt: timestampFromDate(new Date(Date.now() + 10 * 60_000)),
          reason: captured.payload.reason,
        }),
        { signal: lifetime.signal, timeoutMs: 30_000 },
      );
      lifetime.signal.throwIfAborted();
      if (!response.action?.actionId) throw new Error("The server didn't confirm the request.");
      setRefreshActionId(response.action.actionId);
      void queryClient.invalidateQueries({
        queryKey: ["device-actions", lifetime.generation, deviceId],
      });
    } catch (error) {
      if (!lifetime.signal.aborted) {
        setRefreshFailure(toRpcFailure(error));
        setSendWhenReady(false);
      }
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
      const refused: DeviceActionAttempt = {
        ...next,
        status: failure.ambiguous ? "ambiguous" : "rejected",
        failure,
      };
      setDeviceActionAttempt(lifetime, attemptKey, refused);
      if (!lifetime.signal.aborted) {
        const feedback = classifyRpcFailure(failure);
        toast[feedback.tone === "destructive" ? "error" : "warning"](feedback.title);
        // Refresh the review's evidence (check-in and inventory times) for the refusal.
        if (failure.code === Code.FailedPrecondition) void checkPreflight(refused);
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
    // An approver should decide only a request the device can take now; a
    // refusal (such as stale inventory) is shown with its fix instead.
    if (!attempt.approvalId) {
      const checked = await checkPreflight(attempt);
      if (
        !checked ||
        checked.preflight.state !== "checked" ||
        checked.preflight.result.blockedReason
      )
        return;
    }
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
      // An approval-required refusal is resolved by this request; others stand.
      const approvalRefusal =
        attempt.status === "rejected" &&
        attempt.failure?.code === Code.PermissionDenied &&
        (attempt.failure.reason === "approval_required" ||
          attempt.failure.reason === "human_approval_required");
      setDeviceActionAttempt(lifetime, attemptKey, {
        ...attempt,
        ...(approvalRefusal ? { status: "frozen", failure: null } : {}),
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
        {deviceName} did not start the refresh before expiry. Check that the device is online.
        Request inventory again. {refreshLink}
      </p>
    ) : refreshResult === "unknown" ? (
      <p className="text-sm text-warning">
        The outcome of the last refresh is unknown. Check the request before asking again.{" "}
        {refreshLink}
      </p>
    ) : undefined;

  // The server's current refusal of the reviewed request: from its review-time
  // check, or from Send when the device changed in between.
  const preflight = attempt?.preflight;
  const checked = preflight?.state === "checked" ? preflight.result : undefined;
  const refusalReason =
    attempt?.status === "rejected" && attempt.failure?.code === Code.FailedPrecondition
      ? attempt.failure.reason
      : attempt?.status === "frozen"
        ? (checked?.blockedReason ?? "")
        : "";
  const blocker = refusalReason
    ? classifyRpcFailure({
        code: Code.FailedPrecondition,
        codeName: "FailedPrecondition",
        message: refusalReason,
        reason: refusalReason,
        unauthenticated: false,
        denied: false,
        ambiguous: false,
      })
    : undefined;
  const checkedAt = checked?.checkedAt ? timestampDate(checked.checkedAt) : new Date();
  const lastContact = checked?.lastSeenAt
    ? freshnessLabel(timestampDate(checked.lastSeenAt), checkedAt)
    : undefined;
  const inventoryAge = checked?.inventoryReceivedAt
    ? freshnessLabel(timestampDate(checked.inventoryReceivedAt), checkedAt)
    : undefined;
  const inventoryWindow = checked?.inventoryMaxAgeSeconds
    ? `${Math.round(checked.inventoryMaxAgeSeconds / 60)} minutes`
    : "";
  // Why the refusal happened, in the device's own times: a check-in is not an
  // inventory report, so a device can be online with inventory too old to use.
  const blockerEvidence =
    refusalReason === "device_action_inventory_stale" && inventoryAge && inventoryWindow
      ? `${deviceName} ${lastContact ? `last checked in ${lastContact}. Its` : "'s"} latest inventory arrived ${inventoryAge}. This action needs inventory from the last ${inventoryWindow}. Check-ins do not include inventory.`
      : refusalReason === "device_action_offline" && lastContact
        ? `${deviceName} last checked in ${lastContact}.`
        : "";
  // The open action the server named; a new action waits until it ends.
  const blockingAction =
    refusalReason === "device_action_pending"
      ? attempt?.status === "rejected"
        ? attempt.failure?.blockingAction
        : checked?.blockingAction
      : undefined;
  const blockingKind = blockingAction?.spec?.action.case;
  const pendingEvidence = blockingAction ? (
    <span data-blocking-action={blockingAction.actionId}>
      Another action is still running on this device (
      {blockingKind ? actionLabels[blockingKind] : "an action"}, sent{" "}
      <ObservedClock value={blockingAction.createdAt} />
      ). Wait for it to finish or let it expire
      {blockingAction.status ? (
        ""
      ) : (
        <>
          {" "}
          at <ObservedClock value={blockingAction.expiresAt} />
        </>
      )}
      .{" "}
      <Link
        to="/devices/$deviceId/actions/$actionId"
        params={{ deviceId, actionId: blockingAction.actionId }}
        className="underline"
      >
        View action
      </Link>
    </span>
  ) : null;
  const canRefreshInventory =
    canPermission(principal, actionPermissions.refreshInventory) &&
    canPermission(principal, "fleet.read");
  // Only a request that needs no further approval can go out on its own once
  // fresh inventory passes the checks.
  const reviewedCase = attempt?.payload.spec?.action.case;
  const sendableAfterRefresh =
    (reviewedCase !== "cryptoErase" && reviewedCase !== "sanitize") ||
    attempt?.approvalState === ApprovalState.APPROVED;
  const blockedControls = attempt?.approvalId ? "Send is" : "Send and approval requests are";
  const sendBlockedReason = !attempt
    ? ""
    : attempt.status === "rejected"
      ? blocker
        ? `${blockedControls} unavailable. Resolve this problem: ${blocker.title.toLowerCase()}.`
        : `Send is off after this refusal. ${attempt.failure ? classifyRpcFailure(attempt.failure).action : "Edit the action to start a new request."}`
      : attempt.status !== "frozen"
        ? ""
        : preflight?.state === "checking"
          ? "Send is available once the server's checks finish."
          : preflight?.state === "failed"
            ? "Send is available once the server's checks run. Check again."
            : blocker
              ? `${blockedControls} unavailable. Resolve this problem: ${blocker.title.toLowerCase()}.`
              : "";
  // A refusal at Send stays on screen while its evidence is re-checked; only a
  // first review check shows the bare progress line.
  const rechecking = preflight?.state === "checking";
  const reviewCheck = !attempt ? null : rechecking &&
    !(attempt.status === "rejected" && blocker) ? (
    <p role="status" className="text-sm text-muted-foreground">
      Checking whether {deviceName} can take this action now…
    </p>
  ) : preflight?.state === "failed" && attempt.status === "frozen" ? (
    <RpcError failure={preflight.failure} title="Couldn't check this action">
      <Button
        type="button"
        variant="outline"
        disabled={busy}
        onClick={() => void checkPreflight(attempt)}
      >
        Check again
      </Button>
    </RpcError>
  ) : blocker ? (
    <Alert
      data-slot="action-blocker"
      className={blocker.tone === "warning" ? "border-warning/25 bg-warning/10" : undefined}
    >
      <AlertTitle>{blocker.title}</AlertTitle>
      <AlertDescription className="grid gap-2">
        <p>{pendingEvidence ?? (blockerEvidence || blocker.message)}</p>
        {inventoryBlockers[refusalReason] && canRefreshInventory ? (
          refreshResult === "waiting" ? (
            <p role="status">
              Inventory requested. Waiting for {deviceName} to report it; this action is{" "}
              {sendWhenReady
                ? "sent once the server's checks pass"
                : "checked again when it arrives"}
              . {refreshLink}
            </p>
          ) : (
            <>
              {refreshResult === "error" ? (
                <RpcError
                  failure={toRpcFailure(refreshAction.error)}
                  title="Couldn't check the refresh"
                />
              ) : (
                refreshNote
              )}
              {refreshFailure ? (
                <RpcError failure={refreshFailure} title="Couldn't request inventory" />
              ) : null}
              {refreshResult === "unknown" || refreshFailure?.ambiguous ? null : (
                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    type="button"
                    disabled={busy}
                    onClick={() => {
                      setSendWhenReady(sendableAfterRefresh);
                      void requestInventory(attempt);
                    }}
                  >
                    {sendableAfterRefresh
                      ? "Refresh inventory and send when ready"
                      : "Refresh inventory"}
                  </Button>
                  <span className="text-muted-foreground">
                    {sendableAfterRefresh
                      ? "Uses the reason above. The console sends this exact request after fresh inventory passes server checks. Failed checks prevent sending."
                      : "Uses the reason above. The server checks this action again when inventory arrives."}
                  </span>
                </div>
              )}
            </>
          )
        ) : // A named blocking action already says what to do.
        pendingEvidence ? null : (
          <p>{blocker.action}</p>
        )}
        {rechecking ? (
          <p role="status" className="text-muted-foreground">
            Checking again whether {deviceName} can take this action now…
          </p>
        ) : null}
        <Button
          type="button"
          variant="outline"
          className="w-fit"
          disabled={busy || rechecking}
          onClick={() => void checkPreflight(attempt)}
        >
          Check again
        </Button>
      </AlertDescription>
    </Alert>
  ) : checked && attempt.status === "frozen" ? (
    <p role="status" className="text-sm text-muted-foreground">
      Server checks passed {freshnessLabel(checkedAt, new Date())}
      {inventoryAge && inventoryWindow ? `; inventory received ${inventoryAge}` : ""}. The device
      confirms when it runs the action.
    </p>
  ) : null;

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
              This device enrolled again. Refresh the page before choosing storage.
            </p>
          ) : null}
          {storage && eligibleTargets ? (
            <ObservedStorageTargetPicker
              targets={eligibleTargets}
              kind={kind}
              selectedKey={selectedTarget?.key ?? ""}
              onSelect={(key, selection) => {
                setSelectedTarget({ key, selection });
                if (
                  kind === "cryptoErase" &&
                  selection.inUse &&
                  !liveTargets.some(
                    (entry) => entry.selection.target.luksUuid === selection.target.luksUuid,
                  )
                )
                  setLiveTargets([...liveTargets, { key, selection }]);
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
          {kind === "cryptoErase" &&
          eligibleTargets &&
          eligibleTargets.ephemeralMappings.length > 0 ? (
            <p className="text-sm text-muted-foreground">
              The wipe excludes {eligibleTargets.ephemeralMappings.join(", ")}. Power-off destroys
              these temporary swap keys.
            </p>
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
                    data-freeform="power delay in seconds, checked against its proto range"
                    inputMode="numeric"
                    value={powerDelay}
                    aria-invalid={delayError ? true : undefined}
                    aria-describedby={`${prefix}-power-delay-range${delayError ? ` ${prefix}-power-delay-error` : ""}`}
                    onChange={(event) => {
                      setPowerDelay(event.target.value);
                      setFieldErrors([]);
                    }}
                  />
                  <p id={`${prefix}-power-delay-range`} className="text-sm text-muted-foreground">
                    0 to {delayMax} seconds. Leave empty to{" "}
                    {kind === "shutdown" ? "shut down" : "restart"} now.
                  </p>
                  {delayError ? (
                    <p id={`${prefix}-power-delay-error`} className="text-sm text-destructive">
                      {delayError}
                    </p>
                  ) : null}
                  <Label htmlFor={`${prefix}-power-message`}>User notification (optional)</Label>
                  <Input
                    id={`${prefix}-power-message`}
                    value={powerMessage}
                    onChange={(event) => setPowerMessage(event.target.value)}
                    data-freeform="message shown to the device's signed-in user"
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
                        label: "Never: report when the device needs a restart",
                      },
                      {
                        value: OSUpdateRebootMode.OS_UPDATE_REBOOT_MODE_SCHEDULED,
                        label: "Schedule a restart when the device needs one",
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
                        data-freeform="reboot delay in minutes"
                      />
                      <Label htmlFor={`${prefix}-patch-notice`}>User notice (optional)</Label>
                      <Input
                        id={`${prefix}-patch-notice`}
                        maxLength={256}
                        value={patchRebootNotice}
                        onChange={(event) => setPatchRebootNotice(event.target.value)}
                        data-freeform="message shown to the device's signed-in user"
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
                    value={effectiveEraseMode}
                    disabled={busy}
                    aria-describedby={
                      currentSelection?.inUse ? `${prefix}-erase-mode-help` : undefined
                    }
                    onValueChange={(value) =>
                      setEraseMode(
                        Number(value) === CryptoEraseMode.LIVE_ROOT_HEADER
                          ? CryptoEraseMode.LIVE_ROOT_HEADER
                          : CryptoEraseMode.OFFLINE,
                      )
                    }
                    options={[
                      ...(currentSelection?.inUse
                        ? []
                        : [
                            {
                              value: CryptoEraseMode.OFFLINE,
                              label: "Offline: one volume that isn't in use",
                            },
                          ]),
                      {
                        value: CryptoEraseMode.LIVE_ROOT_HEADER,
                        label: "While running: all encrypted volumes, then power off",
                      },
                    ]}
                  />
                  {currentSelection?.inUse ? (
                    <p id={`${prefix}-erase-mode-help`} className="text-sm text-muted-foreground">
                      This volume is in use. The device must remain running for this wipe.
                    </p>
                  ) : null}
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
                          The device no longer reports this volume. Remove the volume. Select
                          another volume.
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
                  <Label htmlFor={`${prefix}-slot`}>Old recovery key to remove</Label>
                  <SelectField
                    id={`${prefix}-slot`}
                    value={retireSlot}
                    disabled={busy}
                    onValueChange={setRetireSlot}
                    options={[
                      { value: "", label: "Keep every existing key" },
                      ...(encryption.data?.observation?.lindmKeyslots ?? []).map((slot) => ({
                        value: String(slot),
                        label:
                          encryption.data?.escrow?.keyslot === slot
                            ? `Key slot ${slot}: the recovery key stored on the server now`
                            : `Key slot ${slot}: an earlier lindm recovery key`,
                      })),
                    ]}
                  />
                  {encryption.data && !encryption.data.observation?.lindmKeyslots.length ? (
                    <p className="text-sm text-muted-foreground">
                      The device reported no lindm recovery keys on this volume, so none can be
                      removed.
                    </p>
                  ) : null}
                </>
              ) : null}
              {kind === "tpm2Bind" ? (
                <>
                  <fieldset className="grid gap-2" disabled={busy}>
                    <legend className="text-sm font-medium">TPM measurements to bind (PCRs)</legend>
                    <p className="text-sm text-muted-foreground">
                      The volume unlocks only while every chosen measurement is unchanged. PCR 7
                      (Secure Boot state) is the usual choice.
                    </p>
                    <div className="grid grid-cols-6 gap-2 sm:grid-cols-8">
                      {Array.from({ length: 24 }, (_, pcr) => (
                        <label key={pcr} className="flex items-center gap-1.5 text-sm">
                          <input
                            type="checkbox"
                            className="accent-primary"
                            checked={pcrs.includes(pcr)}
                            onChange={(event) =>
                              setPcrs(
                                event.target.checked
                                  ? [...pcrs, pcr]
                                  : pcrs.filter((value) => value !== pcr),
                              )
                            }
                          />
                          {pcr}
                        </label>
                      ))}
                    </div>
                  </fieldset>
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
                  <Label htmlFor={`${prefix}-accounts`}>Block local sign-in</Label>
                  <SelectField
                    id={`${prefix}-accounts`}
                    value={accountSelection}
                    onValueChange={setAccountSelection}
                    options={[
                      { value: "none", label: "None, lock sessions only" },
                      { value: "explicit", label: "Specific local accounts" },
                      { value: "all", label: "All local user accounts" },
                    ]}
                  />
                  {accountSelection === "explicit" ? (
                    <>
                      <LocalUserPicker
                        deviceId={deviceId}
                        label="Add a local account"
                        placeholder="Choose an account"
                        value=""
                        disabled={busy}
                        ineligible={(user) =>
                          user.uid === 0n ? "Cannot block root sign-in" : undefined
                        }
                        onChange={(name) => {
                          if (name && !usernames.includes(name)) setUsernames([...usernames, name]);
                        }}
                      />
                      {usernames.length ? (
                        <ul className="flex flex-wrap gap-2" aria-label="Accounts to block">
                          {usernames.map((name) => (
                            <li key={name}>
                              <Button
                                type="button"
                                variant="outline"
                                size="sm"
                                className="h-7 rounded-full bg-muted/40 px-2.5 text-xs"
                                aria-label={`Remove ${name}`}
                                onClick={() =>
                                  setUsernames(usernames.filter((value) => value !== name))
                                }
                              >
                                {name}
                                <X className="size-3 shrink-0" aria-hidden="true" />
                              </Button>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-sm text-muted-foreground">No accounts chosen yet.</p>
                      )}
                    </>
                  ) : null}
                  {currentLockId ? (
                    <p className="text-sm text-warning">
                      An account lock is already active.{" "}
                      <Link
                        to="/devices/$deviceId/actions/$actionId"
                        params={{ deviceId, actionId: currentLockId }}
                        className="underline underline-offset-4"
                      >
                        Review the current lock
                      </Link>
                      . Do not undo it while the device is lost.
                    </p>
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
                    aria-invalid={endpointError !== "" || undefined}
                    aria-describedby={
                      endpointError !== "" ? `${prefix}-endpoints-error` : undefined
                    }
                    onChange={(event) => setEndpoints(event.target.value)}
                    data-freeform="management IP addresses that stay reachable"
                  />
                  {endpointError !== "" ? (
                    <p id={`${prefix}-endpoints-error`} className="text-sm text-destructive">
                      {endpointError}
                    </p>
                  ) : null}
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
                    <Label htmlFor={`${prefix}-nvme-scope`}>What to wipe</Label>
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
                        The wipe removes data from every namespace on this controller.
                      </p>
                    ) : null}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    The device has not reported NVMe details for this disk. Refresh inventory. Try
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
                        data-freeform="pasted SHA-256 digest of the recovery image"
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
                  The action wipes every selected volume. The device powers off within 2 minutes.
                  Include all encrypted volumes.
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
                    data-freeform="typed confirmation of the device name"
                  />
                </div>
              ) : null}
              <Label htmlFor={`${prefix}-reason`}>Reason</Label>
              <Textarea
                id={`${prefix}-reason`}
                required
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                data-freeform="audit reason for this action"
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
          {reviewVolumes.length ? (
            <div data-slot="review-targets" className="grid gap-1 text-sm break-words">
              <p>
                Device: <span className="font-medium">{confirmationName}</span>
              </p>
              <ul className="grid gap-1">
                {reviewVolumes.map((volume) => (
                  <li key={volume.key}>
                    {volume.path ? (
                      <code className="font-mono">{volume.path}</code>
                    ) : (
                      "Device path not reported"
                    )}{" "}
                    · {formatBytes(volume.sizeBytes)}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
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
                    : attempt.status === "frozen" && sendBlockedReason
                      ? blocker
                        ? blocker.tone
                        : "neutral"
                      : "info"
              }
            >
              {attempt.status === "frozen"
                ? preflight?.state === "checking"
                  ? "Checking"
                  : blocker
                    ? "Not ready to send"
                    : preflight?.state === "failed"
                      ? "Not checked"
                      : "Ready to send"
                : {
                    inflight: "Sending",
                    ambiguous: "Outcome unknown",
                    rejected: "Not accepted",
                    accepted: "Sent",
                  }[attempt.status]}
            </StatusBadge>
          </div>
          {reviewCheck}
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
          {attempt.failure && !(attempt.status === "rejected" && blocker) ? (
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
                      ? "This permanently wipes every namespace on the controller. Another admin must approve."
                      : "This permanently wipes the disk. Another admin must approve."
                    : attempt.payload.spec?.action.case === "lockSessions"
                      ? `${attempt.payload.spec.action.value.terminateSessions ? "Signing out sessions can lose unsaved work. " : ""}The device must be in recent contact. This does not erase data or isolate the network. Undo account lock restores the accounts lindm disabled; users must unlock their screens.`
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
          {sendBlockedReason ? (
            <p id={`${prefix}-send-blocked`} className="text-sm text-muted-foreground">
              {sendBlockedReason}
            </p>
          ) : null}
          <div className="flex flex-wrap gap-2">
            {approvalFirst ? null : (
              <Button
                disabled={
                  busy ||
                  (needsRecovery && !recoveryReady && attempt.status !== "ambiguous") ||
                  attempt.status === "accepted" ||
                  attempt.status === "inflight" ||
                  attempt.approvalAmbiguous ||
                  !!sendBlockedReason
                }
                aria-describedby={sendBlockedReason ? `${prefix}-send-blocked` : undefined}
                onClick={() => void send(attempt)}
              >
                {attempt.status === "ambiguous" ? "Retry sending" : "Send action"}
              </Button>
            )}
            <Button
              variant={approvalFirst ? "default" : "outline"}
              disabled={
                busy ||
                (needsRecovery &&
                  !recoveryReady &&
                  !attempt.approvalId &&
                  !attempt.approvalAmbiguous) ||
                attempt.status === "ambiguous" ||
                attempt.status === "inflight" ||
                attempt.status === "accepted" ||
                (!attempt.approvalId && !!blocker)
              }
              aria-describedby={
                !attempt.approvalId && blocker ? `${prefix}-send-blocked` : undefined
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
                setRefreshFailure(null);
                setSendWhenReady(false);
              }}
            >
              Edit action
            </Button>
          </div>
          {approvalFirst ? (
            <p className="text-sm text-muted-foreground">
              You can send this action after another admin approves it.
            </p>
          ) : null}
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
