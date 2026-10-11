import { create } from "@bufbuild/protobuf";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState, type FormEvent } from "react";
import { toast } from "sonner";
import {
  LocalAdminPasswordState,
  RemoveLocalAdminPasswordPolicyRequestSchema,
  RequestLocalAdminPasswordRotationRequestSchema,
  SetLocalAdminPasswordPolicyRequestSchema,
  type LocalAdminPasswordPolicy,
  type RemoveLocalAdminPasswordPolicyRequest,
  type RequestLocalAdminPasswordRotationRequest,
  type SetLocalAdminPasswordPolicyRequest,
} from "../../../gen/lindm/admin/v1/secrets_pb";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useExactRequest, type ExactRequestStatus } from "@/hooks/use-exact-request";
import { usePrincipal } from "@/hooks/use-permissions";
import { blockedReasonLabel, toRpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import { LocalAdminPasswordReveal } from "./local-admin-reveal";
import { Fact, ObservedTime } from "./observations";
import { localAdminPasswordQueryOptions } from "./queries";
import { validateInventory } from "./validation";

const DAY_SECONDS = 86_400;
const HOUR_SECONDS = 3_600;

const escrowStates: Record<LocalAdminPasswordState, { label: string; tone: StatusTone }> = {
  [LocalAdminPasswordState.UNSPECIFIED]: { label: "State not reported", tone: "neutral" },
  [LocalAdminPasswordState.ESCROWED]: { label: "Escrowed, not yet set", tone: "info" },
  [LocalAdminPasswordState.CURRENT]: { label: "Current", tone: "success" },
  [LocalAdminPasswordState.SUPERSEDED]: { label: "Superseded", tone: "neutral" },
  [LocalAdminPasswordState.UNKNOWN]: { label: "Unknown, may be in effect", tone: "warning" },
  [LocalAdminPasswordState.FAILED]: { label: "Failed, never set", tone: "destructive" },
};

export function DeviceLocalAdminPanel({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const query = useQuery(localAdminPasswordQueryOptions(lifetime, deviceId));
  const failure = query.error ? toRpcFailure(query.error) : null;
  const status = failure ? undefined : query.data?.status;
  const policy = status?.policy;
  const manage = canPermission(principal, "secrets.manage");
  const reveal = canPermission(principal, "secrets.reveal");
  const [revealActionId, setRevealActionId] = useState("");
  return (
    <Card>
      <CardHeader>
        <CardTitle>Managed local-admin password</CardTitle>
        <CardDescription>
          The device generates each password, escrows it to the server, and sets it only after the
          server stored it.
        </CardDescription>
        <details className="text-sm text-muted-foreground">
          <summary className="cursor-pointer font-medium">Rotation and custody</summary>
          <p className="mt-2">
            Rotation runs on schedule, on request, and after each reveal once the configured delay
            passes. The account must also be allowlisted in the device's root-owned agent
            configuration. An unknown state means the device was interrupted while setting the
            password; that password remains revealable as a candidate.
          </p>
        </details>
      </CardHeader>
      <CardContent className="grid gap-4">
        <Button
          className="w-fit"
          variant="outline"
          disabled={query.isFetching}
          onClick={() => void query.refetch()}
        >
          Refresh password status
        </Button>
        {query.isPending ? <p role="status">Loading local-admin password status…</p> : null}
        {failure ? <RpcError failure={failure} /> : null}
        {status ? (
          <>
            <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <Fact label="Policy">
                {policy ? (
                  <span>
                    Account <span className="font-mono">{policy.accountName}</span>, rotate every{" "}
                    {durationUnits(policy.rotationInterval?.seconds, DAY_SECONDS)} days, rotate{" "}
                    {durationUnits(policy.postRevealRotationDelay?.seconds, HOUR_SECONDS)} hours
                    after a reveal
                  </span>
                ) : (
                  <StatusBadge status="neutral">No policy configured</StatusBadge>
                )}
              </Fact>
              <Fact label="Next rotation due (server)">
                {status.rotationDueAt ? (
                  <ObservedTime value={status.rotationDueAt} server />
                ) : (
                  "Not scheduled"
                )}
              </Fact>
              <Fact label="Automatic rotation">
                {status.blockedReason ? (
                  <StatusBadge status="warning">
                    {blockedReasonLabel(status.blockedReason)}
                  </StatusBadge>
                ) : policy ? (
                  <StatusBadge status="success">Not blocked</StatusBadge>
                ) : (
                  "Not configured"
                )}
              </Fact>
              <Fact label="Policy set by">
                {policy
                  ? status.policyActorDisplayName.trim() || status.policyActorId || "Unknown actor"
                  : "Not configured"}
              </Fact>
              <Fact label="Server escrow transport key">
                {status.escrowKeyId ? (
                  <span className="break-all font-mono text-xs">{status.escrowKeyId}</span>
                ) : (
                  <StatusBadge status="warning">Not configured, rotation disabled</StatusBadge>
                )}
              </Fact>
            </dl>
            {manage ? (
              <LocalAdminPolicyForm
                // Remounts when the stored policy changes so the form shows stored values.
                key={
                  policy
                    ? `${policy.accountName}:${policy.rotationInterval?.seconds}:${policy.postRevealRotationDelay?.seconds}`
                    : "none"
                }
                deviceId={deviceId}
                policy={policy}
              />
            ) : null}
            {manage && policy ? (
              <div className="grid gap-4 md:grid-cols-2">
                <LocalAdminRotationRequest deviceId={deviceId} />
                <LocalAdminPolicyRemoval deviceId={deviceId} />
              </div>
            ) : null}
            <h3 className="font-semibold">Escrow history</h3>
            {status.escrows.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>State</TableHead>
                    <TableHead>Account</TableHead>
                    <TableHead>Escrowed (server)</TableHead>
                    <TableHead>Settled (server)</TableHead>
                    <TableHead>Last revealed (server)</TableHead>
                    <TableHead>Escrow action</TableHead>
                    {reveal ? <TableHead>Access</TableHead> : null}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {status.escrows.map((escrow) => {
                    const state =
                      escrowStates[escrow.state] ??
                      escrowStates[LocalAdminPasswordState.UNSPECIFIED];
                    return (
                      <TableRow key={escrow.actionId}>
                        <TableCell>
                          <StatusBadge status={state.tone}>{state.label}</StatusBadge>
                        </TableCell>
                        <TableCell>
                          <span className="font-mono">{escrow.accountName}</span> (UID{" "}
                          {escrow.accountUid})
                        </TableCell>
                        <TableCell>
                          <ObservedTime value={escrow.escrowedAt} server />
                        </TableCell>
                        <TableCell>
                          {escrow.settledAt ? (
                            <ObservedTime value={escrow.settledAt} server />
                          ) : (
                            "Not settled"
                          )}
                        </TableCell>
                        <TableCell>
                          {escrow.lastRevealedAt ? (
                            <ObservedTime value={escrow.lastRevealedAt} server />
                          ) : (
                            "Never revealed"
                          )}
                        </TableCell>
                        <TableCell className="break-all font-mono text-xs">
                          {escrow.actionId}
                        </TableCell>
                        {reveal ? (
                          <TableCell>
                            <Button
                              variant="outline"
                              size="sm"
                              disabled={revealActionId === escrow.actionId}
                              onClick={() => setRevealActionId(escrow.actionId)}
                            >
                              {revealActionId === escrow.actionId ? "Selected" : "Reveal password"}
                            </Button>
                          </TableCell>
                        ) : null}
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            ) : (
              <p>No escrowed local-admin password is recorded for this device.</p>
            )}
            {reveal && revealActionId ? (
              <LocalAdminPasswordReveal
                key={revealActionId}
                deviceId={deviceId}
                actionId={revealActionId}
              />
            ) : null}
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}

function durationUnits(seconds: bigint | undefined, unit: number) {
  return seconds === undefined ? "unknown" : (Number(seconds) / unit).toString();
}

function wholeNumber(value: string, label: string, min: number, max: number) {
  const parsed = Number(value);
  if (value.trim() === "" || !Number.isInteger(parsed) || parsed < min || parsed > max)
    throw new Error(`${label} must be a whole number from ${min} to ${max}.`);
  return parsed;
}

function LocalAdminPolicyForm({
  deviceId,
  policy,
}: {
  deviceId: string;
  policy: LocalAdminPasswordPolicy | undefined;
}) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const id = useId();
  const exact = useExactRequest<SetLocalAdminPasswordPolicyRequest>();
  const [account, setAccount] = useState(policy?.accountName ?? "");
  const [intervalDays, setIntervalDays] = useState(
    policy?.rotationInterval ? durationUnits(policy.rotationInterval.seconds, DAY_SECONDS) : "30",
  );
  const [delayHours, setDelayHours] = useState(
    policy?.postRevealRotationDelay
      ? durationUnits(policy.postRevealRotationDelay.seconds, HOUR_SECONDS)
      : "1",
  );
  const [reason, setReason] = useState("");
  const locked = exact.busy || exact.ambiguous;

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void exact.submit({
      capture: () => {
        const days = wholeNumber(intervalDays, "Rotation interval (days)", 1, 365);
        const hours = wholeNumber(delayHours, "Post-reveal rotation delay (hours)", 0, 24);
        const request = create(SetLocalAdminPasswordPolicyRequestSchema, {
          requestId: newRequestId(),
          deviceId,
          policy: {
            accountName: account.trim(),
            rotationInterval: { seconds: BigInt(days * DAY_SECONDS) },
            postRevealRotationDelay: { seconds: BigInt(hours * HOUR_SECONDS) },
          },
          reason: reason.trim(),
        });
        validateInventory(SetLocalAdminPasswordPolicyRequestSchema, request);
        return request;
      },
      send: (request, options) => adminClient.setLocalAdminPasswordPolicy(request, options),
      failureTitle: "Local-admin policy",
      onSuccess: async () => {
        setReason("");
        toast.success("Local-admin policy saved");
        await queryClient.invalidateQueries({
          queryKey: ["local-admin-password", lifetime.generation, deviceId],
        });
      },
    });
  }

  return (
    <form className="grid gap-3 border p-3" onSubmit={submit} autoComplete="off">
      <h3 className="font-semibold">{policy ? "Change policy" : "Set policy"}</h3>
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="grid gap-2">
          <Label htmlFor={`${id}-account`}>Local account</Label>
          <Input
            id={`${id}-account`}
            value={account}
            readOnly={locked}
            maxLength={32}
            spellCheck={false}
            onChange={(event) => setAccount(event.target.value)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-interval`}>Rotation interval (days, 1 to 365)</Label>
          <Input
            id={`${id}-interval`}
            type="number"
            inputMode="numeric"
            min={1}
            max={365}
            step={1}
            value={intervalDays}
            readOnly={locked}
            onChange={(event) => setIntervalDays(event.target.value)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-delay`}>Post-reveal rotation delay (hours, 0 to 24)</Label>
          <Input
            id={`${id}-delay`}
            type="number"
            inputMode="numeric"
            min={0}
            max={24}
            step={1}
            value={delayHours}
            readOnly={locked}
            onChange={(event) => setDelayHours(event.target.value)}
          />
        </div>
      </div>
      <p className="text-sm text-muted-foreground">
        The account cannot be root and must be allowlisted in the device's agent configuration.
        Rotation is authorized with your current authority; if it later changes, rotation is blocked
        until the policy is set again.
      </p>
      <div className="grid gap-2">
        <Label htmlFor={`${id}-reason`}>Audit reason</Label>
        <Textarea
          id={`${id}-reason`}
          value={reason}
          readOnly={locked}
          onChange={(event) => setReason(event.target.value)}
        />
      </div>
      <ExactRequestResult exact={exact} title="Policy not saved" />
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={exact.busy}>
          {exact.busy ? "Saving…" : exact.ambiguous ? "Retry exact policy request" : "Save policy"}
        </Button>
        {exact.ambiguous ? (
          <Button type="button" variant="outline" disabled={exact.busy} onClick={exact.reset}>
            Discard captured request
          </Button>
        ) : null}
      </div>
    </form>
  );
}

function LocalAdminRotationRequest({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const id = useId();
  const exact = useExactRequest<RequestLocalAdminPasswordRotationRequest>();
  const [reason, setReason] = useState("");

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void exact.submit({
      capture: () => {
        const request = create(RequestLocalAdminPasswordRotationRequestSchema, {
          requestId: newRequestId(),
          deviceId,
          reason: reason.trim(),
        });
        validateInventory(RequestLocalAdminPasswordRotationRequestSchema, request);
        return request;
      },
      send: (request, options) => adminClient.requestLocalAdminPasswordRotation(request, options),
      failureTitle: "Rotation request",
      onSuccess: async () => {
        setReason("");
        toast.success("Rotation requested", {
          description: "The device rotates the password on its next action poll.",
        });
        await queryClient.invalidateQueries({
          queryKey: ["local-admin-password", lifetime.generation, deviceId],
        });
      },
    });
  }

  return (
    <form className="grid gap-3 border p-3" onSubmit={submit} autoComplete="off">
      <h3 className="font-semibold">Request rotation</h3>
      <Label htmlFor={`${id}-reason`}>Audit reason</Label>
      <Textarea
        id={`${id}-reason`}
        value={reason}
        readOnly={exact.busy || exact.ambiguous}
        onChange={(event) => setReason(event.target.value)}
      />
      <ExactRequestResult exact={exact} title="Rotation not requested" />
      <div className="flex flex-wrap gap-2">
        <Button type="submit" variant="outline" disabled={exact.busy}>
          {exact.busy
            ? "Requesting…"
            : exact.ambiguous
              ? "Retry exact rotation request"
              : "Request rotation"}
        </Button>
        {exact.ambiguous ? (
          <Button type="button" variant="outline" disabled={exact.busy} onClick={exact.reset}>
            Discard captured request
          </Button>
        ) : null}
      </div>
    </form>
  );
}

function LocalAdminPolicyRemoval({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const id = useId();
  const exact = useExactRequest<RemoveLocalAdminPasswordPolicyRequest>();
  const [reason, setReason] = useState("");

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void exact.submit({
      capture: () => {
        const request = create(RemoveLocalAdminPasswordPolicyRequestSchema, {
          requestId: newRequestId(),
          deviceId,
          reason: reason.trim(),
        });
        validateInventory(RemoveLocalAdminPasswordPolicyRequestSchema, request);
        return request;
      },
      send: (request, options) => adminClient.removeLocalAdminPasswordPolicy(request, options),
      failureTitle: "Policy removal",
      onSuccess: async () => {
        setReason("");
        toast.success("Local-admin policy removed", {
          description: "Escrowed passwords remain revealable.",
        });
        await queryClient.invalidateQueries({
          queryKey: ["local-admin-password", lifetime.generation, deviceId],
        });
      },
    });
  }

  return (
    <form className="grid gap-3 border p-3" onSubmit={submit} autoComplete="off">
      <h3 className="font-semibold">Remove policy</h3>
      <p className="text-sm text-muted-foreground">
        Stops future rotations. The current password stays on the device and escrowed passwords
        remain revealable.
      </p>
      <Label htmlFor={`${id}-reason`}>Audit reason</Label>
      <Textarea
        id={`${id}-reason`}
        value={reason}
        readOnly={exact.busy || exact.ambiguous}
        onChange={(event) => setReason(event.target.value)}
      />
      <ExactRequestResult exact={exact} title="Policy not removed" />
      <div className="flex flex-wrap gap-2">
        <Button type="submit" variant="destructive" disabled={exact.busy}>
          {exact.busy
            ? "Removing…"
            : exact.ambiguous
              ? "Retry exact removal request"
              : "Remove policy"}
        </Button>
        {exact.ambiguous ? (
          <Button type="button" variant="outline" disabled={exact.busy} onClick={exact.reset}>
            Discard captured request
          </Button>
        ) : null}
      </div>
    </form>
  );
}

function ExactRequestResult({ exact, title }: { exact: ExactRequestStatus; title: string }) {
  return (
    <>
      {exact.invalid ? (
        <p role="alert" className="text-sm text-destructive">
          {exact.invalid}
        </p>
      ) : null}
      {exact.failure ? (
        <RpcError failure={exact.failure} title={title}>
          {exact.ambiguous ? (
            <p>
              Refresh the status first. Retry sends the captured request again with the same request
              ID.
            </p>
          ) : null}
        </RpcError>
      ) : null}
    </>
  );
}
