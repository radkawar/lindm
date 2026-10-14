// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useId, useState, type FormEvent } from "react";
import { toast } from "sonner";
import {
  AssistanceDesktop,
  AssistanceReadinessState,
  CreateAssistanceSessionRequestSchema,
  type AssistanceReadiness,
  type CreateAssistanceSessionRequest,
} from "../../../gen/lindm/admin/v1/assistance_pb";
import {
  AssistanceEnablement,
  AssistanceMode,
  AssistancePolicyMode,
  AssistancePolicySchema,
} from "../../../gen/lindm/agent/v1/assistance_pb";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RpcError } from "@/components/ui/rpc-error";
import { SelectField } from "@/components/ui/select-field";
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
import { useExactRequest } from "@/hooks/use-exact-request";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { REASON_MAX_UNITS } from "@/lib/reason";
import { adminClient } from "@/lib/rpc";
import {
  ASSISTANCE_CONTROL_PERMISSION,
  ASSISTANCE_VIEW_PERMISSION,
  AssistanceStateBadge,
  disabledRemedy,
  TimeCell,
  assistanceFailureMessage,
  controlText,
  endCauseText,
  localSessionText,
  modeLabels,
} from "./display";
import {
  CapabilityFields,
  capabilityFields,
  capabilityPermissions,
  policyMode,
} from "./capabilities";
import { AssistancePolicyDialog } from "./policy";
import {
  assistancePolicyQueryOptions,
  assistanceReadinessQueryOptions,
  assistanceSessionsQueryOptions,
} from "./queries";
import { validateRequest } from "@/lib/validation";

const MAX_DURATION_MINUTES = 30;

const modeOptions = [
  { value: String(AssistanceMode.VIEW), label: "View screen" },
  { value: String(AssistanceMode.CONTROL), label: "View and request control" },
] as const;

// Device-detail Remote assistance tab: request form for operators holding
// remote_assistance.view and the device's assistance history for every reader.
export function DeviceAssistanceCard({ deviceId }: { deviceId: string }) {
  const principal = usePrincipal();
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Remote assistance</h2>
        </CardTitle>
        <CardDescription>
          The person on the device decides whether to share. They can stop at any time.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-6">
        {canPermission(principal, "remote_assistance.policy.manage") ? (
          <AssistancePolicyDialog deviceId={deviceId} />
        ) : null}
        {canPermission(principal, ASSISTANCE_VIEW_PERMISSION) ? (
          <AssistanceRequest deviceId={deviceId} />
        ) : null}
        <AssistanceHistory deviceId={deviceId} />
      </CardContent>
    </Card>
  );
}

// The request form appears only when the server knows of nothing that would stop
// the request reaching a person; otherwise one line names the reason and remedy.
function AssistanceRequest({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const query = useQuery(assistanceReadinessQueryOptions(lifetime, deviceId));
  if (query.isPending) return <p role="status">Checking assistance availability…</p>;
  if (query.error)
    return (
      <RpcError failure={toRpcFailure(query.error)} title="Could not check assistance availability">
        <Button variant="outline" disabled={query.isFetching} onClick={() => void query.refetch()}>
          Check again
        </Button>
      </RpcError>
    );
  const readiness = query.data;
  if (readiness.state === AssistanceReadinessState.READY)
    return (
      <AssistanceRequestForm
        deviceId={deviceId}
        policyUnknown={readiness.policy === AssistanceEnablement.UNSPECIFIED}
      />
    );
  return (
    <p
      className="border-l-2 border-muted-foreground/40 pl-3 text-sm"
      data-assistance-gate={AssistanceReadinessState[readiness.state].toLowerCase()}
    >
      <AssistanceGateReason deviceId={deviceId} readiness={readiness} />
    </p>
  );
}

function AssistanceGateReason({
  deviceId,
  readiness,
}: {
  deviceId: string;
  readiness: AssistanceReadiness;
}) {
  switch (readiness.state) {
    case AssistanceReadinessState.DISABLED:
      return readiness.desktop === AssistanceDesktop.ABSENT ? (
        <>
          This device has no desktop session to share. Its configuration also disables remote
          assistance.
        </>
      ) : (
        <>The device configuration disables remote assistance. {disabledRemedy}</>
      );
    case AssistanceReadinessState.NO_DESKTOP:
      return (
        <>
          Inventory from <TimeCell value={readiness.inventoryObservedAt} /> shows no desktop session
          or sign-in screen. Refresh inventory from Actions after a desktop starts.
        </>
      );
    case AssistanceReadinessState.OFFLINE:
      return (
        <>
          {readiness.lastSeenAt ? (
            <>
              This device last checked in <TimeCell value={readiness.lastSeenAt} />.
            </>
          ) : (
            "This device has not checked in yet."
          )}{" "}
          Wait for the device to contact the server before requesting assistance.
        </>
      );
    case AssistanceReadinessState.BUSY:
      return (
        <>
          A remote assistance session is already open on this device.{" "}
          <Link
            to="/devices/$deviceId/assistance/$sessionId"
            params={{ deviceId, sessionId: readiness.openSessionId }}
            className="underline"
          >
            Open that session
          </Link>
        </>
      );
    case AssistanceReadinessState.NOT_ENROLLED:
      return <>This device is not enrolled. It cannot receive assistance requests.</>;
    case AssistanceReadinessState.UNCONFIGURED:
      return (
        <>
          This server does not provide remote assistance. Ask a server administrator to configure
          the assistance relay.
        </>
      );
    default:
      return <>The server did not report assistance availability. Reload to check again.</>;
  }
}

function AssistanceRequestForm({
  deviceId,
  policyUnknown,
}: {
  deviceId: string;
  policyUnknown: boolean;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const policyQuery = useQuery(assistancePolicyQueryOptions(lifetime, deviceId));
  const [capabilities, setCapabilities] = useState(() => create(AssistancePolicySchema));
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const id = useId();
  const exact = useExactRequest<CreateAssistanceSessionRequest>();
  const [mode, setMode] = useState<AssistanceMode>(AssistanceMode.VIEW);
  const [reason, setReason] = useState("");
  const [minutes, setMinutes] = useState(String(MAX_DURATION_MINUTES));
  const locked = exact.busy || exact.ambiguous;
  const precondition = exact.failure ? assistanceFailureMessage(exact.failure) : null;
  const controlAllowed = canPermission(principal, ASSISTANCE_CONTROL_PERMISSION);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void exact.submit({
      capture: () => {
        if (mode === AssistanceMode.CONTROL && !controlAllowed)
          throw new Error("Your role allows viewing only. Choose View screen.");
        const parsed = Number(minutes);
        if (
          minutes.trim() === "" ||
          !Number.isInteger(parsed) ||
          parsed < 1 ||
          parsed > MAX_DURATION_MINUTES
        )
          throw new Error(`Enter a whole number of minutes from 1 to ${MAX_DURATION_MINUTES}.`);
        const request = create(CreateAssistanceSessionRequestSchema, {
          requestId: newRequestId(),
          deviceId,
          mode,
          reason: reason.trim(),
          maxDurationSeconds: parsed * 60,
        });
        request.requestedCapabilities = create(AssistancePolicySchema);
        for (const field of capabilityFields) {
          const requested = policyMode(capabilities, field);
          if (requested !== AssistancePolicyMode.OFF) {
            if (!policyQuery.data || policyQuery.error)
              throw new Error("Refresh the assistance policy before requesting extra features.");
            if (
              !canPermission(principal, capabilityPermissions[field]) ||
              requested > policyMode(policyQuery.data.policy, field)
            )
              throw new Error(
                "A requested feature is no longer allowed. Review the assistance policy.",
              );
          }
          request.requestedCapabilities[field] = requested;
        }
        validateRequest(CreateAssistanceSessionRequestSchema, request);
        return request;
      },
      send: (request, options) => adminClient.createAssistanceSession(request, options),
      failureTitle: "Remote assistance request",
      onSuccess: async (response) => {
        setReason("");
        await queryClient.invalidateQueries({
          queryKey: ["assistance-sessions", lifetime.generation, deviceId],
        });
        const sessionId = response.session?.id;
        if (!sessionId || response.session?.deviceId !== deviceId) {
          toast.error("Requested, but couldn't open the session", {
            description: "Open the session from the history below.",
          });
          return;
        }
        toast.success("Remote assistance requested", {
          description: "Waiting for the user on the device to accept.",
        });
        void navigate({
          to: "/devices/$deviceId/assistance/$sessionId",
          params: { deviceId, sessionId },
        });
      },
    });
  }

  return (
    <form
      className="grid gap-4 border-l-2 border-primary bg-muted/30 p-4"
      onSubmit={submit}
      autoComplete="off"
    >
      <h3 className="text-base font-semibold">Ask to help</h3>
      <div className="grid gap-2">
        <Label htmlFor={`${id}-reason`}>
          Reason (the user sees this; the audit log records it)
        </Label>
        <Textarea
          id={`${id}-reason`}
          data-freeform="support reason shown to the user"
          value={reason}
          readOnly={locked}
          maxLength={REASON_MAX_UNITS}
          onChange={(event) => setReason(event.target.value)}
        />
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-2">
          <Label htmlFor={`${id}-mode`}>Mode</Label>
          <SelectField
            id={`${id}-mode`}
            value={String(mode)}
            disabled={locked}
            options={controlAllowed ? modeOptions : [modeOptions[0]]}
            aria-describedby={`${id}-mode-help`}
            onValueChange={(value) => setMode(Number(value) as AssistanceMode)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-duration`}>
            Maximum duration (minutes, 1 to {MAX_DURATION_MINUTES})
          </Label>
          <Input
            id={`${id}-duration`}
            data-freeform="numeric time limit"
            type="number"
            inputMode="numeric"
            min={1}
            max={MAX_DURATION_MINUTES}
            step={1}
            value={minutes}
            readOnly={locked}
            onChange={(event) => setMinutes(event.target.value)}
          />
        </div>
      </div>
      <p id={`${id}-mode-help`} className="text-sm text-muted-foreground">
        {mode === AssistanceMode.CONTROL
          ? "The user can allow keyboard and mouse control, or choose viewing only."
          : "You can view the shared screen. You cannot type or select items on the device."}
      </p>
      {!controlAllowed ? (
        <p className="text-sm text-muted-foreground">Your role allows viewing only, not control.</p>
      ) : null}
      <CapabilityFields
        value={capabilities}
        ceiling={policyQuery.error ? undefined : policyQuery.data?.policy}
        disabled={locked || policyQuery.isPending}
        onChange={(field, value) =>
          setCapabilities((current) =>
            create(AssistancePolicySchema, { ...current, [field]: value }),
          )
        }
      />
      {policyQuery.error ? (
        <RpcError failure={toRpcFailure(policyQuery.error)} title="Couldn't load assistance policy">
          <Button
            type="button"
            variant="outline"
            disabled={policyQuery.isFetching}
            onClick={() => void policyQuery.refetch()}
          >
            Refresh policy
          </Button>
        </RpcError>
      ) : null}
      {exact.invalid ? (
        <p role="alert" className="text-sm text-destructive">
          {exact.invalid}
        </p>
      ) : null}
      {exact.failure ? (
        <RpcError failure={exact.failure} title="Remote assistance not requested">
          {precondition ? <p>{precondition}</p> : null}
          {exact.ambiguous ? <p>Check the history below. Retry only this same request.</p> : null}
        </RpcError>
      ) : null}
      <p className="text-sm text-muted-foreground">
        The request asks for consent. Sharing starts only after the user accepts. Either person can
        stop the session before its time limit.
        {policyUnknown
          ? " The agent does not report whether its configuration allows assistance. The device can refuse the request."
          : ""}
      </p>
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={exact.busy}>
          {exact.busy
            ? "Requesting…"
            : exact.ambiguous
              ? "Retry same request"
              : "Request remote assistance"}
        </Button>
        {exact.ambiguous ? (
          <Button type="button" variant="outline" disabled={exact.busy} onClick={exact.reset}>
            Discard
          </Button>
        ) : null}
      </div>
    </form>
  );
}

function AssistanceHistory({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const query = useQuery(assistanceSessionsQueryOptions(lifetime, deviceId, pageToken));
  const failure = query.error ? toRpcFailure(query.error) : null;
  const data = failure ? undefined : query.data;
  return (
    <div className="grid gap-3">
      {/* The history polls every 5 s; only a failed read needs a manual retry. */}
      <h3 className="font-semibold">Session history</h3>
      {query.isPending ? <p role="status">Loading assistance history…</p> : null}
      {failure ? (
        <RpcError failure={failure} title="Couldn't load session history">
          <Button
            variant="outline"
            disabled={query.isFetching}
            onClick={() => void query.refetch()}
          >
            Try again
          </Button>
        </RpcError>
      ) : null}
      {data?.sessions.length === 0 ? (
        <EmptyState
          title="No remote assistance sessions yet"
          description="Requests and their outcomes appear here."
        />
      ) : null}
      {data?.sessions.length ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Status</TableHead>
              <TableHead>Admin</TableHead>
              <TableHead>Device user</TableHead>
              <TableHead>Control</TableHead>
              <TableHead>Requested</TableHead>
              <TableHead>Started</TableHead>
              <TableHead>Ended</TableHead>
              <TableHead>Why it ended</TableHead>
              <TableHead>
                <span className="sr-only">Open</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.sessions.map((session) => (
              <TableRow key={session.id}>
                <TableCell>
                  <AssistanceStateBadge session={session} />
                  <p className="text-xs text-muted-foreground">{modeLabels[session.mode]}</p>
                </TableCell>
                <TableCell className="whitespace-normal">
                  {session.operatorDisplay || "Unknown"}
                </TableCell>
                <TableCell className="whitespace-normal">
                  {localSessionText(session) || <span className="text-muted-foreground">None</span>}
                </TableCell>
                <TableCell>
                  {controlText(session) || (
                    <span className="text-muted-foreground">Not answered</span>
                  )}
                </TableCell>
                <TableCell>
                  <TimeCell value={session.createdAt} />
                </TableCell>
                <TableCell>
                  {session.startedAt ? (
                    <TimeCell value={session.startedAt} />
                  ) : (
                    <span className="text-muted-foreground">Never</span>
                  )}
                </TableCell>
                <TableCell>
                  <TimeCell value={session.endedAt} />
                </TableCell>
                <TableCell className="min-w-48 whitespace-normal">
                  {endCauseText(session) || "Still open"}
                </TableCell>
                <TableCell>
                  <Link
                    to="/devices/$deviceId/assistance/$sessionId"
                    params={{ deviceId, sessionId: session.id }}
                    className="text-sm underline"
                  >
                    Details
                  </Link>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : null}
      {pageToken || data?.nextPageToken ? (
        <div className="flex gap-2">
          <Button
            variant="outline"
            disabled={!pageToken || query.isFetching}
            onClick={() => setPageToken("")}
          >
            Newest sessions
          </Button>
          <Button
            variant="outline"
            disabled={!data?.nextPageToken || query.isFetching}
            onClick={() => setPageToken(data?.nextPageToken ?? "")}
          >
            Older sessions
          </Button>
        </div>
      ) : null}
    </div>
  );
}
