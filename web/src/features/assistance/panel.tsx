import { create } from "@bufbuild/protobuf";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useId, useState, type FormEvent } from "react";
import { toast } from "sonner";
import {
  CreateAssistanceSessionRequestSchema,
  type CreateAssistanceSessionRequest,
} from "../../../gen/lindm/admin/v1/assistance_pb";
import { AssistanceMode } from "../../../gen/lindm/agent/v1/assistance_pb";
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
  ASSISTANCE_PERMISSION,
  AssistanceStateBadge,
  TimeCell,
  assistanceFailureMessage,
  controlText,
  endCauseText,
  localSessionText,
  modeLabels,
} from "./display";
import { assistanceSessionsQueryOptions } from "./queries";
import { validateAssistanceRequest } from "./validation";

const MAX_DURATION_MINUTES = 30;

const modeOptions = [
  { value: String(AssistanceMode.VIEW), label: "View screen" },
  { value: String(AssistanceMode.CONTROL), label: "View and request control" },
] as const;

// Device-detail card: request form for operators holding remote_assistance.run and the
// device's assistance history for every reader.
export function DeviceAssistanceCard({ deviceId }: { deviceId: string }) {
  const principal = usePrincipal();
  return (
    <Card>
      <CardHeader>
        <CardTitle>Remote assistance</CardTitle>
        <CardDescription>
          Ask the signed-in local user to share their screen. Nothing is shown until they accept on
          the device, and they can stop the session at any time.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-6">
        {canPermission(principal, ASSISTANCE_PERMISSION) ? (
          <AssistanceRequestForm deviceId={deviceId} />
        ) : null}
        <AssistanceHistory deviceId={deviceId} />
      </CardContent>
    </Card>
  );
}

function AssistanceRequestForm({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const id = useId();
  const exact = useExactRequest<CreateAssistanceSessionRequest>();
  const [mode, setMode] = useState<AssistanceMode>(AssistanceMode.VIEW);
  const [reason, setReason] = useState("");
  const [minutes, setMinutes] = useState(String(MAX_DURATION_MINUTES));
  const locked = exact.busy || exact.ambiguous;
  const precondition = exact.failure ? assistanceFailureMessage(exact.failure) : "";

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void exact.submit({
      capture: () => {
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
        validateAssistanceRequest(CreateAssistanceSessionRequestSchema, request);
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
    <form className="grid gap-3 border p-3" onSubmit={submit} autoComplete="off">
      <h3 className="font-semibold">Request a session</h3>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-2">
          <Label htmlFor={`${id}-mode`}>Mode</Label>
          <SelectField
            id={`${id}-mode`}
            value={String(mode)}
            disabled={locked}
            options={modeOptions}
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
          ? "Control lets you use the keyboard and mouse. The user on the device can allow viewing only."
          : "View shares the screen only. You can't type or click."}{" "}
        The session ends after this time. To continue, request a new session.
      </p>
      <div className="grid gap-2">
        <Label htmlFor={`${id}-reason`}>Reason (shown to the local user and audited)</Label>
        <Textarea
          id={`${id}-reason`}
          value={reason}
          readOnly={locked}
          maxLength={REASON_MAX_UNITS}
          onChange={(event) => setReason(event.target.value)}
        />
      </div>
      {exact.invalid ? (
        <p role="alert" className="text-sm text-destructive">
          {exact.invalid}
        </p>
      ) : null}
      {exact.failure ? (
        <RpcError failure={exact.failure} title="Remote assistance not requested">
          {precondition ? <p>{precondition}</p> : null}
          {exact.ambiguous ? <p>Check the history below before trying again.</p> : null}
        </RpcError>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={exact.busy}>
          {exact.busy ? "Requesting…" : exact.ambiguous ? "Try again" : "Request remote assistance"}
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
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-semibold">Session history</h3>
        <Button variant="outline" disabled={query.isFetching} onClick={() => void query.refetch()}>
          Refresh sessions
        </Button>
      </div>
      {query.isPending ? <p role="status">Loading assistance history…</p> : null}
      {failure ? <RpcError failure={failure} title="Couldn't load session history" /> : null}
      {data?.sessions.length === 0 ? (
        <EmptyState
          title="No remote assistance sessions yet"
          description="Sessions you request appear here."
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
                  <AssistanceStateBadge state={session.state} />
                  <p className="text-xs text-muted-foreground">{modeLabels[session.mode]}</p>
                </TableCell>
                <TableCell className="whitespace-normal">
                  {session.operatorDisplay || "Unknown"}
                </TableCell>
                <TableCell className="whitespace-normal">{localSessionText(session)}</TableCell>
                <TableCell>{controlText(session)}</TableCell>
                <TableCell>
                  <TimeCell value={session.createdAt} />
                </TableCell>
                <TableCell>
                  <TimeCell value={session.startedAt} />
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
    </div>
  );
}
