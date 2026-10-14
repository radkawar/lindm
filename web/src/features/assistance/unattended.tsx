// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useId, useState, type FormEvent } from "react";
import { toast } from "sonner";
import {
  ApprovalState,
  CreateApprovalRequestSchema,
  type Approval,
  type CreateApprovalRequest,
} from "../../../gen/lindm/admin/v1/approvals_pb";
import {
  CreateAssistanceSessionRequestSchema,
  type CreateAssistanceSessionRequest,
} from "../../../gen/lindm/admin/v1/assistance_pb";
import {
  AssistanceUnattendedEnrollmentStatus,
  AssistanceUnattendedGrantState,
  AuthorizeUnattendedAssistanceRequestSchema,
  RevokeUnattendedAssistanceRequestSchema,
  type AssistanceUnattendedGrant,
  type AuthorizeUnattendedAssistanceRequest,
  type RevokeUnattendedAssistanceRequest,
} from "../../../gen/lindm/admin/v1/assistance_unattended_pb";
import {
  AssistanceMode,
  AssistancePolicyMode,
  AssistancePolicySchema,
} from "../../../gen/lindm/agent/v1/assistance_pb";
import {
  AssistanceUnattendedScheduleSchema,
  AssistanceUnattendedWindowSchema,
  type AssistanceUnattendedWindow,
} from "../../../gen/lindm/agent/v1/assistance_unattended_pb";
import { Button } from "@/components/ui/button";
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
import { CapabilityFields, policyMode, type CapabilityField } from "./capabilities";
import { TimeCell, modeLabels } from "./display";
import {
  assistancePolicyQueryOptions,
  unattendedApprovalsQueryOptions,
  unattendedAssistanceQueryOptions,
} from "./queries";
import { validateRequest } from "@/lib/validation";
import { UnattendedLimitsSummary } from "./workflow-policy";

const UNATTENDED_PERMISSION = "remote_assistance.unattended";
const REVOKE_PERMISSIONS = [
  UNATTENDED_PERMISSION,
  "remote_assistance.unattended.approve",
  "remote_assistance.policy.manage",
];
// Features an unattended connection may carry. Sound needs a local choice and
// optional recording needs a local opt-in, so neither is offered here.
const grantFields: readonly CapabilityField[] = [
  "clipboard",
  "keyboard",
  "display",
  "messages",
  "files",
  "elevation",
  "annotation",
];
const weekdays = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const APPROVAL_LIFETIME_SECONDS = 3600;

const grantStateLabels: Record<number, string> = {
  [AssistanceUnattendedGrantState.ACTIVE]: "Active",
  [AssistanceUnattendedGrantState.REVOKED]: "Revoked",
  [AssistanceUnattendedGrantState.EXPIRED]: "Expired",
};
const enrollmentStateLabels: Record<number, string> = {
  [AssistanceUnattendedEnrollmentStatus.ENROLLED]: "Opted in",
  [AssistanceUnattendedEnrollmentStatus.REVOKED]: "Turned off",
  [AssistanceUnattendedEnrollmentStatus.EXPIRED]: "Expired",
};

function scheduleText(windows: readonly AssistanceUnattendedWindow[], zone: string): string {
  return (
    windows
      .map((window) => {
        const hours = String(Math.floor(window.startMinute / 60)).padStart(2, "0");
        const minutes = String(window.startMinute % 60).padStart(2, "0");
        return `${weekdays[window.weekday]} ${hours}:${minutes} for ${window.durationMinutes} min`;
      })
      .join("; ") + (zone ? ` (${zone})` : "")
  );
}

// Unattended access on one device: local opt-ins, approved grants, the
// caller's approval requests and the two-person request form.
export function DeviceUnattendedAssistance({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const query = useQuery(unattendedAssistanceQueryOptions(lifetime, deviceId));
  const policyQuery = useQuery(assistancePolicyQueryOptions(lifetime, deviceId));
  const requester = canPermission(principal, UNATTENDED_PERMISSION);
  const approvals = useQuery({
    ...unattendedApprovalsQueryOptions(lifetime, deviceId),
    enabled: requester,
  });
  const failure = query.error ? toRpcFailure(query.error) : null;
  const mode = policyMode(policyQuery.data?.policy, "unattended");
  const data = failure ? undefined : query.data;
  if (mode === AssistancePolicyMode.OFF && !data?.grants.length && !data?.enrollments.length)
    return null;
  return (
    <section className="grid gap-3" aria-labelledby={`unattended-${deviceId}`}>
      <h3 id={`unattended-${deviceId}`} className="font-semibold">
        Unattended access
      </h3>
      <p className="text-sm text-muted-foreground">
        Reaches only a user who opted in on this device, only while their session is unlocked. A
        second person approves every access period and the user always sees a banner with Stop.
      </p>
      {query.isPending ? <p role="status">Loading unattended access…</p> : null}
      {failure ? <RpcError failure={failure} title="Couldn't load unattended access" /> : null}
      {data ? <EnrollmentTable deviceId={deviceId} enrollments={data.enrollments} /> : null}
      {data ? (
        <GrantTable
          deviceId={deviceId}
          grants={data.grants}
          principalId={approvals.data?.principalId ?? ""}
        />
      ) : null}
      {requester && approvals.data ? (
        <PendingApprovals deviceId={deviceId} approvals={approvals.data.approvals} />
      ) : null}
      {requester && mode !== AssistancePolicyMode.OFF ? (
        <UnattendedRequestForm
          deviceId={deviceId}
          usernames={(data?.enrollments ?? [])
            .filter((row) => row.state === AssistanceUnattendedEnrollmentStatus.ENROLLED)
            .map((row) => row.username)}
        />
      ) : null}
    </section>
  );
}

function useRevoke(deviceId: string) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const exact = useExactRequest<RevokeUnattendedAssistanceRequest>();
  return {
    exact,
    revoke(target: { grantId?: string; enrollmentId?: string }) {
      void exact.submit({
        capture: () => {
          const request = create(RevokeUnattendedAssistanceRequestSchema, {
            deviceId,
            reason: "Revoked from the device page",
            ...target,
          });
          validateRequest(RevokeUnattendedAssistanceRequestSchema, request);
          return request;
        },
        send: (request, options) => adminClient.revokeUnattendedAssistance(request, options),
        failureTitle: "Unattended access",
        onSuccess: async () => {
          await queryClient.invalidateQueries({
            queryKey: unattendedAssistanceQueryOptions(lifetime, deviceId).queryKey,
          });
          toast.success("Unattended access revoked");
        },
      });
    },
  };
}

function EnrollmentTable({
  deviceId,
  enrollments,
}: {
  deviceId: string;
  enrollments: readonly {
    id: string;
    username: string;
    mode: AssistanceMode;
    state: AssistanceUnattendedEnrollmentStatus;
    expiresAt?: Parameters<typeof TimeCell>[0]["value"];
  }[];
}) {
  const principal = usePrincipal();
  const { exact, revoke } = useRevoke(deviceId);
  const canRevoke = REVOKE_PERMISSIONS.some((permission) => canPermission(principal, permission));
  if (enrollments.length === 0)
    return (
      <EmptyState
        title="No user has opted in"
        description="A user can opt in during an attended session that offers unattended access."
      />
    );
  return (
    <>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Device user</TableHead>
            <TableHead>Mode</TableHead>
            <TableHead>Opt-in</TableHead>
            <TableHead>Expires</TableHead>
            <TableHead>
              <span className="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {enrollments.map((enrollment) => (
            <TableRow key={enrollment.id}>
              <TableCell>{enrollment.username}</TableCell>
              <TableCell>{modeLabels[enrollment.mode]}</TableCell>
              <TableCell>{enrollmentStateLabels[enrollment.state] ?? "Unknown"}</TableCell>
              <TableCell>
                <TimeCell value={enrollment.expiresAt} />
              </TableCell>
              <TableCell>
                {canRevoke && enrollment.state === AssistanceUnattendedEnrollmentStatus.ENROLLED ? (
                  <Button
                    variant="outline"
                    disabled={exact.busy}
                    onClick={() => revoke({ enrollmentId: enrollment.id })}
                  >
                    Turn off
                  </Button>
                ) : null}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {exact.failure ? (
        <RpcError failure={exact.failure} title="Couldn't turn off unattended access" />
      ) : null}
    </>
  );
}

function GrantTable({
  deviceId,
  grants,
  principalId,
}: {
  deviceId: string;
  grants: readonly AssistanceUnattendedGrant[];
  principalId: string;
}) {
  const principal = usePrincipal();
  const lifetime = useAuthLifetime();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { exact, revoke } = useRevoke(deviceId);
  const connect = useExactRequest<CreateAssistanceSessionRequest>();
  const canRevoke = REVOKE_PERMISSIONS.some((permission) => canPermission(principal, permission));
  const canConnect =
    canPermission(principal, UNATTENDED_PERMISSION) &&
    canPermission(principal, "remote_assistance.view");
  if (grants.length === 0) return null;

  function start(grant: AssistanceUnattendedGrant) {
    void connect.submit({
      capture: () => {
        const request = create(CreateAssistanceSessionRequestSchema, {
          requestId: newRequestId(),
          deviceId,
          mode: grant.mode,
          reason: grant.reason,
          targetUsername: grant.targetUsername,
          unattendedGrantId: grant.id,
          requestedCapabilities: grant.requestedCapabilities ?? create(AssistancePolicySchema),
        });
        validateRequest(CreateAssistanceSessionRequestSchema, request);
        return request;
      },
      send: (request, options) => adminClient.createAssistanceSession(request, options),
      failureTitle: "Unattended connection",
      onSuccess: async (response) => {
        await queryClient.invalidateQueries({
          queryKey: ["assistance-sessions", lifetime.generation, deviceId],
        });
        const sessionId = response.session?.id;
        if (sessionId && response.session?.deviceId === deviceId)
          void navigate({
            to: "/devices/$deviceId/assistance/$sessionId",
            params: { deviceId, sessionId },
          });
      },
    });
  }

  return (
    <>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Status</TableHead>
            <TableHead>Admin</TableHead>
            <TableHead>Approved by</TableHead>
            <TableHead>Device user</TableHead>
            <TableHead>Window</TableHead>
            <TableHead>
              <span className="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {grants.map((grant) => (
            <TableRow key={grant.id}>
              <TableCell>
                {grantStateLabels[grant.state] ?? "Unknown"}
                <p className="text-xs text-muted-foreground">{modeLabels[grant.mode]}</p>
              </TableCell>
              <TableCell className="whitespace-normal">
                {grant.operatorDisplay || grant.operatorId}
              </TableCell>
              <TableCell className="whitespace-normal">
                {grant.approverDisplay || grant.approverId}
              </TableCell>
              <TableCell>{grant.targetUsername}</TableCell>
              <TableCell className="whitespace-normal">
                From <TimeCell value={grant.notBefore} /> to <TimeCell value={grant.notAfter} />
                {grant.schedule ? (
                  <p className="text-xs text-muted-foreground">
                    {scheduleText(grant.schedule.windows, grant.schedule.timeZone)}
                  </p>
                ) : null}
              </TableCell>
              <TableCell className="flex flex-wrap gap-2">
                {canConnect &&
                grant.state === AssistanceUnattendedGrantState.ACTIVE &&
                grant.operatorId === principalId ? (
                  <Button disabled={connect.busy} onClick={() => start(grant)}>
                    Connect now
                  </Button>
                ) : null}
                {canRevoke && grant.state === AssistanceUnattendedGrantState.ACTIVE ? (
                  <Button
                    variant="outline"
                    disabled={exact.busy}
                    onClick={() => revoke({ grantId: grant.id })}
                  >
                    Revoke
                  </Button>
                ) : null}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {connect.failure ? <RpcError failure={connect.failure} title="Couldn't connect" /> : null}
      {exact.failure ? <RpcError failure={exact.failure} title="Couldn't revoke access" /> : null}
    </>
  );
}

function PendingApprovals({
  deviceId,
  approvals,
}: {
  deviceId: string;
  approvals: readonly Approval[];
}) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const exact = useExactRequest<AuthorizeUnattendedAssistanceRequest>();
  const pending = approvals.filter(
    (approval) =>
      approval.state === ApprovalState.PENDING || approval.state === ApprovalState.APPROVED,
  );
  if (pending.length === 0) return null;

  function activate(approval: Approval) {
    if (approval.payload.case !== "authorizeUnattendedAssistance") return;
    const payload = approval.payload.value;
    void exact.submit({
      capture: () => {
        const request = create(AuthorizeUnattendedAssistanceRequestSchema, {
          ...payload,
          approvalId: approval.id,
        });
        validateRequest(AuthorizeUnattendedAssistanceRequestSchema, request);
        return request;
      },
      send: (request, options) => adminClient.authorizeUnattendedAssistance(request, options),
      failureTitle: "Unattended access",
      onSuccess: async () => {
        await Promise.all([
          queryClient.invalidateQueries({
            queryKey: unattendedAssistanceQueryOptions(lifetime, deviceId).queryKey,
          }),
          queryClient.invalidateQueries({
            queryKey: unattendedApprovalsQueryOptions(lifetime, deviceId).queryKey,
          }),
        ]);
        toast.success("Unattended access activated");
      },
    });
  }

  return (
    <div className="grid gap-2">
      <h4 className="text-sm font-semibold">Your approval requests</h4>
      <ul className="grid gap-2">
        {pending.map((approval) => (
          <li key={approval.id} className="flex flex-wrap items-center gap-2 text-sm">
            <span>
              {approval.state === ApprovalState.APPROVED
                ? `Approved by ${approval.approverDisplayName || approval.approverId}.`
                : "Waiting for a second person to approve."}
            </span>
            {approval.state === ApprovalState.APPROVED ? (
              <Button disabled={exact.busy} onClick={() => activate(approval)}>
                Activate access
              </Button>
            ) : null}
          </li>
        ))}
      </ul>
      {exact.failure ? (
        <RpcError failure={exact.failure} title="Couldn't activate unattended access" />
      ) : null}
    </div>
  );
}

type WindowDraft = { weekday: string; start: string; minutes: string };

function UnattendedRequestForm({ deviceId, usernames }: { deviceId: string; usernames: string[] }) {
  const id = useId();
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const queryClient = useQueryClient();
  const policyQuery = useQuery(assistancePolicyQueryOptions(lifetime, deviceId));
  const exact = useExactRequest<CreateApprovalRequest>();
  const [username, setUsername] = useState("");
  const [mode, setMode] = useState<AssistanceMode>(AssistanceMode.VIEW);
  const [reason, setReason] = useState("");
  const [hours, setHours] = useState("8");
  const [capabilities, setCapabilities] = useState(() => create(AssistancePolicySchema));
  const [windows, setWindows] = useState<WindowDraft[]>([
    { weekday: "1", start: "09:00", minutes: "480" },
  ]);
  const policy = policyQuery.data?.policy;
  const scheduled = policyMode(policy, "unattended") === AssistancePolicyMode.ON;
  const limits = policy?.unattendedLimits;
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  const target = username || usernames[0] || "";

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void exact.submit({
      capture: () => {
        if (!limits) throw new Error("Unattended limits are unavailable. Refresh the policy.");
        if (!target) throw new Error("A user must opt in on the device first.");
        const duration = Number(hours) * 3600;
        if (!Number.isInteger(duration) || duration < 300 || duration > limits.maxApprovalSeconds)
          throw new Error(
            `Enter whole hours from 1 to ${Math.floor(limits.maxApprovalSeconds / 3600)}.`,
          );
        const authorize = create(AuthorizeUnattendedAssistanceRequestSchema, {
          requestId: newRequestId(),
          deviceId,
          mode,
          reason: reason.trim(),
          notBefore: timestampFromDate(new Date()),
          durationSeconds: duration,
          targetUsername: target,
          requestedCapabilities: create(AssistancePolicySchema),
        });
        for (const field of grantFields) {
          const requested = policyMode(capabilities, field);
          if (requested > policyMode(policy, field))
            throw new Error("A requested feature is no longer allowed. Review the policy.");
          if (authorize.requestedCapabilities) authorize.requestedCapabilities[field] = requested;
        }
        if (
          authorize.requestedCapabilities &&
          policyMode(capabilities, "files") >= AssistancePolicyMode.LIMITED
        )
          authorize.requestedCapabilities.fileLimits = policy?.fileLimits;
        if (scheduled) {
          authorize.schedule = create(AssistanceUnattendedScheduleSchema, {
            timeZone: zone,
            windows: windows.map((window) => {
              const [h, m] = window.start.split(":").map(Number);
              return create(AssistanceUnattendedWindowSchema, {
                weekday: Number(window.weekday),
                startMinute: (h ?? 0) * 60 + (m ?? 0),
                durationMinutes: Number(window.minutes),
              });
            }),
          });
        }
        validateRequest(AuthorizeUnattendedAssistanceRequestSchema, authorize);
        const request = create(CreateApprovalRequestSchema, {
          lifetimeSeconds: APPROVAL_LIFETIME_SECONDS,
          payload: { case: "authorizeUnattendedAssistance", value: authorize },
        });
        validateRequest(CreateApprovalRequestSchema, request);
        return request;
      },
      send: (request, options) => adminClient.createApproval(request, options),
      failureTitle: "Unattended access",
      onSuccess: async () => {
        setReason("");
        await queryClient.invalidateQueries({
          queryKey: unattendedApprovalsQueryOptions(lifetime, deviceId).queryKey,
        });
        toast.success("Approval requested", {
          description: "A different person with unattended approval must approve it.",
        });
      },
    });
  }

  return (
    <form className="grid gap-3 border-l-2 border-primary bg-muted/30 p-4" onSubmit={submit}>
      <h4 className="text-sm font-semibold">Request unattended access</h4>
      <UnattendedLimitsSummary policy={limits} />
      {usernames.length === 0 ? (
        <p className="text-sm">
          No user has opted in yet. Offer unattended access in an attended request first.
        </p>
      ) : null}
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="grid gap-2">
          <Label htmlFor={`${id}-user`}>Device user</Label>
          <SelectField
            id={`${id}-user`}
            value={target}
            disabled={exact.busy || usernames.length === 0}
            options={usernames.map((name) => ({ value: name, label: name }))}
            onValueChange={setUsername}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-mode`}>Mode</Label>
          <SelectField
            id={`${id}-mode`}
            value={String(mode)}
            disabled={exact.busy}
            options={[
              { value: String(AssistanceMode.VIEW), label: "View screen" },
              ...(canPermission(principal, "remote_assistance.control")
                ? [{ value: String(AssistanceMode.CONTROL), label: "View and control" }]
                : []),
            ]}
            onValueChange={(value) => setMode(Number(value) as AssistanceMode)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-hours`}>Access period from now (hours)</Label>
          <Input
            data-freeform="numeric access period"
            id={`${id}-hours`}
            type="number"
            min={1}
            step={1}
            value={hours}
            readOnly={exact.busy}
            onChange={(event) => setHours(event.target.value)}
          />
        </div>
      </div>
      <div className="grid gap-2">
        <Label htmlFor={`${id}-reason`}>Reason (shown to the approver and the user)</Label>
        <Textarea
          data-freeform="audit reason shown to the approver and the user"
          id={`${id}-reason`}
          value={reason}
          readOnly={exact.busy}
          maxLength={REASON_MAX_UNITS}
          onChange={(event) => setReason(event.target.value)}
        />
      </div>
      {scheduled ? (
        <fieldset className="grid gap-2 border p-3" disabled={exact.busy}>
          <legend className="px-1 text-sm font-semibold">Weekly schedule ({zone})</legend>
          {windows.map((window, index) => (
            <div key={index} className="grid gap-2 sm:grid-cols-4">
              <SelectField
                aria-label={`Day ${index + 1}`}
                value={window.weekday}
                options={weekdays.map((day, value) => ({ value: String(value), label: day }))}
                onValueChange={(weekday) =>
                  setWindows((current) =>
                    current.map((row, i) => (i === index ? { ...row, weekday } : row)),
                  )
                }
              />
              <Input
                aria-label={`Start ${index + 1}`}
                type="time"
                value={window.start}
                onChange={(event) =>
                  setWindows((current) =>
                    current.map((row, i) =>
                      i === index ? { ...row, start: event.target.value } : row,
                    ),
                  )
                }
              />
              <Input
                data-freeform="numeric schedule time"
                aria-label={`Minutes ${index + 1}`}
                type="number"
                min={15}
                max={720}
                value={window.minutes}
                onChange={(event) =>
                  setWindows((current) =>
                    current.map((row, i) =>
                      i === index ? { ...row, minutes: event.target.value } : row,
                    ),
                  )
                }
              />
              <Button
                type="button"
                variant="outline"
                disabled={windows.length === 1}
                onClick={() => setWindows((current) => current.filter((_, i) => i !== index))}
              >
                Remove
              </Button>
            </div>
          ))}
          <Button
            type="button"
            variant="outline"
            className="w-fit"
            disabled={windows.length >= 7}
            onClick={() =>
              setWindows((current) => [...current, { weekday: "1", start: "09:00", minutes: "60" }])
            }
          >
            Add window
          </Button>
        </fieldset>
      ) : null}
      <CapabilityFields
        value={capabilities}
        ceiling={policy}
        fields={grantFields}
        disabled={exact.busy || policyQuery.isPending}
        onChange={(field, value) =>
          setCapabilities((current) =>
            create(AssistancePolicySchema, { ...current, [field]: value }),
          )
        }
      />
      {exact.invalid ? (
        <p role="alert" className="text-sm text-destructive">
          {exact.invalid}
        </p>
      ) : null}
      {exact.failure ? <RpcError failure={exact.failure} title="Approval not requested" /> : null}
      <Button type="submit" className="w-fit" disabled={exact.busy || usernames.length === 0}>
        {exact.busy ? "Requesting…" : "Request approval"}
      </Button>
    </form>
  );
}
