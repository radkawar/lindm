import { create, toJsonString } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
  ControlRolloutRequest_Operation,
  ControlRolloutRequestSchema,
  PutRolloutRequestSchema,
  PutTargetAssignmentRequestSchema,
  RolloutStateSchema,
  type RolloutState,
} from "../../../gen/lindm/admin/v1/targeting_pb";
import { TargetCandidateSchema } from "../../../gen/lindm/policy/v1/targeting_pb";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import { TargetMutation } from "./mutation";
import { rolloutsQueryOptions, targetAssignmentsQueryOptions } from "./queries";
import { ListStatus, TargetPagination } from "./list";
import { TargetPreviewView } from "./preview";

export function RolloutsView() {
  const principal = usePrincipal();
  return (
    <section className="grid min-w-0 gap-6">
      <PageHeader
        title="Rollouts"
        description="Assign profile revisions to devices and groups. Preview device resources before activation. Rollout progress does not confirm device compliance."
      />
      <TargetPreviewView />
      {canPermission(principal, "resources.assign", true) ? (
        <>
          <Assignments />
          <Rollouts />
        </>
      ) : (
        <p className="text-sm text-muted-foreground">
          Managing assignments and rollouts requires unrestricted resource assignment permission.
          You can preview and activate devices within your authorized scope.
        </p>
      )}
    </section>
  );
}

function Assignments() {
  const lifetime = useAuthLifetime();
  const [afterId, setAfterId] = useState("");
  const list = useQuery(targetAssignmentsQueryOptions(lifetime, afterId));
  return (
    <Card>
      <CardHeader>
        <CardTitle>Target assignments</CardTitle>
        <CardDescription>
          Priority, exclusions, activation/expiry and rollout bindings are retained with each
          revision. Disabling retains a tombstone; it does not erase execution history.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid min-w-0 gap-4">
        <TargetMutation
          title="Create target assignment"
          formKey="target-assignment:new"
          schema={PutTargetAssignmentRequestSchema}
          initial={() =>
            create(PutTargetAssignmentRequestSchema, {
              requestId: newRequestId(),
              assignment: { assignmentId: newRequestId() },
              expectedRevision: 0n,
            })
          }
          send={(request, signal) => adminClient.putTargetAssignment(request, { signal })}
        />
        <Button
          className="w-fit"
          variant="outline"
          disabled={list.isFetching}
          onClick={() => void list.refetch()}
        >
          Refresh assignments
        </Button>
        <ListStatus
          pending={list.isPending}
          error={list.error}
          empty={list.data?.length === 0}
          noun="assignments"
        />
        {!list.error
          ? list.data?.map((candidate) =>
              candidate.assignment ? (
                <article
                  key={candidate.assignment.assignmentId}
                  className="grid min-w-0 gap-3 border p-4"
                >
                  <h3 className="break-all text-sm font-medium">
                    Assignment {candidate.assignment.assignmentId}
                  </h3>
                  <p className="text-sm">
                    Revision {candidate.revision.toString()} · priority{" "}
                    {candidate.assignment.priority} ·{" "}
                    <StatusBadge status={candidate.assignment.disabled ? "neutral" : "info"}>
                      {candidate.assignment.disabled ? "Disabled" : "Enabled"}
                    </StatusBadge>
                  </p>
                  <details>
                    <summary className="cursor-pointer text-sm">
                      Current immutable assignment revision
                    </summary>
                    <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all text-xs">
                      {toJsonString(TargetCandidateSchema, candidate, { prettySpaces: 2 })}
                    </pre>
                  </details>
                  <TargetMutation
                    key={`${candidate.assignment.assignmentId}:${candidate.revision}`}
                    title="Update target assignment"
                    formKey={`target-assignment:${candidate.assignment.assignmentId}`}
                    schema={PutTargetAssignmentRequestSchema}
                    initial={() =>
                      create(PutTargetAssignmentRequestSchema, {
                        requestId: newRequestId(),
                        assignment: candidate.assignment,
                        expectedRevision: candidate.revision,
                      })
                    }
                    send={(request, signal) => adminClient.putTargetAssignment(request, { signal })}
                  />
                </article>
              ) : null,
            )
          : null}
        <TargetPagination
          afterId={afterId}
          nextId={
            list.data?.length === 100 ? list.data.at(-1)?.assignment?.assignmentId : undefined
          }
          busy={list.isFetching}
          onPage={setAfterId}
        />
      </CardContent>
    </Card>
  );
}

function Rollouts() {
  const lifetime = useAuthLifetime();
  const [afterId, setAfterId] = useState("");
  const list = useQuery(rolloutsQueryOptions(lifetime, afterId));
  return (
    <Card>
      <CardHeader>
        <CardTitle>Rollout rings</CardTitle>
        <CardDescription>
          Deploy in stages with canary devices, observation periods and health requirements.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid min-w-0 gap-4">
        <TargetMutation
          title="Create rollout"
          formKey="rollout:new"
          schema={PutRolloutRequestSchema}
          initial={() =>
            create(PutRolloutRequestSchema, {
              requestId: newRequestId(),
              rollout: {
                rolloutId: newRequestId(),
                salt: crypto.getRandomValues(new Uint8Array(32)),
              },
            })
          }
          send={(request, signal) => adminClient.putRollout(request, { signal })}
        />
        <Button
          className="w-fit"
          variant="outline"
          disabled={list.isFetching}
          onClick={() => void list.refetch()}
        >
          Refresh rollouts
        </Button>
        <ListStatus
          pending={list.isPending}
          error={list.error}
          empty={list.data?.length === 0}
          noun="rollouts"
        />
        {!list.error
          ? list.data?.map((state) =>
              state.rollout ? <RolloutCard key={state.rollout.rolloutId} state={state} /> : null,
            )
          : null}
        <TargetPagination
          afterId={afterId}
          nextId={list.data?.length === 100 ? list.data.at(-1)?.rollout?.rolloutId : undefined}
          busy={list.isFetching}
          onPage={setAfterId}
        />
      </CardContent>
    </Card>
  );
}

function RolloutCard({ state }: { state: RolloutState }) {
  const [operation, setOperation] = useState(ControlRolloutRequest_Operation.PAUSE);
  const rollout = state.rollout;
  if (!rollout) return null;
  return (
    <article className="grid min-w-0 gap-3 border p-4">
      <h3 className="break-all text-sm font-medium">Rollout {rollout.rolloutId}</h3>
      <p className="text-sm">
        Revision {state.revision.toString()} · ring{" "}
        {rollout.rings[state.ringIndex]?.name ?? "Not recorded"} ·{" "}
        <StatusBadge status={state.paused ? "warning" : "info"}>
          {state.paused ? "Paused" : "Running"}
        </StatusBadge>
      </p>
      {state.pauseReason ? <p className="text-sm">Pause reason: {state.pauseReason}</p> : null}
      <p className="text-sm">
        Selected {state.selectedCount} · pending {state.pendingCount} · excluded{" "}
        {state.excludedCount}
      </p>
      <details>
        <summary className="cursor-pointer text-sm">
          Complete rollout state and ring policies
        </summary>
        <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all text-xs">
          {toJsonString(RolloutStateSchema, state, { prettySpaces: 2 })}
        </pre>
      </details>
      <div className="grid gap-1.5">
        <Label htmlFor={`rollout-operation-${rollout.rolloutId}`}>Control operation</Label>
        <SelectField
          id={`rollout-operation-${rollout.rolloutId}`}
          value={String(operation)}
          onValueChange={(value) => {
            const next = Number(value);
            if (
              next === ControlRolloutRequest_Operation.PAUSE ||
              next === ControlRolloutRequest_Operation.RESUME ||
              next === ControlRolloutRequest_Operation.PROMOTE
            )
              setOperation(next);
          }}
          options={[
            { value: ControlRolloutRequest_Operation.PAUSE, label: "Pause" },
            { value: ControlRolloutRequest_Operation.RESUME, label: "Resume" },
            {
              value: ControlRolloutRequest_Operation.PROMOTE,
              label: "Promote (health gates still apply)",
            },
          ]}
        />
      </div>
      <TargetMutation
        key={`${rollout.rolloutId}:${state.revision}:${operation}`}
        title="Control rollout"
        formKey={`rollout-control:${rollout.rolloutId}:${operation}`}
        schema={ControlRolloutRequestSchema}
        initial={() =>
          create(ControlRolloutRequestSchema, {
            requestId: newRequestId(),
            rolloutId: rollout.rolloutId,
            expectedRevision: state.revision,
            operation,
          })
        }
        send={(request, signal) => adminClient.controlRollout(request, { signal })}
      />
    </article>
  );
}
