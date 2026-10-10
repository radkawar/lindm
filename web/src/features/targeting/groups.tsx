import { create, toJsonString } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
  DynamicTargetGroupSchema,
  PutDynamicGroupRequestSchema,
} from "../../../gen/lindm/admin/v1/targeting_pb";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { TargetMutation } from "./mutation";
import { dynamicGroupsQueryOptions } from "./queries";
import { ListStatus, TargetPagination } from "./list";

export function DynamicGroupsView() {
  const lifetime = useAuthLifetime();
  const [afterId, setAfterId] = useState("");
  const list = useQuery(dynamicGroupsQueryOptions(lifetime, afterId));
  return (
    <section className="grid min-w-0 gap-6" aria-busy={list.isFetching}>
      <header className="space-y-2">
        <h2 className="text-2xl font-semibold tracking-tight">Dynamic targeting groups</h2>
        <p className="max-w-3xl text-sm text-muted-foreground">
          Static targets use the existing authorization device groups. Dynamic groups evaluate typed
          inventory predicates and static group references; they never grant authorization
          membership. Missing or stale inventory remains unknown, not an automatic inclusion.
        </p>
      </header>
      <TargetMutation
        title="Create dynamic group"
        formKey="dynamic-group:new"
        schema={PutDynamicGroupRequestSchema}
        initial={() =>
          create(PutDynamicGroupRequestSchema, {
            requestId: newRequestId(),
            group: { groupId: newRequestId() },
            expectedRevision: 0n,
          })
        }
        send={(request, signal) => adminClient.putDynamicGroup(request, { signal })}
      />
      <Button
        className="w-fit"
        variant="outline"
        disabled={list.isFetching}
        onClick={() => void list.refetch()}
      >
        Refresh dynamic groups
      </Button>
      <ListStatus
        pending={list.isPending}
        error={list.error}
        empty={list.data?.length === 0}
        noun="dynamic groups"
      />
      {!list.error
        ? list.data?.map((group) => (
            <Card key={group.groupId}>
              <CardHeader>
                <CardTitle>{group.name}</CardTitle>
                <CardDescription>
                  Group {group.groupId} · revision {group.revision.toString()}
                </CardDescription>
              </CardHeader>
              <CardContent className="grid min-w-0 gap-3">
                <details>
                  <summary className="cursor-pointer text-sm">Current typed definition</summary>
                  <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all text-xs">
                    {toJsonString(DynamicTargetGroupSchema, group, { prettySpaces: 2 })}
                  </pre>
                </details>
                <TargetMutation
                  key={`${group.groupId}:${group.revision}`}
                  title="Update dynamic group"
                  formKey={`dynamic-group:${group.groupId}`}
                  schema={PutDynamicGroupRequestSchema}
                  initial={() =>
                    create(PutDynamicGroupRequestSchema, {
                      requestId: newRequestId(),
                      group,
                      expectedRevision: group.revision,
                    })
                  }
                  send={(request, signal) => adminClient.putDynamicGroup(request, { signal })}
                />
              </CardContent>
            </Card>
          ))
        : null}
      <TargetPagination
        afterId={afterId}
        nextId={list.data?.length === 100 ? list.data.at(-1)?.groupId : undefined}
        busy={list.isFetching}
        onPage={setAfterId}
      />
    </section>
  );
}
