import { create } from "@bufbuild/protobuf";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useId, useState, type FormEvent } from "react";
import { toast } from "sonner";
import {
  CreateSecretRequestSchema,
  type CreateSecretRequest,
} from "../../../gen/lindm/admin/v1/secrets_pb";
import { SecretPurpose } from "../../../gen/lindm/resource/v1/common_pb";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { Skeleton } from "@/components/ui/skeleton";
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
import { useListPagination } from "@/hooks/use-list-pagination";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { PAGE_SIZES, type PageSize } from "@/lib/list-search";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import { MaterialField, purposeLabels, purposeOptions, takeMaterial } from "./material";
import { secretsQueryOptions } from "./queries";
import { validateRequest } from "./validation";

export function SecretsView({
  pageSize,
  pageToken,
  onSearch,
  onCreated,
}: {
  pageSize: PageSize;
  pageToken: string;
  onSearch: (next: { pageSize: PageSize; pageToken: string }) => void;
  onCreated: (secretId: string) => void;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const list = useQuery(secretsQueryOptions(lifetime, pageSize, pageToken));
  const pagination = useListPagination({ pageSize, pageToken }, onSearch);
  const failure = list.error ? toRpcFailure(list.error) : null;
  return (
    <section className="flex min-w-0 flex-col gap-6" aria-busy={list.isFetching}>
      <PageHeader
        title="Secrets"
        description="Passwords and keys that profiles can use. Values are never shown in this list."
        actions={
          <Button variant="outline" onClick={() => void list.refetch()} disabled={list.isFetching}>
            Refresh
          </Button>
        }
      />
      {canPermission(principal, "secrets.manage", true) ? (
        <CreateSecretForm onCreated={onCreated} />
      ) : null}
      {failure ? <RpcError failure={failure} /> : null}
      <div className="flex flex-wrap items-center gap-2 border-y py-3 text-sm">
        <Label htmlFor="secrets-page-size">Page size</Label>
        <SelectField
          id="secrets-page-size"
          className="h-9"
          value={pageSize}
          onValueChange={(value) => {
            const next = Number(value);
            if (next === 50 || next === 100 || next === 200) {
              onSearch({ pageSize: next, pageToken: "" });
            }
          }}
          options={PAGE_SIZES.map((size) => ({ value: size, label: size }))}
        />
      </div>
      {list.isPending ? (
        <div role="status" className="grid gap-3 border p-4">
          <span className="text-sm text-muted-foreground">Loading secrets…</span>
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : null}
      {list.isSuccess && list.data.secrets.length === 0 ? (
        <EmptyState title={pageToken === "" ? "No secrets stored" : "No secrets on this page"} />
      ) : null}
      {list.data && list.data.secrets.length > 0 ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Purpose</TableHead>
              <TableHead>Current version</TableHead>
              <TableHead>Updated</TableHead>
              <TableHead>Created by</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.data.secrets.map((secret) => (
              <TableRow key={secret.secretId}>
                <TableCell className="whitespace-normal break-words">
                  <Link
                    to="/secrets/$secretId"
                    params={{ secretId: secret.secretId }}
                    className="underline underline-offset-4"
                  >
                    {secret.displayName.trim() || "Unnamed secret"}
                  </Link>
                </TableCell>
                <TableCell>{purposeLabels[secret.purpose] ?? "Unrecognized purpose"}</TableCell>
                <TableCell>{secret.currentVersion.toString()}</TableCell>
                <TableCell>{formatTimestamp(secret.updatedAt).local}</TableCell>
                <TableCell>{secret.createdByDisplayName.trim() || "Unknown"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : null}
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" disabled={pageToken === ""} onClick={pagination.previous}>
          {pagination.previousLabel}
        </Button>
        <Button
          variant="outline"
          disabled={!list.data?.nextPageToken}
          onClick={() => pagination.next(list.data?.nextPageToken ?? "")}
        >
          Next page
        </Button>
      </div>
    </section>
  );
}

function CreateSecretForm({ onCreated }: { onCreated: (secretId: string) => void }) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const id = useId();
  const exact = useExactRequest<CreateSecretRequest>();
  const [displayName, setDisplayName] = useState("");
  const [purpose, setPurpose] = useState(SecretPurpose.PASSWORD_HASH);
  const [reason, setReason] = useState("");
  const locked = exact.busy || exact.ambiguous;

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    void exact.submit({
      capture: () => {
        const material = takeMaterial(form, purpose);
        const request = create(CreateSecretRequestSchema, {
          requestId: newRequestId(),
          purpose,
          displayName: displayName.trim(),
          material,
          reason: reason.trim(),
        });
        try {
          validateRequest(CreateSecretRequestSchema, request);
        } catch (error) {
          material.material.value?.fill(0);
          throw error;
        }
        return request;
      },
      send: (request, options) => adminClient.createSecret(request, options),
      discard: (request) => request.material?.material.value?.fill(0),
      failureTitle: "Secret creation",
      onSuccess: async (response) => {
        setDisplayName("");
        setReason("");
        toast.success("Secret created", {
          description: "Select it in a profile to send it to devices.",
        });
        await queryClient.invalidateQueries({ queryKey: ["secrets", lifetime.generation] });
        if (response.secret?.secretId) onCreated(response.secret.secretId);
      },
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Create secret</CardTitle>
        <CardDescription>You can't change the purpose later.</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="grid gap-4" onSubmit={submit} autoComplete="off">
          <div className="grid gap-2">
            <Label htmlFor={`${id}-name`}>Display name</Label>
            <Input
              id={`${id}-name`}
              data-freeform="new secret display name"
              value={displayName}
              readOnly={locked}
              maxLength={128}
              onChange={(event) => setDisplayName(event.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor={`${id}-purpose`}>Purpose</Label>
            <SelectField
              id={`${id}-purpose`}
              value={purpose}
              disabled={locked}
              onValueChange={(value) => setPurpose(Number(value) as SecretPurpose)}
              options={purposeOptions}
            />
          </div>
          <MaterialField key={purpose} id={`${id}-material`} purpose={purpose} disabled={locked} />
          <div className="grid gap-2">
            <Label htmlFor={`${id}-reason`}>Reason</Label>
            <Textarea
              id={`${id}-reason`}
              data-freeform="audit reason"
              value={reason}
              readOnly={locked}
              onChange={(event) => setReason(event.target.value)}
            />
          </div>
          {exact.invalid ? (
            <p role="alert" className="text-sm text-destructive">
              {exact.invalid}
            </p>
          ) : null}
          {exact.failure ? (
            <RpcError failure={exact.failure} title="Secret not created">
              {exact.ambiguous ? (
                <p>
                  Check the list to see whether it was created. Try again, or discard to start over.
                </p>
              ) : null}
            </RpcError>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={exact.busy}>
              {exact.busy ? "Storing…" : exact.ambiguous ? "Try again" : "Create secret"}
            </Button>
            {exact.ambiguous ? (
              <Button type="button" variant="outline" disabled={exact.busy} onClick={exact.reset}>
                Discard
              </Button>
            ) : null}
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
