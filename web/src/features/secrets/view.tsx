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
import { ListPagination } from "@/components/ui/list-pagination";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
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
import { Skeleton } from "@/components/ui/skeleton";
import { Timestamp } from "@/components/ui/timestamp";
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
import { SecretRowActions } from "./actions";
import { MaterialField, purposeLabels, purposeOptions, takeMaterial } from "./material";
import { secretsQueryOptions } from "./queries";
import { validateRequest } from "@/lib/validation";
import { secretMaterialHints } from "./validation";

export function SecretsView({
  pageSize,
  pageToken,
  onSearch,
  onCreated,
  creating,
  onCreatingChange,
}: {
  pageSize: PageSize;
  pageToken: string;
  onSearch: (next: { pageSize: PageSize; pageToken: string }) => void;
  onCreated: (secretId: string) => void;
  creating: boolean;
  onCreatingChange: (creating: boolean) => void;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const queryClient = useQueryClient();
  const list = useQuery(secretsQueryOptions(lifetime, pageSize, pageToken));
  const pagination = useListPagination({ pageSize, pageToken }, onSearch);
  const failure = list.error ? toRpcFailure(list.error) : null;
  const canCreate = canPermission(principal, "secrets.manage", true);
  return (
    <section className="flex min-w-0 flex-col gap-6" aria-busy={list.isFetching}>
      <PageHeader
        title="Secrets"
        description="Store passwords and keys for profiles. This list does not show secret values."
        onRefresh={() => {
          void list.refetch();
          void queryClient.invalidateQueries({ queryKey: ["secret-uses", lifetime.generation] });
        }}
        refreshing={list.isFetching}
        actions={
          canCreate ? (
            <Button aria-haspopup="dialog" onClick={() => onCreatingChange(true)}>
              Create secret
            </Button>
          ) : null
        }
      />
      {canCreate ? (
        <Dialog open={creating} onOpenChange={onCreatingChange}>
          <DialogContent keepMounted className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>Create secret</DialogTitle>
              <DialogDescription>You cannot change the purpose later.</DialogDescription>
            </DialogHeader>
            <CreateSecretForm
              onCreated={(secretId) => {
                onCreatingChange(false);
                onCreated(secretId);
              }}
            />
          </DialogContent>
        </Dialog>
      ) : null}
      {failure ? <RpcError failure={failure} /> : null}
      {list.isPending ? (
        <div role="status" className="grid gap-3 border p-4">
          <span className="text-sm text-muted-foreground">Loading secrets…</span>
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : null}
      {list.isSuccess && list.data.secrets.length === 0 ? (
        pageToken === "" ? (
          <EmptyState
            title="No secrets stored"
            description="Store a Wi-Fi key, password hash or other credential. Select the secret in a profile."
            action={
              canCreate ? (
                <Button aria-haspopup="dialog" onClick={() => onCreatingChange(true)}>
                  Create secret
                </Button>
              ) : null
            }
          />
        ) : (
          <EmptyState
            title="No more secrets"
            action={
              <Button variant="outline" onClick={pagination.previous}>
                {pagination.previousLabel}
              </Button>
            }
          />
        )
      ) : null}
      {list.data && list.data.secrets.length > 0 ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Purpose</TableHead>
              {/* Version history and authorship are on the secret page; on narrow
                  screens the row keeps its name, purpose and actions in view. */}
              <TableHead className="hidden md:table-cell">Current version</TableHead>
              <TableHead className="hidden md:table-cell">Updated</TableHead>
              <TableHead className="hidden md:table-cell">Created by</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
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
                <TableCell className="whitespace-normal">
                  {purposeLabels[secret.purpose] ?? "Unrecognized purpose"}
                </TableCell>
                <TableCell className="hidden md:table-cell">
                  {secret.currentVersion.toString()}
                </TableCell>
                <TableCell className="hidden md:table-cell">
                  <Timestamp value={secret.updatedAt} />
                </TableCell>
                <TableCell className="hidden md:table-cell">
                  {secret.createdByDisplayName.trim() || "Unknown"}
                </TableCell>
                <TableCell className="w-10 text-right">
                  <SecretRowActions secret={secret} canManage={canCreate} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : null}
      <ListPagination
        label="Secret pages"
        previousLabel={pagination.previousLabel}
        onPrevious={pageToken === "" ? undefined : pagination.previous}
        onNext={
          list.data?.nextPageToken
            ? () => pagination.next(list.data?.nextPageToken ?? "")
            : undefined
        }
        busy={list.isFetching}
        pageSize={pageSize}
        pageSizes={PAGE_SIZES}
        onPageSizeChange={(next) => {
          if (next === 50 || next === 100 || next === 200)
            onSearch({ pageSize: next, pageToken: "" });
        }}
      />
    </section>
  );
}

function CreateSecretForm({ onCreated }: { onCreated: (secretId: string) => void }) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const id = useId();
  const exact = useExactRequest<CreateSecretRequest>();
  const [displayName, setDisplayName] = useState("");
  const [purpose, setPurpose] = useState(SecretPurpose.UNSPECIFIED);
  const chosen = purpose !== SecretPurpose.UNSPECIFIED;
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
          validateRequest(CreateSecretRequestSchema, request, secretMaterialHints);
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
        setPurpose(SecretPurpose.UNSPECIFIED);
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
          options={[
            { value: SecretPurpose.UNSPECIFIED, label: "Choose a purpose", disabled: true },
            ...purposeOptions,
          ]}
        />
      </div>
      {chosen ? (
        <MaterialField key={purpose} id={`${id}-material`} purpose={purpose} disabled={locked} />
      ) : null}
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
        <Button
          type="submit"
          disabled={exact.busy || !chosen}
          aria-describedby={chosen ? undefined : `${id}-prerequisite`}
        >
          {exact.busy ? "Storing…" : exact.ambiguous ? "Try again" : "Create secret"}
        </Button>
        {exact.ambiguous ? (
          <Button type="button" variant="outline" disabled={exact.busy} onClick={exact.reset}>
            Discard
          </Button>
        ) : null}
      </div>
      {chosen ? null : (
        <p id={`${id}-prerequisite`} className="text-sm text-muted-foreground">
          Choose a purpose to enter the value.
        </p>
      )}
    </form>
  );
}
