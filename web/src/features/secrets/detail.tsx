import { create, toJsonString } from "@bufbuild/protobuf";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { useId, useState, type FormEvent } from "react";
import { toast } from "sonner";
import {
  RotateSecretRequestSchema,
  type RotateSecretRequest,
  type SecretSummary,
} from "../../../gen/lindm/admin/v1/secrets_pb";
import { SecretRefSchema } from "../../../gen/lindm/resource/v1/common_pb";
import { useBreadcrumbTitle } from "@/components/layout/breadcrumb-title";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
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
import { adminClient } from "@/lib/rpc";
import { Timestamp } from "@/components/ui/timestamp";
import { MaterialField, purposeLabels, takeMaterial } from "./material";
import { secretQueryOptions } from "./queries";
import { SecretReveal } from "./reveal";
import { validateRequest } from "./validation";

export function SecretDetailView({ secretId }: { secretId: string }) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const detail = useQuery(secretQueryOptions(lifetime, secretId));
  const failure = detail.error ? toRpcFailure(detail.error) : null;
  const secret = failure ? undefined : detail.data?.secret;
  const versions = failure ? [] : (detail.data?.versions ?? []);
  const [selected, setSelected] = useState<bigint | null>(null);
  const [rotating, setRotating] = useState(false);
  const version = selected ?? secret?.currentVersion ?? 0n;
  const canManage = canPermission(principal, "secrets.manage", true);
  const canReveal = canPermission(principal, "secrets.reveal", true);
  useBreadcrumbTitle(secret ? secret.displayName.trim() || "Unnamed secret" : undefined);
  return (
    <section className="flex min-w-0 flex-col gap-6" aria-busy={detail.isFetching}>
      <Link
        to="/secrets"
        search={{ pageSize: 50, pageToken: "" }}
        className="flex w-fit items-center gap-2 text-sm text-muted-foreground hover:text-foreground focus-visible:underline"
      >
        <ArrowLeft className="size-4" aria-hidden="true" /> Back to secrets
      </Link>
      <PageHeader
        title={secret?.displayName.trim() || "Secret"}
        description="Values stay hidden unless you reveal them."
        actions={
          <>
            <Button
              variant="outline"
              disabled={detail.isFetching}
              onClick={() => void detail.refetch()}
            >
              Refresh
            </Button>
            {secret && canManage ? (
              <Button variant="outline" aria-haspopup="dialog" onClick={() => setRotating(true)}>
                Rotate secret
              </Button>
            ) : null}
          </>
        }
      />
      {failure ? <RpcError failure={failure} /> : null}
      {detail.isPending ? <p role="status">Loading secret…</p> : null}
      {secret ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="grid gap-4 break-words text-sm sm:grid-cols-2 lg:grid-cols-3 [&_dt]:text-xs [&_dt]:text-muted-foreground">
                <div>
                  <dt>Purpose</dt>
                  <dd>{purposeLabels[secret.purpose] ?? "Unrecognized purpose"}</dd>
                </div>
                <div>
                  <dt>Current version</dt>
                  <dd>{secret.currentVersion.toString()}</dd>
                </div>
                <div>
                  <dt>Created</dt>
                  <dd>
                    <Timestamp value={secret.createdAt} /> by{" "}
                    {secret.createdByDisplayName.trim() || "unknown"}
                  </dd>
                </div>
                <div>
                  <dt>Updated</dt>
                  <dd>
                    <Timestamp value={secret.updatedAt} />
                  </dd>
                </div>
              </dl>
              <div className="mt-4">
                <TechnicalDetails
                  items={[
                    { label: "Secret ID", value: secret.secretId },
                    { label: "Subject binding ID", value: secret.subjectBindingId },
                    { label: "Created by ID", value: secret.createdBy },
                    {
                      label: `Profile reference, version ${secret.currentVersion.toString()}`,
                      value: secretReferenceJson(secret, secret.currentVersion),
                    },
                  ]}
                />
              </div>
              <p className="mt-4 text-sm text-muted-foreground">
                To send it to devices, select this secret in a{" "}
                <Link to="/profiles" className="underline underline-offset-4">
                  profile
                </Link>{" "}
                setting of the same type. Devices get a new version only after you update the
                profile.
              </p>
            </CardContent>
          </Card>
          {canManage ? (
            <Dialog open={rotating} onOpenChange={setRotating}>
              <DialogContent keepMounted className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
                <DialogHeader>
                  <DialogTitle>Rotate {secret.displayName.trim() || "secret"}</DialogTitle>
                  <DialogDescription>
                    Saves version {(secret.currentVersion + 1n).toString()}. Devices keep the
                    current version until you update the profile.
                  </DialogDescription>
                </DialogHeader>
                <RotateSecretForm
                  key={secret.currentVersion.toString()}
                  secret={secret}
                  onRotated={() => setRotating(false)}
                />
              </DialogContent>
            </Dialog>
          ) : null}
          <Card>
            <CardHeader>
              <CardTitle>Versions</CardTitle>
              <CardDescription>Newest first. Old versions never change.</CardDescription>
            </CardHeader>
            <CardContent>
              {versions.length === 0 ? (
                <EmptyState title="No versions returned" />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Version</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Created by</TableHead>
                      <TableHead>Reason</TableHead>
                      {canReveal && versions.length > 1 ? <TableHead>Reveal</TableHead> : null}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {versions.map((entry) => (
                      <TableRow key={entry.version.toString()}>
                        <TableCell>
                          {entry.version.toString()}
                          {entry.version === secret.currentVersion ? (
                            <span className="text-muted-foreground"> (current)</span>
                          ) : null}
                        </TableCell>
                        <TableCell>
                          <Timestamp value={entry.createdAt} />
                        </TableCell>
                        <TableCell>{entry.createdByDisplayName.trim() || "Unknown"}</TableCell>
                        <TableCell className="min-w-48 max-w-md whitespace-normal break-words">
                          {entry.reason.trim() || "Not recorded"}
                        </TableCell>
                        {canReveal && versions.length > 1 ? (
                          <TableCell>
                            {entry.version === version ? (
                              <span className="text-sm text-muted-foreground">Selected</span>
                            ) : (
                              <Button variant="outline" onClick={() => setSelected(entry.version)}>
                                Select version {entry.version.toString()}
                              </Button>
                            )}
                          </TableCell>
                        ) : null}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
          {canReveal ? (
            <Card>
              <CardHeader>
                <CardTitle>Reveal version {version.toString()}</CardTitle>
                {versions.length > 1 ? (
                  <CardDescription>
                    Select another version in the table to reveal it.
                  </CardDescription>
                ) : null}
              </CardHeader>
              <CardContent>
                <SecretReveal
                  key={`${secret.secretId}:${version}`}
                  secretId={secret.secretId}
                  secretName={secret.displayName}
                  version={version}
                  approval={detail.data?.revealApproval}
                />
              </CardContent>
            </Card>
          ) : null}
        </>
      ) : null}
    </section>
  );
}

function secretReferenceJson(secret: SecretSummary, version: bigint): string {
  return toJsonString(
    SecretRefSchema,
    create(SecretRefSchema, {
      secretId: secret.secretId,
      version,
      purpose: secret.purpose,
      subjectBindingId: secret.subjectBindingId,
    }),
  );
}

function RotateSecretForm({ secret, onRotated }: { secret: SecretSummary; onRotated: () => void }) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const id = useId();
  const exact = useExactRequest<RotateSecretRequest>();
  const [reason, setReason] = useState("");
  const locked = exact.busy || exact.ambiguous;

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    void exact.submit({
      capture: () => {
        const material = takeMaterial(form, secret.purpose);
        const request = create(RotateSecretRequestSchema, {
          requestId: newRequestId(),
          secretId: secret.secretId,
          expectedVersion: secret.currentVersion,
          material,
          reason: reason.trim(),
        });
        try {
          validateRequest(RotateSecretRequestSchema, request);
        } catch (error) {
          material.material.value?.fill(0);
          throw error;
        }
        return request;
      },
      send: (request, options) => adminClient.rotateSecret(request, options),
      discard: (request) => request.material?.material.value?.fill(0),
      failureTitle: "Secret rotation",
      onSuccess: async (response) => {
        setReason("");
        onRotated();
        toast.success(`Version ${response.secret?.currentVersion.toString() ?? "unknown"} saved`, {
          description: "Update the profile to send it to devices.",
        });
        await Promise.all([
          queryClient.invalidateQueries({
            queryKey: ["secret", lifetime.generation, secret.secretId],
          }),
          queryClient.invalidateQueries({ queryKey: ["secrets", lifetime.generation] }),
        ]);
      },
    });
  }

  return (
    <form className="grid gap-4" onSubmit={submit} autoComplete="off">
      <MaterialField id={`${id}-material`} purpose={secret.purpose} disabled={locked} />
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
        <RpcError failure={exact.failure} title="Secret not rotated">
          {exact.ambiguous ? (
            <p>
              Refresh to see whether a new version was saved. Try again, or discard to start over.
            </p>
          ) : null}
        </RpcError>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={exact.busy}>
          {exact.busy ? "Storing…" : exact.ambiguous ? "Try again" : "Rotate secret"}
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
