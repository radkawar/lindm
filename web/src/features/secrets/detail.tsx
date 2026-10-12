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
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import { formatTimestamp } from "@/lib/time";
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
  const version = selected ?? secret?.currentVersion ?? 0n;
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
          <Button
            variant="outline"
            disabled={detail.isFetching}
            onClick={() => void detail.refetch()}
          >
            Refresh
          </Button>
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
                    {formatTimestamp(secret.createdAt).local} by{" "}
                    {secret.createdByDisplayName.trim() || "unknown"}
                  </dd>
                </div>
                <div>
                  <dt>Updated</dt>
                  <dd>{formatTimestamp(secret.updatedAt).local}</dd>
                </div>
              </dl>
              <div className="mt-4">
                <TechnicalDetails
                  items={[
                    { label: "Secret ID", value: secret.secretId },
                    { label: "Subject binding ID", value: secret.subjectBindingId },
                    { label: "Created by ID", value: secret.createdBy },
                  ]}
                />
              </div>
            </CardContent>
          </Card>
          <SecretReferenceCard secret={secret} version={version} />
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
                      <TableHead>Selection</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {versions.map((entry) => (
                      <TableRow key={entry.version.toString()}>
                        <TableCell>{entry.version.toString()}</TableCell>
                        <TableCell>{formatTimestamp(entry.createdAt).local}</TableCell>
                        <TableCell>{entry.createdByDisplayName.trim() || "Unknown"}</TableCell>
                        <TableCell className="min-w-48 max-w-md whitespace-normal break-words">
                          {entry.reason.trim() || "Not recorded"}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={entry.version === version}
                            aria-pressed={entry.version === version}
                            onClick={() => setSelected(entry.version)}
                          >
                            {entry.version === version ? "Selected" : "Select version"}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
          {canPermission(principal, "secrets.manage", true) ? (
            <RotateSecretForm key={secret.currentVersion.toString()} secret={secret} />
          ) : null}
          {canPermission(principal, "secrets.reveal", true) ? (
            <Card>
              <CardHeader>
                <CardTitle>Reveal version {version.toString()}</CardTitle>
                <CardDescription>Select another version in the table to reveal it.</CardDescription>
              </CardHeader>
              <CardContent>
                <SecretReveal
                  key={`${secret.secretId}:${version}`}
                  secretId={secret.secretId}
                  secretName={secret.displayName}
                  version={version}
                />
              </CardContent>
            </Card>
          ) : null}
        </>
      ) : null}
    </section>
  );
}

function SecretReferenceCard({ secret, version }: { secret: SecretSummary; version: bigint }) {
  const json = toJsonString(
    SecretRefSchema,
    create(SecretRefSchema, {
      secretId: secret.secretId,
      version,
      purpose: secret.purpose,
      subjectBindingId: secret.subjectBindingId,
    }),
    { prettySpaces: 2 },
  );
  return (
    <Card>
      <CardHeader>
        <CardTitle>Use version {version.toString()} in a profile</CardTitle>
        <CardDescription>
          Copy this and paste it into a profile field of the same type. Devices get a new version
          only after you update the profile.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border p-3 text-xs">
          {json}
        </pre>
        <Button
          className="w-fit"
          variant="outline"
          onClick={() =>
            void navigator.clipboard.writeText(json).then(
              () => toast.success("Copied"),
              () =>
                toast.error("Couldn't copy", {
                  description: "Select the text and copy it instead.",
                }),
            )
          }
        >
          Copy
        </Button>
      </CardContent>
    </Card>
  );
}

function RotateSecretForm({ secret }: { secret: SecretSummary }) {
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
    <Card>
      <CardHeader>
        <CardTitle>Rotate secret</CardTitle>
        <CardDescription>
          Saves a new version {(secret.currentVersion + 1n).toString()}. Devices keep the current
          version until you update the profile.
        </CardDescription>
      </CardHeader>
      <CardContent>
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
                  Refresh to see whether a new version was saved. Try again, or discard to start
                  over.
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
      </CardContent>
    </Card>
  );
}
