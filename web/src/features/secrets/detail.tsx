// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { useState } from "react";
import { SecretPurpose } from "../../../gen/lindm/resource/v1/common_pb";
import { useBreadcrumbTitle } from "@/components/layout/breadcrumb-title";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { toRpcFailure } from "@/lib/errors";
import { canPermission } from "@/lib/permissions";
import { Timestamp } from "@/components/ui/timestamp";
import { DeleteSecretDialog, RotateSecretDialog, SecretUsesList, secretName } from "./actions";
import { purposeLabels } from "./material";
import { secretQueryOptions, secretUsesQueryOptions } from "./queries";
import { SecretReveal } from "./reveal";

export function SecretDetailView({ secretId }: { secretId: string }) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const navigate = useNavigate();
  const detail = useQuery(secretQueryOptions(lifetime, secretId));
  const uses = useQuery(secretUsesQueryOptions(lifetime, secretId));
  const failure = detail.error ? toRpcFailure(detail.error) : null;
  const secret = failure ? undefined : detail.data?.secret;
  const versions = failure ? [] : (detail.data?.versions ?? []);
  const [selected, setSelected] = useState<bigint | null>(null);
  const [rotating, setRotating] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const version = selected ?? secret?.currentVersion ?? 0n;
  const canManage = canPermission(principal, "secrets.manage", true);
  const canReveal = canPermission(principal, "secrets.reveal", true);
  useBreadcrumbTitle(secret ? secretName(secret) : undefined);
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
        onRefresh={() => {
          void detail.refetch();
          void uses.refetch();
        }}
        refreshing={detail.isFetching || uses.isFetching}
        actions={
          secret && canManage ? (
            <>
              <Button variant="outline" aria-haspopup="dialog" onClick={() => setRotating(true)}>
                Rotate secret
              </Button>
              <Button
                variant="destructive"
                aria-haspopup="dialog"
                onClick={() => setDeleting(true)}
              >
                Remove secret
              </Button>
            </>
          ) : null
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
                  ]}
                />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Where it&apos;s used</CardTitle>
              <CardDescription>
                Profiles in their current version, and devices that receive it now.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3">
              {uses.error ? (
                <RpcError failure={toRpcFailure(uses.error)} title="Uses not loaded" />
              ) : uses.data ? (
                <SecretUsesList uses={uses.data} currentVersion={secret.currentVersion} />
              ) : (
                <p role="status" className="text-sm text-muted-foreground">
                  Finding where it&apos;s used…
                </p>
              )}
              {editorSettings[secret.purpose] ? (
                <p className="text-sm text-muted-foreground">
                  To use it,{" "}
                  <Link to="/profiles" className="underline underline-offset-4">
                    edit a profile
                  </Link>
                  , add {editorSettings[secret.purpose]} and choose {secretName(secret)} in its
                  secret picker. Devices get a new version only after you update the profile.
                </p>
              ) : (
                <p className="text-sm text-muted-foreground">
                  The{" "}
                  <Link to="/profiles" className="underline underline-offset-4">
                    profile editor
                  </Link>{" "}
                  can&apos;t add {otherSettings[secret.purpose] ?? "settings of this type"} yet, so
                  it can&apos;t choose this secret there.
                </p>
              )}
            </CardContent>
          </Card>
          {canManage ? (
            <>
              <RotateSecretDialog secret={secret} open={rotating} onOpenChange={setRotating} />
              <DeleteSecretDialog
                secret={secret}
                open={deleting}
                onOpenChange={setDeleting}
                onDeleted={() =>
                  void navigate({ to: "/secrets", search: { pageSize: 50, pageToken: "" } })
                }
              />
            </>
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

// Settings that accept each purpose (resource secret fields): the profile
// editor offers local accounts and package repositories; the others exist only
// in profiles it keeps as they are.
const editorSettings: Partial<Record<SecretPurpose, string>> = {
  [SecretPurpose.PASSWORD_HASH]: "a local user with a hashed password",
  [SecretPurpose.REPOSITORY_AUTHENTICATION]: "a package repository that signs in",
};
const otherSettings: Partial<Record<SecretPurpose, string>> = {
  [SecretPurpose.WIFI_PSK]: "Wi-Fi network connections",
  [SecretPurpose.EAP_PASSWORD]: "network connections that sign in with EAP",
  [SecretPurpose.VPN_AUTHENTICATION]: "VPN connections",
  [SecretPurpose.WIREGUARD_PRIVATE_KEY]: "WireGuard VPN connections",
  [SecretPurpose.WIREGUARD_PRESHARED_KEY]: "WireGuard VPN connections",
  [SecretPurpose.PROXY_AUTHENTICATION]: "proxies",
  [SecretPurpose.DIRECTORY_JOIN]: "directory connections",
};
