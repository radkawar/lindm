import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
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
import { canPermission } from "@/lib/permissions";
import { useListPagination } from "@/hooks/use-list-pagination";
import { toRpcFailure } from "@/lib/errors";
import type { PageSize } from "@/lib/list-search";
import { formatTimestamp, freshnessLabel } from "@/lib/time";
import { usePublishAttempts } from "./attempt";
import { CATALOG_SEMANTICS, formatRevisionNumber, formatSha256 } from "./model";
import { profilesQueryOptions } from "./queries";
import { type ProfileListSearch } from "./search";

const PAGE_SIZES = [50, 100] as const;

export function ProfilesView({
  pageSize,
  pageToken,
  onSearch,
}: {
  pageSize: ProfileListSearch["pageSize"];
  pageToken: string;
  onSearch: (next: { pageSize: PageSize; pageToken: string }) => void;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const list = useQuery(profilesQueryOptions(lifetime, pageSize, pageToken));
  const pagination = useListPagination({ pageSize, pageToken }, onSearch);
  const attempts = usePublishAttempts();
  const failure = list.error ? toRpcFailure(list.error) : null;
  const now = new Date();

  return (
    <section className="flex min-w-0 flex-col gap-6" aria-busy={list.isFetching}>
      <PageHeader
        title="Profiles"
        description="Reusable resource configurations. Each row shows the latest published revision."
        actions={
          <>
            <Button
              variant="outline"
              disabled={list.isFetching}
              onClick={() => void list.refetch()}
            >
              Refresh
            </Button>
            {canPermission(principal, "profiles.manage") ? (
              <Button render={<Link to="/profiles/new" />}>Create profile</Button>
            ) : null}
          </>
        }
      />
      <details className="text-xs text-muted-foreground">
        <summary className="w-fit cursor-pointer py-1">Publishing and deployment</summary>
        <p className="mt-2">{CATALOG_SEMANTICS}</p>
      </details>
      {canPermission(principal, "profiles.manage") && attempts.length > 0 ? (
        <Alert>
          <AlertTitle>A publish request is still open</AlertTitle>
          <AlertDescription>
            <ul className="grid gap-1">
              {attempts.map((attempt) => (
                <li key={attempt.payload.requestId} className="break-all">
                  Request {attempt.payload.requestId} for profile {attempt.profileId} is{" "}
                  {attempt.status}.{" "}
                  {attempt.mode === "create" ? (
                    <Link to="/profiles/new" className="underline underline-offset-4">
                      Resume on the create page
                    </Link>
                  ) : (
                    <Link
                      to="/profiles/$profileId"
                      params={{ profileId: attempt.profileId }}
                      search={{ revision: "" }}
                      className="underline underline-offset-4"
                    >
                      Resume this profile
                    </Link>
                  )}
                </li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      ) : null}
      {failure ? (
        <RpcError failure={failure}>
          {list.data ? <p>The profiles below are from the last successful refresh.</p> : null}
        </RpcError>
      ) : null}
      <div className="flex flex-wrap items-center gap-2 border-y py-3 text-sm">
        <Label htmlFor="profile-page-size">Page size</Label>
        <SelectField
          id="profile-page-size"
          className="h-9"
          value={pageSize}
          onValueChange={(value) => {
            const next = Number(value);
            if (next === 50 || next === 100) onSearch({ pageSize: next, pageToken: "" });
          }}
          options={PAGE_SIZES.map((size) => ({ value: size, label: size }))}
        />
      </div>
      {list.isPending ? (
        <div role="status" className="grid gap-3 border p-4">
          <span className="text-sm text-muted-foreground">Loading resource profiles…</span>
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : null}
      {list.isSuccess && list.data.profiles.length === 0 ? (
        <EmptyState
          title={pageToken === "" ? "No profiles yet" : "No profiles on this page"}
          description="Create a profile here, then assign its published revision in Rollouts."
        />
      ) : null}
      {list.data && list.data.profiles.length > 0 ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Description</TableHead>
              <TableHead>Resources</TableHead>
              <TableHead>Revision</TableHead>
              <TableHead>Published</TableHead>
              <TableHead>Actor</TableHead>
              <TableHead>Profile ID</TableHead>
              <TableHead>Spec SHA-256</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.data.profiles.map((profile) => {
              const published = formatTimestamp(profile.publishedAt);
              return (
                <TableRow key={profile.profileId}>
                  <TableCell className="whitespace-normal">
                    <Link
                      to="/profiles/$profileId"
                      params={{ profileId: profile.profileId }}
                      search={{ revision: "" }}
                      className="font-medium underline underline-offset-4"
                    >
                      {profile.name.trim() || "Unnamed profile"}
                    </Link>
                  </TableCell>
                  <TableCell className="max-w-sm whitespace-normal">
                    <p className="line-clamp-2 break-words">
                      {profile.description.trim() || "No description"}
                    </p>
                  </TableCell>
                  <TableCell>{profile.resourceCount}</TableCell>
                  <TableCell>
                    <Link
                      to="/profiles/$profileId"
                      params={{ profileId: profile.profileId }}
                      search={{ revision: profile.revisionId }}
                      className="break-all font-mono text-xs underline underline-offset-4"
                    >
                      {formatRevisionNumber(profile.revisionNumber)} {profile.revisionId}
                    </Link>
                  </TableCell>
                  <TableCell className="whitespace-normal">
                    {published.date ? (
                      <time dateTime={published.utc}>
                        {published.local} ({freshnessLabel(published.date, now)})
                      </time>
                    ) : (
                      "Not recorded"
                    )}
                  </TableCell>
                  <TableCell className="break-all font-mono text-xs">
                    {profile.actorId.trim() || "Unknown actor"}
                  </TableCell>
                  <TableCell className="break-all font-mono text-xs">{profile.profileId}</TableCell>
                  <TableCell className="break-all font-mono text-xs">
                    {formatSha256(profile.specSha256)}
                  </TableCell>
                </TableRow>
              );
            })}
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
