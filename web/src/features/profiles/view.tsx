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
import { usePublishAttempts, type PublishStatus } from "./attempt";
import { CATALOG_SEMANTICS, formatRevisionNumber } from "./model";
import { profilesQueryOptions } from "./queries";
import { type ProfileListSearch } from "./search";

const PAGE_SIZES = [50, 100] as const;

const ATTEMPT_LABEL: Record<PublishStatus, string> = {
  inflight: "A profile is still saving.",
  ambiguous: "A save may not have gone through.",
  conflict: "A save was blocked by a newer change.",
  rejected: "A save was rejected.",
  published: "A profile was published.",
};

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
        description="Sets of device settings you can assign to devices."
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
      <p className="text-sm text-muted-foreground">{CATALOG_SEMANTICS}</p>
      {canPermission(principal, "profiles.manage") && attempts.length > 0 ? (
        <Alert>
          <AlertTitle>A profile hasn't finished saving</AlertTitle>
          <AlertDescription>
            <ul className="grid gap-1">
              {attempts.map((attempt) => (
                <li key={attempt.payload.requestId} className="break-all">
                  {ATTEMPT_LABEL[attempt.status]}{" "}
                  {attempt.mode === "create" ? (
                    <Link to="/profiles/new" className="underline underline-offset-4">
                      Continue creating it
                    </Link>
                  ) : (
                    <Link
                      to="/profiles/$profileId"
                      params={{ profileId: attempt.profileId }}
                      search={{ revision: "" }}
                      className="underline underline-offset-4"
                    >
                      Open the profile to finish
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
          <span className="text-sm text-muted-foreground">Loading profiles…</span>
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : null}
      {list.isSuccess && list.data.profiles.length === 0 ? (
        <EmptyState
          title={pageToken === "" ? "No profiles yet" : "No profiles on this page"}
          description="Create a profile, then assign it to devices in Rollouts."
        />
      ) : null}
      {list.data && list.data.profiles.length > 0 ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Description</TableHead>
              <TableHead>Settings</TableHead>
              <TableHead>Revision</TableHead>
              <TableHead>Published</TableHead>
              <TableHead>Published by</TableHead>
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
                      className="underline underline-offset-4"
                    >
                      {formatRevisionNumber(profile.revisionNumber)}
                    </Link>
                  </TableCell>
                  <TableCell className="whitespace-normal">
                    {published.date ? (
                      <time dateTime={published.utc}>
                        {published.local} ({freshnessLabel(published.date, now)})
                      </time>
                    ) : (
                      "Unknown"
                    )}
                  </TableCell>
                  <TableCell className="break-all">{profile.actorId.trim() || "Unknown"}</TableCell>
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
