import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
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
  const list = useQuery(profilesQueryOptions(lifetime, pageSize, pageToken));
  const pagination = useListPagination({ pageSize, pageToken }, onSearch);
  const attempts = usePublishAttempts();
  const failure = list.error ? toRpcFailure(list.error) : null;
  const now = new Date();

  return (
    <section className="flex min-w-0 flex-col gap-4" aria-busy={list.isFetching}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold">Service profiles</h1>
          <p className="max-w-3xl text-sm text-muted-foreground">
            These rows are catalog heads. {CATALOG_SEMANTICS}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" disabled={list.isFetching} onClick={() => void list.refetch()}>
            Refresh
          </Button>
          <Button render={<Link to="/profiles/new" />}>Publish a profile</Button>
        </div>
      </div>
      {attempts.length > 0 ? (
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
        <Alert variant="destructive">
          <AlertTitle>{failure.denied ? "Not authorized" : "Profile list failed"}</AlertTitle>
          <AlertDescription>
            {failure.codeName}: {failure.message}
          </AlertDescription>
        </Alert>
      ) : null}
      <div className="flex items-center gap-2 text-sm">
        <Label htmlFor="profile-page-size">Page size</Label>
        <select
          id="profile-page-size"
          className="h-8 rounded-lg border border-input bg-background px-2"
          value={pageSize}
          onChange={(event) => {
            const next = Number(event.target.value);
            if (next === 50 || next === 100) onSearch({ pageSize: next, pageToken: "" });
          }}
        >
          {PAGE_SIZES.map((size) => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </select>
      </div>
      {list.isPending ? <p role="status">Loading service profiles…</p> : null}
      {list.isSuccess && list.data.profiles.length === 0 ? (
        <p role="status">
          {pageToken === ""
            ? "No service profiles are in the catalog."
            : "This page has no service profiles."}
        </p>
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
