import { toJsonString } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState, type ReactNode } from "react";
import {
  ProfileResourceSchema,
  type ProfileResource,
} from "../../../gen/lindm/policy/v1/profile_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { usePublishAttempt } from "./attempt";
import { ProfileEditor } from "./editor";
import {
  CATALOG_SEMANTICS,
  draftFromPayload,
  draftFromSpec,
  formatRevisionNumber,
  formatSha256,
  usableUuid,
  type DraftSpec,
} from "./model";
import { profileRevisionQueryOptions } from "./queries";
import type { ProfileDetailSearch } from "./search";

type EditorSource = {
  draft: DraftSpec;
  expectedRevisionId?: string;
  sourceNote: string;
};

export function ProfileDetailView({
  profileId,
  revision,
  onSearch,
}: {
  profileId: string;
  revision: string;
  onSearch: (next: ProfileDetailSearch) => void;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const displayed = useQuery(profileRevisionQueryOptions(lifetime, profileId, revision));
  const headQuery = useQuery({
    ...profileRevisionQueryOptions(lifetime, profileId, ""),
    enabled: revision !== "",
  });
  const attempt = usePublishAttempt(profileId);
  const [copyGeneration, setCopyGeneration] = useState(0);
  const [editorSource, setEditorSource] = useState<EditorSource | null>(null);
  const [lookup, setLookup] = useState("");
  const [lookupError, setLookupError] = useState("");
  const failure = displayed.error ? toRpcFailure(displayed.error) : null;
  const headFailure = revision !== "" && headQuery.error ? toRpcFailure(headQuery.error) : null;
  const record = failure ? undefined : displayed.data;
  const head = revision === "" ? record : headQuery.data;
  const isHead =
    revision === "" ||
    (record !== undefined && head !== undefined && record.revisionId === head.revisionId);
  const headLabel =
    revision === "" || isHead
      ? "This revision is the catalog head."
      : headQuery.isPending
        ? "This is an exact retained revision. Its catalog-head comparison is still loading."
        : headFailure
          ? "This is an exact retained revision. The catalog head could not be compared."
          : "This retained revision is not the catalog head.";
  const published = formatTimestamp(record?.publishedAt);

  function displayedSource(): EditorSource | null {
    if (!record?.spec || !head?.spec || headFailure) return null;
    return {
      draft: draftFromSpec(record.spec),
      expectedRevisionId: head.revisionId,
      sourceNote: `This editor was initialized from revision ${record.revisionId} against catalog head ${head.revisionId}. The expected revision below is the current compare-and-swap target.`,
    };
  }

  // Pin the editor independently of read-query errors, pending states and
  // exact-revision navigation. Only the explicit replacement action resets it.
  if (editorSource === null) {
    const source = displayedSource();
    if (source) setEditorSource(source);
    else if (attempt) {
      setEditorSource({
        draft: draftFromPayload(attempt.payload),
        expectedRevisionId: attempt.payload.expectedRevisionId,
        sourceNote:
          "This draft was initialized from the captured request. Refreshing catalog data does not change its saved expected revision.",
      });
    }
  }

  return (
    <section className="flex min-w-0 flex-col gap-6" aria-busy={displayed.isFetching}>
      <Link
        to="/profiles"
        search={{ pageSize: 50, pageToken: "" }}
        className="w-fit text-sm underline underline-offset-4"
      >
        Back to profiles
      </Link>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 space-y-2">
          <h1 className="break-words text-2xl font-semibold tracking-tight">
            {record?.spec?.name.trim() || "Resource profile"}
          </h1>
          <p className="break-all font-mono text-xs text-muted-foreground">{profileId}</p>
        </div>
        <Button
          variant="outline"
          disabled={displayed.isFetching}
          onClick={() => {
            void displayed.refetch();
            if (revision !== "") void headQuery.refetch();
          }}
        >
          Refresh revision
        </Button>
      </div>
      <p className="max-w-3xl text-sm text-muted-foreground">
        {revision === ""
          ? "This read selected the catalog head. "
          : "This read selected an exact retained revision. "}
        Reading it does not show whether any device is assigned to it or has applied it.{" "}
        {CATALOG_SEMANTICS}
      </p>
      <Card>
        <CardHeader>
          <CardTitle>Read an exact revision</CardTitle>
          <CardDescription>
            Leave this empty only by opening the catalog head. A revision ID reads that retained
            specification, even if it is no longer the head.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-wrap items-end gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              const canonical = usableUuid(lookup);
              if (canonical === null) {
                setLookupError("Enter a revision UUID.");
                return;
              }
              setLookupError("");
              onSearch({ revision: canonical });
            }}
          >
            <div className="grid min-w-0 grow basis-64 gap-1.5">
              <Label htmlFor="exact-revision">Exact revision ID</Label>
              <Input
                id="exact-revision"
                value={lookup}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) => setLookup(event.target.value)}
              />
            </div>
            <Button type="submit">Read exact revision</Button>
            <Button
              type="button"
              variant="outline"
              disabled={revision === ""}
              onClick={() => onSearch({ revision: "" })}
            >
              Catalog head
            </Button>
          </form>
          {lookupError !== "" ? (
            <p role="alert" className="mt-2 text-sm text-destructive">
              {lookupError}
            </p>
          ) : null}
        </CardContent>
      </Card>
      {failure ? (
        <Alert variant="destructive">
          <AlertTitle>
            {failure.denied ? "Not authorized" : "Profile revision unavailable"}
          </AlertTitle>
          <AlertDescription>
            {failure.codeName}: {failure.message}
          </AlertDescription>
        </Alert>
      ) : null}
      {displayed.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading profile revision…</span>
          <Skeleton className="h-40 w-full" />
        </div>
      ) : null}
      {record?.spec ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Revision</CardTitle>
              <CardDescription>{headLabel}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="mb-4 flex flex-wrap gap-2">
                <Badge variant={isHead ? "default" : "outline"}>
                  {isHead ? "Catalog head" : "Exact revision"}
                </Badge>
                {!isHead && head ? (
                  <Link
                    to="/profiles/$profileId"
                    params={{ profileId }}
                    search={{ revision: "" }}
                    className="text-sm underline underline-offset-4"
                  >
                    Open catalog head {head.revisionId}
                  </Link>
                ) : null}
              </div>
              <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <Fact label="Revision ID">{record.revisionId}</Fact>
                <Fact label="Revision number">{formatRevisionNumber(record.revisionNumber)}</Fact>
                <Fact label="Published">
                  {published.date ? (
                    <time dateTime={published.utc}>{published.local}</time>
                  ) : (
                    published.local
                  )}
                </Fact>
                <Fact label="Actor">{record.actorId.trim() || "Unknown actor"}</Fact>
                <Fact label="Spec SHA-256">{formatSha256(record.specSha256)}</Fact>
                <Fact label="Resources">{record.spec.resources.length}</Fact>
                <Fact label="Description">
                  {record.spec.description.trim() || "No description"}
                </Fact>
              </dl>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Resources</CardTitle>
              <CardDescription>
                Typed desired state, dependencies and ownership are catalog values, not native
                observations or proof of capability support.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3">
              {record.spec.resources.map((resource) => (
                <ResourceFacts key={resource.resourceId} resource={resource} />
              ))}
            </CardContent>
          </Card>
        </>
      ) : null}
      {headFailure ? (
        <Alert variant="destructive">
          <AlertTitle>Catalog head unavailable</AlertTitle>
          <AlertDescription>
            A new unsent draft cannot target the catalog head until it loads.
            {attempt ? " The open request can still be retried exactly." : ""}{" "}
            {headFailure.codeName}: {headFailure.message}
          </AlertDescription>
        </Alert>
      ) : null}
      {revision !== "" && headQuery.isPending ? (
        <p role="status" className="text-sm text-muted-foreground">
          Loading catalog head for compare-and-swap…
        </p>
      ) : null}
      {editorSource && canPermission(principal, "profiles.manage") ? (
        <div className="grid gap-3">
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              variant="outline"
              disabled={attempt !== null || !record?.spec || !head?.spec || headFailure !== null}
              onClick={() => {
                const source = displayedSource();
                if (!source || attempt) return;
                setEditorSource(source);
                setCopyGeneration((current) => current + 1);
              }}
            >
              Replace unsent draft with this revision
            </Button>
          </div>
          <p className="max-w-3xl text-sm text-muted-foreground">
            Refreshing the revision does not change a prepared draft, its expected revision, or a
            frozen request ID. A full browser reload or sign-out clears this tab's drafts and
            requests. Replacing the draft copies the revision shown above and targets the loaded
            catalog head. It does not publish.
          </p>
          <ProfileEditor
            key={`${profileId}:${copyGeneration}`}
            mode="edit"
            profileId={profileId}
            initialDraft={editorSource.draft}
            initialExpectedRevisionId={editorSource.expectedRevisionId}
            sourceNote={editorSource.sourceNote}
          />
        </div>
      ) : null}
    </section>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="mb-1 text-sm text-muted-foreground">{label}</dt>
      <dd className="break-words text-sm">{children}</dd>
    </div>
  );
}

function ResourceFacts({ resource }: { resource: ProfileResource }) {
  return (
    <article className="grid min-w-0 gap-3 border bg-muted/20 p-4">
      <h2 className="break-all text-sm font-medium">
        {resource.desired?.ref?.canonicalKey || "Resource reference not recorded"}
      </h2>
      <dl className="grid gap-3 sm:grid-cols-2">
        <Fact label="Resource ID">{resource.resourceId}</Fact>
        <Fact label="Kind">{resource.desired?.state.case ?? "Not recorded"}</Fact>
        <Fact label="Dependencies">
          {resource.dependsOn.length === 0
            ? "None"
            : resource.dependsOn
                .map(
                  (dependency) =>
                    `${dependency.ref?.kind ?? "Unknown"} / ${dependency.ref?.canonicalKey ?? "Unknown"} (condition ${dependency.condition})`,
                )
                .join(", ")}
        </Fact>
      </dl>
      <details>
        <summary className="cursor-pointer text-sm">Complete typed resource specification</summary>
        <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all text-xs">
          {toJsonString(ProfileResourceSchema, resource, { prettySpaces: 2 })}
        </pre>
      </details>
    </article>
  );
}
