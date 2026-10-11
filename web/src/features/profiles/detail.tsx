import { toJsonString } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState, type ReactNode } from "react";
import {
  ProfileResourceSchema,
  type ProfileResource,
} from "../../../gen/lindm/policy/v1/profile_pb";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import { ProfileRevisionPicker } from "./picker";

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
  const headKnown = record !== undefined && head !== undefined && headFailure === null;
  const revisionLabel = !headKnown
    ? "Saved revision"
    : isHead
      ? "Latest revision"
      : "Older revision";
  const headLabel = !headKnown
    ? headFailure
      ? "Couldn't check whether this is the latest revision."
      : "Checking whether this is the latest revision…"
    : isHead
      ? "This is the latest revision."
      : "This is an older revision. A newer one is available.";
  const published = formatTimestamp(record?.publishedAt);

  function displayedSource(): EditorSource | null {
    if (!record?.spec || !head?.spec || headFailure) return null;
    return {
      draft: draftFromSpec(record.spec),
      expectedRevisionId: head.revisionId,
      sourceNote: "This draft starts from the revision shown above.",
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
        sourceNote: "This draft keeps the changes you were saving.",
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
      <PageHeader
        title={record?.spec?.name.trim() || "Profile"}
        description={record?.spec?.description.trim() || undefined}
        actions={
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
        }
      />
      <p className="max-w-3xl text-sm text-muted-foreground">
        {revisionLabel}. {CATALOG_SEMANTICS}
      </p>
      <Card>
        <CardHeader>
          <CardTitle>Find a revision</CardTitle>
          <CardDescription>Choose a saved version to inspect.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-wrap items-end gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              const canonical = usableUuid(lookup);
              if (canonical === null) {
                setLookupError("Choose a revision.");
                return;
              }
              setLookupError("");
              onSearch({ revision: canonical });
            }}
          >
            <div className="grid min-w-0 grow basis-64 gap-1.5">
              <ProfileRevisionPicker
                label="Saved revision"
                profileId={profileId}
                value={lookup}
                onChange={setLookup}
              />
            </div>
            <Button type="submit">Open revision</Button>
            <Button
              type="button"
              variant="outline"
              disabled={revision === ""}
              onClick={() => onSearch({ revision: "" })}
            >
              Latest revision
            </Button>
          </form>
          {lookupError !== "" ? (
            <p role="alert" className="mt-2 text-sm text-destructive">
              {lookupError}
            </p>
          ) : null}
        </CardContent>
      </Card>
      {failure ? <RpcError failure={failure} /> : null}
      {displayed.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading profile…</span>
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
                <StatusBadge status={headKnown && isHead ? "info" : "neutral"}>
                  {revisionLabel}
                </StatusBadge>
                {headKnown && !isHead && head ? (
                  <Link
                    to="/profiles/$profileId"
                    params={{ profileId }}
                    search={{ revision: "" }}
                    className="text-sm underline underline-offset-4"
                  >
                    Open latest revision
                  </Link>
                ) : null}
              </div>
              <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <Fact label="Revision">{formatRevisionNumber(record.revisionNumber)}</Fact>
                <Fact label="Published">
                  {published.date ? (
                    <time dateTime={published.utc}>{published.local}</time>
                  ) : (
                    published.local
                  )}
                </Fact>
                <Fact label="Published by">
                  {!record.actorId.trim()
                    ? "The system"
                    : record.actorId === principal.id
                      ? "You"
                      : "Another administrator"}
                </Fact>
                <Fact label="Settings">{record.spec.resources.length}</Fact>
                <Fact label="Description">
                  {record.spec.description.trim() || "No description"}
                </Fact>
              </dl>
              <TechnicalDetails
                className="mt-4"
                items={[
                  { label: "Profile ID", value: profileId },
                  { label: "Revision ID", value: record.revisionId },
                  { label: "Publisher ID", value: record.actorId },
                  { label: "Spec SHA-256", value: formatSha256(record.specSha256) },
                ]}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Settings</CardTitle>
              <CardDescription>What this profile sets on assigned devices.</CardDescription>
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
        <RpcError failure={headFailure}>
          <p>
            Couldn't load the latest revision. Refresh before editing.
            {attempt ? " You can still retry saving your draft." : ""}
          </p>
        </RpcError>
      ) : null}
      {revision !== "" && headQuery.isPending ? (
        <p role="status" className="text-sm text-muted-foreground">
          Loading latest revision…
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
              Start over from this revision
            </Button>
          </div>
          <p className="max-w-3xl text-sm text-muted-foreground">
            Your draft is kept until you publish it or reload the page.
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
  const kind = resource.desired?.state.case;
  return (
    <article className="grid min-w-0 gap-3 border bg-muted/20 p-4">
      <h2 className="break-all text-sm font-medium">
        {kind === "sshServer"
          ? "SSH settings"
          : resource.desired?.ref?.canonicalKey || "Unnamed setting"}
      </h2>
      <dl className="grid gap-3 sm:grid-cols-2">
        <Fact label="Type">{kind === "sshServer" ? "SSH server" : (kind ?? "Unknown")}</Fact>
        <Fact label="Depends on">
          {resource.dependsOn.length === 0
            ? "None"
            : resource.dependsOn
                .map(
                  (dependency) =>
                    `${dependency.ref?.kind ?? "Unknown"} / ${dependency.ref?.canonicalKey ?? "Unknown"}`,
                )
                .join(", ")}
        </Fact>
      </dl>
      <TechnicalDetails
        summary="Full setting"
        items={[{ label: "Setting ID", value: resource.resourceId }]}
      >
        <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all text-xs">
          {toJsonString(ProfileResourceSchema, resource, { prettySpaces: 2 })}
        </pre>
      </TechnicalDetails>
    </article>
  );
}
