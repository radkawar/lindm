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
import { Timestamp } from "@/components/ui/timestamp";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { toRpcFailure } from "@/lib/errors";
import { settingTechnicalIds, settingTitle } from "@/lib/setting-identity";
import { applicabilityFeatures, applicabilityPlatforms } from "@/lib/resource-labels";
import { usePublishAttempt } from "./attempt";
import { ProfileEditor } from "./editor";
import {
  draftFromPayload,
  draftFromSpec,
  formatRevisionNumber,
  formatSha256,
  publisherLabel,
  usableUuid,
  type DraftSpec,
} from "./model";
import { profileRevisionQueryOptions } from "./queries";
import type { ProfileDetailSearch } from "./search";
import { ProfileRevisionPicker } from "./picker";
import { desiredField, resourceKinds } from "./resource-draft";

// Setting types in administrator words; the generated arm name stays in Details.
function kindLabel(arm: string | undefined) {
  return resourceKinds.find((entry) => entry.arm === arm)?.label ?? "Other setting type";
}
// ResourceRef.kind numbers follow the desired-state field numbers (see withDerivedRef).
function refKindLabel(kind: number | undefined) {
  return kindLabel(
    resourceKinds.find((entry) => (desiredField(entry.arm)?.number ?? 0) - 9 === kind)?.arm,
  );
}

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
  const revisionLabel = !headKnown ? "Saved version" : isHead ? "Latest version" : "Older version";
  const headLabel = !headKnown
    ? headFailure
      ? "Couldn't check whether this is the latest version."
      : "Checking whether this is the latest version…"
    : isHead
      ? "This is the latest version."
      : "This is an older version. A newer one is available.";

  function displayedSource(): EditorSource | null {
    if (!record?.spec || !head?.spec || headFailure) return null;
    return {
      draft: draftFromSpec(record.spec),
      expectedRevisionId: head.revisionId,
      sourceNote: "This draft starts from the version shown above.",
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

  const canManage = canPermission(principal, "profiles.manage");
  const settings = record?.spec ? (
    <div className="grid gap-3">
      {record.spec.resources.map((resource) => (
        <ResourceFacts
          key={resource.resourceId}
          resource={resource}
          resources={record.spec?.resources ?? []}
        />
      ))}
    </div>
  ) : null;

  return (
    <section className="flex min-w-0 flex-col gap-4" aria-busy={displayed.isFetching}>
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
        onRefresh={() => {
          void displayed.refetch();
          if (revision !== "") void headQuery.refetch();
        }}
        refreshing={displayed.isFetching}
        actions={
          canPermission(principal, "resources.assign") ? (
            <Link to="/rollouts" className="text-sm font-medium underline underline-offset-4">
              Assign in Rollouts
            </Link>
          ) : null
        }
      />
      <div
        data-profile-version
        className="flex flex-wrap items-center gap-x-3 gap-y-2 border-y py-3 text-sm"
      >
        {record ? (
          <>
            <StatusBadge status={headKnown && isHead ? "info" : "neutral"}>
              {revisionLabel}
            </StatusBadge>
            <span>Version {formatRevisionNumber(record.revisionNumber)}</span>
            <span data-profile-publisher>
              Published <Timestamp value={record.publishedAt} /> by{" "}
              {publisherLabel(record.actorId, record.actorDisplayName, principal.id)}
            </span>
            {headKnown && !isHead ? (
              <Link
                to="/profiles/$profileId"
                params={{ profileId }}
                search={{ revision: "" }}
                className="underline underline-offset-4"
              >
                Open latest version
              </Link>
            ) : !headKnown ? (
              <span className="text-muted-foreground">{headLabel}</span>
            ) : null}
          </>
        ) : null}
        <details className="ml-auto min-w-0" data-profile-version-picker>
          <summary className="cursor-pointer text-sm underline-offset-4 hover:underline">
            Open another version
          </summary>
          <form
            className="mt-2 flex flex-wrap items-end gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              const canonical = usableUuid(lookup);
              if (canonical === null) {
                setLookupError("Choose a version.");
                return;
              }
              setLookupError("");
              onSearch({ revision: canonical });
            }}
          >
            <div className="grid min-w-0 grow basis-64 gap-1.5">
              <ProfileRevisionPicker
                label="Saved version"
                profileId={profileId}
                value={lookup}
                onChange={setLookup}
              />
            </div>
            <Button type="submit" variant="outline">
              Open version
            </Button>
          </form>
          {lookupError !== "" ? (
            <p role="alert" className="mt-2 text-sm text-destructive">
              {lookupError}
            </p>
          ) : null}
        </details>
        {record ? (
          <TechnicalDetails
            className="basis-full"
            items={[
              { label: "Profile ID", value: profileId },
              { label: "Version ID", value: record.revisionId },
              { label: "Publisher ID", value: record.actorId },
              { label: "Spec SHA-256", value: formatSha256(record.specSha256) },
            ]}
          />
        ) : null}
      </div>
      {failure ? <RpcError failure={failure} /> : null}
      {displayed.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading profile…</span>
          <Skeleton className="h-40 w-full" />
        </div>
      ) : null}
      {headFailure ? (
        <RpcError failure={headFailure}>
          <p>
            Cannot load the latest version. Refresh before editing.
            {attempt ? " Retry saving your existing draft if necessary." : ""}
          </p>
        </RpcError>
      ) : null}
      {revision !== "" && headQuery.isPending ? (
        <p role="status" className="text-sm text-muted-foreground">
          Loading latest version…
        </p>
      ) : null}
      {editorSource && canManage ? (
        <ProfileEditor
          key={`${profileId}:${copyGeneration}`}
          mode="edit"
          profileId={profileId}
          initialDraft={editorSource.draft}
          initialExpectedRevisionId={editorSource.expectedRevisionId}
          sourceNote={`${editorSource.sourceNote} It is kept until you publish it or reload the page.`}
          headerAction={
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={attempt !== null || !record?.spec || !head?.spec || headFailure !== null}
              onClick={() => {
                const source = displayedSource();
                if (!source || attempt) return;
                setEditorSource(source);
                setCopyGeneration((current) => current + 1);
              }}
            >
              Start over from this version
            </Button>
          }
        />
      ) : null}
      {settings && record ? (
        canManage && editorSource ? (
          // The draft above is the working copy; the published settings of the
          // version shown stay one click away for comparison.
          <details className="min-w-0 border p-4" data-profile-published-settings>
            <summary className="cursor-pointer text-sm font-medium">
              Settings in version {formatRevisionNumber(record.revisionNumber)} as published
            </summary>
            <div className="mt-3">{settings}</div>
          </details>
        ) : (
          <Card>
            <CardHeader>
              <CardTitle>Settings</CardTitle>
              <CardDescription>What this profile sets on assigned devices.</CardDescription>
            </CardHeader>
            <CardContent>{settings}</CardContent>
          </Card>
        )
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

function ResourceFacts({
  resource,
  resources,
}: {
  resource: ProfileResource;
  resources: ProfileResource[];
}) {
  const kind = resource.desired?.state.case;
  const title = kind === "sshServer" ? undefined : settingTitle(undefined, resource.desired);
  const platforms = applicabilityPlatforms(resource.applicability);
  const features = applicabilityFeatures(resource.applicability);
  return (
    <article className="grid min-w-0 gap-3 border bg-muted/20 p-4" data-profile-setting>
      <h2 className="grid gap-0.5 text-sm font-medium">
        <span>{kindLabel(kind)}</span>
        {title ? (
          <span className="break-all text-xs font-normal text-muted-foreground">{title}</span>
        ) : null}
      </h2>
      <dl className="grid gap-3 sm:grid-cols-2">
        <Fact label="Depends on">
          {resource.dependsOn.length === 0 ? (
            "Nothing else in this profile"
          ) : (
            <ul className="grid gap-0.5">
              {resource.dependsOn.map((dependency, index) => (
                <li key={index} className="break-all">
                  {refKindLabel(dependency.ref?.kind)}{" "}
                  <span className="text-xs">
                    {settingTitle(
                      dependency.ref,
                      resources.find(
                        (other) =>
                          other.desired?.ref?.kind === dependency.ref?.kind &&
                          other.desired?.ref?.canonicalKey === dependency.ref?.canonicalKey,
                      )?.desired,
                    )}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Fact>
        <Fact label="Applies to">
          {platforms ? `Only ${platforms}` : "Every device it's assigned to"}
          {features ? `, when the device supports ${features}` : ""}
        </Fact>
      </dl>
      <TechnicalDetails
        summary="Full setting"
        items={[
          { label: "Setting ID", value: resource.resourceId },
          { label: "Setting type", value: kind },
          ...settingTechnicalIds(resource.desired?.ref),
        ]}
      >
        <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all text-xs">
          {toJsonString(ProfileResourceSchema, resource, { prettySpaces: 2 })}
        </pre>
      </TechnicalDetails>
    </article>
  );
}
