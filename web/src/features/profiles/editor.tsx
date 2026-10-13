import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { toast } from "sonner";
import type { ProfileRevision } from "../../../gen/lindm/admin/v1/profiles_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { getAuthLifetime } from "@/lib/auth-lifetime";
import { classifyRpcFailure, toRpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { formatTimestamp } from "@/lib/time";
import {
  beginAttempt,
  clearAttempt,
  settleAttempt,
  usePublishAttempt,
  type PublishAttempt,
} from "./attempt";
import {
  DESCRIPTION_MAX,
  MAX_RESOURCES,
  NAME_MAX,
  NO_DRAFT_ERRORS,
  capturePayload,
  classifyPublishError,
  publishErrors,
  publishRefusalErrors,
  draftFromPayload,
  draftFromSpec,
  emptyDraft,
  formatRevisionNumber,
  newResource,
  removeResource,
  updateResource,
  type DraftErrors,
  type DraftSpec,
  type PublishPayload,
} from "./model";
import { qualifiedKindsQueryOptions, profileRevisionQueryOptions } from "./queries";
import { type Qualification } from "./qualification";
import { ResourceFields } from "./resource-form";
import { RolloutHint } from "./rollout-hint";

// Mention the bound only when an administrator is about to meet it.
const NEAR_RESOURCE_LIMIT = MAX_RESOURCES - 4;

export function ProfileEditor({
  mode,
  profileId,
  initialDraft,
  initialExpectedRevisionId,
  sourceNote,
  onPrepareAnother,
  headerAction,
}: {
  mode: "create" | "edit";
  profileId: string;
  initialDraft?: DraftSpec;
  initialExpectedRevisionId?: string;
  sourceNote: string;
  onPrepareAnother?: () => void;
  // A control that replaces this draft, shown beside the editor title.
  headerAction?: ReactNode;
}) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const attempt = usePublishAttempt(profileId);
  const inFlight = useRef(false);
  const [draft, setDraft] = useState<DraftSpec>(() => initialDraft ?? emptyDraft());
  const [reason, setReason] = useState("");
  const [requestId, setRequestId] = useState(newRequestId);
  const [expectedRevisionId, setExpectedRevisionId] = useState(initialExpectedRevisionId);
  const [fieldErrors, setFieldErrors] = useState<DraftErrors>(NO_DRAFT_ERRORS);
  const [note, setNote] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  // One switch for every setting's dependency, ownership and verification fields.
  const [advanced, setAdvanced] = useState(false);
  const kinds = useQuery(qualifiedKindsQueryOptions(lifetime));
  const qualification: Qualification = kinds.data
    ? { status: "known", kinds: kinds.data }
    : { status: "unknown" };

  const locked = attempt !== null;
  const shown = attempt ? draftFromPayload(attempt.payload) : draft;
  const shownReason = attempt ? attempt.payload.reason : reason;
  const shownExpected = attempt ? attempt.payload.expectedRevisionId : expectedRevisionId;
  const shownRequestId = attempt ? attempt.payload.requestId : requestId;
  const creating = shownExpected === undefined;

  const publish = useMutation({
    retry: false,
    gcTime: 0,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (payload: PublishPayload) => {
      const response = await adminClient.publishProfileRevision(payload, {
        signal: lifetime.signal,
      });
      lifetime.signal.throwIfAborted();
      if (!response.revision?.spec || response.revision.revisionId === "") {
        throw new Error("The server did not confirm profile publication.");
      }
      return response.revision;
    },
    onSuccess: (revision, payload) => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      settleAttempt(lifetime, payload.profileId, {
        status: "published",
        published: revision,
        failure: null,
        conflict: false,
      });
      toast.success("Profile published");
      void queryClient.invalidateQueries({ queryKey: ["profiles", lifetime.generation] });
      void queryClient.invalidateQueries({
        queryKey: ["resource-profile-heads", lifetime.generation],
      });
      void queryClient.invalidateQueries({
        queryKey: ["profile-revision", lifetime.generation, payload.profileId],
      });
    },
    onError: (error, payload) => {
      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
      // The server names the refused setting and stored nothing: return to the
      // editable draft with the refusal on that setting.
      const refusal = publishRefusalErrors(error);
      if (refusal) {
        clearAttempt(lifetime, payload.profileId);
        setRequestId(newRequestId());
        setFieldErrors(refusal);
        toast.error("Not published", { description: "Fix the marked setting, then publish." });
        return;
      }
      const classified = classifyPublishError(error);
      settleAttempt(lifetime, payload.profileId, {
        status: classified.conflict
          ? "conflict"
          : classified.failure.ambiguous
            ? "ambiguous"
            : "rejected",
        failure: classified.failure,
        conflict: classified.conflict,
      });
      const feedback = classifyRpcFailure(classified.failure);
      const notify = feedback.tone === "destructive" ? toast.error : toast;
      notify(feedback.title, { description: feedback.action });
    },
    onSettled: () => {
      inFlight.current = false;
    },
  });

  function send(payload: PublishPayload) {
    if (inFlight.current || attempt?.status === "inflight") return;
    const started = beginAttempt(lifetime, {
      profileId,
      mode,
      payload,
      status: "inflight",
      failure: null,
      conflict: false,
      refreshedHead: null,
      refreshFailure: null,
      published: null,
    });
    if (!started) return;
    setNote("");
    inFlight.current = true;
    publish.mutate(payload);
  }

  function unlock(nextDraft: DraftSpec, nextExpected: string | undefined, nextReason: string) {
    if (inFlight.current || attempt?.status === "inflight") return;
    setDraft(nextDraft);
    setExpectedRevisionId(nextExpected);
    setReason(nextReason);
    setRequestId(newRequestId());
    setFieldErrors(NO_DRAFT_ERRORS);
    clearAttempt(lifetime, profileId);
  }

  function changeDraft(next: DraftSpec) {
    setFieldErrors(NO_DRAFT_ERRORS);
    setDraft(next);
  }

  function continueAfterPublish() {
    if (!attempt || attempt.status !== "published") return;
    if (mode === "create") {
      clearAttempt(lifetime, profileId);
      onPrepareAnother?.();
      return;
    }
    const published = attempt.published;
    if (published?.spec) {
      setDraft(draftFromSpec(published.spec));
      setExpectedRevisionId(published.revisionId);
      setReason("");
      setRequestId(newRequestId());
      setFieldErrors(NO_DRAFT_ERRORS);
      setNote("Ready for your next change. Not published yet.");
    }
    clearAttempt(lifetime, profileId);
  }

  // A published draft is finished: show the outcome where the editor starts and
  // leave edit mode until the administrator asks for another change.
  if (attempt?.status === "published") {
    return (
      <Card className="min-w-0" data-profile-editor data-profile-published>
        <CardHeader>
          <CardTitle>{mode === "create" ? "Profile details" : "Edit profile"}</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3">
          <AttemptStatus attempt={attempt} />
          <div>
            <Button type="button" variant="outline" onClick={continueAfterPublish}>
              {mode === "create" ? "Create another profile" : "Make another change"}
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="min-w-0" data-profile-editor>
      <CardHeader>
        <CardTitle>{creating ? "Profile details" : "Edit profile"}</CardTitle>
        {headerAction ? <CardAction>{headerAction}</CardAction> : null}
      </CardHeader>
      <CardContent>
        <form
          className="grid min-w-0 gap-4"
          aria-describedby="profile-publish-note"
          onSubmit={(event) => {
            event.preventDefault();
            if (inFlight.current || attempt?.status === "inflight") return;
            if (attempt?.status === "ambiguous") {
              send(attempt.payload);
              return;
            }
            if (attempt) return;
            if (mode === "edit" && expectedRevisionId === undefined) {
              setFieldErrors({
                profile: ["Load the latest version before publishing."],
                settings: {},
              });
              return;
            }
            try {
              const payload = capturePayload({
                requestId,
                profileId,
                expectedRevisionId,
                reason,
                draft,
              });
              const errors = publishErrors(payload);
              if (errors.profile.length > 0 || Object.keys(errors.settings).length > 0) {
                setFieldErrors(errors);
                return;
              }
              setFieldErrors(NO_DRAFT_ERRORS);
              send(payload);
            } catch (error) {
              setFieldErrors({
                profile: [error instanceof Error ? error.message : "A setting is invalid"],
                settings: {},
              });
            }
          }}
        >
          <p id="profile-publish-note" className="text-sm text-muted-foreground">
            {sourceNote}
          </p>
          {locked ? (
            <p className="text-sm">This save pauses editing. Retry the save or start over.</p>
          ) : null}
          <div className="grid gap-1.5">
            <Label htmlFor="profile-name">Name</Label>
            <Input
              id="profile-name"
              data-freeform="new or renamed profile name"
              required
              maxLength={NAME_MAX * 2}
              value={shown.name}
              readOnly={locked}
              onChange={(event) => changeDraft({ ...draft, name: event.target.value })}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="profile-description">Description</Label>
            <Textarea
              id="profile-description"
              data-freeform="profile description"
              maxLength={DESCRIPTION_MAX * 2}
              value={shown.description}
              readOnly={locked}
              onChange={(event) => changeDraft({ ...draft, description: event.target.value })}
            />
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2 border-t pt-4">
            <h3 className="text-base font-semibold">Settings</h3>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                className="accent-primary"
                checked={advanced}
                onChange={(event) => setAdvanced(event.target.checked)}
              />
              Advanced options
            </label>
          </div>
          {kinds.isError ? (
            <p role="status" className="text-sm text-muted-foreground">
              Couldn't check which setting types this server can apply to devices.{" "}
              <Button
                type="button"
                variant="link"
                className="h-auto p-0"
                onClick={() => void kinds.refetch()}
              >
                Check again
              </Button>
            </p>
          ) : null}
          <div className="grid gap-3">
            {shown.resources.map((resource, index) => (
              <ResourceFields
                key={resource.resourceId}
                index={index}
                resource={resource}
                resources={shown.resources}
                locked={locked}
                errors={fieldErrors.settings[index] ?? []}
                advanced={advanced}
                qualification={qualification}
                onChange={(next) => changeDraft(updateResource(draft, next))}
                onRemove={() => changeDraft(removeResource(draft, resource.resourceId))}
              />
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              type="button"
              variant="outline"
              disabled={locked || shown.resources.length >= MAX_RESOURCES}
              aria-describedby={
                shown.resources.length >= NEAR_RESOURCE_LIMIT ? "profile-setting-limit" : undefined
              }
              onClick={() =>
                changeDraft({ ...draft, resources: [...draft.resources, newResource()] })
              }
            >
              Add setting
            </Button>
            {shown.resources.length >= NEAR_RESOURCE_LIMIT ? (
              <p id="profile-setting-limit" className="text-sm text-muted-foreground">
                {shown.resources.length >= MAX_RESOURCES
                  ? `A profile holds at most ${MAX_RESOURCES} settings. Remove one, or put the rest in another profile.`
                  : `${MAX_RESOURCES - shown.resources.length} more settings fit in this profile.`}
              </p>
            ) : null}
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="profile-reason">Reason</Label>
            <Textarea
              id="profile-reason"
              data-freeform="audit reason"
              required
              value={shownReason}
              readOnly={locked}
              onChange={(event) => {
                setFieldErrors(NO_DRAFT_ERRORS);
                setReason(event.target.value);
              }}
            />
          </div>
          {fieldErrors.profile.length > 0 || Object.keys(fieldErrors.settings).length > 0 ? (
            <div
              id="profile-draft-errors"
              role="alert"
              className="border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive"
            >
              <ul className="grid gap-1">
                {fieldErrors.profile.map((error) => (
                  <li key={error}>{error}</li>
                ))}
                {Object.keys(fieldErrors.settings).map((index) => (
                  <li key={`setting-${index}`}>
                    Setting {Number(index) + 1} needs changes before publishing.
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {note !== "" ? (
            <Alert>
              <AlertDescription>{note}</AlertDescription>
            </Alert>
          ) : null}
          {attempt ? <AttemptStatus attempt={attempt} /> : null}
          <RolloutHint />
          <div className="flex flex-wrap gap-2">
            {!attempt ? (
              <Button type="submit">{creating ? "Publish profile" : "Publish changes"}</Button>
            ) : null}
            {attempt?.status === "inflight" ? (
              <Button type="button" disabled>
                Publishing…
              </Button>
            ) : null}
            {attempt?.status === "ambiguous" ? <Button type="submit">Retry</Button> : null}
            {attempt?.status === "conflict" ? (
              <Button
                type="button"
                variant="outline"
                disabled={refreshing}
                onClick={() => {
                  if (refreshing) return;
                  setRefreshing(true);
                  void queryClient
                    .fetchQuery(profileRevisionQueryOptions(lifetime, profileId, ""))
                    .then((head) => {
                      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
                      settleAttempt(lifetime, profileId, {
                        refreshedHead: head,
                        refreshFailure: null,
                      });
                    })
                    .catch((error: unknown) => {
                      if (getAuthLifetime() !== lifetime || lifetime.signal.aborted) return;
                      settleAttempt(lifetime, profileId, { refreshFailure: toRpcFailure(error) });
                    })
                    .finally(() => setRefreshing(false));
                }}
              >
                {refreshing ? "Loading latest version…" : "Load latest version"}
              </Button>
            ) : null}
            {attempt?.status === "conflict" && attempt.refreshedHead ? (
              <>
                <Button
                  type="button"
                  disabled={attempt.status === "conflict" && refreshing}
                  onClick={() => {
                    if (attempt?.status !== "conflict") return;
                    const head = attempt.refreshedHead;
                    if (!head) return;
                    unlock(
                      draftFromPayload(attempt.payload),
                      head.revisionId,
                      attempt.payload.reason,
                    );
                    setNote("Your changes now build on the latest version. Not published yet.");
                  }}
                >
                  Keep my changes on the latest version
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  disabled={!attempt.refreshedHead.spec}
                  onClick={() => {
                    if (attempt?.status !== "conflict") return;
                    const head = attempt.refreshedHead;
                    if (!head?.spec) return;
                    unlock(draftFromSpec(head.spec), head.revisionId, attempt.payload.reason);
                    setNote("Draft replaced with the latest version. Not published yet.");
                  }}
                >
                  Discard my changes and use the latest version
                </Button>
              </>
            ) : null}
            {attempt && attempt.status !== "inflight" ? (
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  if (!attempt || attempt.status === "inflight") return;
                  unlock(
                    draftFromPayload(attempt.payload),
                    attempt.payload.expectedRevisionId,
                    attempt.payload.reason,
                  );
                  setNote("Edit the draft again. The draft remains unpublished.");
                }}
              >
                Edit draft
              </Button>
            ) : null}
          </div>
          <TechnicalDetails
            summary="View JSON"
            items={[
              { label: "Profile ID", value: profileId },
              { label: "Based on version", value: shownExpected },
              { label: "Request ID", value: shownRequestId },
            ]}
          >
            <pre
              className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap break-all border bg-muted/30 p-3"
              aria-label="Profile draft JSON"
            >
              {JSON.stringify(
                {
                  name: shown.name,
                  description: shown.description,
                  resources: shown.resources.map((resource) => JSON.parse(resource.document)),
                },
                null,
                2,
              )}
            </pre>
          </TechnicalDetails>
        </form>
      </CardContent>
    </Card>
  );
}

// Moves the reader to the outcome: the form above it has just been replaced.
function PublishedOutcome({ published }: { published: ProfileRevision }) {
  const outcome = useRef<HTMLDivElement>(null);
  useEffect(() => {
    outcome.current?.scrollIntoView({ block: "nearest" });
    outcome.current?.focus({ preventScroll: true });
  }, []);
  return (
    <Alert ref={outcome} tabIndex={-1} data-profile-publish-outcome>
      <AlertTitle>Profile published</AlertTitle>
      <AlertDescription>
        <p>
          The server saved version {formatRevisionNumber(published.revisionNumber)}. Devices remain
          unchanged until you activate it from{" "}
          <Link to="/rollouts" className="underline underline-offset-4">
            Rollouts
          </Link>
          .
        </p>
        <p>
          <Link
            to="/profiles/$profileId"
            params={{ profileId: published.profileId }}
            search={{ revision: published.revisionId }}
            className="underline underline-offset-4"
          >
            View this version
          </Link>
        </p>
      </AlertDescription>
    </Alert>
  );
}

function AttemptStatus({ attempt }: { attempt: PublishAttempt }) {
  if (attempt.status === "published" && attempt.published) {
    return <PublishedOutcome published={attempt.published} />;
  }
  if (attempt.status === "inflight") {
    return (
      <p role="status" className="border bg-muted/30 p-3 text-sm">
        Publishing…
      </p>
    );
  }
  if (!attempt.failure) return null;
  return (
    <div className="grid gap-3">
      <RpcError failure={attempt.failure}>
        <p>
          {attempt.conflict
            ? "Another administrator published a newer version. Load that version. Choose whether to keep your changes."
            : attempt.failure.ambiguous
              ? "The save outcome is unknown. Retry the same save. It cannot publish twice."
              : ""}
        </p>
      </RpcError>
      {attempt.refreshFailure ? <RpcError failure={attempt.refreshFailure} /> : null}
      {attempt.refreshedHead ? (
        <RefreshedHead head={attempt.refreshedHead} expected={attempt.payload.expectedRevisionId} />
      ) : null}
    </div>
  );
}

function RefreshedHead({
  head,
  expected,
}: {
  head: ProfileRevision;
  expected: string | undefined;
}) {
  const published = formatTimestamp(head.publishedAt);
  const same = expected !== undefined && expected === head.revisionId;
  return (
    <Alert>
      <AlertTitle>Latest version</AlertTitle>
      <AlertDescription>
        <p>
          {head.spec?.name.trim() || "Unnamed profile"}, version{" "}
          {formatRevisionNumber(head.revisionNumber)}, {head.spec?.resources.length ?? 0} settings.
          {published.date ? ` Published ${published.local}.` : ""}
        </p>
        <p>
          {same
            ? "Your draft already uses this version."
            : expected
              ? "This is newer than the version your draft started from."
              : "A profile with this ID already exists. Keep your changes only if you meant to update it."}
        </p>
        <p>
          <Link
            to="/profiles/$profileId"
            params={{ profileId: head.profileId }}
            search={{ revision: head.revisionId }}
            className="underline underline-offset-4"
          >
            View this version
          </Link>
        </p>
      </AlertDescription>
    </Alert>
  );
}
