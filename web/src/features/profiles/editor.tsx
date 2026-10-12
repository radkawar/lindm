import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useRef, useState } from "react";
import { toast } from "sonner";
import type { ProfileRevision } from "../../../gen/lindm/admin/v1/profiles_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
  CATALOG_SEMANTICS,
  DESCRIPTION_MAX,
  MAX_RESOURCES,
  NAME_MAX,
  capturePayload,
  classifyPublishError,
  publishErrors,
  draftFromPayload,
  draftFromSpec,
  emptyDraft,
  formatRevisionNumber,
  newResource,
  removeResource,
  updateResource,
  type DraftSpec,
  type PublishPayload,
} from "./model";
import { profileRevisionQueryOptions } from "./queries";
import { ResourceFields } from "./resource-form";

export function ProfileEditor({
  mode,
  profileId,
  initialDraft,
  initialExpectedRevisionId,
  sourceNote,
  onPrepareAnother,
}: {
  mode: "create" | "edit";
  profileId: string;
  initialDraft?: DraftSpec;
  initialExpectedRevisionId?: string;
  sourceNote: string;
  onPrepareAnother?: () => void;
}) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const attempt = usePublishAttempt(profileId);
  const inFlight = useRef(false);
  const [draft, setDraft] = useState<DraftSpec>(() => initialDraft ?? emptyDraft());
  const [reason, setReason] = useState("");
  const [requestId, setRequestId] = useState(newRequestId);
  const [expectedRevisionId, setExpectedRevisionId] = useState(initialExpectedRevisionId);
  const [fieldErrors, setFieldErrors] = useState<string[]>([]);
  const [note, setNote] = useState("");
  const [refreshing, setRefreshing] = useState(false);

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
        throw new Error("The server didn't confirm the profile was published.");
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
    setFieldErrors([]);
    clearAttempt(lifetime, profileId);
  }

  function changeDraft(next: DraftSpec) {
    setFieldErrors([]);
    setDraft(next);
  }

  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle>{creating ? "Create profile" : "Edit profile"}</CardTitle>
        <CardDescription>{CATALOG_SEMANTICS}</CardDescription>
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
              setFieldErrors(["Load the latest version before publishing."]);
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
              if (errors.length > 0) {
                setFieldErrors(errors);
                return;
              }
              setFieldErrors([]);
              send(payload);
            } catch (error) {
              setFieldErrors([error instanceof Error ? error.message : "A setting is invalid"]);
            }
          }}
        >
          <p id="profile-publish-note" className="text-sm text-muted-foreground">
            {sourceNote}
          </p>
          <TechnicalDetails
            items={[
              { label: "Profile ID", value: profileId },
              { label: "Based on version", value: shownExpected },
              { label: "Request ID", value: shownRequestId },
            ]}
          />
          {locked ? (
            <p className="text-sm">
              Editing is paused while this save is pending. Retry it, or start over.
            </p>
          ) : null}
          <div className="grid gap-1.5">
            <Label htmlFor="profile-name">Name</Label>
            <Input
              id="profile-name"
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
              maxLength={DESCRIPTION_MAX * 2}
              value={shown.description}
              readOnly={locked}
              onChange={(event) => changeDraft({ ...draft, description: event.target.value })}
            />
          </div>
          <div className="grid gap-3">
            {shown.resources.map((resource, index) => (
              <ResourceFields
                key={resource.resourceId}
                index={index}
                resource={resource}
                resources={shown.resources}
                locked={locked}
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
              onClick={() =>
                changeDraft({ ...draft, resources: [...draft.resources, newResource()] })
              }
            >
              Add setting
            </Button>
            <p className="text-sm text-muted-foreground">
              {shown.resources.length} of {MAX_RESOURCES} settings.
            </p>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="profile-reason">Reason</Label>
            <Textarea
              id="profile-reason"
              required
              value={shownReason}
              readOnly={locked}
              onChange={(event) => {
                setFieldErrors([]);
                setReason(event.target.value);
              }}
            />
          </div>
          {fieldErrors.length > 0 ? (
            <div
              id="profile-draft-errors"
              role="alert"
              className="border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive"
            >
              <ul className="grid gap-1">
                {fieldErrors.map((error) => (
                  <li key={error}>{error}</li>
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
            {attempt && attempt.status !== "inflight" && attempt.status !== "published" ? (
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  if (!attempt || attempt.status === "inflight" || attempt.status === "published") {
                    return;
                  }
                  unlock(
                    draftFromPayload(attempt.payload),
                    attempt.payload.expectedRevisionId,
                    attempt.payload.reason,
                  );
                  setNote("You can edit the draft again. Not published yet.");
                }}
              >
                Edit draft
              </Button>
            ) : null}
            {attempt?.status === "published" ? (
              <Button
                type="button"
                variant="outline"
                onClick={() => {
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
                    setFieldErrors([]);
                    setNote("Ready for your next change. Not published yet.");
                  }
                  clearAttempt(lifetime, profileId);
                }}
              >
                {mode === "create" ? "Create another profile" : "Make another change"}
              </Button>
            ) : null}
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function AttemptStatus({ attempt }: { attempt: PublishAttempt }) {
  if (attempt.status === "published" && attempt.published) {
    const published = attempt.published;
    return (
      <Alert>
        <AlertTitle>Profile published</AlertTitle>
        <AlertDescription>
          <p>
            Version {formatRevisionNumber(published.revisionNumber)} is saved. To apply it to
            devices, assign it in Rollouts.
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
            ? "Someone published a newer version first. Load it, then choose whether to keep your changes."
            : attempt.failure.ambiguous
              ? "We couldn't confirm the save. Retry: it won't publish twice."
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
            ? "Your draft is already based on this version."
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
