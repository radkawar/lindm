import { create, fromJsonString } from "@bufbuild/protobuf";
import { timestampNow, type Timestamp as ProtoTimestamp } from "@bufbuild/protobuf/wkt";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Timestamp } from "@/components/ui/timestamp";
import type { PickerSlot } from "@/components/ui/search-picker";
import { permissionLabels } from "@/lib/permissions";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { isUnauthenticated, toRpcFailure, type RpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import {
  ApplyOrganizationRequestSchema,
  type ApplyOrganizationResponse,
  type OrganizationOutcome,
} from "../../../gen/lindm/org/v1/apply_pb";
import { OrganizationSchema, type Organization } from "../../../gen/lindm/org/v1/organization_pb";
import { applyOrganization } from "./organization-api";
import { sessionQueryKey, sessionQueryOptions } from "./queries";
import { ScopeEditor } from "./scope-editor";

const kindLabels: Record<string, string> = {
  account: "Account",
  authorization: "Access policy",
  group: "Device group",
  dynamic_group: "Dynamic device group",
  profile: "Profile",
  rollout: "Rollout",
  assignment: "Resource assignment",
  activation: "Device activation",
  provisioning_token: "Provisioning token",
  enrollment_grant: "Enrollment code",
  advisory_exception: "Advisory exception",
};
const plannedLabels: Record<string, string> = {
  created: "Will create",
  updated: "Will update",
  unchanged: "No change",
  pending: "Needs attention",
  unsupported: "Cannot apply",
};
const appliedLabels: Record<string, string> = {
  created: "Created",
  updated: "Updated",
  unchanged: "Unchanged",
  pending: "Needs attention",
  unsupported: "Not applied",
};

function outcomeName(outcome: OrganizationOutcome, organization: Organization | null) {
  if (outcome.kind === "assignment") {
    const assignment = organization?.assignments.find(
      (item) => item.assignment?.assignmentId === outcome.id,
    );
    const profile = organization?.profiles.find((item) => item.id === assignment?.profileId);
    return profile?.spec?.name ? `${profile.spec.name} assignment` : "Resource assignment";
  }
  return outcome.name && outcome.name !== outcome.id
    ? outcome.name
    : (kindLabels[outcome.kind] ?? "Organization item");
}

export function OrganizationImport({
  devicePicker,
  groupPicker,
}: {
  devicePicker: PickerSlot;
  groupPicker: PickerSlot;
}) {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const session = useQuery(sessionQueryOptions());
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [result, setResult] = useState<ApplyOrganizationResponse | null>(null);
  const [applied, setApplied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [message, setMessage] = useState("");
  const [failure, setFailure] = useState<RpcFailure | null>(null);
  const [reviewedAt, setReviewedAt] = useState<ProtoTimestamp | undefined>(undefined);
  const controller = useRef<AbortController | null>(null);
  const active = useRef(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const uploadVersion = useRef(0);
  useEffect(() => {
    const current = new AbortController();
    controller.current = current;
    const clear = () => {
      setResult(null);
      setOrganization(null);
    };
    lifetime.signal.addEventListener("abort", clear, { once: true });
    return () => {
      current.abort();
      lifetime.signal.removeEventListener("abort", clear);
    };
  }, [lifetime.signal]);
  const secrets = result?.secrets ?? [];

  async function upload(file: File | undefined) {
    if (!file || active.current || secrets.length) return;
    const signal = controller.current?.signal;
    const version = ++uploadVersion.current;
    setOrganization(null);
    setResult(null);
    setFailure(null);
    setMessage("");
    setConfirmed(false);
    setApplied(false);
    setReviewedAt(undefined);
    try {
      // The HTTP boundary also bounds input. This avoids reading an unbounded local file.
      if (file.size > 16 * 1024 * 1024) throw new Error("oversized upload");
      const value = fromJsonString(OrganizationSchema, await file.text());
      if (signal?.aborted || lifetime.signal.aborted || version !== uploadVersion.current) return;
      setOrganization(value);
    } catch {
      if (!signal?.aborted && !lifetime.signal.aborted && version === uploadVersion.current)
        setMessage(
          "Choose a valid organization JSON file, at most 16 MiB. Unknown fields are not accepted.",
        );
    }
  }

  async function send(apply: boolean) {
    const current = controller.current;
    const csrf = session.data?.csrfToken;
    if (
      !organization ||
      !csrf ||
      !current ||
      active.current ||
      current.signal.aborted ||
      lifetime.signal.aborted ||
      secrets.length
    )
      return;
    if (
      apply &&
      (!confirmed || !result || result.failureCode || result.planSha256.length !== 32 || applied)
    )
      return;
    const hash = result?.planSha256;
    active.current = true;
    setBusy(true);
    setFailure(null);
    setMessage("");
    setConfirmed(false);
    // Consume the reviewed plan before sending. Neither account issuance nor a
    // partially completed import is retried, even after an ambiguous transport error.
    setResult(null);
    setApplied(apply);
    try {
      const response = await applyOrganization(
        create(ApplyOrganizationRequestSchema, {
          organization,
          apply,
          expectedPlanSha256: apply ? hash : undefined,
        }),
        csrf,
        AbortSignal.any([current.signal, lifetime.signal]),
      );
      if (current.signal.aborted || lifetime.signal.aborted) return;
      setResult(response);
      if (!apply) setReviewedAt(timestampNow());
      if (apply) {
        await client.invalidateQueries({ queryKey: ["local-accounts", lifetime.generation] });
        await client.invalidateQueries({ queryKey: ["authorization", lifetime.generation] });
      }
    } catch (error) {
      if (current.signal.aborted || lifetime.signal.aborted) return;
      setFailure(toRpcFailure(error));
      if (isUnauthenticated(error)) await client.invalidateQueries({ queryKey: sessionQueryKey });
    } finally {
      active.current = false;
      if (!current.signal.aborted && !lifetime.signal.aborted) setBusy(false);
    }
  }

  async function copySecret(secret: string) {
    try {
      await navigator.clipboard.writeText(secret);
      setMessage("Secret copied. Share it only through an approved private channel.");
    } catch {
      setMessage("Clipboard access was denied. Select and copy the displayed secret manually.");
    }
  }
  function downloadSecrets() {
    const url = URL.createObjectURL(
      new Blob(
        [
          JSON.stringify(
            secrets.map((secret) => ({
              kind: secret.kind,
              name: secret.name,
              secret: secret.secret,
              expiresAt: formatTimestamp(secret.expiresAt).utc,
            })),
            null,
            2,
          ),
        ],
        { type: "application/json" },
      ),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "organization-secrets.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  return (
    <section
      className="grid min-w-0 gap-4 border bg-card p-4 sm:p-6"
      aria-label="Import organization"
      aria-busy={busy}
    >
      <h2 className="text-base font-semibold">Import organization</h2>
      <p className="text-sm text-muted-foreground">
        Upload an organization file, review current changes, then apply that reviewed plan using
        this console session.
      </p>
      <label className="grid gap-2 text-sm font-medium">
        Organization JSON
        <Input
          ref={fileInput}
          type="file"
          accept=".json,application/json"
          disabled={busy || secrets.length > 0}
          onChange={(event) => {
            void upload(event.target.files?.[0]);
          }}
        />
      </label>
      {organization ? <p className="text-sm font-medium break-words">{organization.name}</p> : null}
      {message ? (
        <p role="status" className="text-sm">
          {message}
        </p>
      ) : null}
      {failure ? (
        <RpcError failure={failure}>
          <p>
            {applied
              ? "Some changes may have completed. Check current accounts and resources before reviewing again. Issued secrets cannot be retrieved by retrying."
              : "The current plan could not be reviewed. No apply was requested."}
          </p>
        </RpcError>
      ) : null}
      {result?.failureCode ? (
        <div role="alert" className="grid gap-2 border border-destructive p-3 text-sm">
          <p>
            {result.failureReason === "organization_review_changed"
              ? "The organization changed after review. Review a fresh plan before applying."
              : applied
                ? "The import stopped before all work completed. Retain the outcomes and save any secrets below before reviewing again."
                : "The organization could not be reviewed. Check the reported cause before continuing."}
          </p>
          <TechnicalDetails
            items={[
              { label: "Failure code", value: result.failureCode },
              { label: "Reported cause", value: result.failureReason },
            ]}
          />
        </div>
      ) : null}
      {result ? (
        <>
          <h3 className="font-semibold">{applied ? "Recorded outcomes" : "Review current plan"}</h3>
          {!applied ? (
            <p className="text-sm text-muted-foreground">
              Reviewed <Timestamp value={reviewedAt} />. No changes have been applied.
            </p>
          ) : (
            <p className="text-sm">
              These are control-plane outcomes, not proof that devices have applied changes.
            </p>
          )}
          {!result.outcomes.length ? (
            <p className="text-sm">No item outcomes were returned.</p>
          ) : null}
          <ul className="grid gap-3">
            {result.outcomes.map((outcome, index) => (
              <li
                key={`${outcome.kind}:${outcome.id}:${index}`}
                className="grid gap-2 border-b pb-3"
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <span className="min-w-0 break-words font-medium">
                    {outcomeName(outcome, organization)}
                  </span>
                  <StatusBadge
                    status={
                      outcome.status === "unsupported" || outcome.status === "pending"
                        ? "warning"
                        : applied
                          ? "neutral"
                          : "info"
                    }
                  >
                    {(applied ? appliedLabels : plannedLabels)[outcome.status] ?? "Unknown outcome"}
                  </StatusBadge>
                </div>
                <p className="text-sm text-muted-foreground">
                  {kindLabels[outcome.kind] ?? "Organization item"}
                </p>
                {outcome.kind === "authorization" && outcome.status !== "unchanged" ? (
                  <p className="text-sm">
                    Replaces the complete access policy and signs out non-owner sessions.
                  </p>
                ) : null}
                {outcome.kind === "account" && outcome.status === "updated" ? (
                  <p className="text-sm">
                    Enables the account, replaces access and ends existing sessions.
                  </p>
                ) : null}
                {outcome.kind === "account" && outcome.status === "created" ? (
                  <p className="text-sm">
                    The account holder must enroll using a shown-once secret.
                  </p>
                ) : null}
                <TechnicalDetails
                  items={[
                    { label: "Reference", value: outcome.id },
                    { label: "Reported detail", value: outcome.detail },
                    { label: "Reported status", value: outcome.status },
                  ]}
                />
              </li>
            ))}
          </ul>
          <TechnicalDetails
            items={[
              {
                label: "Reviewed plan SHA-256",
                value: Array.from(result.planSha256, (value) =>
                  value.toString(16).padStart(2, "0"),
                ).join(""),
              },
            ]}
          />
          {!applied && organization ? (
            <section className="grid gap-4" aria-label="Reviewed account access">
              {organization.accounts.map((account) => (
                <div className="grid gap-3 border p-3" key={account.username}>
                  <h4 className="font-medium break-words">
                    {account.username}: {account.role}
                  </h4>
                  {account.breakGlass ? <p className="text-sm">Emergency owner access</p> : null}
                  <ScopeEditor
                    scopes={account.scopes}
                    disabled
                    onChange={() => {}}
                    devicePicker={devicePicker}
                    groupPicker={groupPicker}
                  />
                </div>
              ))}
              {organization.authorization ? (
                <div className="grid gap-3 border p-3">
                  <h4 className="font-medium">Replacement access policy</h4>
                  {organization.authorization.roles.map((role) => (
                    <p className="text-sm" key={role.name}>
                      {role.name}:{" "}
                      {role.permissions
                        .map(
                          (permission) => permissionLabels[permission] ?? "Unrecognized permission",
                        )
                        .join(", ")}
                    </p>
                  ))}
                  <p className="text-sm">
                    Independent approval:{" "}
                    {organization.authorization.approvalRequiredPermissions
                      .map(
                        (permission) => permissionLabels[permission] ?? "Unrecognized permission",
                      )
                      .join(", ") || "No additional requirements"}
                  </p>
                  {organization.authorization.groupBindings.map((binding, index) => (
                    <div className="grid gap-2" key={index}>
                      <p className="text-sm">
                        Directory binding {index + 1}: {binding.role}
                      </p>
                      <TechnicalDetails
                        items={[{ label: "Directory group reference", value: binding.group }]}
                      />
                      <ScopeEditor
                        scopes={binding.scopes}
                        disabled
                        onChange={() => {}}
                        devicePicker={devicePicker}
                        groupPicker={groupPicker}
                      />
                    </div>
                  ))}
                </div>
              ) : null}
            </section>
          ) : null}
        </>
      ) : null}
      {secrets.length ? (
        <section
          className="grid min-w-0 max-w-full gap-4 border-2 border-primary p-4"
          aria-label="Shown-once organization secrets"
          data-sensitive="true"
        >
          <h3 className="min-w-0 font-semibold break-words">Save these secrets now</h3>
          <p className="min-w-0 text-sm break-words">
            Secrets exist only on this page until dismissed or you leave. Copy or download only to
            an approved private location; downloads are not encrypted.
          </p>
          {secrets.map((secret, index) => (
            <div className="grid min-w-0 max-w-full gap-2" key={`${secret.kind}:${index}`}>
              <h4 className="min-w-0 font-medium break-words">{secret.name}</h4>
              <p className="min-w-0 text-sm break-words">
                {kindLabels[secret.kind] ?? "Credential"}. Expires:{" "}
                <Timestamp value={secret.expiresAt} missing="Unknown" />
              </p>
              <code className="block min-w-0 max-w-full border bg-background p-3 break-all select-all">
                {secret.secret}
              </code>
              <Button
                type="button"
                className="h-auto min-h-9 w-fit min-w-0 max-w-full text-left whitespace-normal"
                variant="outline"
                onClick={() => {
                  void copySecret(secret.secret);
                }}
              >
                <span className="min-w-0 break-words">Copy secret for {secret.name}</span>
              </Button>
            </div>
          ))}
          <div className="flex min-w-0 flex-wrap gap-2">
            <Button
              type="button"
              className="h-auto min-h-9 min-w-0 max-w-full whitespace-normal"
              variant="outline"
              onClick={downloadSecrets}
            >
              Download secrets
            </Button>
            <Button
              type="button"
              className="h-auto min-h-9 min-w-0 max-w-full whitespace-normal"
              variant="outline"
              onClick={() =>
                setResult((current) => (current ? { ...current, secrets: [] } : current))
              }
            >
              Dismiss secrets
            </Button>
          </div>
        </section>
      ) : null}
      {!applied && result && !result.failureCode ? (
        <div className="grid gap-3 border border-warning p-3 text-sm">
          <p>
            Apply only the plan shown above. Omitted items are not deleted. Changes are not atomic:
            a failure can leave earlier items applied. Accounts are enabled with the specified roles
            and device access; authorization changes replace the whole access policy. Device work
            may still need approval or a check-in.
          </p>
          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              checked={confirmed}
              disabled={busy}
              onChange={(event) => setConfirmed(event.target.checked)}
            />
            I reviewed the affected accounts, resources and access changes.
          </label>
        </div>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant="outline"
          disabled={!organization || busy || secrets.length > 0}
          onClick={() => {
            void send(false);
          }}
        >
          {busy ? "Working…" : "Review current plan"}
        </Button>
        {!applied && result && !result.failureCode ? (
          <Button
            type="button"
            disabled={busy || !confirmed || result.planSha256.length !== 32}
            onClick={() => {
              void send(true);
            }}
          >
            Apply reviewed plan
          </Button>
        ) : null}
        {organization ? (
          <Button
            type="button"
            variant="outline"
            disabled={busy || secrets.length > 0}
            onClick={() => {
              setOrganization(null);
              setResult(null);
              setFailure(null);
              setMessage("");
              if (fileInput.current) fileInput.current.value = "";
            }}
          >
            Clear import
          </Button>
        ) : null}
      </div>
      {secrets.length ? (
        <p className="text-sm">
          Save or dismiss the secrets before reviewing or uploading another file.
        </p>
      ) : null}
    </section>
  );
}
