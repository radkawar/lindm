import { create } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { queryOptions, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { Skeleton } from "@/components/ui/skeleton";
import type { PickerSlot } from "@/components/ui/search-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { isUnauthenticated, toRpcFailure, type RpcFailure } from "@/lib/errors";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import {
  CreateAccountRequestSchema,
  UpdateAccountRequestSchema,
  type AccountEnrollment,
  type LocalAccount,
} from "../../../gen/lindm/auth/v1/auth_pb";
import { createAccount, fetchAccounts, resetAccount, updateAccount } from "./local-api";
import { sessionQueryKey, sessionQueryOptions } from "./queries";
import type { DeviceScope } from "../../../gen/lindm/auth/v1/authorization_pb";
import { normalizedScopes, ScopeEditor } from "./scope-editor";
import { IdentitySettings } from "./identity-settings";

export function accountsQueryOptions(lifetime: AuthLifetime) {
  return queryOptions({
    queryKey: ["local-accounts", lifetime.generation],
    meta: { authGeneration: lifetime.generation },
    queryFn: ({ signal }) => fetchAccounts(AbortSignal.any([signal, lifetime.signal])),
    retry: false,
  });
}

export function Accounts({
  devicePicker,
  groupPicker,
}: {
  devicePicker: PickerSlot;
  groupPicker: PickerSlot;
}) {
  const lifetime = useAuthLifetime();
  const client = useQueryClient();
  const session = useQuery(sessionQueryOptions());
  const accounts = useQuery(accountsQueryOptions(lifetime));
  const [username, setUsername] = useState("");
  const [role, setRole] = useState("admin");
  const [emergency, setEmergency] = useState(false);
  const [scopes, setScopes] = useState<DeviceScope[]>([]);
  const [enrollment, setEnrollment] = useState<AccountEnrollment | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<RpcFailure | null>(null);
  const csrf = session.data?.csrfToken ?? "";

  async function perform(done: string, action: () => Promise<AccountEnrollment | void>) {
    if (busy || !csrf || lifetime.signal.aborted) return;
    setBusy(true);
    setError(null);
    setEnrollment(null);
    try {
      const result = await action();
      lifetime.signal.throwIfAborted();
      if (result) setEnrollment(result);
      toast.success(done, {
        description: result ? "Copy the enrollment secret shown on this page." : undefined,
      });
      await client.invalidateQueries({ queryKey: accountsQueryOptions(lifetime).queryKey });
    } catch (failure) {
      if (!lifetime.signal.aborted) {
        if (isUnauthenticated(failure))
          await client.invalidateQueries({ queryKey: sessionQueryKey });
        // Account responses can contain enrollment secrets. Keep decoder errors out of diagnostics.
        setError(
          toRpcFailure(
            failure instanceof ConnectError
              ? failure
              : new ConnectError("Couldn't confirm the account change.", Code.Unknown),
          ),
        );
      }
    } finally {
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void perform("Account created", () =>
      createAccount(
        create(CreateAccountRequestSchema, {
          username,
          role,
          breakGlass: emergency,
          scopes: normalizedScopes(scopes),
        }),
        csrf,
        lifetime.signal,
      ),
    );
  }

  return (
    <section className="grid min-w-0 gap-6" aria-busy={accounts.isFetching || busy}>
      <PageHeader
        title="Local accounts"
        description="Manage who can sign in to the console and what they can do."
      />
      <IdentitySettings />
      {error ? (
        <RpcError failure={error}>
          {error.ambiguous ? (
            <p>The change may have gone through. Refresh the list before trying again.</p>
          ) : null}
        </RpcError>
      ) : null}
      {busy ? (
        <p role="status" className="border bg-muted/30 p-3 text-sm text-muted-foreground">
          Saving…
        </p>
      ) : null}
      {enrollment ? (
        <section
          className="grid min-w-0 gap-3 border-2 border-primary bg-primary/5 p-4 sm:p-6"
          aria-label="One-time enrollment secret"
        >
          <h2 className="font-semibold">Save this enrollment secret now</h2>
          <TechnicalDetails items={[{ label: "Account ID", value: enrollment.accountId }]} />
          <p className="max-w-3xl text-sm">
            Send it to the account holder privately and have them open /enroll. It won't be shown
            again.
          </p>
          <code className="border bg-background p-3 break-all select-all">{enrollment.secret}</code>
          <p className="text-sm">
            Expires:{" "}
            {enrollment.expiresAt
              ? timestampDate(enrollment.expiresAt).toLocaleString()
              : "Unknown"}
          </p>
          <Button className="w-fit" variant="outline" onClick={() => setEnrollment(null)}>
            Dismiss secret
          </Button>
        </section>
      ) : null}
      <form className="grid min-w-0 gap-3 border bg-card p-4 sm:p-6" onSubmit={submit}>
        <h2 className="text-lg font-semibold">Create account</h2>
        <Label htmlFor="new-username">Username</Label>
        <Input
          id="new-username"
          required
          value={username}
          disabled={busy}
          autoComplete="off"
          onChange={(event) => setUsername(event.target.value)}
        />
        <Label htmlFor="new-role">Role</Label>
        <SelectField
          id="new-role"
          className="h-9 min-w-0"
          value={role}
          disabled={busy || emergency}
          onValueChange={(value) => setRole(value)}
          options={accounts.data?.roles.map((name) => ({ value: name, label: name })) ?? []}
        />
        <ScopeEditor
          scopes={scopes}
          disabled={busy}
          onChange={setScopes}
          devicePicker={devicePicker}
          groupPicker={groupPicker}
        />
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={emergency}
            disabled={busy}
            onChange={(event) => {
              setEmergency(event.target.checked);
              if (event.target.checked) setRole("owner");
            }}
          />
          Emergency (break-glass) owner
        </label>
        <Button
          className="w-fit"
          type="submit"
          disabled={busy || !accounts.data?.roles.includes(role)}
        >
          Create account
        </Button>
      </form>
      {accounts.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading accounts…</span>
          <Skeleton className="h-40 w-full" />
          <Skeleton className="h-40 w-full" />
        </div>
      ) : null}
      {accounts.isError ? (
        <RpcError failure={toRpcFailure(accounts.error)}>
          {accounts.data ? <p>Showing the accounts from the last refresh.</p> : null}
        </RpcError>
      ) : null}
      {!accounts.isError && accounts.data?.accounts.length === 0 ? (
        <EmptyState
          title="No local accounts"
          description="Create an account to give someone console access."
        />
      ) : null}
      <div className="grid min-w-0 gap-4">
        {accounts.data?.accounts.map((account) => (
          <AccountEditor
            key={`${account.id}:${account.role}:${account.enabled}:${account.breakGlass}:${account.enrolled}:${JSON.stringify(account.scopes)}`}
            account={account}
            roles={accounts.data?.roles ?? []}
            busy={busy}
            devicePicker={devicePicker}
            groupPicker={groupPicker}
            onSave={(enabled, selectedRole, breakGlass, selectedScopes) =>
              void perform("Account saved", () =>
                updateAccount(
                  create(UpdateAccountRequestSchema, {
                    accountId: account.id,
                    enabled,
                    role: selectedRole,
                    breakGlass,
                    scopes: normalizedScopes(selectedScopes),
                  }),
                  csrf,
                  lifetime.signal,
                ),
              )
            }
            onReset={() => {
              if (
                window.confirm(
                  `Reset ${account.username}? They'll be signed out and must set up their password and authenticator again.`,
                )
              )
                void perform("Credentials reset", () =>
                  resetAccount(account.id, csrf, lifetime.signal),
                );
            }}
          />
        ))}
      </div>
    </section>
  );
}

function AccountEditor({
  account,
  roles,
  busy,
  onSave,
  onReset,
  devicePicker,
  groupPicker,
}: {
  account: LocalAccount;
  roles: string[];
  busy: boolean;
  onSave: (enabled: boolean, role: string, breakGlass: boolean, scopes: DeviceScope[]) => void;
  onReset: () => void;
  devicePicker: PickerSlot;
  groupPicker: PickerSlot;
}) {
  const [enabled, setEnabled] = useState(account.enabled);
  const [role, setRole] = useState(account.role);
  const [emergency, setEmergency] = useState(account.breakGlass);
  const [scopes, setScopes] = useState(account.scopes);
  return (
    <form
      className="grid min-w-0 gap-4 border bg-card p-4 sm:p-6"
      onSubmit={(event) => {
        event.preventDefault();
        onSave(enabled, role, emergency, scopes);
      }}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="break-words font-semibold">{account.username}</h2>
        <div className="flex flex-wrap gap-2">
          <StatusBadge status={account.enabled ? "success" : "neutral"}>
            {account.enabled ? "Enabled" : "Disabled"}
          </StatusBadge>
          <StatusBadge status={account.enrolled ? "success" : "warning"}>
            {account.enrolled ? "Set up" : "Not set up yet"}
          </StatusBadge>
          {account.breakGlass ? <StatusBadge status="warning">Emergency owner</StatusBadge> : null}
        </div>
      </div>
      <label className="grid gap-2 text-sm font-medium">
        Role
        <SelectField
          aria-label="Role"
          className="h-9 min-w-0"
          value={role}
          disabled={busy || emergency}
          onValueChange={(value) => setRole(value)}
          options={[
            ...(!roles.includes(role) ? [{ value: role, label: `${role} (unavailable)` }] : []),
            ...roles.map((name) => ({ value: name, label: name })),
          ]}
        />
      </label>
      <ScopeEditor
        scopes={scopes}
        disabled={busy}
        onChange={setScopes}
        devicePicker={devicePicker}
        groupPicker={groupPicker}
      />
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={enabled}
          disabled={busy}
          onChange={(event) => setEnabled(event.target.checked)}
        />
        Enabled
      </label>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={emergency}
          disabled={busy}
          onChange={(event) => {
            setEmergency(event.target.checked);
            if (event.target.checked) setRole("owner");
          }}
        />
        Emergency (break-glass) owner
      </label>
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy || !roles.includes(role)}>
          Save account
        </Button>
        <Button type="button" variant="outline" disabled={busy} onClick={onReset}>
          Reset credentials
        </Button>
      </div>
    </form>
  );
}
