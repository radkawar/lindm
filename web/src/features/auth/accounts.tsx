import { create } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { queryOptions, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { isUnauthenticated } from "@/lib/errors";
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

export function Accounts() {
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
  const [error, setError] = useState("");
  const csrf = session.data?.csrfToken ?? "";

  async function perform(action: () => Promise<AccountEnrollment | void>) {
    if (busy || !csrf || lifetime.signal.aborted) return;
    setBusy(true);
    setError("");
    setEnrollment(null);
    try {
      const result = await action();
      lifetime.signal.throwIfAborted();
      if (result) setEnrollment(result);
      toast.success("Account operation completed", {
        description: result
          ? "Secure the one-time enrollment secret shown on this page."
          : undefined,
      });
      await client.invalidateQueries({ queryKey: accountsQueryOptions(lifetime).queryKey });
    } catch (failure) {
      if (!lifetime.signal.aborted) {
        if (isUnauthenticated(failure))
          await client.invalidateQueries({ queryKey: sessionQueryKey });
        setError(
          "Account operation failed. Refresh the account list before trying again; the operation may have completed.",
        );
      }
    } finally {
      if (!lifetime.signal.aborted) setBusy(false);
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void perform(() =>
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
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Local administrator accounts</h1>
        <p className="max-w-3xl text-sm text-muted-foreground">
          Authorized account managers can create, disable, change roles or reset authenticators.
        </p>
        <details className="text-xs text-muted-foreground">
          <summary className="w-fit cursor-pointer py-1">Authenticator reset requirements</summary>
          <p className="mt-2">
            Reset revokes access and requires new password and WebAuthn enrollment.
          </p>
        </details>
      </header>
      <IdentitySettings />
      {error ? (
        <Alert variant="destructive">
          <AlertTitle>Account operation not confirmed</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {busy ? (
        <p role="status" className="border bg-muted/30 p-3 text-sm text-muted-foreground">
          Submitting account operation…
        </p>
      ) : null}
      {enrollment ? (
        <section
          className="grid min-w-0 gap-3 border-2 border-primary bg-primary/5 p-4 sm:p-6"
          aria-label="One-time enrollment secret"
        >
          <h2 className="font-semibold">Save this enrollment secret now</h2>
          <p className="break-all font-mono text-xs">Account: {enrollment.accountId}</p>
          <p className="max-w-3xl text-sm">
            Give the account holder this secret through a trusted channel and direct them to
            /enroll. It is shown only in this tab and is not recoverable.
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
        <ScopeEditor scopes={scopes} disabled={busy} onChange={setScopes} />
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
          Designated break-glass owner
        </label>
        <Button
          className="w-fit"
          type="submit"
          disabled={busy || !accounts.data?.roles.includes(role)}
        >
          Create and issue enrollment secret
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
        <Alert variant="destructive">
          <AlertTitle>Accounts unavailable</AlertTitle>
          <AlertDescription>Unable to load accounts.</AlertDescription>
        </Alert>
      ) : null}
      {accounts.data?.accounts.length === 0 ? (
        <p
          role="status"
          className="border border-dashed bg-muted/30 px-6 py-10 text-center text-sm text-muted-foreground"
        >
          No local administrator accounts.
        </p>
      ) : null}
      <div className="grid min-w-0 gap-4">
        {accounts.data?.accounts.map((account) => (
          <AccountEditor
            key={`${account.id}:${account.role}:${account.enabled}:${account.breakGlass}:${account.enrolled}:${JSON.stringify(account.scopes)}`}
            account={account}
            roles={accounts.data?.roles ?? []}
            busy={busy}
            onSave={(enabled, selectedRole, breakGlass, selectedScopes) =>
              void perform(() =>
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
                  `Reset ${account.username}? Existing sessions and authenticator will be revoked.`,
                )
              )
                void perform(() => resetAccount(account.id, csrf, lifetime.signal));
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
}: {
  account: LocalAccount;
  roles: string[];
  busy: boolean;
  onSave: (enabled: boolean, role: string, breakGlass: boolean, scopes: DeviceScope[]) => void;
  onReset: () => void;
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
          <Badge variant={account.enabled ? "secondary" : "outline"}>
            {account.enabled ? "Enabled" : "Disabled"}
          </Badge>
          <Badge variant="outline">
            {account.enrolled ? "Authenticator enrolled" : "Awaiting enrollment"}
          </Badge>
          {account.breakGlass ? <Badge variant="destructive">Break-glass owner</Badge> : null}
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
      <ScopeEditor scopes={scopes} disabled={busy} onChange={setScopes} />
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
        Designated break-glass owner
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
