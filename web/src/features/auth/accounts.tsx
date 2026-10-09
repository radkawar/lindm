import { create } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import { queryOptions, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
        create(CreateAccountRequestSchema, { username, role, breakGlass: emergency }),
        csrf,
        lifetime.signal,
      ),
    );
  }

  return (
    <section className="grid gap-6">
      <header>
        <h1 className="text-2xl font-semibold">Local administrator accounts</h1>
        <p>
          Only owners can create, disable, change roles or reset authenticators. Reset revokes
          access and requires new password and WebAuthn enrollment.
        </p>
      </header>
      {error ? <p role="alert">{error}</p> : null}
      {enrollment ? (
        <section className="grid gap-2 rounded border p-4" aria-label="One-time enrollment secret">
          <h2 className="font-semibold">Save this enrollment secret now</h2>
          <p>Account: {enrollment.accountId}</p>
          <p>
            Give the account holder this secret through a trusted channel and direct them to
            /enroll. It is shown only in this tab and is not recoverable.
          </p>
          <code className="break-all select-all">{enrollment.secret}</code>
          <p>
            Expires:{" "}
            {enrollment.expiresAt
              ? timestampDate(enrollment.expiresAt).toLocaleString()
              : "Unknown"}
          </p>
          <Button variant="outline" onClick={() => setEnrollment(null)}>
            Dismiss secret
          </Button>
        </section>
      ) : null}
      <form className="grid max-w-md gap-3" onSubmit={submit}>
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
        <select
          id="new-role"
          className="rounded border p-2"
          value={role}
          disabled={busy || emergency}
          onChange={(event) => setRole(event.target.value)}
        >
          <option value="admin">Admin</option>
          <option value="owner">Owner</option>
        </select>
        <label className="flex gap-2">
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
        <Button type="submit" disabled={busy}>
          Create and issue enrollment secret
        </Button>
      </form>
      {accounts.isPending ? <p role="status">Loading accounts…</p> : null}
      {accounts.isError ? <p role="alert">Unable to load accounts.</p> : null}
      <div className="grid gap-3">
        {accounts.data?.accounts.map((account) => (
          <AccountEditor
            key={`${account.id}:${account.role}:${account.enabled}:${account.breakGlass}:${account.enrolled}`}
            account={account}
            busy={busy}
            onSave={(enabled, selectedRole, breakGlass) =>
              void perform(() =>
                updateAccount(
                  create(UpdateAccountRequestSchema, {
                    accountId: account.id,
                    enabled,
                    role: selectedRole,
                    breakGlass,
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
  busy,
  onSave,
  onReset,
}: {
  account: LocalAccount;
  busy: boolean;
  onSave: (enabled: boolean, role: string, breakGlass: boolean) => void;
  onReset: () => void;
}) {
  const [enabled, setEnabled] = useState(account.enabled);
  const [role, setRole] = useState(account.role);
  const [emergency, setEmergency] = useState(account.breakGlass);
  return (
    <form
      className="grid gap-3 rounded border p-4"
      onSubmit={(event) => {
        event.preventDefault();
        onSave(enabled, role, emergency);
      }}
    >
      <h2 className="font-semibold">{account.username}</h2>
      <p>{account.enrolled ? "Authenticator enrolled" : "Awaiting enrollment"}</p>
      <label className="flex gap-2">
        Role
        <select
          className="rounded border p-1"
          value={role}
          disabled={busy || emergency}
          onChange={(event) => setRole(event.target.value)}
        >
          <option value="admin">Admin</option>
          <option value="owner">Owner</option>
        </select>
      </label>
      <label className="flex gap-2">
        <input
          type="checkbox"
          checked={enabled}
          disabled={busy}
          onChange={(event) => setEnabled(event.target.checked)}
        />
        Enabled
      </label>
      <label className="flex gap-2">
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
      <div className="flex gap-2">
        <Button type="submit" disabled={busy}>
          Save account
        </Button>
        <Button type="button" variant="outline" disabled={busy} onClick={onReset}>
          Reset credentials
        </Button>
      </div>
    </form>
  );
}
