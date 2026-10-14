// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { queryOptions, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState, type FormEvent, type ReactNode } from "react";
import { toast } from "sonner";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { RpcError } from "@/components/ui/rpc-error";
import { StatusBadge } from "@/components/ui/status-badge";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Timestamp } from "@/components/ui/timestamp";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { PickerSlot } from "@/components/ui/search-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { isUnauthenticated, toRpcFailure, type RpcFailure } from "@/lib/errors";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { roleLabel } from "@/lib/roles";
import {
  CreateAccountRequestSchema,
  UpdateAccountRequestSchema,
  type AccountEnrollment,
  type CreateAccountRequest,
  type LocalAccount,
} from "../../../gen/lindm/auth/v1/auth_pb";
import { createAccount, fetchAccounts, resetAccount, updateAccount } from "./local-api";
import { sessionQueryKey, sessionQueryOptions } from "./queries";
import type { DeviceScope } from "../../../gen/lindm/auth/v1/authorization_pb";
import { normalizedScopes, ScopeEditor } from "./scope-editor";
import { IdentitySettings } from "./identity-settings";
import { OrganizationImport } from "./organization-import";

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
  creating,
  onCreatingChange,
}: {
  devicePicker: PickerSlot;
  groupPicker: PickerSlot;
  // The Create account dialog lives in the URL, so the command palette can open it.
  creating: boolean;
  onCreatingChange: (creating: boolean) => void;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const client = useQueryClient();
  const session = useQuery(sessionQueryOptions());
  const accounts = useQuery(accountsQueryOptions(lifetime));
  const [dialog, setDialog] = useState<{ edit: string } | null>(null);
  const [enrollment, setEnrollment] = useState<AccountEnrollment | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<RpcFailure | null>(null);
  const [search, setSearch] = useState("");
  const matchingAccounts =
    accounts.data?.accounts
      .filter((account) =>
        account.username.toLocaleLowerCase().includes(search.trim().toLocaleLowerCase()),
      )
      .sort((a, b) => a.username.localeCompare(b.username)) ?? [];
  const csrf = session.data?.csrfToken ?? "";
  const roles = accounts.data?.roles ?? [];
  const editing = dialog
    ? accounts.data?.accounts.find((account) => account.id === dialog.edit)
    : undefined;

  async function perform(done: string, action: () => Promise<AccountEnrollment | void>) {
    if (busy || !csrf || lifetime.signal.aborted) return;
    setBusy(true);
    setError(null);
    setEnrollment(null);
    try {
      const result = await action();
      lifetime.signal.throwIfAborted();
      if (result) setEnrollment(result);
      setDialog(null);
      if (creating) onCreatingChange(false);
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

  const failure = error ? (
    <RpcError failure={error}>
      {error.ambiguous ? (
        <p>The change outcome is unknown. Refresh the list before trying again.</p>
      ) : null}
    </RpcError>
  ) : null;

  return (
    // One minmax(0, 1fr) column: a child's min-content (a long name in a row or an
    // opened dialog's trigger state) never widens the page past the viewport.
    <section
      className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-6"
      aria-busy={accounts.isFetching || busy}
    >
      <PageHeader
        title="Accounts"
        description="Who can sign in to this console, with which role and device access."
        onRefresh={() => {
          void accounts.refetch();
          void client.invalidateQueries({ queryKey: ["identity-settings", lifetime.generation] });
        }}
        refreshing={accounts.isFetching}
        actions={
          <Button
            aria-haspopup="dialog"
            disabled={!accounts.data}
            onClick={() => {
              setError(null);
              onCreatingChange(true);
            }}
          >
            Create account
          </Button>
        }
      />
      {dialog === null && !creating ? failure : null}
      {enrollment ? (
        <section
          className="grid min-w-0 gap-3 border-2 border-primary bg-primary/5 p-4 sm:p-6"
          aria-label="One-time enrollment secret"
        >
          <h2 className="font-semibold">Save this enrollment secret now</h2>
          <p className="max-w-3xl text-sm">
            Send the secret privately to the account holder with the enrollment address below. The
            console never shows this secret again.
          </p>
          <code className="border bg-background p-3 break-all select-all">{enrollment.secret}</code>
          <p className="break-all text-sm">Enrollment address: {window.location.origin}/enroll</p>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              onClick={() => {
                navigator.clipboard.writeText(enrollment.secret).then(
                  () =>
                    toast.success(
                      "Enrollment secret copied. Share it privately, then clear the clipboard.",
                    ),
                  () => toast.error("Could not copy. Select the secret and copy it manually."),
                );
              }}
            >
              Copy enrollment secret
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                navigator.clipboard.writeText(`${window.location.origin}/enroll`).then(
                  () => toast.success("Enrollment address copied"),
                  () =>
                    toast.error(
                      "Could not copy. Select the enrollment address and copy it manually.",
                    ),
                );
              }}
            >
              Copy enrollment address
            </Button>
          </div>
          <p className="text-sm">
            Expires: <Timestamp value={enrollment.expiresAt} missing="Unknown" />
          </p>
          <TechnicalDetails items={[{ label: "Account ID", value: enrollment.accountId }]} />
          <Button className="w-fit" variant="outline" onClick={() => setEnrollment(null)}>
            Dismiss secret
          </Button>
        </section>
      ) : null}
      {accounts.isPending ? (
        <div role="status" className="grid gap-3">
          <span className="text-sm text-muted-foreground">Loading accounts…</span>
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : null}
      {accounts.isError ? (
        <RpcError failure={toRpcFailure(accounts.error)}>
          {accounts.data ? <p>Showing the accounts from the last refresh.</p> : null}
        </RpcError>
      ) : null}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="grid w-full gap-2 sm:max-w-sm">
          <Label htmlFor="account-search">Find an account</Label>
          <Input
            id="account-search"
            type="search"
            placeholder="Search by username"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          {accounts.data ? (
            <p role="status" className="text-xs text-muted-foreground">
              {matchingAccounts.length} of {accounts.data.accounts.length} accounts
            </p>
          ) : null}
        </div>
        <a href="#identity-settings-heading" className="text-sm underline underline-offset-4">
          Review sign-in source
        </a>
      </div>
      {accounts.data && accounts.data.accounts.length > 0 && matchingAccounts.length === 0 ? (
        <EmptyState
          title="No accounts match this search"
          description="Search for another username, or clear the search to see all accounts."
          action={
            <Button variant="outline" onClick={() => setSearch("")}>
              Clear search
            </Button>
          }
        />
      ) : null}
      {!accounts.isError && accounts.data?.accounts.length === 0 ? (
        <EmptyState
          title="No local accounts"
          description="Create an account to give someone console access."
          action={
            <Button aria-haspopup="dialog" onClick={() => onCreatingChange(true)}>
              Create account
            </Button>
          }
        />
      ) : null}
      {accounts.data && matchingAccounts.length > 0 ? (
        <Table aria-label="Local accounts">
          <TableHeader>
            <TableRow>
              <TableHead>Username</TableHead>
              <TableHead className="hidden md:table-cell">Role</TableHead>
              <TableHead className="hidden md:table-cell">Device access</TableHead>
              <TableHead className="hidden md:table-cell">Sign-in</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {matchingAccounts.map((account) => (
              <TableRow key={account.id} className="align-top">
                <TableCell className="max-w-0 font-medium whitespace-normal break-words md:max-w-none">
                  {account.username}
                  {account.id === principal.id ? (
                    <span className="font-normal text-muted-foreground"> (you)</span>
                  ) : null}
                  <div className="mt-2 grid gap-2 text-xs font-normal md:hidden">
                    <p>
                      {account.breakGlass ? "Emergency owner" : roleLabel(account.role)}
                      {account.role && !roles.includes(account.role) ? " (role removed)" : ""}
                    </p>
                    <p>{scopeSummary(account.scopes)}</p>
                    <AccountState account={account} />
                  </div>
                </TableCell>
                <TableCell className="hidden md:table-cell">
                  {account.breakGlass ? "Emergency owner" : roleLabel(account.role)}
                  {account.role && !roles.includes(account.role) ? (
                    <span className="text-muted-foreground"> (role removed)</span>
                  ) : null}
                </TableCell>
                <TableCell className="hidden whitespace-normal md:table-cell">
                  {scopeSummary(account.scopes)}
                </TableCell>
                <TableCell className="hidden min-w-48 whitespace-normal md:table-cell">
                  <AccountState account={account} />
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    variant="outline"
                    aria-haspopup="dialog"
                    aria-label={`Edit ${account.username}`}
                    onClick={() => {
                      setError(null);
                      setDialog({ edit: account.id });
                    }}
                  >
                    Edit
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : null}
      <Dialog
        open={creating}
        onOpenChange={(open) => {
          if (!open && !busy) onCreatingChange(false);
        }}
      >
        <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Create account</DialogTitle>
            <DialogDescription>
              The account holder gets a one-time enrollment secret to set their password and
              authenticator.
            </DialogDescription>
          </DialogHeader>
          <CreateAccountForm
            roles={roles}
            busy={busy}
            devicePicker={devicePicker}
            groupPicker={groupPicker}
            failure={failure}
            onCreate={(request) =>
              void perform("Account created", () => createAccount(request, csrf, lifetime.signal))
            }
          />
        </DialogContent>
      </Dialog>
      <Dialog
        open={editing !== undefined}
        onOpenChange={(open) => {
          if (!open && !busy) setDialog(null);
        }}
      >
        <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-2xl">
          {editing ? (
            <>
              <DialogHeader>
                <DialogTitle className="break-all">Edit {editing.username}</DialogTitle>
                <DialogDescription>
                  Changes apply at the account's next request. Resetting credentials signs them out.
                </DialogDescription>
              </DialogHeader>
              <AccountEditor
                key={`${editing.id}:${editing.role}:${editing.enabled}:${editing.breakGlass}:${editing.enrolled}:${JSON.stringify(editing.scopes)}`}
                account={editing}
                roles={roles}
                busy={busy}
                devicePicker={devicePicker}
                groupPicker={groupPicker}
                failure={failure}
                onSave={(enabled, selectedRole, breakGlass, selectedScopes) =>
                  void perform("Account saved", () =>
                    updateAccount(
                      create(UpdateAccountRequestSchema, {
                        accountId: editing.id,
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
                onReset={() =>
                  void perform("Credentials reset", () =>
                    resetAccount(editing.id, csrf, lifetime.signal),
                  )
                }
              />
            </>
          ) : null}
        </DialogContent>
      </Dialog>
      <IdentitySettings />
      <OrganizationImport devicePicker={devicePicker} groupPicker={groupPicker} />
    </section>
  );
}

// Enrollment sets the password and the passkey in one step, and a reset clears both.
function AccountState({ account }: { account: LocalAccount }) {
  const [status, label, description] = !account.enabled
    ? ([
        "neutral",
        "Disabled",
        "An administrator must enable this account before sign-in.",
      ] as const)
    : !account.enrolled
      ? (["warning", "Waiting for enrollment", "No password or passkey set yet."] as const)
      : (["success", "Password and passkey set", "Can sign in."] as const);
  return (
    <div className="grid justify-items-start gap-1">
      <StatusBadge status={status}>{label}</StatusBadge>
      <span className="text-xs whitespace-normal text-muted-foreground">{description}</span>
    </div>
  );
}

function scopeSummary(scopes: DeviceScope[]): string {
  if (scopes.length === 0) return "All devices";
  const count = (values: number, noun: string) =>
    values === 0 ? null : `${values} ${noun}${values === 1 ? "" : "s"}`;
  const parts = [
    count(new Set(scopes.flatMap((scope) => scope.groupIds)).size, "group"),
    count(new Set(scopes.flatMap((scope) => scope.deviceIds)).size, "device"),
    count(new Set(scopes.flatMap((scope) => scope.labels)).size, "label"),
  ].filter((part) => part !== null);
  return parts.length ? `Limited to ${parts.join(", ")}` : "Limited";
}

function roleOptions(roles: string[], current: string) {
  return [
    ...(current && !roles.includes(current)
      ? [{ value: current, label: `${roleLabel(current)} (unavailable)` }]
      : []),
    ...roles.map((name) => ({ value: name, label: roleLabel(name) })),
  ];
}

function CreateAccountForm({
  roles,
  busy,
  devicePicker,
  groupPicker,
  failure,
  onCreate,
}: {
  roles: string[];
  busy: boolean;
  devicePicker: PickerSlot;
  groupPicker: PickerSlot;
  failure: ReactNode;
  onCreate: (request: CreateAccountRequest) => void;
}) {
  const [username, setUsername] = useState("");
  const [role, setRole] = useState("admin");
  const [emergency, setEmergency] = useState(false);
  const [scopes, setScopes] = useState<DeviceScope[]>([]);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onCreate(
      create(CreateAccountRequestSchema, {
        username,
        role,
        breakGlass: emergency,
        scopes: normalizedScopes(scopes),
      }),
    );
  }

  return (
    <form className="grid min-w-0 gap-3" onSubmit={submit}>
      <Label htmlFor="new-username">Username</Label>
      <Input
        id="new-username"
        data-freeform="new account username"
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
        options={roleOptions(roles, "")}
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
      {failure}
      <Button className="w-fit" type="submit" disabled={busy || !roles.includes(role)}>
        {busy ? "Saving…" : "Create account"}
      </Button>
    </form>
  );
}

function AccountEditor({
  account,
  roles,
  busy,
  failure,
  onSave,
  onReset,
  devicePicker,
  groupPicker,
}: {
  account: LocalAccount;
  roles: string[];
  busy: boolean;
  failure: ReactNode;
  onSave: (enabled: boolean, role: string, breakGlass: boolean, scopes: DeviceScope[]) => void;
  onReset: () => void;
  devicePicker: PickerSlot;
  groupPicker: PickerSlot;
}) {
  const [enabled, setEnabled] = useState(account.enabled);
  const [role, setRole] = useState(account.role);
  const [emergency, setEmergency] = useState(account.breakGlass);
  const [scopes, setScopes] = useState(account.scopes);
  const [confirmingReset, setConfirmingReset] = useState(false);
  const resetButton = useRef<HTMLButtonElement>(null);
  return (
    <form
      className="grid min-w-0 gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        onSave(enabled, role, emergency, scopes);
      }}
    >
      <label className="grid gap-2 text-sm font-medium">
        Role
        <SelectField
          aria-label="Role"
          className="h-9 min-w-0"
          value={role}
          disabled={busy || emergency}
          onValueChange={(value) => setRole(value)}
          options={roleOptions(roles, role)}
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
      {failure}
      {confirmingReset ? (
        <section
          aria-labelledby="reset-credentials-heading"
          tabIndex={-1}
          ref={(node) => node?.focus()}
          className="grid gap-3 border border-destructive p-4 text-sm outline-none"
        >
          <h3 id="reset-credentials-heading" className="font-semibold break-words">
            Reset {account.username}'s credentials?
          </h3>
          <p>
            This reset signs out {account.username} and removes their password and passkey. They
            cannot sign in until they enroll with the new one-time secret shown here. You cannot
            undo this reset.
          </p>
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="destructive" disabled={busy} onClick={onReset}>
              {busy ? "Resetting…" : "Reset credentials"}
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={busy}
              onClick={() => {
                setConfirmingReset(false);
                requestAnimationFrame(() => resetButton.current?.focus());
              }}
            >
              Keep credentials
            </Button>
          </div>
        </section>
      ) : (
        <div className="flex flex-wrap gap-2">
          <Button type="submit" disabled={busy || !roles.includes(role)}>
            {busy ? "Saving…" : "Save account"}
          </Button>
          <Button
            ref={resetButton}
            type="button"
            variant="outline"
            disabled={busy}
            onClick={() => setConfirmingReset(true)}
          >
            Reset credentials…
          </Button>
        </div>
      )}
    </form>
  );
}
