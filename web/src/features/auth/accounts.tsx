import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { queryOptions, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent, type ReactNode } from "react";
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
}: {
  devicePicker: PickerSlot;
  groupPicker: PickerSlot;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const client = useQueryClient();
  const session = useQuery(sessionQueryOptions());
  const accounts = useQuery(accountsQueryOptions(lifetime));
  const [dialog, setDialog] = useState<"create" | { edit: string } | null>(null);
  const [enrollment, setEnrollment] = useState<AccountEnrollment | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<RpcFailure | null>(null);
  const csrf = session.data?.csrfToken ?? "";
  const roles = accounts.data?.roles ?? [];
  const editing =
    dialog !== null && dialog !== "create"
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
        <p>The change may have gone through. Refresh the list before trying again.</p>
      ) : null}
    </RpcError>
  ) : null;

  return (
    <section className="grid min-w-0 gap-6" aria-busy={accounts.isFetching || busy}>
      <PageHeader
        title="Accounts"
        description="Who can sign in to this console, with which role and device access."
        actions={
          <>
            <Button
              variant="outline"
              disabled={accounts.isFetching}
              onClick={() => void accounts.refetch()}
            >
              Refresh
            </Button>
            <Button
              aria-haspopup="dialog"
              disabled={!accounts.data}
              onClick={() => {
                setError(null);
                setDialog("create");
              }}
            >
              Create account
            </Button>
          </>
        }
      />
      {dialog === null ? failure : null}
      {enrollment ? (
        <section
          className="grid min-w-0 gap-3 border-2 border-primary bg-primary/5 p-4 sm:p-6"
          aria-label="One-time enrollment secret"
        >
          <h2 className="font-semibold">Save this enrollment secret now</h2>
          <p className="max-w-3xl text-sm">
            Send it to the account holder privately and have them open /enroll. It won't be shown
            again.
          </p>
          <code className="border bg-background p-3 break-all select-all">{enrollment.secret}</code>
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
      {!accounts.isError && accounts.data?.accounts.length === 0 ? (
        <EmptyState
          title="No local accounts"
          description="Create an account to give someone console access."
          action={
            <Button aria-haspopup="dialog" onClick={() => setDialog("create")}>
              Create account
            </Button>
          }
        />
      ) : null}
      {accounts.data && accounts.data.accounts.length > 0 ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Username</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Device access</TableHead>
              <TableHead>Sign-in</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {[...accounts.data.accounts]
              .sort((a, b) => a.username.localeCompare(b.username))
              .map((account) => (
                <TableRow key={account.id}>
                  <TableCell className="font-medium whitespace-normal break-all">
                    {account.username}
                    {account.id === principal.id ? (
                      <span className="font-normal text-muted-foreground"> (you)</span>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    {account.breakGlass ? "Emergency owner" : roleLabel(account.role)}
                    {account.role && !roles.includes(account.role) ? (
                      <span className="text-muted-foreground"> (role removed)</span>
                    ) : null}
                  </TableCell>
                  <TableCell className="whitespace-normal">
                    {scopeSummary(account.scopes)}
                  </TableCell>
                  <TableCell>
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
        open={dialog === "create"}
        onOpenChange={(open) => {
          if (!open && !busy) setDialog(null);
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
                onReset={() => {
                  if (
                    window.confirm(
                      `Reset ${editing.username}? They'll be signed out and must set up their password and authenticator again.`,
                    )
                  )
                    void perform("Credentials reset", () =>
                      resetAccount(editing.id, csrf, lifetime.signal),
                    );
                }}
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

function AccountState({ account }: { account: LocalAccount }) {
  if (!account.enabled) return <StatusBadge status="neutral">Disabled</StatusBadge>;
  if (!account.enrolled) return <StatusBadge status="warning">Waiting for setup</StatusBadge>;
  return <StatusBadge status="success">Set up</StatusBadge>;
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
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy || !roles.includes(role)}>
          {busy ? "Saving…" : "Save account"}
        </Button>
        <Button type="button" variant="outline" disabled={busy} onClick={onReset}>
          Reset credentials
        </Button>
      </div>
    </form>
  );
}
