import { create } from "@bufbuild/protobuf";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { MoreHorizontal } from "lucide-react";
import { useId, useRef, useState, type FormEvent, type ReactNode } from "react";
import { toast } from "sonner";
import {
  DeleteSecretRequestSchema,
  RotateSecretRequestSchema,
  type DeleteSecretRequest,
  type ListSecretUsesResponse,
  type RotateSecretRequest,
  type SecretSettingUse,
  type SecretSummary,
} from "../../../gen/lindm/admin/v1/secrets_pb";
import { ResourceKind } from "../../../gen/lindm/resource/v1/identity_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RpcError } from "@/components/ui/rpc-error";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useExactRequest } from "@/hooks/use-exact-request";
import { toRpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { adminClient } from "@/lib/rpc";
import { MaterialField, purposeLabels, takeMaterial } from "./material";
import { secretUsesQueryOptions } from "./queries";
import { validateRequest } from "@/lib/validation";
import { secretMaterialHints } from "./validation";

export function secretName(secret: SecretSummary): string {
  return secret.displayName.trim() || "Unnamed secret";
}

function count(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? "" : "s"}`;
}

function confirmationKey(text: string): string {
  return text
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]/gu, "");
}

// Typed confirmation of a secret name ignores capitals, spaces and punctuation,
// so "officewifi" confirms "Office Wi-Fi" and still names this secret. A name
// with no letters or digits must be typed exactly.
export function confirmsSecretName(typed: string, name: string): boolean {
  const expected = confirmationKey(name);
  return expected === "" ? typed.trim() === name.trim() : confirmationKey(typed) === expected;
}

export const CONFIRMATION_HINT = "Capitals, spaces and punctuation don't matter.";

// Only these setting kinds carry secret references.
const settingKindLabels: Partial<Record<ResourceKind, string>> = {
  [ResourceKind.LOCAL_USER]: "Local account",
  [ResourceKind.NETWORK_CONNECTION]: "Network connection",
  [ResourceKind.PROXY]: "Proxy",
  [ResourceKind.PACKAGE_REPOSITORY]: "Package repository",
  [ResourceKind.DIRECTORY_CLIENT]: "Directory connection",
};

function SettingLine({
  setting,
  currentVersion,
}: {
  setting: SecretSettingUse;
  currentVersion: bigint;
}) {
  const kind = settingKindLabels[setting.resource?.kind ?? ResourceKind.UNSPECIFIED] ?? "Setting";
  const name = setting.name.trim();
  return (
    <li className="break-words text-muted-foreground">
      {name ? `${kind} ${name}` : kind}
      {setting.version === 0n
        ? null
        : setting.version === currentVersion
          ? ", current version"
          : `, version ${setting.version.toString()} (current is ${currentVersion.toString()})`}
    </li>
  );
}

export function usesTotal(uses: ListSecretUsesResponse): number {
  return uses.profileCount + uses.deviceCount;
}

// The blast radius of changing or deleting a secret: the profiles whose current
// version uses it and the devices whose current settings receive it.
export function SecretUsesList({
  uses,
  currentVersion,
}: {
  uses: ListSecretUsesResponse;
  currentVersion: bigint;
}) {
  if (usesTotal(uses) === 0)
    return (
      <p className="text-sm" data-review-impact="targets">
        No profile or device uses this secret.
      </p>
    );
  const hidden = uses.deviceCount - uses.visibleDeviceCount;
  return (
    <div className="grid gap-4 text-sm" data-review-impact="targets">
      <section className="grid gap-2" aria-label="Profiles that use this secret">
        <h3 className="font-medium">
          {uses.profileCount === 0 ? "No profile uses it" : count(uses.profileCount, "profile")}
        </h3>
        {uses.profiles.length > 0 ? (
          <ul className="grid gap-2">
            {uses.profiles.map((profile) => (
              <li key={profile.profileId} className="grid gap-0.5">
                <span className="break-words">
                  <Link
                    to="/profiles/$profileId"
                    params={{ profileId: profile.profileId }}
                    search={{ revision: "" }}
                    className="underline underline-offset-4"
                  >
                    {profile.profileName.trim() || "Unnamed profile"}
                  </Link>{" "}
                  <span className="text-muted-foreground">
                    version {profile.revisionNumber.toString()}
                  </span>
                </span>
                <ul>
                  {profile.settings.map((setting, index) => (
                    <SettingLine key={index} setting={setting} currentVersion={currentVersion} />
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        ) : null}
        {uses.profiles.length < uses.profileCount ? (
          <p className="text-muted-foreground">
            Showing the first {uses.profiles.length}. Search profiles for the rest.
          </p>
        ) : null}
      </section>
      <section className="grid gap-2" aria-label="Devices that receive this secret">
        <h3 className="font-medium">
          {uses.deviceCount === 0 ? "No device receives it yet" : count(uses.deviceCount, "device")}
        </h3>
        {uses.devices.length > 0 ? (
          <ul className="grid gap-2">
            {uses.devices.map((device) => (
              <li key={device.deviceId} className="grid gap-0.5">
                <span className="break-words">
                  <Link
                    to="/devices/$deviceId"
                    params={{ deviceId: device.deviceId }}
                    search={{ pageSize: 50, pageToken: "", manager: "", namePrefix: "" }}
                    className="underline underline-offset-4"
                  >
                    {device.hostname.trim() || "Unnamed device"}
                  </Link>
                </span>
                <ul>
                  {device.settings.map((setting, index) => (
                    <SettingLine key={index} setting={setting} currentVersion={currentVersion} />
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        ) : null}
        {uses.devices.length < uses.visibleDeviceCount ? (
          <p className="text-muted-foreground">
            Showing the first {count(uses.devices.length, "device")}.
          </p>
        ) : null}
        {hidden > 0 ? (
          <p className="text-muted-foreground">
            {count(hidden, "more device")} outside the devices you manage.
          </p>
        ) : null}
      </section>
    </div>
  );
}

function UsesState({
  secret,
  open,
  children,
}: {
  secret: SecretSummary;
  open: boolean;
  children: (uses: ListSecretUsesResponse) => ReactNode;
}) {
  const lifetime = useAuthLifetime();
  const uses = useQuery({ ...secretUsesQueryOptions(lifetime, secret.secretId), enabled: open });
  if (uses.error) return <RpcError failure={toRpcFailure(uses.error)} title="Uses not loaded" />;
  if (!uses.data)
    return (
      <div role="status" className="grid gap-2">
        <span className="text-sm text-muted-foreground">Finding where it&apos;s used…</span>
        <Skeleton className="h-8 w-full" />
      </div>
    );
  return <>{children(uses.data)}</>;
}

export function SecretUsesDialog({
  secret,
  open,
  onOpenChange,
}: {
  secret: SecretSummary;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Where {secretName(secret)} is used</DialogTitle>
          <DialogDescription>
            Profiles in their current version, and devices that receive it now.
          </DialogDescription>
        </DialogHeader>
        <UsesState secret={secret} open={open}>
          {(uses) => <SecretUsesList uses={uses} currentVersion={secret.currentVersion} />}
        </UsesState>
      </DialogContent>
    </Dialog>
  );
}

export function RotateSecretDialog({
  secret,
  open,
  onOpenChange,
}: {
  secret: SecretSummary;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent keepMounted className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Rotate {secretName(secret)}</DialogTitle>
          <DialogDescription>
            Saves version {(secret.currentVersion + 1n).toString()}. Devices keep the current
            version until you update the profile.
          </DialogDescription>
        </DialogHeader>
        <RotateSecretForm
          key={secret.currentVersion.toString()}
          secret={secret}
          onRotated={() => onOpenChange(false)}
        />
      </DialogContent>
    </Dialog>
  );
}

function RotateSecretForm({ secret, onRotated }: { secret: SecretSummary; onRotated: () => void }) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const id = useId();
  const exact = useExactRequest<RotateSecretRequest>();
  const [reason, setReason] = useState("");
  const locked = exact.busy || exact.ambiguous;

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    void exact.submit({
      capture: () => {
        const material = takeMaterial(form, secret.purpose);
        const request = create(RotateSecretRequestSchema, {
          requestId: newRequestId(),
          secretId: secret.secretId,
          expectedVersion: secret.currentVersion,
          material,
          reason: reason.trim(),
        });
        try {
          validateRequest(RotateSecretRequestSchema, request, secretMaterialHints);
        } catch (error) {
          material.material.value?.fill(0);
          throw error;
        }
        return request;
      },
      send: (request, options) => adminClient.rotateSecret(request, options),
      discard: (request) => request.material?.material.value?.fill(0),
      failureTitle: "Secret rotation",
      onSuccess: async (response) => {
        setReason("");
        onRotated();
        toast.success(`Version ${response.secret?.currentVersion.toString() ?? "unknown"} saved`, {
          description: "Update the profile to send it to devices.",
        });
        await Promise.all([
          queryClient.invalidateQueries({
            queryKey: ["secret", lifetime.generation, secret.secretId],
          }),
          queryClient.invalidateQueries({ queryKey: ["secrets", lifetime.generation] }),
          queryClient.invalidateQueries({
            queryKey: ["secret-uses", lifetime.generation, secret.secretId],
          }),
        ]);
      },
    });
  }

  return (
    <form className="grid gap-4" onSubmit={submit} autoComplete="off">
      <MaterialField id={`${id}-material`} purpose={secret.purpose} disabled={locked} />
      <div className="grid gap-2">
        <Label htmlFor={`${id}-reason`}>Reason</Label>
        <Textarea
          id={`${id}-reason`}
          data-freeform="audit reason"
          value={reason}
          readOnly={locked}
          onChange={(event) => setReason(event.target.value)}
        />
      </div>
      {exact.invalid ? (
        <p role="alert" className="text-sm text-destructive">
          {exact.invalid}
        </p>
      ) : null}
      {exact.failure ? (
        <RpcError failure={exact.failure} title="Secret not rotated">
          {exact.ambiguous ? (
            <p>
              Refresh to see whether a new version was saved. Try again, or discard to start over.
            </p>
          ) : null}
        </RpcError>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={exact.busy}>
          {exact.busy ? "Storing…" : exact.ambiguous ? "Try again" : "Rotate secret"}
        </Button>
        {exact.ambiguous ? (
          <Button type="button" variant="outline" disabled={exact.busy} onClick={exact.reset}>
            Discard
          </Button>
        ) : null}
      </div>
    </form>
  );
}

export function DeleteSecretDialog({
  secret,
  open,
  onOpenChange,
  onDeleted,
}: {
  secret: SecretSummary;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDeleted?: () => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Delete {secretName(secret)}</DialogTitle>
          <DialogDescription>
            {purposeLabels[secret.purpose] ?? "Unrecognized purpose"}, version{" "}
            {secret.currentVersion.toString()}
          </DialogDescription>
        </DialogHeader>
        <UsesState secret={secret} open={open}>
          {(uses) =>
            usesTotal(uses) > 0 ? (
              <div className="grid gap-4">
                <Alert>
                  <AlertTitle>In use, so it can&apos;t be deleted</AlertTitle>
                  <AlertDescription>
                    Choose another secret in these profiles and publish them. Devices stop using it
                    once they apply the new version.
                  </AlertDescription>
                </Alert>
                <SecretUsesList uses={uses} currentVersion={secret.currentVersion} />
                <div className="grid gap-1">
                  <Button
                    variant="destructive"
                    className="w-fit"
                    disabled
                    aria-describedby={`delete-blocked-${secret.secretId}`}
                  >
                    Delete secret
                  </Button>
                  <p
                    id={`delete-blocked-${secret.secretId}`}
                    className="text-sm text-muted-foreground"
                  >
                    Available once no profile or device uses it.
                  </p>
                </div>
              </div>
            ) : (
              <DeleteSecretForm
                secret={secret}
                onDeleted={() => {
                  onOpenChange(false);
                  onDeleted?.();
                }}
              />
            )
          }
        </UsesState>
      </DialogContent>
    </Dialog>
  );
}

function DeleteSecretForm({ secret, onDeleted }: { secret: SecretSummary; onDeleted: () => void }) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const id = useId();
  const exact = useExactRequest<DeleteSecretRequest>();
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const name = secret.displayName.trim() || secret.secretId;
  const locked = exact.busy || exact.ambiguous;
  const confirmed = confirmsSecretName(confirmation, name);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void exact.submit({
      capture: () => {
        if (!confirmed) throw new Error("Type the secret name as shown to confirm.");
        const request = create(DeleteSecretRequestSchema, {
          requestId: newRequestId(),
          secretId: secret.secretId,
          reason: reason.trim(),
        });
        validateRequest(DeleteSecretRequestSchema, request);
        return request;
      },
      send: (request, options) => adminClient.deleteSecret(request, options),
      failureTitle: "Secret deletion",
      onSuccess: async () => {
        toast.success("Secret deleted");
        onDeleted();
        await queryClient.invalidateQueries({ queryKey: ["secrets", lifetime.generation] });
        queryClient.removeQueries({ queryKey: ["secret", lifetime.generation, secret.secretId] });
      },
    });
  }

  return (
    <form
      className="grid gap-4"
      onSubmit={submit}
      autoComplete="off"
      data-review-destructive="delete-secret"
    >
      <dl className="grid gap-3 text-sm">
        <div data-review-impact="targets">
          <dt className="font-medium">Secret</dt>
          <dd className="break-words">{secretName(secret)}</dd>
        </div>
        <div data-review-impact="count">
          <dt className="font-medium">Used by</dt>
          <dd>No profile or device uses it.</dd>
        </div>
        <div data-review-impact="effects">
          <dt className="font-medium">Effect</dt>
          <dd>
            {secret.currentVersion === 1n
              ? "Erases the stored value from the server."
              : `Erases all ${secret.currentVersion.toString()} versions of the value from the server.`}{" "}
            Who created and changed it stays in the audit log.
          </dd>
        </div>
        <div data-review-impact="reversibility">
          <dt className="font-medium">Undo</dt>
          <dd>Not possible. To use this credential again, create a new secret.</dd>
        </div>
        <div data-review-impact="approval">
          <dt className="font-medium">Approval</dt>
          <dd>Not required.</dd>
        </div>
      </dl>
      <div className="grid gap-2">
        <Label htmlFor={`${id}-reason`}>Reason</Label>
        <Textarea
          id={`${id}-reason`}
          data-freeform="audit reason"
          value={reason}
          readOnly={locked}
          onChange={(event) => setReason(event.target.value)}
        />
      </div>
      <div className="grid gap-2">
        <Label htmlFor={`${id}-confirmation`} className="block leading-normal">
          Type <span className="break-all">{name}</span> to confirm
        </Label>
        <Input
          id={`${id}-confirmation`}
          data-freeform="typed confirmation of the secret name"
          value={confirmation}
          readOnly={locked}
          autoComplete="off"
          aria-describedby={`${id}-confirmation-hint`}
          aria-invalid={confirmation.trim() !== "" && !confirmed}
          onChange={(event) => setConfirmation(event.target.value)}
        />
        <p id={`${id}-confirmation-hint`} className="text-sm text-muted-foreground">
          {CONFIRMATION_HINT}
        </p>
      </div>
      {exact.invalid ? (
        <p role="alert" className="text-sm text-destructive">
          {exact.invalid}
        </p>
      ) : null}
      {exact.failure ? (
        <RpcError failure={exact.failure} title="Secret not deleted">
          {exact.ambiguous ? (
            <p>Refresh to see whether it was deleted. Try again, or discard to start over.</p>
          ) : null}
        </RpcError>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button
          type="submit"
          variant="destructive"
          data-review-confirm
          disabled={exact.busy || !confirmed || reason.trim() === ""}
          aria-describedby={confirmed && reason.trim() !== "" ? undefined : `${id}-prerequisite`}
        >
          {exact.busy ? "Deleting…" : exact.ambiguous ? "Try again" : "Delete secret"}
        </Button>
        {exact.ambiguous ? (
          <Button type="button" variant="outline" disabled={exact.busy} onClick={exact.reset}>
            Discard
          </Button>
        ) : null}
      </div>
      {confirmed && reason.trim() !== "" ? null : (
        <p id={`${id}-prerequisite`} className="text-sm text-muted-foreground">
          Enter a reason and type the name to delete.
        </p>
      )}
    </form>
  );
}

// Row actions on a secret in the list; dialogs restore focus to the menu button.
export function SecretRowActions({
  secret,
  canManage,
}: {
  secret: SecretSummary;
  canManage: boolean;
}) {
  const [open, setOpen] = useState<"uses" | "rotate" | "delete" | null>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const change = (kind: "uses" | "rotate" | "delete") => (next: boolean) => {
    setOpen(next ? kind : null);
    if (!next) trigger.current?.focus();
  };
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger
          render={
            <Button
              ref={trigger}
              size="icon-sm"
              variant="ghost"
              aria-label={`Actions for ${secretName(secret)}`}
            />
          }
        >
          <MoreHorizontal aria-hidden="true" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="min-w-44">
          <DropdownMenuItem aria-haspopup="dialog" onClick={() => setOpen("uses")}>
            Where it&apos;s used
          </DropdownMenuItem>
          {canManage ? (
            <>
              <DropdownMenuItem aria-haspopup="dialog" onClick={() => setOpen("rotate")}>
                Rotate…
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                variant="destructive"
                aria-haspopup="dialog"
                onClick={() => setOpen("delete")}
              >
                Delete…
              </DropdownMenuItem>
            </>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
      <SecretUsesDialog secret={secret} open={open === "uses"} onOpenChange={change("uses")} />
      {canManage ? (
        <>
          {open === "rotate" ? (
            <RotateSecretDialog secret={secret} open onOpenChange={change("rotate")} />
          ) : null}
          <DeleteSecretDialog
            secret={secret}
            open={open === "delete"}
            onOpenChange={change("delete")}
          />
        </>
      ) : null}
    </>
  );
}
