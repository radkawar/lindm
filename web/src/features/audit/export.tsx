import { create } from "@bufbuild/protobuf";
import { useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
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
import { RpcError } from "@/components/ui/rpc-error";
import type { PickerSlot } from "@/components/ui/search-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { useExactRequest } from "@/hooks/use-exact-request";
import { usePrincipal } from "@/hooks/use-permissions";
import { synchronizeAuthLifetime } from "@/lib/auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { reasonError } from "@/lib/reason";
import { adminClient, clearCsrfToken } from "@/lib/rpc";
import {
  CreateAuditExportRequestSchema,
  type CreateAuditExportRequest,
} from "../../../gen/lindm/integrations/v1/reports_pb";
import { AUDIT_VIEWS, auditFilter, auditRangeLabel, type AuditSearch } from "./search";

export function AuditExport({
  search,
  accountPicker: AccountPicker,
  devicePicker: DevicePicker,
  disabled,
}: {
  search: AuditSearch;
  accountPicker: PickerSlot;
  devicePicker: PickerSlot;
  disabled: boolean;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const client = useQueryClient();
  const navigate = useNavigate();
  const action = useExactRequest<CreateAuditExportRequest>();
  const [open, setOpen] = useState(false);
  const [scope, setScope] = useState(search);
  const [reason, setReason] = useState("");
  const [artifactId, setArtifactId] = useState("");
  const authorized = canPermission(principal, "integrations.manage", true);
  const blocked = action.busy || action.ambiguous;

  function submit() {
    void action.submit({
      capture: () => {
        const invalid = reasonError(reason);
        if (invalid) throw new Error(invalid);
        return create(CreateAuditExportRequestSchema, {
          requestId: newRequestId(),
          filter: auditFilter(scope),
          afterHash: new Uint8Array(32),
          maxEvents: 100000,
          retentionDays: 30,
          reason,
        });
      },
      send: async (request, options) => {
        try {
          return await adminClient.createAuditExport(request, options);
        } catch (error) {
          if (toRpcFailure(error).unauthenticated) {
            synchronizeAuthLifetime(null);
            clearCsrfToken();
            client.clear();
            await navigate({ to: "/" });
          }
          throw error;
        }
      },
      failureTitle: "Couldn't confirm the audit export",
      onSuccess: async (response) => {
        if (!response.artifact) throw new Error("The server did not return an export.");
        setArtifactId(response.artifact.id);
        toast.success("Audit export queued");
        await client.invalidateQueries({ queryKey: ["integrations", lifetime.generation] });
      },
    });
  }

  return (
    <>
      <Button
        variant="outline"
        aria-haspopup="dialog"
        disabled={!authorized || (disabled && !blocked)}
        title={
          !authorized
            ? "Export requires unrestricted integration management permission."
            : undefined
        }
        onClick={() => {
          if (!blocked) {
            setScope(search);
            setArtifactId("");
            action.reset();
          }
          setOpen(true);
        }}
      >
        {blocked ? "Review pending export" : "Export filtered evidence"}
      </Button>
      {!authorized ? (
        <p className="text-xs text-muted-foreground">
          Export requires unrestricted integration management permission.
        </p>
      ) : null}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Export filtered evidence</DialogTitle>
            <DialogDescription>
              Includes every matching event, not just this page. Kept for 30 days.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 border p-3" aria-label="Export scope">
            <p className="font-medium">
              {AUDIT_VIEWS.find((view) => view.value === scope.view)?.label}
            </p>
            <p>{auditRangeLabel(scope)}</p>
            {scope.actorId ? (
              <AccountPicker
                label="Actor account"
                value={scope.actorId}
                onChange={(actorId) => setScope({ ...scope, actorId })}
                disabled
              />
            ) : (
              <p>All actors, including the system</p>
            )}
            {scope.deviceId ? (
              <DevicePicker
                label="Target device"
                value={scope.deviceId}
                onChange={(deviceId) => setScope({ ...scope, deviceId })}
                disabled
              />
            ) : (
              <p>All devices and events without a device</p>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            A signed selection, not a complete audit chain. More than 100,000 matches fails the
            export; narrow the range and try again.
          </p>
          {action.failure ? <RpcError failure={action.failure} /> : null}
          {action.invalid ? (
            <p role="alert" className="text-sm text-destructive">
              {action.invalid}
            </p>
          ) : null}
          {action.ambiguous ? (
            <div className="grid gap-2">
              <p>
                The export may already be queued. Retry the same export before starting another.
              </p>
              <Button disabled={action.busy} onClick={submit}>
                Retry same export
              </Button>
            </div>
          ) : null}
          {artifactId ? (
            <div className="grid gap-2" role="status">
              <p>Export queued for the scope above.</p>
              <Link
                to="/integrations"
                hash={`report-${artifactId}`}
                className="underline underline-offset-4"
              >
                View export and download evidence
              </Link>
            </div>
          ) : (
            <form
              className="grid gap-3"
              onSubmit={(event) => {
                event.preventDefault();
                submit();
              }}
            >
              <Label htmlFor="audit-export-reason">Reason for export</Label>
              <Input
                id="audit-export-reason"
                required
                value={reason}
                disabled={blocked}
                onChange={(event) => setReason(event.target.value)}
              />
              <Button type="submit" disabled={blocked}>
                {action.busy ? "Starting export…" : "Start export"}
              </Button>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
