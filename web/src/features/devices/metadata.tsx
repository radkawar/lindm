import { create } from "@bufbuild/protobuf";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { toast } from "sonner";
import {
  DeviceMetadataSchema,
  SetDeviceMetadataRequestSchema,
  type DeviceMetadata,
  type SetDeviceMetadataRequest,
} from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { Textarea } from "@/components/ui/textarea";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { classifyRpcFailure, toRpcFailure } from "@/lib/errors";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import { AttributeFields, readAttributeInputs } from "./attributes";
import { validateInventory } from "./validation";

export function DeviceMetadataCard({
  deviceId,
  metadata,
}: {
  deviceId: string;
  metadata: DeviceMetadata | undefined;
}) {
  const principal = usePrincipal();
  const [editing, setEditing] = useState<DeviceMetadata | null>(null);
  const value = metadata ?? create(DeviceMetadataSchema);
  return (
    <Card>
      <CardHeader>
        <CardTitle>Owner, labels and attributes</CardTitle>
        <CardDescription>Saving replaces all of these at once.</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <dl className="grid gap-2 text-sm">
          <dt className="text-muted-foreground">Owner</dt>
          <dd>
            {value.owner.case === "ownerPrincipalId" ? (
              <>
                Console user
                <TechnicalDetails items={[{ label: "User ID", value: value.owner.value }]} />
              </>
            ) : value.owner.case ? (
              value.owner.value
            ) : (
              "Unassigned"
            )}
          </dd>
          <dt className="text-muted-foreground">Labels</dt>
          <dd>{value.labels.length ? value.labels.join(", ") : "No labels"}</dd>
          <dt className="text-muted-foreground">Attributes</dt>
          <dd>
            {Object.keys(value.attributes).length ? (
              <ul>
                {Object.entries(value.attributes).map(([key, attribute]) => (
                  <li key={key}>
                    <span className="font-mono">{key}</span>:{" "}
                    {attribute.value.value?.toString() ?? "Not set"} (
                    {attribute.value.case?.replace("Value", "") ?? "unknown"})
                  </li>
                ))}
              </ul>
            ) : (
              "No attributes"
            )}
          </dd>
        </dl>
        {canPermission(principal, "inventory.manage") ? (
          editing ? (
            <MetadataForm deviceId={deviceId} metadata={editing} onClose={() => setEditing(null)} />
          ) : (
            <Button className="w-fit" onClick={() => setEditing(value)}>
              Edit
            </Button>
          )
        ) : (
          <p className="text-sm text-muted-foreground">
            You need inventory management access to edit these.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function MetadataForm({
  deviceId,
  metadata,
  onClose,
}: {
  deviceId: string;
  metadata: DeviceMetadata;
  onClose: () => void;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const canEditLabels = canPermission(principal, "accounts.manage", true);
  const queryClient = useQueryClient();
  const [attributes, setAttributes] = useState(metadata.attributes);
  const [ownerKind, setOwnerKind] = useState(metadata.owner.case ?? "");
  const [captured, setCaptured] = useState<SetDeviceMetadataRequest | null>(null);
  const [inputError, setInputError] = useState("");
  const inFlight = useRef(false);
  const mutation = useMutation({
    retry: false,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (request: SetDeviceMetadataRequest) => {
      await adminClient.setDeviceMetadata(request, { signal: lifetime.signal });
      lifetime.signal.throwIfAborted();
    },
    onSuccess: () => {
      if (!lifetime.signal.aborted) toast.success("Device details saved");
      void queryClient.invalidateQueries({ queryKey: ["device", lifetime.generation, deviceId] });
      void queryClient.invalidateQueries({ queryKey: ["devices", lifetime.generation] });
    },
    onError: (error) => {
      const failure = toRpcFailure(error);
      if (!lifetime.signal.aborted) {
        toast[
          classifyRpcFailure(failure).tone === "destructive"
            ? "error"
            : classifyRpcFailure(failure).tone === "warning"
              ? "warning"
              : "message"
        ](failure.ambiguous ? "Couldn't confirm changes were saved" : "Couldn't save changes");
      }
    },
    onSettled: () => {
      inFlight.current = false;
    },
  });
  const failure = mutation.error ? toRpcFailure(mutation.error) : null;
  return (
    <form
      className="grid gap-3 border-t pt-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (inFlight.current) return;
        try {
          let request = captured;
          if (!request) {
            const data = new FormData(event.currentTarget);
            const ownerText = String(data.get("owner") ?? "").trim();
            const value = create(DeviceMetadataSchema, {
              labels: canEditLabels
                ? String(data.get("labels") ?? "")
                    .split(/\s+/)
                    .filter(Boolean)
                : metadata.labels,
              owner:
                ownerKind === "ownerPrincipalId"
                  ? { case: "ownerPrincipalId", value: ownerText }
                  : ownerKind === "ownerText"
                    ? { case: "ownerText", value: ownerText }
                    : undefined,
              attributes: readAttributeInputs(data, attributes),
            });
            request = create(SetDeviceMetadataRequestSchema, {
              requestId: newRequestId(),
              deviceId,
              metadata: value,
              reason: String(data.get("reason") ?? "").trim(),
            });
            validateInventory(SetDeviceMetadataRequestSchema, request);
            setCaptured(request);
          }
          setInputError("");
          inFlight.current = true;
          mutation.mutate(request);
        } catch (error) {
          setInputError(toRpcFailure(error).message);
        }
      }}
    >
      <fieldset disabled={captured !== null} className="grid gap-3">
        <div className="grid gap-1.5">
          <Label htmlFor="metadata-owner-kind">Owner type</Label>
          <SelectField
            id="metadata-owner-kind"
            value={ownerKind}
            disabled={captured !== null}
            onValueChange={(value) => setOwnerKind(value as typeof ownerKind)}
            options={[
              { value: "", label: "Unassigned" },
              { value: "ownerText", label: "Name" },
              { value: "ownerPrincipalId", label: "Console user ID" },
            ]}
          />
        </div>
        {ownerKind ? (
          <div className="grid gap-1.5">
            <Label htmlFor="metadata-owner">
              Owner {ownerKind === "ownerPrincipalId" ? "user ID" : "name"}
            </Label>
            <Input
              id="metadata-owner"
              name="owner"
              defaultValue={metadata.owner.value ?? ""}
              required
            />
          </div>
        ) : null}
        <div className="grid gap-1.5">
          <Label htmlFor="metadata-labels">Labels (space-separated)</Label>
          <Input
            id="metadata-labels"
            name="labels"
            defaultValue={metadata.labels.join(" ")}
            readOnly={!canEditLabels}
          />
        </div>
        {!canEditLabels ? (
          <p className="text-sm text-muted-foreground">
            Labels control who can see this device. You need account management access to change
            them.
          </p>
        ) : null}
        <AttributeFields attributes={attributes} onChange={setAttributes} />
        <div className="grid gap-1.5">
          <Label htmlFor="metadata-reason">Reason</Label>
          <Textarea id="metadata-reason" name="reason" required />
        </div>
      </fieldset>
      {captured ? (
        <TechnicalDetails items={[{ label: "Request ID", value: captured.requestId }]} />
      ) : null}
      {failure ? (
        <RpcError failure={failure}>
          {failure.ambiguous ? <p>We couldn&apos;t confirm the save. Retry to make sure.</p> : null}
        </RpcError>
      ) : null}
      {inputError ? (
        <p role="alert" className="text-sm text-destructive">
          {inputError}
        </p>
      ) : null}
      {mutation.isSuccess ? <p role="status">Saved.</p> : null}
      <div className="flex gap-2">
        <Button type="submit" disabled={mutation.isPending || mutation.isSuccess}>
          {mutation.isPending ? "Saving…" : captured ? "Retry" : "Save"}
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={mutation.isPending || failure?.ambiguous}
          onClick={onClose}
        >
          {mutation.isSuccess ? "Close" : "Cancel"}
        </Button>
        {captured && !failure?.ambiguous ? (
          <Button
            type="button"
            variant="outline"
            disabled={mutation.isPending}
            onClick={() => {
              setCaptured(null);
              mutation.reset();
            }}
          >
            Edit and try again
          </Button>
        ) : null}
      </div>
    </form>
  );
}
