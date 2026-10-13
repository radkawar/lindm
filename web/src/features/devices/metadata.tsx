import { create } from "@bufbuild/protobuf";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { toast } from "sonner";
import { X } from "lucide-react";
import {
  DeviceMetadataSchema,
  SetDeviceMetadataRequestSchema,
  type DeviceMetadata,
  type SetDeviceMetadataRequest,
} from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { SuggestionField } from "../../../gen/lindm/admin/v1/suggestions_pb";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import type { PickerSlot } from "@/components/ui/search-picker";
import { SuggestionPicker } from "@/components/ui/suggestion-picker";
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
import { checkRequest, validateRequest } from "@/lib/validation";

const LABEL_HINT =
  "Use letters, digits and . _ : / -. Start with a letter or digit. Use at most 64 characters.";

export function DeviceMetadataCard({
  deviceId,
  metadata,
  accountPicker,
}: {
  deviceId: string;
  metadata: DeviceMetadata | undefined;
  accountPicker: PickerSlot;
}) {
  const principal = usePrincipal();
  const [editing, setEditing] = useState<DeviceMetadata | null>(null);
  const value = metadata ?? create(DeviceMetadataSchema);
  return (
    <Card>
      <CardHeader>
        <CardTitle>Owner, labels and attributes</CardTitle>
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
                    {attribute.value.value?.toString() ?? "Not set"}
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
            <MetadataForm
              deviceId={deviceId}
              metadata={editing}
              accountPicker={accountPicker}
              onClose={() => setEditing(null)}
            />
          ) : (
            <Button className="w-fit" variant="outline" onClick={() => setEditing(value)}>
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
  accountPicker,
}: {
  deviceId: string;
  metadata: DeviceMetadata;
  onClose: () => void;
  accountPicker: PickerSlot;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const canEditLabels = canPermission(principal, "accounts.manage", true);
  const queryClient = useQueryClient();
  const [attributes, setAttributes] = useState(metadata.attributes);
  const [labels, setLabels] = useState(metadata.labels);
  const [labelError, setLabelError] = useState("");
  const [ownerKind, setOwnerKind] = useState(metadata.owner.case ?? "");
  const [ownerPrincipalId, setOwnerPrincipalId] = useState(
    metadata.owner.case === "ownerPrincipalId" ? metadata.owner.value : "",
  );
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
        ](failure.ambiguous ? "Server did not confirm the save" : "Could not save changes");
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
          // First submit captures the exact request and shows what changes;
          // the second sends that same request.
          if (!captured) {
            const data = new FormData(event.currentTarget);
            const ownerText = String(data.get("owner") ?? "").trim();
            const value = create(DeviceMetadataSchema, {
              labels: canEditLabels ? labels : metadata.labels,
              owner:
                ownerKind === "ownerPrincipalId"
                  ? { case: "ownerPrincipalId", value: ownerPrincipalId }
                  : ownerKind === "ownerText"
                    ? { case: "ownerText", value: ownerText }
                    : undefined,
              attributes: readAttributeInputs(data, attributes),
            });
            const request = create(SetDeviceMetadataRequestSchema, {
              requestId: newRequestId(),
              deviceId,
              metadata: value,
              reason: String(data.get("reason") ?? "").trim(),
            });
            validateRequest(SetDeviceMetadataRequestSchema, request, {
              "metadata.labels": LABEL_HINT,
            });
            if (metadataChanges(metadata, value).length === 0) {
              setInputError("Nothing changed. Edit a field. To leave without changes, cancel.");
              return;
            }
            setInputError("");
            setCaptured(request);
            return;
          }
          setInputError("");
          inFlight.current = true;
          mutation.mutate(captured);
        } catch (error) {
          setInputError(toRpcFailure(error).message);
        }
      }}
    >
      <fieldset disabled={captured !== null} className="grid gap-3">
        <div className="grid gap-1.5">
          <Label htmlFor="metadata-owner-kind">Who owns this device</Label>
          <SelectField
            id="metadata-owner-kind"
            value={ownerKind}
            disabled={captured !== null}
            onValueChange={(value) => setOwnerKind(value as typeof ownerKind)}
            options={[
              { value: "", label: "No owner recorded" },
              { value: "ownerPrincipalId", label: "Someone with a console account" },
              { value: "ownerText", label: "Someone without a console account" },
            ]}
          />
          <p className="text-xs text-muted-foreground">
            Pick the account when the owner signs in to this console; otherwise type their name.
          </p>
        </div>
        {ownerKind === "ownerPrincipalId" ? (
          accountPicker({
            label: "Owner account",
            value: ownerPrincipalId,
            onChange: setOwnerPrincipalId,
            disabled: captured !== null,
          })
        ) : ownerKind === "ownerText" ? (
          <div className="grid gap-1.5">
            <Label htmlFor="metadata-owner">Owner name</Label>
            <Input
              id="metadata-owner"
              name="owner"
              defaultValue={metadata.owner.case === "ownerText" ? metadata.owner.value : ""}
              required
              data-freeform="owner's name for someone without a console account"
            />
          </div>
        ) : null}
        <div className="grid gap-2">
          {canEditLabels ? (
            <SuggestionPicker
              label="Add a label"
              field={SuggestionField.DEVICE_LABEL}
              placeholder="Choose or type a label"
              note="Labels already used on your devices. Type a new one to create it."
              allowTyped
              typedDescription="New label"
              value=""
              disabled={captured !== null}
              onChange={(label) => {
                if (!label) return;
                // Checked when added, against the same schema rule as Save.
                const problem = checkRequest(
                  DeviceMetadataSchema,
                  create(DeviceMetadataSchema, { labels: [label] }),
                );
                setLabelError(problem ? `“${label}” can't be a label. ${LABEL_HINT}` : "");
                if (!problem && !labels.includes(label)) setLabels([...labels, label]);
              }}
            />
          ) : (
            <span className="text-sm font-medium">Labels</span>
          )}
          {labelError ? (
            <p id="metadata-label-error" role="alert" className="text-sm text-destructive">
              {labelError}
            </p>
          ) : null}
          {labels.length ? (
            <ul className="flex flex-wrap gap-2" aria-label="Labels">
              {labels.map((label) => (
                <li key={label}>
                  {canEditLabels ? (
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="h-7 max-w-72 rounded-full bg-muted/40 px-2.5 text-xs"
                      aria-label={`Remove label ${label}`}
                      onClick={() => setLabels(labels.filter((value) => value !== label))}
                    >
                      <span className="truncate">{label}</span>
                      <X className="size-3 shrink-0" aria-hidden="true" />
                    </Button>
                  ) : (
                    <span className="rounded-full border px-2.5 py-1 text-xs">{label}</span>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">No labels.</p>
          )}
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
          <Textarea
            id="metadata-reason"
            name="reason"
            required
            data-freeform="audit reason for this change"
          />
        </div>
      </fieldset>
      {captured?.metadata ? (
        <section
          aria-labelledby="metadata-review"
          className="grid gap-2 border bg-muted/30 p-3 text-sm"
        >
          <h3 id="metadata-review" className="font-medium">
            Review before saving
          </h3>
          <ul className="grid gap-1">
            {metadataChanges(metadata, captured.metadata).map((change) => (
              <li key={change}>{change}</li>
            ))}
          </ul>
          <p className="text-muted-foreground">
            Other settings stay unchanged. Labels can change who has access to this device.
          </p>
          <TechnicalDetails items={[{ label: "Request ID", value: captured.requestId }]} />
        </section>
      ) : null}
      {failure ? (
        <RpcError failure={failure}>
          {failure.ambiguous ? (
            <p>The server did not confirm the save. Retry the same request.</p>
          ) : null}
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
          {mutation.isPending
            ? "Saving…"
            : failure
              ? "Retry"
              : captured
                ? "Save these changes"
                : "Review changes"}
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={mutation.isPending || failure?.ambiguous}
          onClick={onClose}
        >
          {mutation.isSuccess ? "Close" : "Cancel"}
        </Button>
        {captured && !failure?.ambiguous && !mutation.isSuccess ? (
          <Button
            type="button"
            variant="outline"
            disabled={mutation.isPending}
            onClick={() => {
              setCaptured(null);
              mutation.reset();
            }}
          >
            {failure ? "Edit and try again" : "Change something"}
          </Button>
        ) : null}
      </div>
    </form>
  );
}

function ownerLabel(metadata: DeviceMetadata) {
  return metadata.owner.case === "ownerPrincipalId"
    ? "a console account"
    : metadata.owner.case === "ownerText"
      ? `“${metadata.owner.value}”`
      : "no owner";
}

// Plain sentences naming each field that changes, old → new.
function metadataChanges(before: DeviceMetadata, after: DeviceMetadata): string[] {
  const changes: string[] = [];
  if (
    before.owner.case !== after.owner.case ||
    (before.owner.value ?? "") !== (after.owner.value ?? "")
  ) {
    changes.push(
      before.owner.case === "ownerPrincipalId" && after.owner.case === "ownerPrincipalId"
        ? "Owner: a different console account"
        : `Owner: ${ownerLabel(before)} → ${ownerLabel(after)}`,
    );
  }
  const added = after.labels.filter((label) => !before.labels.includes(label));
  const removed = before.labels.filter((label) => !after.labels.includes(label));
  if (added.length) changes.push(`Add labels: ${added.join(", ")}`);
  if (removed.length) changes.push(`Remove labels: ${removed.join(", ")}`);
  const keys = new Set([...Object.keys(before.attributes), ...Object.keys(after.attributes)]);
  for (const key of [...keys].sort()) {
    const old = before.attributes[key]?.value.value?.toString();
    const next = after.attributes[key]?.value.value?.toString();
    if (old === next) continue;
    changes.push(
      old === undefined
        ? `Set ${key} to ${next}`
        : next === undefined
          ? `Clear ${key} (was ${old})`
          : `${key}: ${old} → ${next}`,
    );
  }
  return changes;
}
