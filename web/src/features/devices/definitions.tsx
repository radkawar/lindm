// SPDX-License-Identifier: Apache-2.0

import { create } from "@bufbuild/protobuf";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { toast } from "sonner";
import {
  AttributeDefinitionSchema,
  AttributeType,
  SetAttributeDefinitionRequestSchema,
  type AttributeDefinition,
  type SetAttributeDefinitionRequest,
} from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ListPagination } from "@/components/ui/list-pagination";
import { SelectField } from "@/components/ui/select-field";
import { Textarea } from "@/components/ui/textarea";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { classifyRpcFailure, toRpcFailure } from "@/lib/errors";
import { RpcError } from "@/components/ui/rpc-error";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import {
  ATTRIBUTE_TYPE_LABEL,
  attributeName,
  definitionFieldErrors,
  keyFromName,
  type DefinitionFieldErrors,
} from "./attribute-names";
import { attributeDefinitionsQueryOptions } from "./queries";
import { validateRequest } from "@/lib/validation";

export function AttributeDefinitions() {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const canRead = canPermission(principal, "fleet.read", true);
  const [afterKey, setAfterKey] = useState("");
  const [editing, setEditing] = useState<AttributeDefinition | null>(null);
  const definitions = useQuery({
    ...attributeDefinitionsQueryOptions(lifetime, afterKey),
    enabled: canRead,
  });
  const failure = definitions.error ? toRpcFailure(definitions.error) : null;
  const data = failure ? undefined : definitions.data;
  const canManage = canPermission(principal, "inventory.manage", true);
  if (!canRead) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Custom attributes</CardTitle>
        <CardDescription>
          Attributes you can set on devices. Each one is text, a number, yes/no, or a fixed list.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {failure ? <RpcError failure={failure} /> : null}
        {definitions.isPending ? <p role="status">Loading attributes…</p> : null}
        {data ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Allowed values</TableHead>
                {canManage ? <TableHead>Action</TableHead> : null}
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.definitions.map((definition) => (
                <TableRow key={definition.key}>
                  <TableCell>
                    <span className="grid">
                      <span>{attributeName(definition)}</span>
                      {definition.displayName ? (
                        <span className="font-mono text-xs text-muted-foreground">
                          {definition.key}
                        </span>
                      ) : null}
                    </span>
                  </TableCell>
                  <TableCell>{ATTRIBUTE_TYPE_LABEL[definition.type] ?? "Unknown"}</TableCell>
                  <TableCell className="whitespace-normal">
                    {definition.enumValues.join(", ") || "Any"}
                  </TableCell>
                  {canManage ? (
                    <TableCell>
                      <Button
                        variant="outline"
                        disabled={editing !== null}
                        onClick={() => setEditing(definition)}
                      >
                        Edit {attributeName(definition)}
                      </Button>
                    </TableCell>
                  ) : null}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : null}
        {data?.definitions.length === 0 ? <p>No custom attributes yet.</p> : null}
        <ListPagination
          label="Custom attribute pages"
          busy={definitions.isFetching}
          onPrevious={afterKey ? () => setAfterKey("") : undefined}
          onNext={data?.nextAfterKey ? () => setAfterKey(data.nextAfterKey) : undefined}
        />
        {canManage && !editing ? (
          <Button
            className="w-fit"
            onClick={() =>
              setEditing(create(AttributeDefinitionSchema, { type: AttributeType.STRING }))
            }
          >
            Add attribute
          </Button>
        ) : null}
        {editing ? <DefinitionForm definition={editing} onClose={() => setEditing(null)} /> : null}
      </CardContent>
    </Card>
  );
}

function DefinitionForm({
  definition,
  onClose,
}: {
  definition: AttributeDefinition;
  onClose: () => void;
}) {
  const lifetime = useAuthLifetime();
  const queryClient = useQueryClient();
  const existing = definition.key !== "";
  const [type, setType] = useState(definition.type);
  const [displayName, setDisplayName] = useState(attributeName(definition));
  const [key, setKey] = useState(definition.key);
  const [keyEdited, setKeyEdited] = useState(existing);
  const [errors, setErrors] = useState<DefinitionFieldErrors>({});
  const [captured, setCaptured] = useState<SetAttributeDefinitionRequest | null>(null);
  const [inputError, setInputError] = useState("");
  const inFlight = useRef(false);
  const save = useMutation({
    retry: false,
    meta: { authGeneration: lifetime.generation },
    mutationFn: async (request: SetAttributeDefinitionRequest) => {
      await adminClient.setAttributeDefinition(request, { signal: lifetime.signal });
      lifetime.signal.throwIfAborted();
    },
    onSuccess: () => {
      if (!lifetime.signal.aborted) toast.success("Attribute saved");
      void queryClient.invalidateQueries({
        queryKey: ["attribute-definitions", lifetime.generation],
      });
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
        ](failure.ambiguous ? "Server did not confirm the save" : "Could not save attribute");
      }
    },
    onSettled: () => {
      inFlight.current = false;
    },
  });
  const failure = save.error ? toRpcFailure(save.error) : null;
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
            const fields = {
              displayName: displayName.trim(),
              key: key.trim(),
              type,
              enumValues:
                type === AttributeType.ENUM
                  ? String(data.get("enum") ?? "")
                      .split("\n")
                      .map((value) => value.trim())
                      .filter(Boolean)
                  : [],
              reason: String(data.get("reason") ?? "").trim(),
            };
            const found = definitionFieldErrors(fields);
            setErrors(found);
            if (Object.keys(found).length) {
              setInputError("");
              return;
            }
            request = create(SetAttributeDefinitionRequestSchema, {
              requestId: newRequestId(),
              definition: {
                key: fields.key,
                displayName: fields.displayName,
                type,
                enumValues: fields.enumValues,
              },
              reason: fields.reason,
            });
            validateRequest(SetAttributeDefinitionRequestSchema, request);
            setCaptured(request);
          }
          setInputError("");
          inFlight.current = true;
          save.mutate(request);
        } catch {
          setInputError("The server cannot save these entries. Check each field. Try again.");
        }
      }}
    >
      <fieldset disabled={captured !== null} className="grid gap-3">
        <div className="grid gap-1.5">
          <Label htmlFor="definition-name">Name</Label>
          <Input
            id="definition-name"
            data-freeform="attribute display name"
            value={displayName}
            aria-invalid={errors.displayName ? true : undefined}
            aria-describedby={errors.displayName ? "definition-name-error" : undefined}
            onChange={(event) => {
              setDisplayName(event.target.value);
              if (!keyEdited) setKey(keyFromName(event.target.value));
              setErrors((current) => ({ ...current, displayName: undefined }));
            }}
          />
          {errors.displayName ? (
            <p id="definition-name-error" className="text-sm text-destructive">
              {errors.displayName}
            </p>
          ) : null}
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="definition-key">Key</Label>
          <Input
            id="definition-key"
            data-freeform="name of a new attribute definition"
            className="font-mono"
            value={key}
            readOnly={existing}
            aria-invalid={errors.key ? true : undefined}
            aria-describedby={errors.key ? "definition-key-error" : "definition-key-hint"}
            onChange={(event) => {
              setKey(event.target.value);
              setKeyEdited(true);
              setErrors((current) => ({ ...current, key: undefined }));
            }}
          />
          {errors.key ? (
            <p id="definition-key-error" className="text-sm text-destructive">
              {errors.key}
            </p>
          ) : (
            <p id="definition-key-hint" className="text-xs text-muted-foreground">
              {existing
                ? "You cannot change the key after creating the attribute."
                : "The name supplies the key. Use lowercase letters, digits, hyphens, underscores or dots. The key cannot change later."}
            </p>
          )}
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="definition-type">Type</Label>
          <SelectField
            id="definition-type"
            value={type}
            disabled={captured !== null}
            onValueChange={(value) => setType(Number(value) as AttributeType)}
            options={[
              AttributeType.STRING,
              AttributeType.INT,
              AttributeType.BOOL,
              AttributeType.ENUM,
            ].map((value) => ({ value, label: ATTRIBUTE_TYPE_LABEL[value] }))}
          />
        </div>
        {type === AttributeType.ENUM ? (
          <div className="grid gap-1.5">
            <Label htmlFor="definition-enum">Allowed values (one per line)</Label>
            <Textarea
              id="definition-enum"
              name="enum"
              data-freeform="allowed values chosen for a new enum definition"
              defaultValue={definition.enumValues.join("\n")}
              aria-invalid={errors.enumValues ? true : undefined}
              aria-describedby={errors.enumValues ? "definition-enum-error" : undefined}
              onChange={() => setErrors((current) => ({ ...current, enumValues: undefined }))}
            />
            {errors.enumValues ? (
              <p id="definition-enum-error" className="text-sm text-destructive">
                {errors.enumValues}
              </p>
            ) : null}
          </div>
        ) : null}
        <div className="grid gap-1.5">
          <Label htmlFor="definition-reason">Reason</Label>
          <Textarea
            id="definition-reason"
            name="reason"
            data-freeform="audit reason for this change"
            aria-invalid={errors.reason ? true : undefined}
            aria-describedby={errors.reason ? "definition-reason-error" : undefined}
            onChange={() => setErrors((current) => ({ ...current, reason: undefined }))}
          />
          {errors.reason ? (
            <p id="definition-reason-error" className="text-sm text-destructive">
              {errors.reason}
            </p>
          ) : null}
        </div>
      </fieldset>
      {captured ? (
        <TechnicalDetails items={[{ label: "Request ID", value: captured.requestId }]} />
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
      {save.isSuccess ? <p role="status">Attribute saved.</p> : null}
      <div className="flex gap-2">
        <Button type="submit" disabled={save.isPending || save.isSuccess}>
          {save.isPending ? "Saving…" : captured ? "Retry" : "Save attribute"}
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={save.isPending || failure?.ambiguous}
          onClick={onClose}
        >
          {save.isSuccess ? "Close" : "Cancel"}
        </Button>
        {captured && failure && !failure.ambiguous ? (
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              setCaptured(null);
              save.reset();
            }}
          >
            Edit and try again
          </Button>
        ) : null}
      </div>
    </form>
  );
}
