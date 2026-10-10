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
import { newRequestId } from "@/lib/ids";
import { canPermission } from "@/lib/permissions";
import { adminClient } from "@/lib/rpc";
import { attributeDefinitionsQueryOptions } from "./queries";
import { validateInventory } from "./validation";

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
        <CardTitle>Custom attribute definitions</CardTitle>
        <CardDescription>
          Each key has one type: string, integer, boolean or enum. Definition changes require
          unrestricted inventory management permission; the server rejects incompatible changes to
          values already in use.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {failure ? <RpcError failure={failure} /> : null}
        {definitions.isPending ? <p role="status">Loading definitions…</p> : null}
        {data ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Key</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Enum values</TableHead>
                {canManage ? <TableHead>Action</TableHead> : null}
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.definitions.map((definition) => (
                <TableRow key={definition.key}>
                  <TableCell>{definition.key}</TableCell>
                  <TableCell>
                    {AttributeType[definition.type]?.toLowerCase() ?? "Unknown"}
                  </TableCell>
                  <TableCell className="whitespace-normal">
                    {definition.enumValues.join(", ") || "Not an enum"}
                  </TableCell>
                  {canManage ? (
                    <TableCell>
                      <Button
                        variant="outline"
                        disabled={editing !== null}
                        onClick={() => setEditing(definition)}
                      >
                        Edit {definition.key}
                      </Button>
                    </TableCell>
                  ) : null}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : null}
        {data?.definitions.length === 0 ? <p>No definitions on this page.</p> : null}
        <div className="flex gap-2">
          <Button
            variant="outline"
            disabled={!afterKey || definitions.isFetching}
            onClick={() => setAfterKey("")}
          >
            First keys
          </Button>
          <Button
            variant="outline"
            disabled={!data?.nextAfterKey || definitions.isFetching}
            onClick={() => setAfterKey(data?.nextAfterKey ?? "")}
          >
            Next keys
          </Button>
          <Button
            variant="outline"
            disabled={definitions.isFetching}
            onClick={() => void definitions.refetch()}
          >
            Refresh definitions
          </Button>
        </div>
        {canManage && !editing ? (
          <Button
            className="w-fit"
            onClick={() =>
              setEditing(create(AttributeDefinitionSchema, { type: AttributeType.STRING }))
            }
          >
            Define a new key
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
  const [type, setType] = useState(definition.type);
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
      if (!lifetime.signal.aborted) toast.success("Attribute definition saved");
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
        ](failure.ambiguous ? "Definition save outcome unknown" : "Definition not saved", {
          description: "Review the inline result and captured request before continuing.",
        });
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
            request = create(SetAttributeDefinitionRequestSchema, {
              requestId: newRequestId(),
              definition: {
                key: String(data.get("key") ?? "").trim(),
                type,
                enumValues:
                  type === AttributeType.ENUM
                    ? String(data.get("enum") ?? "")
                        .split("\n")
                        .map((value) => value.trim())
                        .filter(Boolean)
                    : [],
              },
              reason: String(data.get("reason") ?? "").trim(),
            });
            validateInventory(SetAttributeDefinitionRequestSchema, request);
            setCaptured(request);
          }
          setInputError("");
          inFlight.current = true;
          save.mutate(request);
        } catch (error) {
          setInputError(toRpcFailure(error).message);
        }
      }}
    >
      <fieldset disabled={captured !== null} className="grid gap-3">
        <div className="grid gap-1.5">
          <Label htmlFor="definition-key">Key</Label>
          <Input
            id="definition-key"
            name="key"
            defaultValue={definition.key}
            readOnly={definition.key !== ""}
            required
          />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="definition-type">Type</Label>
          <SelectField
            id="definition-type"
            value={type}
            disabled={captured !== null}
            onValueChange={(value) => setType(Number(value) as AttributeType)}
            options={[
              { value: AttributeType.STRING, label: "String" },
              { value: AttributeType.INT, label: "Integer" },
              { value: AttributeType.BOOL, label: "Boolean" },
              { value: AttributeType.ENUM, label: "Enum" },
            ]}
          />
        </div>
        {type === AttributeType.ENUM ? (
          <div className="grid gap-1.5">
            <Label htmlFor="definition-enum">Allowed enum values (one per line)</Label>
            <Textarea
              id="definition-enum"
              name="enum"
              defaultValue={definition.enumValues.join("\n")}
              required
            />
          </div>
        ) : null}
        <div className="grid gap-1.5">
          <Label htmlFor="definition-reason">Audit reason</Label>
          <Textarea id="definition-reason" name="reason" required />
        </div>
      </fieldset>
      {captured ? (
        <p className="break-all font-mono text-xs">Request ID {captured.requestId}</p>
      ) : null}
      {failure ? (
        <RpcError failure={failure}>
          <p>{failure.ambiguous ? " Outcome unknown; retry the same captured request." : ""}</p>
        </RpcError>
      ) : null}
      {inputError ? (
        <p role="alert" className="text-sm text-destructive">
          {inputError}
        </p>
      ) : null}
      {save.isSuccess ? <p role="status">Definition saved.</p> : null}
      <div className="flex gap-2">
        <Button type="submit" disabled={save.isPending || save.isSuccess}>
          {save.isPending ? "Saving…" : captured ? "Retry same request" : "Save definition"}
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
            Edit a new request
          </Button>
        ) : null}
      </div>
    </form>
  );
}
