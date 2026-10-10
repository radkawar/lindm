import { create, fromJsonString } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
  AttributeType,
  AttributeValueSchema,
  type AttributeValue,
} from "../../../gen/lindm/admin/v1/inventory_management_pb";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";
import { toRpcFailure } from "@/lib/errors";
import { RpcError } from "@/components/ui/rpc-error";
import { attributeDefinitionsQueryOptions } from "./queries";

export function readAttributeInputs(data: FormData, attributes: Record<string, AttributeValue>) {
  const result: Record<string, AttributeValue> = {};
  for (const [key, attribute] of Object.entries(attributes)) {
    const text = String(data.get(`attribute:${key}`) ?? "");
    switch (attribute.value.case) {
      case "stringValue":
        result[key] = create(AttributeValueSchema, { value: { case: "stringValue", value: text } });
        break;
      case "enumValue":
        result[key] = create(AttributeValueSchema, { value: { case: "enumValue", value: text } });
        break;
      case "intValue":
        if (!/^-?\d+$/.test(text)) throw new Error(`${key}: enter a whole integer.`);
        result[key] = fromJsonString(AttributeValueSchema, JSON.stringify({ intValue: text }));
        break;
      case "boolValue":
        result[key] = create(AttributeValueSchema, {
          value: { case: "boolValue", value: text === "true" },
        });
        break;
      default:
        throw new Error(`${key}: attribute type is not defined.`);
    }
  }
  return result;
}

export function AttributeFields({
  attributes,
  onChange,
  disabled = false,
}: {
  attributes: Record<string, AttributeValue>;
  onChange: (attributes: Record<string, AttributeValue>) => void;
  disabled?: boolean;
}) {
  const lifetime = useAuthLifetime();
  const principal = usePrincipal();
  const canReadDefinitions = canPermission(principal, "fleet.read", true);
  const [afterKey, setAfterKey] = useState("");
  const [selected, setSelected] = useState("");
  const definitions = useQuery({
    ...attributeDefinitionsQueryOptions(lifetime, afterKey),
    enabled: canReadDefinitions,
  });
  const failure = definitions.error ? toRpcFailure(definitions.error) : null;
  const choices = failure ? [] : (definitions.data?.definitions ?? []);
  return (
    <fieldset className="grid min-w-0 gap-3" disabled={disabled}>
      <legend className="mb-2 text-sm font-medium">
        Typed attributes (all must match when filtering)
      </legend>
      {Object.entries(attributes).map(([key, attribute]) => {
        const field = attribute.value;
        const definition = choices.find((item) => item.key === key);
        return (
          <div className="flex flex-wrap items-end gap-2" key={key}>
            <div className="grid min-w-0 flex-1 gap-1.5">
              <Label htmlFor={`attribute:${key}`}>
                {key} ({field.case?.replace("Value", "") ?? "unknown"})
              </Label>
              {field.case === "boolValue" ? (
                <SelectField
                  id={`attribute:${key}`}
                  name={`attribute:${key}`}
                  defaultValue={String(field.value)}
                  disabled={disabled}
                  options={[
                    { value: "true", label: "True" },
                    { value: "false", label: "False" },
                  ]}
                />
              ) : (
                <>
                  <Input
                    id={`attribute:${key}`}
                    name={`attribute:${key}`}
                    defaultValue={field.value?.toString() ?? ""}
                    inputMode={field.case === "intValue" ? "numeric" : "text"}
                    list={field.case === "enumValue" ? `enum:${key}` : undefined}
                  />
                  {field.case === "enumValue" && definition ? (
                    <datalist id={`enum:${key}`}>
                      {definition.enumValues.map((value) => (
                        <option key={value} value={value} />
                      ))}
                    </datalist>
                  ) : null}
                </>
              )}
            </div>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                const next = { ...attributes };
                delete next[key];
                onChange(next);
              }}
            >
              Remove {key}
            </Button>
          </div>
        );
      })}
      <div className="flex flex-wrap items-center gap-2">
        <Label htmlFor="attribute-key">Defined key</Label>
        <SelectField
          id="attribute-key"
          className="max-w-full"
          value={selected}
          disabled={disabled}
          onValueChange={setSelected}
          options={[
            { value: "", label: "Choose a key" },
            ...choices
              .filter((definition) => !Object.hasOwn(attributes, definition.key))
              .map((definition) => ({
                value: definition.key,
                label: `${definition.key} (${AttributeType[definition.type]?.toLowerCase() ?? "unknown"})`,
              })),
          ]}
        />
        <Button
          type="button"
          variant="outline"
          disabled={!choices.some((definition) => definition.key === selected)}
          onClick={() => {
            const definition = choices.find((item) => item.key === selected);
            if (!definition) return;
            let value: AttributeValue;
            switch (definition.type) {
              case AttributeType.STRING:
                value = create(AttributeValueSchema, { value: { case: "stringValue", value: "" } });
                break;
              case AttributeType.INT:
                value = create(AttributeValueSchema, { value: { case: "intValue", value: 0n } });
                break;
              case AttributeType.BOOL:
                value = create(AttributeValueSchema, {
                  value: { case: "boolValue", value: false },
                });
                break;
              case AttributeType.ENUM:
                value = create(AttributeValueSchema, {
                  value: { case: "enumValue", value: definition.enumValues[0] ?? "" },
                });
                break;
              default:
                return;
            }
            onChange({ ...attributes, [selected]: value });
            setSelected("");
          }}
        >
          Add attribute
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={!afterKey}
          onClick={() => {
            setAfterKey("");
            setSelected("");
          }}
        >
          First keys
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={!definitions.data?.nextAfterKey || !!failure}
          onClick={() => {
            setAfterKey(definitions.data?.nextAfterKey ?? "");
            setSelected("");
          }}
        >
          Next keys
        </Button>
      </div>
      {!canReadDefinitions ? (
        <p className="text-sm text-muted-foreground">
          Unrestricted fleet read permission is required to browse available keys. Existing typed
          values can still be edited.
        </p>
      ) : definitions.isPending ? (
        <p role="status">Loading attribute definitions…</p>
      ) : null}
      {failure ? <RpcError failure={failure} /> : null}
    </fieldset>
  );
}
