import { type JsonObject } from "@bufbuild/protobuf";
import { ProfileResourceSchema } from "../../../gen/lindm/policy/v1/profile_pb";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { type DraftResource } from "./model";
import {
  desiredField,
  initialState,
  object,
  resourceKinds,
  selectedKind,
  withDerivedRef,
} from "./resource-draft";
import { TypedFields, type ReferenceChoice } from "./typed-fields";

export function ResourceFields({
  index,
  resource,
  resources,
  locked,
  onChange,
  onRemove,
}: {
  index: number;
  resource: DraftResource;
  resources: DraftResource[];
  locked: boolean;
  onChange: (next: DraftResource) => void;
  onRemove: () => void;
}) {
  const document = object(JSON.parse(resource.document));
  const arm = selectedKind(document);
  const kind = resourceKinds.find((entry) => entry.arm === arm);
  const field = desiredField(arm);
  const desired = object(document.desired);
  const id = `resource-${resource.resourceId}`;
  const references: ReferenceChoice[] = resources.flatMap((entry, position) => {
    if (entry.resourceId === resource.resourceId) return [];
    const candidate = withDerivedRef(object(JSON.parse(entry.document)));
    const ref = object(object(candidate.desired).ref);
    const candidateKind = resourceKinds.find((item) => item.arm === selectedKind(candidate));
    return ref.canonicalKey
      ? [
          {
            ref,
            label: `${candidateKind?.label ?? "Setting"} (setting ${position + 1})`,
          },
        ]
      : [];
  });
  function update(next: JsonObject) {
    onChange({ ...resource, document: JSON.stringify(withDerivedRef(next), null, 2) });
  }
  const metadataFields = ProfileResourceSchema.fields.filter(
    (entry) => !["resourceId", "desired"].includes(entry.jsonName),
  );
  return (
    <fieldset disabled={locked} className="grid min-w-0 gap-4 border bg-muted/20 p-4">
      <legend className="px-1 text-sm font-medium">Setting {index + 1}</legend>
      <div className="flex flex-wrap items-center justify-end gap-2">
        <Button type="button" variant="outline" size="sm" disabled={locked} onClick={onRemove}>
          Remove setting {index + 1}
        </Button>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor={`${id}-kind`}>Setting type</Label>
        <SelectField
          id={`${id}-kind`}
          value={arm}
          disabled={locked}
          options={[
            { value: "", label: "Choose a setting type" },
            ...(!kind && arm ? [{ value: arm, label: "Existing setting type" }] : []),
            ...resourceKinds
              .filter((entry) => desiredField(entry.arm))
              .map((entry) => ({ value: entry.arm, label: entry.label })),
          ]}
          onValueChange={(next) => {
            if (next !== arm)
              update({ ...document, desired: next ? { [next]: initialState(next) } : {} });
          }}
        />
      </div>
      {kind ? <p className="text-sm text-muted-foreground">{kind.help}</p> : null}
      {field?.fieldKind === "message" && kind ? (
        <TypedFields
          schema={field.message}
          value={object(desired[arm])}
          id={`${id}-desired`}
          references={references}
          disabled={locked}
          onChange={(next) => update({ ...document, desired: { ...desired, [arm]: next } })}
        />
      ) : arm ? (
        <p className="text-sm text-muted-foreground">
          This setting type can't be edited here. It will be kept as is.
        </p>
      ) : null}
      <details className="min-w-0">
        <summary className="cursor-pointer py-1 text-sm font-medium">Advanced options</summary>
        <div className="mt-3">
          <TypedFields
            schema={{ ...ProfileResourceSchema, fields: metadataFields }}
            value={document}
            id={`${id}-metadata`}
            references={references}
            disabled={locked}
            onChange={update}
          />
        </div>
      </details>
      <details className="min-w-0 text-xs text-muted-foreground">
        <summary className="w-fit cursor-pointer py-1">View JSON</summary>
        <pre
          className="max-h-96 overflow-auto whitespace-pre-wrap break-all border bg-muted/30 p-3"
          aria-label={`Resource ${index + 1} JSON`}
        >
          {resource.document}
        </pre>
      </details>
    </fieldset>
  );
}
