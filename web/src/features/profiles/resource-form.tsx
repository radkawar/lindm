import { create, fromJson, type JsonObject } from "@bufbuild/protobuf";
import { Trash2Icon } from "lucide-react";
import { ProfileResourceSchema } from "../../../gen/lindm/policy/v1/profile_pb";
import { KernelModuleBlocklistSchema } from "../../../gen/lindm/resource/v1/host_pb";
import { FirewallZoneDesiredSchema } from "../../../gen/lindm/resource/v1/network_pb";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { Textarea } from "@/components/ui/textarea";
import { firewallZoneLabel } from "@/lib/setting-identity";
import { cn } from "cn";
import { checkRequest } from "@/lib/validation";
import { EncryptionComplianceFields } from "./encryption-fields";
import { MODULE_NAME_RULE, type DraftResource } from "./model";
import { OwnershipFields } from "./ownership-fields";
import { kindQualification, qualifiedOwnership, type Qualification } from "./qualification";
import {
  desiredField,
  initialState,
  object,
  resourceKinds,
  selectedKind,
  withDerivedRef,
} from "./resource-draft";
import { TypedFields, type ReferenceChoice } from "./typed-fields";
import { SSHBannerFields } from "./ssh-banner-fields";

const BLOCK_KERNEL_MODULES = "Block kernel modules";

// What a setting manages, in words, for its heading and its Remove label:
// "Systemd service cups.service", "Firewall zone: Unnamed zone on wlan0".
function settingSummary(document: JsonObject, kindLabel: string | undefined): string {
  if (!kindLabel) return "";
  const desired = object(document.desired);
  if (desired.firewallZone !== undefined) {
    try {
      const zone = fromJson(FirewallZoneDesiredSchema, desired.firewallZone, {
        ignoreUnknownFields: true,
      });
      return `${kindLabel}: ${firewallZoneLabel(zone)}`;
    } catch {
      return kindLabel;
    }
  }
  // Singleton settings have a fixed "system…" identity that says nothing more.
  const key = String(object(object(withDerivedRef(document).desired).ref).canonicalKey ?? "");
  return key && !key.startsWith("system") && !key.endsWith("/") ? `${kindLabel} ${key}` : kindLabel;
}

export function ResourceFields({
  index,
  resource,
  resources,
  locked,
  errors,
  advanced,
  qualification,
  onChange,
  onRemove,
}: {
  index: number;
  resource: DraftResource;
  resources: DraftResource[];
  locked: boolean;
  errors: string[];
  advanced: boolean;
  qualification: Qualification;
  onChange: (next: DraftResource) => void;
  onRemove: () => void;
}) {
  const document = object(JSON.parse(resource.document));
  const arm = selectedKind(document);
  const kind = resourceKinds.find((entry) => entry.arm === arm);
  const field = desiredField(arm);
  const desired = object(document.desired);
  const moduleBlocklist = object(desired.managedFile).kernelModuleBlocklist !== undefined;
  const selectedTask = moduleBlocklist ? "blockKernelModules" : arm;
  // Checked as typed against the schema's module-name rule, not only at Publish.
  const modules = moduleBlocklist
    ? ((object(object(desired.managedFile).kernelModuleBlocklist).modules as string[]) ?? [])
    : [];
  const named = modules.filter((name) => name !== "");
  const invalidModules =
    checkRequest(
      KernelModuleBlocklistSchema,
      create(KernelModuleBlocklistSchema, { modules: named }),
    )?.fields.flatMap((problem) => {
      const entry = /^modules\[(\d+)\]$/.exec(problem.path)?.[1];
      return entry === undefined ? [] : [named[Number(entry)] ?? ""];
    }) ?? [];
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
    (entry) => !["resourceId", "desired", "ownership"].includes(entry.jsonName),
  );
  const state = object(desired[arm]);
  // Fields the typed form leaves out: the kernel module list has its own
  // control; numeric account IDs are chosen by the device unless already set or
  // the administrator opens Advanced options.
  const hiddenFields = [
    "kernelModuleBlocklist",
    ...(!advanced && state.uid === undefined ? ["uid"] : []),
    ...(!advanced && state.gid === undefined ? ["gid"] : []),
  ];
  const kindLabel = moduleBlocklist ? BLOCK_KERNEL_MODULES : kind?.label;
  const summary = settingSummary(document, kindLabel);
  const selectedQualification = arm ? kindQualification(qualification, arm) : null;
  const ownership = object(document.ownership);
  // qualifiedOwnership keeps a qualified choice and replaces any other.
  const supportedOwnership = qualifiedOwnership(ownership, selectedQualification);
  const ownershipRefused =
    !!selectedQualification &&
    (supportedOwnership.mode !== ownership.mode ||
      supportedOwnership.release !== ownership.release);
  const unavailable = resourceKinds
    .filter((entry) => desiredField(entry.arm))
    .some((entry) => kindQualification(qualification, entry.arm) === undefined);
  function choose(nextDesired: JsonObject, nextArm: string) {
    const ownership = qualifiedOwnership(
      object(document.ownership),
      kindQualification(qualification, nextArm),
    );
    update({ ...document, desired: nextDesired, ownership });
  }
  return (
    <fieldset
      disabled={locked}
      data-setting-index={index}
      aria-describedby={errors.length > 0 ? `${id}-errors` : undefined}
      className={cn(
        "grid min-w-0 gap-4 border bg-muted/20 p-4",
        errors.length > 0 && "border-destructive",
      )}
    >
      <legend className="sr-only">Setting {index + 1}</legend>
      <div className="flex min-w-0 items-start justify-between gap-2">
        <div className="min-w-0 break-words text-sm font-medium" aria-hidden="true">
          Setting {index + 1}
          {summary ? <span className="font-normal text-muted-foreground"> · {summary}</span> : null}
        </div>
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          disabled={locked}
          aria-label={`Remove setting ${index + 1}${summary ? `: ${summary}` : ""}`}
          title="Remove this setting"
          onClick={onRemove}
        >
          <Trash2Icon aria-hidden="true" />
        </Button>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor={`${id}-kind`}>Setting type</Label>
        <SelectField
          id={`${id}-kind`}
          value={selectedTask}
          disabled={locked}
          aria-describedby={unavailable ? `${id}-kind-help` : undefined}
          options={[
            { value: "", label: "Choose a setting type", disabled: true },
            ...(!kind && arm ? [{ value: arm, label: "Existing setting type" }] : []),
            { value: "blockKernelModules", label: BLOCK_KERNEL_MODULES },
            ...resourceKinds
              .filter((entry) => desiredField(entry.arm))
              .map((entry) =>
                kindQualification(qualification, entry.arm) === undefined &&
                entry.arm !== selectedTask
                  ? {
                      value: entry.arm,
                      label: `${entry.label} (not available yet)`,
                      disabled: true,
                    }
                  : { value: entry.arm, label: entry.label },
              ),
          ]}
          onValueChange={(next) => {
            if (next === selectedTask || next === "") return;
            if (next === "blockKernelModules") {
              choose(
                {
                  managedFile: {
                    path: "/etc/modprobe.d/99-lindm-blocklist.conf",
                    presence: "PRESENCE_PRESENT",
                    kernelModuleBlocklist: { modules: ["usb_storage", "uas"] },
                  },
                },
                "managedFile",
              );
            } else {
              choose({ [next]: initialState(next) }, next);
            }
          }}
        />
        {unavailable ? (
          <p id={`${id}-kind-help`} className="text-xs text-muted-foreground">
            Types marked not available yet can't be applied to devices by this server.
          </p>
        ) : null}
      </div>
      {arm && selectedQualification === undefined ? (
        <p role="note" className="border border-warning/30 bg-warning/10 p-3 text-sm">
          Devices can't apply this setting type yet. It stays in the profile but is never sent to
          devices.
        </p>
      ) : null}
      {ownershipRefused ? (
        <div
          role="note"
          data-setting-ownership-refused
          className="flex flex-wrap items-center gap-2 border border-warning/30 bg-warning/10 p-3 text-sm"
        >
          <span>
            Devices won't apply this setting with its current ownership choices (under Advanced
            options).
          </span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={locked}
            onClick={() => update({ ...document, ownership: supportedOwnership })}
          >
            Use supported choices
          </Button>
        </div>
      ) : null}
      {kind && !moduleBlocklist ? (
        <p className="text-sm text-muted-foreground">{kind.help}</p>
      ) : null}
      {moduleBlocklist ? (
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor={`${id}-modules`}>Modules to block</Label>
            <Textarea
              id={`${id}-modules`}
              data-freeform="kernel module names to block; may not be loaded on any device yet"
              value={modules.join("\n")}
              onChange={(event) =>
                update({
                  ...document,
                  desired: {
                    ...desired,
                    managedFile: {
                      ...object(desired.managedFile),
                      kernelModuleBlocklist: { modules: event.target.value.split("\n") },
                    },
                  },
                })
              }
              aria-invalid={invalidModules.length > 0 || undefined}
              aria-describedby={`${id}-module-help${invalidModules.length > 0 ? ` ${id}-module-error` : ""}`}
            />
            <p id={`${id}-module-help`} className="text-sm text-muted-foreground">
              Enter one module name per line, using underscores rather than hyphens.
            </p>
            {invalidModules.length > 0 ? (
              <p id={`${id}-module-error`} className="text-sm text-destructive">
                Not a module name: {invalidModules.join(", ")}. Module names {MODULE_NAME_RULE}
              </p>
            ) : null}
          </div>
          <p className="text-sm">
            Assigned devices block future loads and rebuild their boot files. Active drivers stay
            loaded until restart; built-in drivers cannot be blocked.
          </p>
        </div>
      ) : arm === "encryptionCompliance" ? (
        <EncryptionComplianceFields
          id={`${id}-encryption`}
          value={object(desired[arm])}
          disabled={locked}
          onChange={(next) => update({ ...document, desired: { ...desired, [arm]: next } })}
        />
      ) : arm === "sshServer" ? (
        <SSHBannerFields
          id={`${id}-banner`}
          value={object(desired[arm])}
          disabled={locked}
          onChange={(next) => update({ ...document, desired: { ...desired, [arm]: next } })}
        />
      ) : field?.fieldKind === "message" && kind ? (
        <TypedFields
          schema={{
            ...field.message,
            fields: field.message.fields.filter((entry) => !hiddenFields.includes(entry.jsonName)),
          }}
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
      {errors.length > 0 ? (
        <ul
          id={`${id}-errors`}
          data-setting-errors
          className="grid gap-1 border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive"
        >
          {errors.map((error) => (
            <li key={error}>{error}</li>
          ))}
        </ul>
      ) : null}
      {advanced ? (
        <div className="grid min-w-0 gap-3 border-t pt-3" data-setting-advanced>
          <h4 className="text-sm font-medium">Dependencies, ownership and verification</h4>
          <TypedFields
            schema={{ ...ProfileResourceSchema, fields: metadataFields }}
            value={document}
            id={`${id}-metadata`}
            references={references}
            disabled={locked}
            onChange={update}
          />
          <fieldset className="grid min-w-0 gap-3 border p-3">
            <legend className="px-1 text-sm font-medium">Ownership</legend>
            <OwnershipFields
              id={`${id}-ownership`}
              value={ownership}
              qualified={selectedQualification}
              references={references}
              disabled={locked}
              onChange={(next) => update({ ...document, ownership: next })}
            />
          </fieldset>
        </div>
      ) : null}
    </fieldset>
  );
}
