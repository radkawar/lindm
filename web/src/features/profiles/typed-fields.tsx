import {
  getOption,
  ScalarType,
  type DescEnum,
  type DescField,
  type DescMessage,
  type JsonObject,
  type JsonValue,
} from "@bufbuild/protobuf";
import { field as validationRules } from "@bufbuild/protovalidate/gen/buf/validate/validate_pb.js";
import { SuggestionField } from "../../../gen/lindm/admin/v1/suggestions_pb";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { SearchPicker } from "@/components/ui/search-picker";
import { SuggestionPicker } from "@/components/ui/suggestion-picker";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Textarea } from "@/components/ui/textarea";
import { newRequestId } from "@/lib/ids";
import { object, sameReference } from "./resource-draft";
import { useProfilePickers } from "./field-pickers";
import { OSUpdateFields } from "./os-update-fields";

const labels: Record<string, string> = {
  nativeName: "Package name",
  ecosystem: "Package format",
  presence: "Should be",
  runtime: "Running state",
  enablement: "Start at boot",
  unit: "Unit name",
  gid: "GID",
  uid: "UID",
  secretId: "Secret",
  deviceId: "Device",
  personId: "Person",
  principalId: "Account",
  approvedRootId: "Approved home folder root",
  subjectBindingId: "Secret subject",
  artifactId: "Artifact",
  catalogId: "Nix catalog entry",
  approvedInputId: "Approved Nix input",
  approvedTokenId: "Approved security token",
  credentialId: "Certificate credential",
  issuerProfileId: "Certificate issuer",
  connectionUuid: "Network connection",
  enrollmentGeneration: "Device enrollment",
  uidGeneration: "Local account incarnation",
  assignmentId: "Person assignment",
  ruleId: "Rule reference",
  zoneId: "Zone reference",
  repositoryId: "Repository reference",
  hardwareId: "Hardware match",
  osId: "Operating system",
  appId: "Application name",
  nativeId: "Native name",
  collectionId: "Collection name",
  any: "Any approved version",
  exact: "Pin exact version",
  deb: "DEB version",
  rpm: "RPM version",
  apt: "APT repository",
  dropIn: "Service drop-in",
  daily: "Daily, UTC",
  intervalSeconds: "Interval (seconds)",
  installedShell: "Installed login shell",
  localUserNames: "Local names",
  maxAgeSeconds: "Re-check within (seconds)",
  completeMembershipDimension: "Remove members not listed here",
  noNewPrivileges: "Prevent privilege escalation",
  requireLuksRoot: "Require LUKS root encryption",
  requireEscrow: "Require recovery escrow",
  requireTpm: "Require TPM binding",
  minLength: "Minimum password length",
  minClasses: "Minimum character classes",
  historyCount: "Remembered passwords",
  maxAgeDays: "Maximum password age (days)",
  failureLimit: "Failed login limit",
  unlockAfterSeconds: "Unlock after (seconds)",
  memoryMaxBytes: "Memory limit (bytes)",
  cpuWeight: "CPU weight",
  tasksMax: "Task limit",
  sourceNetworks: "Source networks",
  defaultIngress: "Default incoming traffic",
  defaultEgress: "Default outgoing traffic",
  content: "File contents (nonsecret)",
  persistent: "Persist across reboots",
  selection: "Updates to install",
  maintenance: "Maintenance window",
  timeZone: "Time zone (IANA)",
  weekdays: "Window days",
  localStartMinute: "Window start (minutes after local midnight)",
  durationMinutes: "Window length (minutes)",
  rebootPolicy: "Reboot after updates",
  maxDelayMinutes: "Maximum reboot delay (minutes)",
  notice: "Reboot notice",
  deferralDays: "Defer each update (days)",
  user: "Local user name",
  group: "Local group name",
  primaryGroup: "Primary local group name",
  modules: "Kernel module names",
};

// Inventory managers report packages under their database's name.
const packageManagers: Record<string, string> = {
  PACKAGE_ECOSYSTEM_DEB: "dpkg",
  PACKAGE_ECOSYSTEM_RPM: "rpm",
  PACKAGE_ECOSYSTEM_ALPM: "pacman",
};

// Values the fleet already reports are suggested; a profile may still name one
// that no device has yet, so typed values stay allowed.
function suggestionFor(field: DescField, siblings: JsonObject) {
  switch (`${field.parent.typeName}.${field.jsonName}`) {
    case "lindm.resource.v1.PackageIdentity.nativeName":
      return {
        field: SuggestionField.PACKAGE_NAME,
        manager: packageManagers[String(siblings.ecosystem ?? "")],
      };
    case "lindm.resource.v1.PlatformProduct.osId":
      return { field: SuggestionField.OS_ID };
    case "lindm.resource.v1.PlatformProduct.version":
      return { field: SuggestionField.OS_VERSION, osId: String(siblings.osId ?? "") || undefined };
    case "lindm.resource.v1.PlatformProduct.architecture":
    case "lindm.resource.v1.FlatpakAppDesired.architecture":
    case "lindm.resource.v1.AlpmRepository.architecture":
      return { field: SuggestionField.ARCHITECTURE };
    case "lindm.resource.v1.LocalUserDesired.name":
    case "lindm.resource.v1.MemberSet.localUserNames":
    case "lindm.resource.v1.SudoPrincipal.user":
    case "lindm.resource.v1.NativeAccountBinding.name":
      return { field: SuggestionField.LOCAL_USER_NAME };
    case "lindm.resource.v1.LoginShell.installedShell":
      return { field: SuggestionField.LOGIN_SHELL };
    case "lindm.resource.v1.FlatpakAppDesired.appId":
      return { field: SuggestionField.FLATPAK_APP };
    case "lindm.resource.v1.SnapAppDesired.name":
      return { field: SuggestionField.SNAP_NAME };
    default:
      return undefined;
  }
}

// Why each remaining text field is typed: the value is new, external or only
// known per device, so the server has no list to choose from.
const freeform: Record<string, string> = {
  unit: "systemd unit to manage; may not be installed yet",
  name: "name this setting creates or manages; may not exist yet",
  group: "local group name; may not exist yet",
  primaryGroup: "local group name; may not exist yet",
  names: "account or domain names for this setting",
  homeDirectory: "home folder path to create",
  path: "file path to write",
  executable: "command path to allow",
  key: "kernel setting name",
  value: "value for this setting",
  modules: "kernel module names; may not be loaded anywhere yet",
  product: "platform product name",
};
function freeformReason(field: DescField) {
  if (freeform[field.jsonName]) return freeform[field.jsonName];
  if (field.fieldKind === "scalar" || field.fieldKind === "list")
    if (field.scalar !== ScalarType.STRING && field.scalar !== ScalarType.BYTES)
      return "numeric value for this setting";
  return "configuration value for this setting, such as an address, version or key";
}

export function fieldLabel(name: string): string {
  const words = name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replaceAll("_", " ")
    .toLowerCase();
  return labels[name] ?? words.charAt(0).toUpperCase() + words.slice(1);
}

function enumOptions(schema: DescEnum) {
  const first = schema.values[0]?.name ?? "";
  const prefix = first.endsWith("UNSPECIFIED") ? first.slice(0, -"UNSPECIFIED".length) : "";
  return schema.values
    .filter((value) => value.number !== 0)
    .map((value) => ({
      value: value.name,
      label: fieldLabel(value.name.slice(prefix.length)),
    }));
}

export type ReferenceChoice = { label: string; ref: JsonObject };
type Props = {
  schema: DescMessage;
  value: JsonObject;
  onChange: (value: JsonObject) => void;
  id: string;
  references: ReferenceChoice[];
  disabled: boolean;
};

// The generated descriptors remain the only field schema. This editor changes
// one field at a time, retaining all other desired and profile metadata verbatim.
export function TypedFields({ schema, value, onChange, id, references, disabled }: Props) {
  if (schema.typeName === "lindm.resource.v1.OSUpdateDesired") {
    return <OSUpdateFields value={value} onChange={onChange} id={id} disabled={disabled} />;
  }
  const oneofs = schema.oneofs;
  function change(field: DescField, next: JsonValue | undefined) {
    const updated = { ...value };
    if (field.oneof) for (const sibling of field.oneof.fields) delete updated[sibling.jsonName];
    if (next === undefined) delete updated[field.jsonName];
    else updated[field.jsonName] = next;
    if (
      schema.typeName === "lindm.resource.v1.NativePackageDesired" &&
      field.jsonName === "package" &&
      updated.exact !== undefined &&
      object(value.package).ecosystem !== object(next).ecosystem
    ) {
      updated.exact =
        object(next).ecosystem === "PACKAGE_ECOSYSTEM_RPM" ? { rpm: {} } : { deb: "" };
    }
    onChange(updated);
  }
  return (
    <div className="grid min-w-0 gap-3">
      {oneofs.map((oneof) => {
        const selected = oneof.fields.find((field) => value[field.jsonName] !== undefined);
        return (
          <div className="grid gap-1.5" key={oneof.name}>
            <Label htmlFor={`${id}-${oneof.name}`}>{fieldLabel(oneof.name)}</Label>
            <SelectField
              id={`${id}-${oneof.name}`}
              disabled={disabled}
              value={selected?.jsonName ?? ""}
              options={[
                { value: "", label: "Choose an option" },
                ...oneof.fields.map((field) => ({
                  value: field.jsonName,
                  label: fieldLabel(field.jsonName),
                })),
              ]}
              onValueChange={(name) => {
                const updated = { ...value };
                for (const field of oneof.fields) delete updated[field.jsonName];
                const field = oneof.fields.find((item) => item.jsonName === name);
                if (field)
                  updated[name] =
                    field.fieldKind === "message"
                      ? {}
                      : field.fieldKind === "scalar" && field.scalar !== ScalarType.STRING
                        ? 0
                        : "";
                if (
                  schema.typeName === "lindm.resource.v1.NativePackageDesired" &&
                  name === "exact"
                ) {
                  updated.exact =
                    object(value.package).ecosystem === "PACKAGE_ECOSYSTEM_RPM"
                      ? { rpm: {} }
                      : { deb: "" };
                }
                onChange(updated);
              }}
            />
          </div>
        );
      })}
      {schema.fields
        // Adoption approval is bound by an approved assignment, never authored
        // in a profile; the server rejects a profile-supplied marker.
        .filter(
          (field) =>
            !(
              schema.typeName === "lindm.resource.v1.OwnershipPolicy" &&
              field.jsonName === "adoptionApprovalId"
            ),
        )
        .filter((field) => !field.oneof || value[field.jsonName] !== undefined)
        .map((field) => (
          <TypedField
            key={field.number}
            field={field}
            value={value[field.jsonName]}
            id={`${id}-${field.jsonName}`}
            references={references}
            siblings={value}
            disabled={disabled}
            onChange={(next) => change(field, next)}
          />
        ))}
    </div>
  );
}

function TypedField({
  field,
  value,
  onChange,
  id,
  references,
  siblings,
  disabled,
}: {
  field: DescField;
  value: JsonValue | undefined;
  onChange: (value: JsonValue | undefined) => void;
  id: string;
  references: ReferenceChoice[];
  siblings: JsonObject;
  disabled: boolean;
}) {
  const suggestion = suggestionFor(field, siblings);
  const pickers = useProfilePickers();
  const Picker =
    field.jsonName === "secretId"
      ? pickers.secret
      : field.jsonName === "deviceId"
        ? pickers.device
        : ["personId", "principalId"].includes(field.jsonName)
          ? pickers.account
          : undefined;
  const label =
    field.jsonName === "mode" && field.fieldKind === "scalar"
      ? "Permissions (octal)"
      : fieldLabel(field.jsonName);
  const rules = getOption(field, validationRules);
  const recordReference =
    field.fieldKind === "scalar" &&
    rules.type.case === "string" &&
    ["uuid", "tuuid"].includes(rules.type.value.wellKnown.case ?? "");
  const generatedReference = ["ruleId", "zoneId", "repositoryId"].includes(field.jsonName);
  const optional =
    !field.oneof && (field.fieldKind === "message" ? !rules.required : field.proto.proto3Optional);
  if (field.fieldKind === "list") {
    const items = Array.isArray(value) ? value : [];
    const repeated = rules.type.case === "repeated" ? rules.type.value : undefined;
    const limit = repeated?.maxItems === undefined ? undefined : Number(repeated.maxItems);
    return (
      <fieldset className="grid min-w-0 gap-3 border p-3">
        <legend className="px-1 text-sm font-medium">{label}</legend>
        {items.length === 0 ? <p className="text-xs text-muted-foreground">No entries.</p> : null}
        {items.map((item, index) => (
          <div key={index} className="grid min-w-0 gap-2 border-l pl-3">
            {field.listKind === "message" ? (
              <MessageInput
                schema={field.message}
                value={object(item)}
                onChange={(next) => onChange(items.map((entry, i) => (i === index ? next : entry)))}
                id={`${id}-${index}`}
                label={`${label} ${index + 1}`}
                references={references}
                disabled={disabled}
              />
            ) : field.listKind === "enum" ? (
              <SelectField
                aria-label={`${label} ${index + 1}`}
                value={String(item)}
                disabled={disabled}
                options={enumOptions(field.enum)}
                onValueChange={(next) =>
                  onChange(items.map((entry, i) => (i === index ? next : entry)))
                }
              />
            ) : suggestion ? (
              <SuggestionPicker
                label={`${label} ${index + 1}`}
                {...suggestion}
                allowTyped
                disabled={disabled}
                value={String(item)}
                onChange={(next) => onChange(items.map((entry, i) => (i === index ? next : entry)))}
              />
            ) : (
              <Input
                aria-label={`${label} ${index + 1}`}
                data-freeform={freeformReason(field)}
                value={String(item)}
                disabled={disabled}
                onChange={(event) =>
                  onChange(items.map((entry, i) => (i === index ? event.target.value : entry)))
                }
              />
            )}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              disabled={disabled}
              onClick={() => onChange(items.filter((_, i) => i !== index))}
            >
              Remove {label.toLowerCase()} {index + 1}
            </Button>
          </div>
        ))}
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={disabled || (limit !== undefined && items.length >= limit)}
          onClick={() =>
            onChange([
              ...items,
              field.listKind === "message"
                ? field.message.fields.some((entry) => entry.jsonName === "ruleId")
                  ? { ruleId: newRequestId() }
                  : {}
                : field.listKind === "enum"
                  ? (enumOptions(field.enum)[0]?.value ?? "")
                  : "",
            ])
          }
        >
          Add {label.toLowerCase()}
        </Button>
      </fieldset>
    );
  }
  if (field.fieldKind === "map") return null;
  const managed = value !== undefined;
  return (
    <div className="grid min-w-0 gap-1.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        {(Picker || suggestion) && (!optional || managed) ? null : (
          <Label htmlFor={id}>{label}</Label>
        )}
        {optional ? (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            disabled={disabled}
            onClick={() =>
              onChange(
                managed
                  ? undefined
                  : field.fieldKind === "message"
                    ? field.message.typeName === "google.protobuf.Timestamp"
                      ? new Date().toISOString()
                      : {}
                    : field.fieldKind === "enum"
                      ? enumOptions(field.enum)[0]?.value
                      : field.scalar === ScalarType.BOOL
                        ? true
                        : field.scalar === ScalarType.STRING || field.scalar === ScalarType.BYTES
                          ? ""
                          : 0,
              )
            }
          >
            {managed ? "Leave unmanaged" : "Manage"}
          </Button>
        ) : null}
      </div>
      {optional && !managed ? (
        <p className="text-xs text-muted-foreground">Not managed.</p>
      ) : field.fieldKind === "message" &&
        field.message.typeName === "google.protobuf.Timestamp" ? (
        <Input
          id={id}
          disabled={disabled}
          type="datetime-local"
          aria-label={`${label} (UTC)`}
          value={typeof value === "string" ? value.slice(0, 16) : ""}
          onChange={(event) =>
            onChange(event.target.value ? `${event.target.value}:00Z` : undefined)
          }
        />
      ) : field.fieldKind === "message" ? (
        <MessageInput
          schema={field.message}
          value={object(value)}
          onChange={onChange}
          id={id}
          label={label}
          references={references}
          disabled={disabled}
        />
      ) : field.fieldKind === "enum" ? (
        <SelectField
          id={id}
          disabled={disabled}
          value={
            typeof value === "number"
              ? (field.enum.values.find((entry) => entry.number === value)?.name ?? "")
              : String(value ?? "")
          }
          options={[{ value: "", label: "Choose an option" }, ...enumOptions(field.enum)]}
          onValueChange={onChange}
        />
      ) : field.scalar === ScalarType.BOOL ? (
        <SelectField
          id={id}
          disabled={disabled}
          value={String(value ?? false)}
          options={[
            { value: "true", label: "Yes" },
            { value: "false", label: "No" },
          ]}
          onValueChange={(next) => onChange(next === "true")}
        />
      ) : Picker ? (
        <Picker label={label} value={String(value ?? "")} onChange={onChange} disabled={disabled} />
      ) : suggestion ? (
        <SuggestionPicker
          label={label}
          {...suggestion}
          allowTyped
          disabled={disabled}
          value={String(value ?? "")}
          onChange={(next) => onChange(next === "" && optional ? undefined : next)}
        />
      ) : recordReference && generatedReference ? (
        <>
          <p className="text-xs text-muted-foreground">Created automatically for this setting.</p>
          <TechnicalDetails items={[{ label, value: String(value ?? "") }]} />
        </>
      ) : field.scalar === ScalarType.BYTES && field.jsonName === "content" ? (
        <FileContent id={id} value={String(value ?? "")} onChange={onChange} disabled={disabled} />
      ) : (
        <Input
          id={id}
          data-freeform={
            recordReference
              ? "reference issued by another system; the server has no catalog"
              : field.jsonName === "mode"
                ? "file permissions in octal"
                : freeformReason(field)
          }
          disabled={disabled}
          value={
            field.jsonName === "mode" && typeof value === "number"
              ? value.toString(8)
              : String(value ?? "")
          }
          aria-describedby={
            recordReference || ["uid", "gid"].includes(field.jsonName)
              ? `${id}-description`
              : undefined
          }
          type={
            field.scalar === ScalarType.STRING ||
            field.scalar === ScalarType.BYTES ||
            field.jsonName === "mode"
              ? "text"
              : "number"
          }
          placeholder={field.scalar === ScalarType.BYTES ? "Base64-encoded public data" : undefined}
          onChange={(event) => {
            const next = event.target.value;
            if (field.jsonName === "mode") {
              if (/^[0-7]{0,4}$/.test(next))
                onChange(next === "" ? undefined : Number.parseInt(next, 8));
            } else if (
              field.scalar === ScalarType.STRING ||
              field.scalar === ScalarType.BYTES ||
              [
                ScalarType.UINT64,
                ScalarType.INT64,
                ScalarType.SINT64,
                ScalarType.FIXED64,
                ScalarType.SFIXED64,
              ].includes(field.scalar)
            )
              onChange(next);
            else onChange(next === "" ? undefined : Number(next));
          }}
        />
      )}
      {recordReference && !generatedReference && !Picker ? (
        <p id={`${id}-description`} className="text-xs text-muted-foreground">
          Copy this reference from the system that issued it; the server does not provide a
          selection catalog.
        </p>
      ) : null}
      {["uid", "gid"].includes(field.jsonName) ? (
        <p id={`${id}-description`} className="text-xs text-muted-foreground">
          {field.jsonName === "uid"
            ? "Numeric user ID on the device"
            : "Numeric group ID on the device"}
        </p>
      ) : null}
    </div>
  );
}

function MessageInput({
  schema,
  value,
  onChange,
  id,
  label,
  references,
  disabled,
}: Props & { label: string }) {
  const pickers = useProfilePickers();
  const BindingPicker =
    schema.typeName === "lindm.resource.v1.SecretRef"
      ? pickers.secretReference
      : schema.typeName === "lindm.resource.v1.DeviceBinding"
        ? pickers.deviceBinding
        : undefined;
  if (BindingPicker) {
    return (
      <div className="grid gap-3">
        <BindingPicker
          label={label}
          value={JSON.stringify(value)}
          disabled={disabled}
          onChange={(next) => onChange(next === "" ? {} : object(JSON.parse(next)))}
        />
        {schema.typeName === "lindm.resource.v1.SecretRef" && value.secretId ? (
          <TypedFields
            schema={{
              ...schema,
              fields: schema.fields.filter((field) => field.jsonName === "version"),
            }}
            value={value}
            onChange={onChange}
            id={id}
            references={references}
            disabled={disabled}
          />
        ) : null}
      </div>
    );
  }
  if (schema.typeName === "lindm.resource.v1.ResourceRef") {
    const allowed = id.endsWith("-repository")
      ? references.filter(
          (entry) => entry.ref.kind === 13 || entry.ref.kind === "RESOURCE_KIND_PACKAGE_REPOSITORY",
        )
      : id.endsWith("-service")
        ? references.filter(
            (entry) => entry.ref.kind === 1 || entry.ref.kind === "RESOURCE_KIND_SYSTEMD_SERVICE",
          )
        : references;
    const choices = allowed.map((entry, index) => ({ value: String(index), label: entry.label }));
    const current = allowed.findIndex((entry) => sameReference(entry.ref, value));
    const repository = id.endsWith("-repository");
    return (
      <div className="grid gap-1.5">
        <SearchPicker
          label={label}
          disabled={disabled}
          value={current < 0 ? (value.canonicalKey ? "unavailable" : "") : String(current)}
          options={choices}
          onChange={(next) => {
            if (next === "") onChange({});
            else if (allowed[Number(next)]) onChange({ ...allowed[Number(next)].ref });
          }}
        />
        <TechnicalDetails
          items={[{ label: "Current reference", value: String(value.canonicalKey ?? "") }]}
        />
        {repository ? (
          <div className="grid gap-1.5">
            <Label htmlFor={`${id}-approved`}>Approved source</Label>
            <Input
              id={`${id}-approved`}
              data-freeform="approved repository reference copied from device configuration; no server catalog"
              disabled={disabled}
              spellCheck={false}
              aria-describedby={`${id}-approved-description`}
              value={current < 0 ? String(value.canonicalKey ?? "") : ""}
              onChange={(event) =>
                onChange(
                  event.target.value === ""
                    ? {}
                    : {
                        kind: "RESOURCE_KIND_PACKAGE_REPOSITORY",
                        canonicalKey: event.target.value.trim().toLowerCase(),
                      },
                )
              }
            />
            <p id={`${id}-approved-description`} className="text-xs text-muted-foreground">
              Copy the full apt/ or rpm/ reference from the device's approved source configuration;
              the server does not provide a selection catalog.
            </p>
          </div>
        ) : allowed.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            Add the setting this depends on to this profile first.
          </p>
        ) : null}
      </div>
    );
  }
  if (schema.fields.length === 0) return <p className="text-xs text-muted-foreground">Selected.</p>;
  return (
    <div className="border-l pl-3">
      <TypedFields
        schema={schema}
        value={value}
        onChange={onChange}
        id={id}
        references={references}
        disabled={disabled}
      />
    </div>
  );
}

function FileContent({
  id,
  value,
  onChange,
  disabled,
}: {
  id: string;
  value: string;
  onChange: (value: string) => void;
  disabled: boolean;
}) {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(
      Uint8Array.from(atob(value), (char) => char.charCodeAt(0)),
    );
  } catch {
    return (
      <p className="text-sm text-muted-foreground">
        This file isn't text and will be kept as is. Clear it to replace it with text.
      </p>
    );
  }
  return (
    <Textarea
      id={id}
      rows={6}
      data-freeform="file contents to write"
      spellCheck={false}
      disabled={disabled}
      value={text}
      onChange={(event) =>
        onChange(
          btoa(
            Array.from(new TextEncoder().encode(event.target.value), (byte) =>
              String.fromCharCode(byte),
            ).join(""),
          ),
        )
      }
    />
  );
}
