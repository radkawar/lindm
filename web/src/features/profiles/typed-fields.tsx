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
import { ApprovedReferenceKind } from "../../../gen/lindm/admin/v1/approved_references_pb";
import { SuggestionField } from "../../../gen/lindm/admin/v1/suggestions_pb";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SelectField } from "@/components/ui/select-field";
import { SearchPicker, type PickerProps } from "@/components/ui/search-picker";
import { SuggestionPicker } from "@/components/ui/suggestion-picker";
import { Textarea } from "@/components/ui/textarea";
import { newRequestId } from "@/lib/ids";
import { object, sameReference } from "./resource-draft";
import { useProfilePickers } from "./field-pickers";
import { OSUpdateFields } from "./os-update-fields";
import { ApprovedReferencePicker } from "./approved-picker";

// A local user's home folder must sit under a root its device approved.
function HomeRootPicker(props: PickerProps) {
  return <ApprovedReferencePicker kind={ApprovedReferenceKind.HOME_ROOT} {...props} />;
}

const labels: Record<string, string> = {
  nativeName: "Package name",
  ecosystem: "Package format",
  presence: "Required presence",
  runtime: "Running state",
  enablement: "Start at boot",
  unit: "Unit name",
  gid: "GID",
  uid: "UID",
  secretId: "Secret",
  deviceId: "Device",
  personId: "Person",
  principalId: "Account",
  approvedRootId: "Approved root for home folders",
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
  DEB: "DEB (Debian, Ubuntu)",
  RPM: "RPM (Fedora, RHEL, openSUSE)",
  ALPM: "pacman (Arch Linux)",
  dropIn: "Service drop-in",
  daily: "Daily, UTC",
  intervalSeconds: "Interval (seconds)",
  installedShell: "Sign-in shell",
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
  failureLimit: "Failed sign-in limit",
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
  primaryGroup: "Primary group for the local user",
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

// Choices no lindm agent applies yet (no Nix, Flatpak or OSTree provider and no
// person-desktop session scope). They are never offered; a saved value stays
// visible, read-only, until the administrator chooses another option.
const unavailableChoices: Record<string, true> = {
  PACKAGE_ECOSYSTEM_NIX: true,
  "lindm.resource.v1.NativeVersion.nix": true,
  "lindm.resource.v1.RepositoryDesired.nix": true,
  "lindm.resource.v1.RepositoryDesired.flatpak": true,
  "lindm.resource.v1.RepositoryDesired.ostree": true,
  "lindm.resource.v1.SessionScope.personDesktop": true,
};
const UNAVAILABLE_NOTE =
  "No lindm agent can apply this yet. The editor keeps the saved value. Choose another option to change it.";

function enumOptions(schema: DescEnum, current?: JsonValue) {
  const first = schema.values[0]?.name ?? "";
  const prefix = first.endsWith("UNSPECIFIED") ? first.slice(0, -"UNSPECIFIED".length) : "";
  return schema.values
    .filter(
      (value) =>
        value.number !== 0 &&
        (!unavailableChoices[value.name] || value.name === current || value.number === current),
    )
    .map((value) => ({
      value: value.name,
      label:
        schema.typeName === "lindm.resource.v1.FirewallVerdict" &&
        value.name === "FIREWALL_VERDICT_DROP"
          ? "Discard"
          : unavailableChoices[value.name]
            ? `${fieldLabel(value.name.slice(prefix.length))} (not available)`
            : fieldLabel(value.name.slice(prefix.length)),
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
    // Architecture names differ per package format; a new format starts from
    // the device's own architecture again.
    if (
      schema.typeName === "lindm.resource.v1.PackageIdentity" &&
      field.jsonName === "ecosystem" &&
      value.ecosystem !== next
    ) {
      delete updated.architecture;
    }
    onChange(updated);
  }
  return (
    <div className="grid min-w-0 gap-3">
      {oneofs.map((oneof) => {
        const selected = oneof.fields.find((field) => value[field.jsonName] !== undefined);
        const unavailable =
          !!selected && !!unavailableChoices[`${schema.typeName}.${selected.jsonName}`];
        return (
          <div className="grid gap-1.5" key={oneof.name}>
            <Label htmlFor={`${id}-${oneof.name}`}>{fieldLabel(oneof.name)}</Label>
            <SelectField
              id={`${id}-${oneof.name}`}
              disabled={disabled}
              value={selected?.jsonName ?? ""}
              aria-describedby={unavailable ? `${id}-${oneof.name}-unavailable` : undefined}
              options={[
                { value: "", label: "Choose an option" },
                ...oneof.fields
                  .filter(
                    (field) =>
                      field === selected ||
                      !unavailableChoices[`${schema.typeName}.${field.jsonName}`],
                  )
                  .map((field) => ({
                    value: field.jsonName,
                    label:
                      field === selected && unavailable
                        ? `${fieldLabel(field.jsonName)} (not available)`
                        : fieldLabel(field.jsonName),
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
            {unavailable ? (
              <p id={`${id}-${oneof.name}-unavailable`} className="text-xs text-muted-foreground">
                {UNAVAILABLE_NOTE}
              </p>
            ) : null}
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
        .map((field) =>
          schema.typeName === "lindm.resource.v1.PackageIdentity" &&
          field.jsonName === "architecture" ? (
            <PackageArchitectureField
              key={field.number}
              id={`${id}-${field.jsonName}`}
              ecosystem={String(value.ecosystem ?? "")}
              value={String(value.architecture ?? "")}
              disabled={disabled}
              onChange={(next) => change(field, next === "" ? undefined : next)}
            />
          ) : (
            <TypedField
              key={field.number}
              field={field}
              value={value[field.jsonName]}
              id={`${id}-${field.jsonName}`}
              references={references}
              siblings={value}
              disabled={disabled || !!unavailableChoices[`${schema.typeName}.${field.jsonName}`]}
              onChange={(next) => change(field, next)}
            />
          ),
        )}
    </div>
  );
}

// Native spellings per package format, from each package database.
const packageArchitectures: Record<string, [string, string][]> = {
  PACKAGE_ECOSYSTEM_DEB: [
    ["amd64", "64-bit PC (amd64) only"],
    ["arm64", "64-bit ARM (arm64) only"],
    ["i386", "32-bit PC (i386) only"],
    ["armhf", "32-bit ARM (armhf) only"],
    ["all", "Architecture-independent build (all) only"],
  ],
  PACKAGE_ECOSYSTEM_RPM: [
    ["x86_64", "64-bit PC (x86_64) only"],
    ["aarch64", "64-bit ARM (aarch64) only"],
    ["i686", "32-bit PC (i686) only"],
    ["noarch", "Architecture-independent build (noarch) only"],
  ],
  PACKAGE_ECOSYSTEM_ALPM: [
    ["x86_64", "64-bit PC (x86_64) only"],
    ["aarch64", "64-bit ARM (aarch64) only"],
    ["any", "Architecture-independent build (any) only"],
  ],
};

// An empty architecture follows each device's own package architecture, so one
// setting serves amd64 and arm64 devices alike; pinning one is the exception.
function PackageArchitectureField({
  id,
  ecosystem,
  value,
  disabled,
  onChange,
}: {
  id: string;
  ecosystem: string;
  value: string;
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  const known = packageArchitectures[ecosystem] ?? [];
  const options = [
    { value: "", label: "This device's architecture" },
    ...known.map(([architecture, label]) => ({ value: architecture, label })),
    ...(value !== "" && !known.some(([architecture]) => architecture === value)
      ? [{ value, label: `${value} only` }]
      : []),
  ];
  return (
    <div className="grid min-w-0 gap-1.5">
      <Label htmlFor={id}>Architecture</Label>
      <SelectField
        id={id}
        disabled={disabled}
        value={value}
        options={options}
        aria-describedby={`${id}-description`}
        onValueChange={onChange}
      />
      <p id={`${id}-description`} className="text-xs text-muted-foreground">
        Each device installs its own build. Choose one architecture only if devices need that build.
      </p>
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
          : field.parent.typeName === "lindm.resource.v1.HomePolicy" &&
              field.jsonName === "approvedRootId"
            ? HomeRootPicker
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
                options={enumOptions(field.enum, item)}
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
          options={[{ value: "", label: "Choose an option" }, ...enumOptions(field.enum, value)]}
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
        <p className="text-xs text-muted-foreground">Created automatically for this setting.</p>
      ) : recordReference ? (
        // No list exists for this identity; it is never typed in, only kept. The
        // value itself is in the editor's single View JSON.
        <p className="text-xs text-muted-foreground">
          {value ? "The editor keeps the saved reference." : "No reference."} The console cannot
          choose this reference yet.
        </p>
      ) : field.scalar === ScalarType.BYTES && field.jsonName === "content" ? (
        <FileContent id={id} value={String(value ?? "")} onChange={onChange} disabled={disabled} />
      ) : (
        <Input
          id={id}
          data-freeform={
            field.jsonName === "mode" ? "file permissions in octal" : freeformReason(field)
          }
          disabled={disabled}
          value={
            field.jsonName === "mode" && typeof value === "number"
              ? value.toString(8)
              : String(value ?? "")
          }
          aria-describedby={
            ["uid", "gid"].includes(field.jsonName) ? `${id}-description` : undefined
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
      {["uid", "gid"].includes(field.jsonName) ? (
        <p id={`${id}-description`} className="text-xs text-muted-foreground">
          Leave unset to let the device assign the next free{" "}
          {field.jsonName === "uid" ? "user" : "group"} ID.
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
        {repository && allowed.length === 0 ? null : (
          <SearchPicker
            label={repository ? "Repository in this profile" : label}
            disabled={disabled}
            value={
              current < 0
                ? value.canonicalKey && !repository
                  ? "unavailable"
                  : ""
                : String(current)
            }
            options={choices}
            onChange={(next) => {
              if (next === "") onChange({});
              else if (allowed[Number(next)]) onChange({ ...allowed[Number(next)].ref });
            }}
          />
        )}
        {repository ? (
          <ApprovedReferencePicker
            kind={ApprovedReferenceKind.PACKAGE_SOURCE}
            label={
              allowed.length === 0 ? "Approved package source" : "Or an approved source on devices"
            }
            disabled={disabled}
            value={current < 0 ? String(value.canonicalKey ?? "") : ""}
            onChange={(next) =>
              onChange(next ? { kind: "RESOURCE_KIND_PACKAGE_REPOSITORY", canonicalKey: next } : {})
            }
          />
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
        The device keeps this non-text file unchanged. Clear it to replace it with text.
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
