import { type DescField, type JsonObject, type JsonValue } from "@bufbuild/protobuf";
import { ResourceDesiredStateSchema } from "../../../gen/lindm/resource/v1/resource_pb";
import { ResourceKindSchema } from "../../../gen/lindm/resource/v1/identity_pb";
import { newRequestId } from "@/lib/ids";

export function object(value: JsonValue | undefined): JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : {};
}

export const resourceKinds = [
  {
    arm: "systemdService",
    label: "Systemd service",
    help: "Manage an existing service, not its executable or unit content.",
  },
  {
    arm: "nativePackage",
    label: "Native package",
    help: "Select a DEB or RPM package and approved repository. Exact versions remain native versions, not semantic versions.",
  },
  {
    arm: "managedFile",
    label: "Managed file",
    help: "Manage a nonsecret file at an approved path. Existing files require ownership or approved adoption.",
  },
  {
    arm: "localUser",
    label: "Local user",
    help: "Manage a local account only. Home data is never recursively deleted. Passwords use immutable secret references, never plaintext.",
  },
  {
    arm: "localGroup",
    label: "Local group",
    help: "Manage local membership. Exact membership requires ownership of the complete membership dimension.",
  },
  {
    arm: "sysctl",
    label: "Kernel setting",
    help: "Set one approved dotted sysctl key. Persistent settings also require ownership of the managed configuration.",
  },
  {
    arm: "systemdDefinition",
    label: "Systemd timer or service drop-in",
    help: "Schedule an existing service or set approved service limits. No commands or arbitrary unit content.",
  },
  {
    arm: "firewallZone",
    label: "Firewall zone",
    help: "Configure typed rules. Native backend support and connectivity safety are evaluated on each target.",
  },
  {
    arm: "encryptionCompliance",
    label: "Encryption compliance",
    help: "Check root encryption and optional escrow or TPM requirements. This policy does not encrypt disks or rotate keys.",
  },
  {
    arm: "passwordPolicy",
    label: "Password policy",
    help: "Manage selected local authentication controls. Native PAM ownership and module support are required.",
  },
  {
    arm: "sessionPolicy",
    label: "Login and session policy",
    help: "Select login or desktop scope. Screen locking and login limits require distinct native capabilities.",
  },
  {
    arm: "repository",
    label: "Package repository",
    help: "Declare an approved package source for package selection. Publication does not qualify its native provider.",
  },
];

export function desiredField(arm: string): DescField | undefined {
  return ResourceDesiredStateSchema.fields.find((field) => field.jsonName === arm);
}

export function selectedKind(document: JsonObject): string {
  const desired = object(document.desired);
  return (
    ResourceDesiredStateSchema.fields.find(
      (field) => field.oneof && desired[field.jsonName] !== undefined,
    )?.jsonName ?? ""
  );
}

export function initialState(arm: string): JsonObject {
  switch (arm) {
    case "systemdService":
      return {
        unit: "",
        runtime: "SERVICE_RUNTIME_STATE_ACTIVE",
        enablement: "SERVICE_ENABLEMENT_UNMANAGED",
      };
    case "localUser":
    case "localGroup":
      return { name: "", presence: "PRESENCE_PRESENT" };
    case "nativePackage":
      return {
        package: { ecosystem: "PACKAGE_ECOSYSTEM_DEB", nativeName: "", architecture: "amd64" },
        presence: "PRESENCE_PRESENT",
        any: {},
        removal: "PACKAGE_REMOVAL_POLICY_PRESERVE_DATA",
      };
    case "repository":
      return { repositoryId: newRequestId(), presence: "PRESENCE_PRESENT", apt: {} };
    case "firewallZone":
      return {
        zoneId: newRequestId(),
        presence: "PRESENCE_PRESENT",
        defaultIngress: "FIREWALL_VERDICT_DROP",
        defaultEgress: "FIREWALL_VERDICT_ACCEPT",
      };
    case "managedFile":
      return { path: "", presence: "PRESENCE_PRESENT" };
    case "sysctl":
      return { key: "", value: "", persistent: true };
    case "systemdDefinition":
      return {
        presence: "PRESENCE_PRESENT",
        timer: { unit: "", schedule: { daily: { hour: 0, minute: 0 } }, enabled: true },
      };
    case "encryptionCompliance":
      return { requireLuksRoot: true };
    default:
      return {};
  }
}

// These are the display-side derivations of the canonical identities. The server
// independently validates both the typed state and the supplied ref at publication.
export function withDerivedRef(document: JsonObject): JsonObject {
  const arm = selectedKind(document);
  const field = desiredField(arm);
  if (!field || !resourceKinds.some((kind) => kind.arm === arm)) return document;
  const desired = object(document.desired);
  const state = object(desired[arm]);
  let key = "";
  switch (arm) {
    case "systemdService":
      key = String(state.unit ?? "");
      break;
    case "localUser":
    case "localGroup":
      key = String(state.name ?? "");
      break;
    case "managedFile":
      key = String(state.path ?? "");
      break;
    case "sysctl":
      key = String(state.key ?? "");
      break;
    case "firewallZone":
      key = String(state.zoneId ?? "").toLowerCase();
      break;
    case "nativePackage": {
      const pkg = object(state.package);
      const ecosystems: Record<string, string> = {
        PACKAGE_ECOSYSTEM_DEB: "deb",
        PACKAGE_ECOSYSTEM_RPM: "rpm",
        PACKAGE_ECOSYSTEM_ALPM: "alpm",
        PACKAGE_ECOSYSTEM_NIX: "nix",
        "1": "deb",
        "2": "rpm",
        "3": "alpm",
        "4": "nix",
      };
      key = `${ecosystems[String(pkg.ecosystem)] ?? ""}/${String(pkg.nativeName ?? "")}/${String(pkg.architecture ?? "")}`;
      break;
    }
    case "repository": {
      const source =
        ["apt", "rpm", "alpm", "flatpak", "nix", "ostree"].find(
          (name) => state[name] !== undefined,
        ) ?? "";
      key = `${source}/${String(state.repositoryId ?? "").toLowerCase()}`;
      break;
    }
    case "passwordPolicy":
      key = "system/local-auth";
      break;
    case "encryptionCompliance":
      key = "system/root";
      break;
    case "systemdDefinition":
      key =
        state.timer !== undefined
          ? `timer/${String(object(state.timer).unit ?? "")}`
          : `drop-in/${String(object(state.dropIn).unit ?? "")}`;
      break;
    case "sessionPolicy": {
      const desktop = object(object(state.scope).personDesktop);
      const person = object(desktop.person);
      const desktops: Record<string, string> = {
        DESKTOP_GNOME: "gnome",
        DESKTOP_KDE: "kde",
        "1": "gnome",
        "2": "kde",
      };
      key =
        object(state.scope).personDesktop === undefined
          ? "system/login"
          : `person/${String(person.assignmentId ?? "").toLowerCase()}/${desktops[String(desktop.desktop)] ?? ""}`;
      break;
    }
  }
  return {
    ...document,
    desired: { ...desired, ref: { kind: field.number - 9, canonicalKey: key } },
  };
}

export function sameReference(left: JsonObject, right: JsonObject): boolean {
  const leftKind =
    typeof left.kind === "number"
      ? left.kind
      : ResourceKindSchema.values.find((entry) => entry.name === left.kind)?.number;
  const rightKind =
    typeof right.kind === "number"
      ? right.kind
      : ResourceKindSchema.values.find((entry) => entry.name === right.kind)?.number;
  return (
    leftKind !== undefined && leftKind === rightKind && left.canonicalKey === right.canonicalKey
  );
}

export function replaceReference(
  value: JsonValue,
  previous: JsonObject,
  next: JsonObject,
): JsonValue {
  if (Array.isArray(value)) return value.map((item) => replaceReference(item, previous, next));
  if (value === null || typeof value !== "object") return value;
  if (value.canonicalKey !== undefined && sameReference(value, previous)) return { ...next };
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      item === undefined ? item : replaceReference(item, previous, next),
    ]),
  );
}
