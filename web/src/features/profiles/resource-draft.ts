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
    help: "Start, stop or enable an existing service.",
  },
  {
    arm: "nativePackage",
    label: "Package",
    help: "Install or remove a DEB or RPM package from an approved repository.",
  },
  {
    arm: "managedFile",
    label: "Managed file",
    help: "Write a file at an approved path. Don't put secrets here.",
  },
  {
    arm: "localUser",
    label: "Local user",
    help: "Create or remove a local account. Home folders are never deleted.",
  },
  {
    arm: "localGroup",
    label: "Local group",
    help: "Create a local group and set its members.",
  },
  {
    arm: "sysctl",
    label: "Kernel setting",
    help: "Set one approved kernel (sysctl) setting.",
  },
  {
    arm: "systemdDefinition",
    label: "Systemd timer or service drop-in",
    help: "Schedule an existing service or set its resource limits.",
  },
  {
    arm: "firewallZone",
    label: "Firewall zone",
    help: "Set firewall rules for a zone.",
  },
  {
    arm: "encryptionCompliance",
    label: "Encryption compliance",
    help: "Check that disks are encrypted. This doesn't encrypt disks or rotate keys.",
  },
  {
    arm: "passwordPolicy",
    label: "Password policy",
    help: "Set local password rules.",
  },
  {
    arm: "sessionPolicy",
    label: "Login and session policy",
    help: "Set screen lock and login limits.",
  },
  {
    arm: "repository",
    label: "Package repository",
    help: "Add an approved package source that packages in this profile can use.",
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
