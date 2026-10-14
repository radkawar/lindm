// SPDX-License-Identifier: Apache-2.0

import { ResourceKind } from "../../gen/lindm/resource/v1/identity_pb";
import {
  ResourceFeature,
  type Applicability,
  type PlatformProduct,
} from "../../gen/lindm/resource/v1/common_pb";

const KIND_LABELS: Record<number, string> = {
  [ResourceKind.SYSTEMD_SERVICE]: "Service",
  [ResourceKind.LOCAL_GROUP]: "Local group",
  [ResourceKind.LOCAL_USER]: "Local account",
  [ResourceKind.SUDO_RULE]: "Administrator access",
  [ResourceKind.SSH_SERVER]: "SSH server",
  [ResourceKind.TIME_SYNC]: "Time synchronization",
  [ResourceKind.TRUST_CA]: "Trusted certificate",
  [ResourceKind.FIREWALL_ZONE]: "Firewall zone",
  [ResourceKind.NETWORK_CONNECTION]: "Network connection",
  [ResourceKind.DNS]: "DNS",
  [ResourceKind.PROXY]: "Proxy",
  [ResourceKind.NATIVE_PACKAGE]: "System package",
  [ResourceKind.PACKAGE_REPOSITORY]: "Package repository",
  [ResourceKind.FLATPAK_APP]: "Flatpak application",
  [ResourceKind.OS_UPDATE_POLICY]: "Operating system updates",
  [ResourceKind.SESSION_POLICY]: "Session policy",
  [ResourceKind.PASSWORD_POLICY]: "Password policy",
  [ResourceKind.SNAP_APP]: "Snap application",
  [ResourceKind.CERTIFICATE_ENROLLMENT]: "Certificate enrollment",
  [ResourceKind.DIRECTORY_CLIENT]: "Directory connection",
  [ResourceKind.MANAGED_FILE]: "Managed file",
  [ResourceKind.SYSCTL]: "Kernel setting",
  [ResourceKind.SYSTEMD_DEFINITION]: "Systemd configuration",
  [ResourceKind.ENCRYPTION_COMPLIANCE]: "Encryption compliance check",
};

// Plain words for a managed item's kind; never the protocol name.
export function resourceKindLabel(kind: ResourceKind | undefined): string {
  return (kind !== undefined && KIND_LABELS[kind]) || "Other setting";
}

const FEATURE_LABELS: Record<number, string> = {
  [ResourceFeature.SAFE_RELEASE]: "safe removal",
  [ResourceFeature.NETWORK_TIME_SECURITY]: "Network Time Security",
  [ResourceFeature.FIREWALL_FORWARD]: "firewall forwarding rules",
  [ResourceFeature.FIREWALL_DEFAULT_EGRESS]: "a default outbound firewall rule",
  [ResourceFeature.FIREWALL_ZONE_BINDING]: "firewall zone binding",
  [ResourceFeature.DNSSEC]: "DNSSEC",
  [ResourceFeature.DNS_OVER_TLS]: "DNS over TLS",
  [ResourceFeature.WIFI_EAP]: "enterprise Wi-Fi sign-in",
  [ResourceFeature.VPN_OPENVPN]: "OpenVPN",
  [ResourceFeature.VPN_WIREGUARD]: "WireGuard",
  [ResourceFeature.VPN_IPSEC]: "IPsec VPN",
  [ResourceFeature.VISIBLE_LOCK]: "a visible screen lock",
  [ResourceFeature.PAM_PASSWORD_QUALITY]: "password quality rules",
  [ResourceFeature.PAM_HISTORY]: "password history",
  [ResourceFeature.PAM_LOCKOUT]: "sign-in lockout",
  [ResourceFeature.SECURITY_ADVISORIES]: "security advisories",
  [ResourceFeature.TPM_KEY]: "TPM-protected keys",
  [ResourceFeature.PKCS11_KEY]: "smart card or token keys",
};

const ARCHITECTURE_LABELS: Record<string, string> = {
  x86_64: "64-bit Intel/AMD",
  amd64: "64-bit Intel/AMD",
  aarch64: "64-bit Arm",
  arm64: "64-bit Arm",
};

function platformLabel(product: PlatformProduct): string {
  const name = [product.product || product.osId, product.version].filter(Boolean).join(" ");
  return `${name} on ${ARCHITECTURE_LABELS[product.architecture] ?? product.architecture}`;
}

function listLabel(items: string[]): string {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} or ${items.at(-1)}`;
}

// "Ubuntu 24.04 on 64-bit Arm or Fedora 44 on 64-bit Intel/AMD".
export function applicabilityPlatforms(applicability: Applicability | undefined): string {
  return listLabel([...new Set(applicability?.products.map(platformLabel) ?? [])]);
}

export function applicabilityFeatures(applicability: Applicability | undefined): string {
  const features = applicability?.features.map(
    (feature) => FEATURE_LABELS[feature] ?? "a capability",
  );
  if (!features?.length) return "";
  return features.length === 1
    ? features[0]
    : `${features.slice(0, -1).join(", ")} and ${features.at(-1)}`;
}
