import { create } from "@bufbuild/protobuf";
import {
  SecretMaterialSchema,
  type SecretMaterial,
} from "../../../gen/lindm/agent/v1/secret_delivery_pb";
import { SecretPurpose } from "../../../gen/lindm/resource/v1/common_pb";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

export const purposeLabels: Record<SecretPurpose, string> = {
  [SecretPurpose.UNSPECIFIED]: "Unspecified",
  [SecretPurpose.PASSWORD_HASH]: "Local password hash",
  [SecretPurpose.WIFI_PSK]: "Wi-Fi pre-shared key",
  [SecretPurpose.EAP_PASSWORD]: "EAP password",
  [SecretPurpose.VPN_AUTHENTICATION]: "VPN authentication",
  [SecretPurpose.WIREGUARD_PRIVATE_KEY]: "WireGuard private key",
  [SecretPurpose.WIREGUARD_PRESHARED_KEY]: "WireGuard preshared key",
  [SecretPurpose.PROXY_AUTHENTICATION]: "Proxy authentication",
  [SecretPurpose.REPOSITORY_AUTHENTICATION]: "Repository authentication",
  [SecretPurpose.DIRECTORY_JOIN]: "Directory join",
};

export const purposeOptions = [
  SecretPurpose.PASSWORD_HASH,
  SecretPurpose.WIFI_PSK,
  SecretPurpose.EAP_PASSWORD,
  SecretPurpose.VPN_AUTHENTICATION,
  SecretPurpose.WIREGUARD_PRIVATE_KEY,
  SecretPurpose.WIREGUARD_PRESHARED_KEY,
  SecretPurpose.PROXY_AUTHENTICATION,
  SecretPurpose.REPOSITORY_AUTHENTICATION,
  SecretPurpose.DIRECTORY_JOIN,
].map((purpose) => ({ value: purpose, label: purposeLabels[purpose] }));

const MATERIAL_NAME = "secret-material";

// The material control is uncontrolled: its text never enters React state.
export function MaterialField({
  id,
  purpose,
  disabled,
}: {
  id: string;
  purpose: SecretPurpose;
  disabled: boolean;
}) {
  const hintId = `${id}-hint`;
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>
        {purpose === SecretPurpose.PASSWORD_HASH
          ? "Password hash"
          : purpose === SecretPurpose.WIFI_PSK
            ? "Wi-Fi passphrase or PSK"
            : "Secret value"}
      </Label>
      {purpose === SecretPurpose.PASSWORD_HASH ? (
        <Input
          key="password-hash"
          id={id}
          name={MATERIAL_NAME}
          className="font-mono"
          autoComplete="off"
          spellCheck={false}
          disabled={disabled}
          aria-describedby={hintId}
        />
      ) : purpose === SecretPurpose.WIFI_PSK ? (
        <Input
          key="wifi-psk"
          id={id}
          name={MATERIAL_NAME}
          type="password"
          autoComplete="off"
          spellCheck={false}
          disabled={disabled}
          aria-describedby={hintId}
        />
      ) : (
        <Textarea
          key="opaque"
          id={id}
          name={MATERIAL_NAME}
          className="font-mono"
          autoComplete="off"
          spellCheck={false}
          disabled={disabled}
          aria-describedby={hintId}
        />
      )}
      <p id={hintId} className="text-sm text-muted-foreground">
        {purpose === SecretPurpose.PASSWORD_HASH
          ? "A yescrypt, SHA-512 or bcrypt hash, for example from mkpasswd. Never enter the plain password."
          : purpose === SecretPurpose.WIFI_PSK
            ? "8 to 63 characters, or 64 hexadecimal digits."
            : "Up to 4096 bytes of text, saved exactly as entered."}{" "}
        You'll need to enter it again if saving fails.
      </p>
    </div>
  );
}

// Reads the material control into zeroizable bytes and clears the control.
export function takeMaterial(form: HTMLFormElement, purpose: SecretPurpose): SecretMaterial {
  const control = form.elements.namedItem(MATERIAL_NAME);
  if (!(control instanceof HTMLInputElement || control instanceof HTMLTextAreaElement))
    throw new Error("The secret value field is missing.");
  const value = new TextEncoder().encode(control.value);
  control.value = "";
  return create(SecretMaterialSchema, {
    material:
      purpose === SecretPurpose.PASSWORD_HASH
        ? { case: "passwordHash", value }
        : purpose === SecretPurpose.WIFI_PSK
          ? { case: "wifiPsk", value }
          : { case: "opaque", value },
  });
}
