import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SearchPicker, type PickerProps } from "@/components/ui/search-picker";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { authorizationQueryOptions } from "./authorization-queries";
import { identitySettingsQueryOptions } from "./identity-settings";

const referenceLabels: Record<string, string> = {
  keycloak: "Keycloak group path",
  entra: "Entra group object ID",
  okta: "Okta immutable group reference",
  google: "Google immutable group reference",
};

// Identity-provider references are not device-group identities. There is no provider
// catalog API: known policy references are selectable, new references are explicit setup.
export function DirectoryGroupPicker(props: PickerProps) {
  const lifetime = useAuthLifetime();
  const policy = useQuery(authorizationQueryOptions(lifetime));
  const identity = useQuery(identitySettingsQueryOptions(lifetime));
  const [reference, setReference] = useState("");
  const keycloak = identity.data?.primarySource === "keycloak";
  const referenceLabel = referenceLabels[identity.data?.primarySource ?? ""];
  const known = [
    ...new Set([
      ...(policy.data?.authorization?.policy?.groupBindings.map((binding) => binding.group) ?? []),
      ...(props.value ? [props.value] : []),
    ]),
  ];
  return (
    <div className="grid gap-2">
      <SearchPicker
        {...props}
        options={known.map((value, index) => ({
          value,
          label: keycloak ? value : `Configured directory group ${index + 1}`,
          description: keycloak
            ? "Keycloak group path"
            : "Display name unavailable from the identity provider",
        }))}
        note="Search configured directory groups only; a directory-wide catalog is not available."
      />
      {props.value ? (
        <TechnicalDetails items={[{ label: "Directory group reference", value: props.value }]} />
      ) : null}
      <details className="text-sm">
        <summary className="w-fit cursor-pointer py-1">Advanced directory setup</summary>
        <div className="mt-2 grid gap-3 border p-3">
          <p>
            Obtain the exact group reference from your identity provider. Device groups cannot grant
            console sign-in access.
          </p>
          <label className="grid gap-2 font-medium">
            {referenceLabel ?? "Directory group reference unavailable"}
            <Input
              autoComplete="off"
              disabled={props.disabled || !referenceLabel}
              value={reference}
              onChange={(event) => setReference(event.target.value)}
            />
          </label>
          <Button
            type="button"
            className="w-fit"
            variant="outline"
            disabled={props.disabled || !reference.trim() || !referenceLabel || identity.isError}
            onClick={() => {
              props.onChange(reference.trim());
              setReference("");
            }}
          >
            Use directory reference
          </Button>
        </div>
      </details>
    </div>
  );
}
