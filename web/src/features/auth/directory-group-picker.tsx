// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { SuggestionField } from "../../../gen/lindm/admin/v1/suggestions_pb";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { PickerProps } from "@/components/ui/search-picker";
import { SuggestionPicker } from "@/components/ui/suggestion-picker";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { identitySettingsQueryOptions } from "./identity-settings";

const referenceLabels: Record<string, string> = {
  keycloak: "Keycloak group path",
  entra: "Entra group object ID",
  okta: "Okta immutable group reference",
  google: "Google immutable group reference",
};

// Identity-provider references are not device-group identities. There is no provider
// catalog API: the choices are groups seen in members' sign-ins (SuggestValues
// DIRECTORY_GROUP); a group nobody has signed in with yet is explicit setup below.
export function DirectoryGroupPicker(props: PickerProps) {
  const lifetime = useAuthLifetime();
  const identity = useQuery(identitySettingsQueryOptions(lifetime));
  const [reference, setReference] = useState("");
  const referenceLabel = referenceLabels[identity.data?.primarySource ?? ""];
  return (
    <div className="grid gap-2">
      <SuggestionPicker
        {...props}
        field={SuggestionField.DIRECTORY_GROUP}
        note="Type the start of a group name. Results include only groups from previous member sign-ins."
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
              data-freeform="identity-provider group reference not yet seen at sign-in"
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
