import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import type { SecretSummary } from "../../../gen/lindm/admin/v1/secrets_pb";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { SearchPicker, type PickerProps } from "@/components/ui/search-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { purposeLabels } from "./material";
import { secretQueryOptions, secretsQueryOptions } from "./queries";

export function SecretPicker({
  onSelect,
  ...props
}: PickerProps & { onSelect?: (secret: SecretSummary | undefined) => void }) {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const query = useQuery(secretsQueryOptions(lifetime, 100, pageToken));
  const selected = useQuery({
    ...secretQueryOptions(lifetime, props.value),
    enabled: !!props.value,
  });
  const secrets = query.error ? [] : [...(query.data?.secrets ?? [])];
  const selectedSecret = selected.error ? undefined : selected.data?.secret;
  if (selectedSecret && !secrets.some((secret) => secret.secretId === selectedSecret.secretId)) {
    secrets.unshift(selectedSecret);
  }
  return (
    <SearchPicker
      {...props}
      onChange={(value) => {
        if (onSelect) {
          onSelect(secrets.find((secret) => secret.secretId === value));
        } else {
          props.onChange(value);
        }
      }}
      disabled={props.disabled || query.isPending || !!query.error}
      options={secrets.map((secret) => ({
        value: secret.secretId,
        label: secret.displayName.trim() || "Unnamed secret",
        description: purposeLabels[secret.purpose] ?? "Unrecognized purpose",
      }))}
      note="Searches up to 100 secrets on this page. Use Next page for more secrets."
    >
      {query.isPending ? <p role="status">Loading secrets…</p> : null}
      {query.error ? <RpcError failure={toRpcFailure(query.error)} /> : null}
      {selected.error ? <RpcError failure={toRpcFailure(selected.error)} /> : null}
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant="outline"
          disabled={props.disabled || query.isFetching || !pageToken}
          onClick={() => setPageToken("")}
        >
          First page
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={
            props.disabled || query.isFetching || !!query.error || !query.data?.nextPageToken
          }
          onClick={() => setPageToken(query.data?.nextPageToken ?? "")}
        >
          Next page
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={props.disabled || query.isFetching || selected.isFetching}
          onClick={() => {
            void query.refetch();
            if (props.value) void selected.refetch();
          }}
        >
          Refresh secrets
        </Button>
      </div>
    </SearchPicker>
  );
}

export function SecretReferencePicker(props: PickerProps) {
  let secretId = "";
  if (props.value) {
    try {
      const reference: unknown = JSON.parse(props.value);
      if (
        reference &&
        typeof reference === "object" &&
        "secretId" in reference &&
        typeof reference.secretId === "string"
      ) {
        secretId = reference.secretId;
      }
    } catch {
      // An incomplete draft has no selected server record.
    }
  }
  return (
    <>
      {props.name ? <input type="hidden" name={props.name} value={props.value} /> : null}
      <SecretPicker
        {...props}
        name={undefined}
        value={secretId}
        onSelect={(secret) =>
          props.onChange(
            secret
              ? JSON.stringify({
                  secretId: secret.secretId,
                  subjectBindingId: secret.subjectBindingId,
                  version: secret.currentVersion.toString(),
                  purpose: secret.purpose,
                })
              : "",
          )
        }
      />
    </>
  );
}
