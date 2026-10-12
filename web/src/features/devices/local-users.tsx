import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CollectionStatus } from "../../../gen/lindm/inventory/v1/observation_pb";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { SearchPicker, type PickerOption, type PickerProps } from "@/components/ui/search-picker";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { formatTimestamp } from "@/lib/time";
import { deviceQueryOptions } from "./queries";

// Chooses a local account from the device's latest host inventory. When the
// device has not reported its accounts the typed name is offered instead,
// marked as unverified, so a missing inventory never blocks the operator.
export function LocalUserPicker({
  deviceId,
  ineligible,
  placeholder,
  ...props
}: PickerProps & {
  deviceId: string;
  // Returns why an account can't be chosen here, or undefined when it can.
  ineligible?: (user: { name: string; uid: bigint }) => string | undefined;
  placeholder?: string;
}) {
  const lifetime = useAuthLifetime();
  const device = useQuery(deviceQueryOptions(lifetime, deviceId));
  const [search, setSearch] = useState("");
  const host = device.data?.host;
  const inventory = host?.observation?.details?.localUsers;
  const reported = inventory?.status === CollectionStatus.SUCCESS;
  const received = formatTimestamp(host?.receivedAt);
  const typed = search.trim();
  const needle = typed.toLowerCase();
  const options: PickerOption[] = (reported ? inventory.users : [])
    .filter((user) => user.name.toLowerCase().includes(needle))
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((user) => {
      const reason = ineligible?.(user);
      return {
        value: user.name,
        label: user.name,
        description: reason ?? [`UID ${user.uid}`, user.shell].filter(Boolean).join(" · "),
        disabled: reason !== undefined,
      };
    });
  if (props.value && !options.some((option) => option.value === props.value)) {
    options.unshift({
      value: props.value,
      label: props.value,
      description: reported ? "Not in the device's latest account list" : "Current selection",
    });
  }
  if (!reported && typed && !options.some((option) => option.value === typed)) {
    options.push({
      value: typed,
      label: `Use “${typed}”`,
      description: "Not checked: the device hasn't reported its local accounts",
    });
  }
  return (
    <SearchPicker
      {...props}
      search={search}
      onSearchChange={setSearch}
      options={options}
      placeholder={placeholder}
      note={
        reported
          ? `Local accounts the device reported ${received.local}.`
          : "The device hasn't reported its local accounts. Type the exact account name."
      }
      footer={
        device.isPending ? (
          <p role="status" className="text-xs text-muted-foreground">
            Loading local accounts…
          </p>
        ) : device.error ? (
          <RpcError failure={toRpcFailure(device.error)} title="Couldn't load local accounts">
            <Button type="button" variant="outline" onClick={() => void device.refetch()}>
              Retry
            </Button>
          </RpcError>
        ) : undefined
      }
    />
  );
}
