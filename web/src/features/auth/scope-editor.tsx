import { create } from "@bufbuild/protobuf";
import { DeviceScopeSchema, type DeviceScope } from "../../../gen/lindm/auth/v1/authorization_pb";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { MultiPicker, type PickerSlot } from "@/components/ui/search-picker";

export function ScopeEditor({
  scopes,
  disabled,
  onChange,
  devicePicker,
  groupPicker,
}: {
  scopes: DeviceScope[];
  disabled: boolean;
  onChange: (scopes: DeviceScope[]) => void;
  devicePicker: PickerSlot;
  groupPicker: PickerSlot;
}) {
  return (
    <fieldset className="grid min-w-0 gap-4 border p-4" disabled={disabled}>
      <legend className="px-1 text-sm font-semibold">Device access</legend>
      <p className="max-w-3xl text-sm text-muted-foreground">
        Leave empty to allow all devices. Otherwise the account can manage devices that match any
        rule.
      </p>
      {scopes.map((scope, index) => (
        <div className="grid min-w-0 gap-3 border bg-muted/20 p-4" key={index}>
          <h3 className="text-sm font-semibold">Rule {index + 1}</h3>
          <label className="grid gap-2 text-sm font-medium">
            Labels (device must have all, one per line)
            <Textarea
              className="font-mono text-xs"
              value={scope.labels.join("\n")}
              onChange={(event) =>
                onChange(
                  scopes.map((current, position) =>
                    position === index
                      ? create(DeviceScopeSchema, {
                          ...current,
                          labels: event.target.value.split("\n"),
                        })
                      : current,
                  ),
                )
              }
            />
          </label>
          {(["deviceIds", "groupIds"] as const).map((field) => (
            <MultiPicker
              key={field}
              label={field === "deviceIds" ? "Devices" : "Groups"}
              values={scope[field]}
              picker={field === "deviceIds" ? devicePicker : groupPicker}
              disabled={disabled}
              onChange={(values) =>
                onChange(
                  scopes.map((current, position) =>
                    position === index
                      ? create(DeviceScopeSchema, { ...current, [field]: values })
                      : current,
                  ),
                )
              }
            />
          ))}
          <Button
            className="w-fit"
            type="button"
            variant="outline"
            onClick={() => onChange(scopes.filter((_, position) => position !== index))}
          >
            Remove rule
          </Button>
        </div>
      ))}
      <Button
        className="w-fit"
        type="button"
        variant="outline"
        onClick={() => onChange([...scopes, create(DeviceScopeSchema)])}
      >
        Add rule
      </Button>
    </fieldset>
  );
}

export function normalizedScopes(scopes: DeviceScope[]): DeviceScope[] {
  return scopes.map((scope) =>
    create(DeviceScopeSchema, {
      labels: scope.labels.filter((value) => value !== ""),
      deviceIds: scope.deviceIds.filter((value) => value !== ""),
      groupIds: scope.groupIds.filter((value) => value !== ""),
    }),
  );
}
