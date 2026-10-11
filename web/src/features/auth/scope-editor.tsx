import { create } from "@bufbuild/protobuf";
import { DeviceScopeSchema, type DeviceScope } from "../../../gen/lindm/auth/v1/authorization_pb";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";

export function ScopeEditor({
  scopes,
  disabled,
  onChange,
}: {
  scopes: DeviceScope[];
  disabled: boolean;
  onChange: (scopes: DeviceScope[]) => void;
}) {
  return (
    <fieldset className="grid min-w-0 gap-4 border p-4" disabled={disabled}>
      <legend className="px-1 text-sm font-semibold">Device access</legend>
      <p className="max-w-3xl text-sm text-muted-foreground">
        Leave empty to allow all devices. Otherwise the account can manage devices that match any
        rule. Enter one value per line.
      </p>
      {scopes.map((scope, index) => (
        <div className="grid min-w-0 gap-3 border bg-muted/20 p-4" key={index}>
          <h3 className="text-sm font-semibold">Rule {index + 1}</h3>
          {(["labels", "deviceIds", "groupIds"] as const).map((field) => (
            <label key={field} className="grid gap-2 text-sm font-medium">
              {field === "labels"
                ? "Labels (device must have all)"
                : field === "deviceIds"
                  ? "Device IDs"
                  : "Group IDs"}
              <Textarea
                className="font-mono text-xs"
                value={scope[field].join("\n")}
                onChange={(event) => {
                  const values = event.target.value.split("\n");
                  onChange(
                    scopes.map((current, position) =>
                      position === index
                        ? create(DeviceScopeSchema, { ...current, [field]: values })
                        : current,
                    ),
                  );
                }}
              />
            </label>
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
