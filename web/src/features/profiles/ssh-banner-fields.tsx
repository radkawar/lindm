import { type JsonObject } from "@bufbuild/protobuf";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

export function SSHBannerFields({
  id,
  value,
  disabled,
  onChange,
}: {
  id: string;
  value: JsonObject;
  disabled: boolean;
  onChange: (value: JsonObject) => void;
}) {
  const unsupported = Object.keys(value).some((key) => key !== "bannerText");
  return (
    <div className="grid min-w-0 gap-1.5">
      <Label htmlFor={id}>Notice before SSH sign-in</Label>
      <Textarea
        id={id}
        data-freeform="SSH banner text"
        value={String(value.bannerText ?? "")}
        disabled={disabled || unsupported}
        rows={6}
        aria-describedby={`${id}-help`}
        onChange={(event) => onChange({ bannerText: event.target.value })}
      />
      <p id={`${id}-help`} className="text-sm text-muted-foreground">
        {unsupported
          ? "This setting includes SSH controls that this editor cannot change. It keeps those controls unchanged."
          : "Anyone who connects sees this text. Keep it public. Replacing an existing notice requires an approved assignment."}
      </p>
      {!unsupported ? (
        <details className="text-xs text-muted-foreground">
          <summary className="cursor-pointer">Details</summary>
          <p className="mt-2">
            Removing this setting restores the earlier notice unless someone changed it on the
            device.
          </p>
        </details>
      ) : null}
    </div>
  );
}
