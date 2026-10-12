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
          ? "This setting also contains SSH controls that are not supported here. They are kept unchanged."
          : "Anyone who connects sees this text, so keep it public. Replacing a notice a device already has needs an approved assignment. Removing this setting puts the earlier notice back unless someone changed it on the device since."}
      </p>
    </div>
  );
}
