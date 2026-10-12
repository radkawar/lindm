import { type JsonObject } from "@bufbuild/protobuf";

// EncryptionComplianceDesired: require_luks_root is always true, and
// require_escrow / require_tpm are optional booleans that may only be set to
// true. Each extra check is therefore two choices: not checked, or required.
// The device reports compliance; nothing here encrypts disks or moves keys.
const CHECKS = [
  {
    field: "requireEscrow",
    legend: "Recovery key escrow",
    required: "The device must have escrowed its disk recovery key with lindm.",
  },
  {
    field: "requireTpm",
    legend: "TPM unlock",
    required: "The root disk must be bound to the device's TPM.",
  },
] as const;

export function EncryptionComplianceFields({
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
  return (
    <div className="grid min-w-0 gap-4">
      <p className="text-sm">
        Always checked: the root disk is encrypted with LUKS. Devices that fail a check are reported
        as not compliant.
      </p>
      {CHECKS.map((check) => {
        const required = value[check.field] === true;
        const name = `${id}-${check.field}`;
        return (
          <fieldset
            key={check.field}
            className="grid min-w-0 gap-2"
            data-encryption-check={check.field}
          >
            <legend className="mb-1 text-sm font-medium">{check.legend}</legend>
            {(
              [
                [false, "Don't check", "Compliance doesn't depend on this."],
                [true, "Required", check.required],
              ] as const
            ).map(([choice, label, meaning]) => (
              <label key={label} className="flex items-start gap-2 text-sm">
                <input
                  type="radio"
                  className="mt-1 accent-primary"
                  name={name}
                  checked={required === choice}
                  disabled={disabled}
                  onChange={() => {
                    const next = { ...value };
                    if (choice) next[check.field] = true;
                    else delete next[check.field];
                    onChange(next);
                  }}
                />
                <span className="grid gap-0.5">
                  <span>{label}</span>
                  <span className="text-xs text-muted-foreground">{meaning}</span>
                </span>
              </label>
            ))}
          </fieldset>
        );
      })}
    </div>
  );
}
