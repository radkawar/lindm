import { create } from "@bufbuild/protobuf";
import {
  RolloutRingSchema,
  type RolloutRing,
  type TargetRef,
} from "../../../gen/lindm/policy/v1/targeting_pb";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NumberControl, OptionalControls } from "./controls";

export type StagePlan = { mode: "once" | "stages"; rings: RolloutRing[] };

const FINAL = 10000;
const NAME = /^[a-zA-Z0-9_.-]{1,64}$/;

// Guardrails match the seeded demo rollout and declarative apply: pause when
// more than 5% fail, 10% stay unverified or 10% are unreachable.
function stage(name: string, cumulativeBasisPoints: number, manualPromotion: boolean) {
  return create(RolloutRingSchema, {
    name,
    cumulativeBasisPoints,
    minimumCanaries: 1,
    minimumObserved: 1,
    soakSeconds: 3600,
    healthMaxAgeSeconds: 86400,
    failureBasisPoints: 500,
    unknownBasisPoints: 1000,
    unavailableBasisPoints: 1000,
    manualPromotion,
  });
}

export function initialStagePlan(): StagePlan {
  return { mode: "once", rings: [stage("pilot", 1000, true), stage("everyone", FINAL, false)] };
}

// The rings sent to the server: one "everyone" stage, or the edited stages with
// the final one forced to every targeted device. Every cohort is the target.
export function planRings(plan: StagePlan, target?: TargetRef): RolloutRing[] {
  const rings = plan.mode === "once" ? [stage("everyone", FINAL, false)] : plan.rings;
  return rings.map((ring, index) =>
    create(RolloutRingSchema, {
      ...ring,
      cohort: target,
      cumulativeBasisPoints: index === rings.length - 1 ? FINAL : ring.cumulativeBasisPoints,
    }),
  );
}

// The first reason this plan can't be rolled out, in admin words; empty when valid.
export function planProblem(plan: StagePlan): string {
  if (plan.mode === "once") return "";
  const rings = plan.rings;
  if (rings.length < 2) return "Add a stage before the final one, or roll out to everyone at once.";
  const names = new Set<string>();
  for (const [index, ring] of rings.entries()) {
    const label = `Stage ${index + 1}`;
    if (!NAME.test(ring.name))
      return `${label} needs a name of letters, numbers, dots, dashes or underscores.`;
    if (names.has(ring.name)) return `${label} has the same name as an earlier stage.`;
    names.add(ring.name);
    if (index === rings.length - 1) {
      if (ring.cumulativeBasisPoints !== FINAL)
        return "The final stage must cover 100% of targeted devices.";
      continue;
    }
    if (ring.cumulativeBasisPoints <= 0 || ring.cumulativeBasisPoints > FINAL)
      return `${label} must cover more than 0% and at most 100% of targeted devices.`;
    if (index > 0 && ring.cumulativeBasisPoints < rings[index - 1].cumulativeBasisPoints)
      return `${label} can't cover fewer devices than the stage before it.`;
  }
  return "";
}

export function StagesEditor({
  plan,
  onChange,
  disabled,
}: {
  plan: StagePlan;
  onChange: (plan: StagePlan) => void;
  disabled?: boolean;
}) {
  const rings = plan.rings;
  const setRings = (next: RolloutRing[]) =>
    onChange({
      ...plan,
      rings: next.map((ring, index) =>
        index === next.length - 1
          ? create(RolloutRingSchema, { ...ring, cumulativeBasisPoints: FINAL })
          : ring,
      ),
    });
  const problem = planProblem(plan);
  return (
    <fieldset disabled={disabled} className="grid min-w-0 gap-3">
      <legend className="mb-1.5 text-sm font-medium">Stages</legend>
      <div className="flex flex-wrap gap-x-4 gap-y-2">
        <label className="flex items-center gap-2 text-sm">
          <input
            type="radio"
            name="rollout-stages"
            checked={plan.mode === "once"}
            onChange={() => onChange({ ...plan, mode: "once" })}
          />
          Everyone at once
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="radio"
            name="rollout-stages"
            checked={plan.mode === "stages"}
            onChange={() => onChange({ ...plan, mode: "stages" })}
          />
          In stages
        </label>
      </div>
      {plan.mode === "once" ? (
        <p className="text-sm text-muted-foreground">
          Every targeted device gets the change as soon as the rollout starts. It pauses on its own
          if more than 5% fail.
        </p>
      ) : (
        <ol className="grid min-w-0 gap-3">
          {rings.map((ring, index) => {
            const final = index === rings.length - 1;
            const set = (next: Partial<RolloutRing>) =>
              setRings(
                rings.map((item, i) =>
                  i === index ? create(RolloutRingSchema, { ...ring, ...next }) : item,
                ),
              );
            return (
              <li key={index} className="grid min-w-0 gap-3 border p-3" data-stage={index + 1}>
                <div className="grid min-w-0 items-start gap-3 sm:grid-cols-2">
                  <label className="grid gap-1.5 text-sm">
                    {`Stage ${index + 1} name`}
                    <Input
                      required
                      data-freeform="new rollout stage name"
                      maxLength={64}
                      pattern="[a-zA-Z0-9_.\-]+"
                      spellCheck={false}
                      value={ring.name}
                      onChange={(event) => set({ name: event.target.value })}
                    />
                  </label>
                  {final ? (
                    <label className="grid gap-1.5 text-sm">
                      {`Stage ${index + 1} share of devices (%)`}
                      <Input
                        type="number"
                        readOnly
                        value={100}
                        className="bg-muted text-muted-foreground"
                        aria-describedby="final-stage"
                      />
                      <span id="final-stage" className="text-xs text-muted-foreground">
                        The final stage always covers every targeted device, so the rollout
                        finishes.
                      </span>
                    </label>
                  ) : (
                    <NumberControl
                      label={`Stage ${index + 1} share of devices (%)`}
                      percent
                      value={ring.cumulativeBasisPoints}
                      onChange={(cumulativeBasisPoints) => set({ cumulativeBasisPoints })}
                    />
                  )}
                </div>
                {!final ? (
                  <label className="flex items-start gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={ring.manualPromotion}
                      onChange={(event) => set({ manualPromotion: event.target.checked })}
                    />
                    {`Wait for an administrator before ${rings[index + 1].name || "the next stage"}`}
                  </label>
                ) : null}
                <OptionalControls title={`Stage ${index + 1} health checks`}>
                  <p className="text-sm text-muted-foreground">
                    The rollout pauses when more than these shares of its devices fail, stay
                    unverified or are unreachable.
                  </p>
                  <div className="grid gap-3 sm:grid-cols-3">
                    <NumberControl
                      label={`Stage ${index + 1} failed devices allowed (%)`}
                      percent
                      value={ring.failureBasisPoints}
                      onChange={(failureBasisPoints) => set({ failureBasisPoints })}
                    />
                    <NumberControl
                      label={`Stage ${index + 1} unverified devices allowed (%)`}
                      percent
                      value={ring.unknownBasisPoints}
                      onChange={(unknownBasisPoints) => set({ unknownBasisPoints })}
                    />
                    <NumberControl
                      label={`Stage ${index + 1} unreachable devices allowed (%)`}
                      percent
                      value={ring.unavailableBasisPoints}
                      onChange={(unavailableBasisPoints) => set({ unavailableBasisPoints })}
                    />
                  </div>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <NumberControl
                      label={`Stage ${index + 1} minimum devices that report back`}
                      value={ring.minimumObserved}
                      onChange={(minimumObserved) =>
                        set({ minimumObserved, minimumCanaries: minimumObserved })
                      }
                    />
                    <NumberControl
                      label={`Stage ${index + 1} observation period (minutes)`}
                      value={Math.round(ring.soakSeconds / 60)}
                      onChange={(minutes) => set({ soakSeconds: minutes * 60 })}
                    />
                  </div>
                </OptionalControls>
                {rings.length > 2 ? (
                  <Button
                    type="button"
                    variant="outline"
                    className="w-fit"
                    onClick={() => setRings(rings.filter((_, i) => i !== index))}
                  >
                    {`Remove stage ${index + 1}`}
                  </Button>
                ) : null}
              </li>
            );
          })}
        </ol>
      )}
      {plan.mode === "stages" ? (
        <Button
          type="button"
          variant="outline"
          className="w-fit"
          disabled={rings.length >= 16}
          onClick={() => {
            const last = rings.length - 1;
            const before = rings[last - 1]?.cumulativeBasisPoints ?? 0;
            setRings([
              ...rings.slice(0, last),
              stage(`wave-${rings.length}`, Math.min(FINAL, before + 2500), true),
              rings[last],
            ]);
          }}
        >
          Add a stage before the final one
        </Button>
      ) : null}
      {problem ? (
        <p role="alert" className="text-sm text-destructive" data-stage-problem>
          {problem}
        </p>
      ) : null}
    </fieldset>
  );
}
