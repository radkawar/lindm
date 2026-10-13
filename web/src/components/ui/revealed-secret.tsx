import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";

// A revealed secret value with a visible auto-hide countdown, Copy (raw value),
// Hide now and the audited reason it was revealed for. While it shows, the
// caller renders nothing else: the request form returns after it hides. The
// caller hides the value when `hidesAt` passes; this only shows the time left.
export function RevealedSecret({
  label,
  display,
  raw,
  hidesAt,
  reason,
  note,
  onHide,
  copiedMessage,
}: {
  label: string;
  display: string;
  raw: string;
  hidesAt: number;
  reason: string;
  note?: string;
  onHide: () => void;
  copiedMessage: string;
}) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, []);
  const seconds = Math.max(0, Math.ceil((hidesAt - now) / 1000));
  return (
    <div className="grid gap-2" data-revealed-secret>
      <p
        className="whitespace-pre-wrap break-words rounded-md border p-3 font-mono text-base tracking-wide"
        aria-label={label}
      >
        {display}
      </p>
      <p className="text-sm text-muted-foreground" data-reveal-countdown>
        Hides in {seconds} s or when you leave the page.{note ? ` ${note}` : ""}
      </p>
      <p className="text-sm" data-reveal-reason>
        <span className="text-muted-foreground">Reason recorded: </span>
        {reason}
      </p>
      <div className="flex flex-wrap gap-2">
        <Button
          variant="outline"
          onClick={() => {
            navigator.clipboard.writeText(raw).then(
              () => toast.success(copiedMessage),
              () => toast.error("Could not copy the value. Select the value. Copy it manually."),
            );
          }}
        >
          Copy
        </Button>
        <Button variant="outline" onClick={onHide}>
          Hide now
        </Button>
      </div>
    </div>
  );
}
