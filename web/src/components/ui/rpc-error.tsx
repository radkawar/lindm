import type { ReactNode } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { classifyRpcFailure, type RpcFailure } from "@/lib/errors";
import { RAW_VALIDATION_TEXT } from "@/lib/validation";

export function RpcError({
  failure,
  title,
  children,
}: {
  failure: RpcFailure;
  title?: string;
  children?: ReactNode;
}) {
  const presentation = classifyRpcFailure(failure);
  return (
    <Alert
      variant={presentation.tone === "destructive" ? "destructive" : "default"}
      className={presentation.tone === "warning" ? "border-warning/25 bg-warning/10" : undefined}
    >
      <AlertTitle>
        {presentation.tone === "destructive" && title ? title : presentation.title}
      </AlertTitle>
      <AlertDescription>
        <p>
          {RAW_VALIDATION_TEXT.test(presentation.message)
            ? "Some values aren't valid. Check the form."
            : presentation.message}
        </p>
        <p>{presentation.action}</p>
        <details data-slot="support-details" className="mt-2">
          <summary className="cursor-pointer">Details for support</summary>
          <dl className="mt-2 grid gap-1 break-words text-xs">
            <div>
              <dt className="inline font-medium">Code: </dt>
              <dd className="inline">{failure.codeName}</dd>
            </div>
            {failure.reason ? (
              <div>
                <dt className="inline font-medium">Reason: </dt>
                <dd className="inline">{failure.reason}</dd>
              </div>
            ) : null}
            <div>
              <dt className="inline font-medium">Message: </dt>
              <dd className="inline whitespace-pre-wrap">{failure.message}</dd>
            </div>
          </dl>
        </details>
        {children}
      </AlertDescription>
    </Alert>
  );
}
