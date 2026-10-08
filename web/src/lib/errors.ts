import { Code, ConnectError } from "@connectrpc/connect";

export type RpcFailure = {
  code: Code;
  codeName: string;
  message: string;
  unauthenticated: boolean;
  denied: boolean;
  ambiguous: boolean;
};

const AMBIGUOUS: Record<number, true> = {
  [Code.Canceled]: true,
  [Code.Unknown]: true,
  [Code.DeadlineExceeded]: true,
  [Code.Aborted]: true,
  [Code.Internal]: true,
  [Code.Unavailable]: true,
  [Code.DataLoss]: true,
};

const CODE_NAME: Record<number, string> = {
  [Code.Canceled]: "Canceled",
  [Code.Unknown]: "Unknown",
  [Code.InvalidArgument]: "InvalidArgument",
  [Code.DeadlineExceeded]: "DeadlineExceeded",
  [Code.NotFound]: "NotFound",
  [Code.AlreadyExists]: "AlreadyExists",
  [Code.PermissionDenied]: "PermissionDenied",
  [Code.ResourceExhausted]: "ResourceExhausted",
  [Code.FailedPrecondition]: "FailedPrecondition",
  [Code.Aborted]: "Aborted",
  [Code.OutOfRange]: "OutOfRange",
  [Code.Unimplemented]: "Unimplemented",
  [Code.Internal]: "Internal",
  [Code.Unavailable]: "Unavailable",
  [Code.DataLoss]: "DataLoss",
  [Code.Unauthenticated]: "Unauthenticated",
};

export function toRpcFailure(error: unknown): RpcFailure {
  const connectError = ConnectError.from(error);
  const ambiguous = AMBIGUOUS[connectError.code] === true;
  const raw = connectError.rawMessage.trim();
  let message = raw === "" ? connectError.message.trim() : raw;
  if (message === "") {
    message = ambiguous
      ? "The request ended without a result. Retry the same request ID before starting a new one."
      : "The request was rejected.";
  } else if (message.length > 300) {
    message = `${message.slice(0, 300)}…`;
  }
  return {
    code: connectError.code,
    codeName: CODE_NAME[connectError.code] ?? "Unknown",
    message,
    unauthenticated: connectError.code === Code.Unauthenticated,
    denied: connectError.code === Code.PermissionDenied,
    ambiguous,
  };
}

export function isUnauthenticated(error: unknown): boolean {
  return toRpcFailure(error).unauthenticated;
}
