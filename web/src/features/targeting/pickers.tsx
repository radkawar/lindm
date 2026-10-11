import { createContext, useContext, type ReactNode } from "react";
import type { TargetPickers } from "./fields";

const Context = createContext<TargetPickers | null>(null);
export function TargetPickerProvider({
  pickers,
  children,
}: {
  pickers: TargetPickers;
  children: ReactNode;
}) {
  return <Context value={pickers}>{children}</Context>;
}
export function useTargetPickers() {
  const pickers = useContext(Context);
  if (!pickers) throw new Error("Targeting pickers must be composed by the route.");
  return pickers;
}
