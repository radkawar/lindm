import { createContext, useContext, type ReactNode } from "react";
import { type PickerSlot } from "@/components/ui/search-picker";

export type ResourcePickers = {
  secret: PickerSlot;
  device: PickerSlot;
  account: PickerSlot;
  secretReference: PickerSlot;
  deviceBinding: PickerSlot;
};

const ProfilePickerContext = createContext<ResourcePickers | null>(null);

export function ProfilePickerProvider({
  pickers,
  children,
}: {
  pickers: ResourcePickers;
  children: ReactNode;
}) {
  return <ProfilePickerContext value={pickers}>{children}</ProfilePickerContext>;
}

export function useProfilePickers(): ResourcePickers {
  const pickers = useContext(ProfilePickerContext);
  if (!pickers) throw new Error("Profile fields require route-composed pickers");
  return pickers;
}
