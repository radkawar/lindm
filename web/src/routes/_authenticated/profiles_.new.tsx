import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { ProfileEditor } from "@/features/profiles/editor";
import {
  replaceReservedCreateProfileId,
  reservedCreateProfileId,
} from "@/features/profiles/attempt";
import { CATALOG_SEMANTICS } from "@/features/profiles/model";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { canPermission } from "@/lib/permissions";
import { ProfilePickerProvider } from "@/features/profiles/field-pickers";
import { DevicePicker, DeviceBindingPicker } from "@/features/devices/picker";
import { AccountPicker } from "@/features/auth/picker";
import { SecretPicker, SecretReferencePicker } from "@/features/secrets/picker";

export const Route = createFileRoute("/_authenticated/profiles_/new")({
  beforeLoad: ({ context }) => {
    if (!canPermission(context.principal, "profiles.manage"))
      throw new Error("Profile publishing is not authorized.");
  },
  component: ProfileCreateRoute,
});

function ProfileCreateRoute() {
  const lifetime = useAuthLifetime();
  const [profileId, setProfileId] = useState(() => reservedCreateProfileId(lifetime));
  return (
    <section className="flex min-w-0 flex-col gap-4">
      <Link
        to="/profiles"
        search={{ pageSize: 50, pageToken: "" }}
        className="w-fit text-sm underline underline-offset-4"
      >
        Back to profiles
      </Link>
      <div>
        <h1 className="text-2xl font-semibold">Create profile</h1>
        <p className="max-w-3xl text-sm text-muted-foreground">{CATALOG_SEMANTICS}</p>
      </div>
      <ProfilePickerProvider
        pickers={{
          device: DevicePicker,
          deviceBinding: DeviceBindingPicker,
          account: AccountPicker,
          secret: SecretPicker,
          secretReference: SecretReferencePicker,
        }}
      >
        <ProfileEditor
          key={profileId}
          mode="create"
          profileId={profileId}
          sourceNote="Add the settings this profile should apply, then publish."
          onPrepareAnother={() => setProfileId(replaceReservedCreateProfileId(lifetime))}
        />
      </ProfilePickerProvider>
    </section>
  );
}
