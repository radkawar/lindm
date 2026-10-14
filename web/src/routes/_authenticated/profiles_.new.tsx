// SPDX-License-Identifier: Apache-2.0

import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { ProfileEditor } from "@/features/profiles/editor";
import {
  replaceReservedCreateProfileId,
  reservedCreateProfileId,
} from "@/features/profiles/attempt";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { canPermission } from "@/lib/permissions";
import { ProfilePickerProvider } from "@/features/profiles/field-pickers";
import { DevicePicker, DeviceBindingPicker } from "@/features/devices/picker";
import { AccountPicker } from "@/features/auth/picker";
import { SecretPicker, SecretReferencePicker } from "@/features/secrets/picker";

export const Route = createFileRoute("/_authenticated/profiles_/new")({
  beforeLoad: ({ context }) => {
    if (!canPermission(context.principal, "profiles.manage"))
      throw new Error("You do not have profile-publishing permission.");
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
      <h1 className="text-2xl font-semibold">Create profile</h1>
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
          sourceNote="Add device settings. Publish the profile."
          onPrepareAnother={() => setProfileId(replaceReservedCreateProfileId(lifetime))}
        />
      </ProfilePickerProvider>
    </section>
  );
}
