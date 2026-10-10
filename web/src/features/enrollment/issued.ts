import type { Timestamp } from "@bufbuild/protobuf/wkt";

export type IssuedGrant = {
  requestId: string;
  grantId: string;
  expiresAt: Timestamp | undefined;
  secret: string | null;
  deliveryUnknown: boolean;
  hidden: boolean;
};
