-- The rows a single-host (local accounts) deployment last served by the release
-- before c793dfef holds. Its permission vocabulary had remote_assistance.run,
-- which granted both viewing and controlling a device.
-- authorization_policy.definition is that release's deterministic protobuf
-- encoding of expect.json "persisted", written by UpdateAuthorization at
-- revision 3. Two local accounts are assigned custom roles naming run.
UPDATE authorization_policy SET
  digest = decode('9a1f4c2e7b6d5a3c8e0f1b2d4c6a8e0f2b4d6c8a0e1f3b5d7c9a1e3f5b7d9c0a', 'hex'),
  definition = decode(
    '0a2a0a116c65676163792d617373697374616e6365121572656d6f74655f617373697374616e63652e72756e0a3d0a0c' ||
    '6c65676163792d6d69786564120a666c6565742e72656164121572656d6f74655f617373697374616e63652e72756e12' ||
    '0a61756469742e726561640ad4030a116c65676163792d65766572797468696e67120a666c6565742e72656164121165' ||
    '6e726f6c6c6d656e742e6d616e616765120d6465766963652e7265766f6b65120a61756469742e726561641216657865' ||
    '637574696f6e5f74727573742e6d616e616765120f70726f66696c65732e6d616e61676512107265736f75726365732e' ||
    '61737369676e120f6163636f756e74732e6d616e6167651210696e76656e746f72792e6d616e61676512127265636f76' ||
    '6572795f6b6579732e72656164121472656d6f74655f657865637574696f6e2e72756e121572656d6f74655f61737369' ||
    '7374616e63652e72756e120b736372697074732e72756e121364657374727563746976652e6578656375746512106170' ||
    '70726f76616c732e6d616e6167651213696e746567726174696f6e732e6d616e616765121672656c656173655f757064' ||
    '617465732e6d616e616765121a61647669736f72795f657863657074696f6e732e6d616e6167651211656e6372797074' ||
    '696f6e2e6d616e616765120c616374696f6e732e6c6f636b1214616374696f6e732e72656c656173652d6c6f636b1212' ||
    '616374696f6e732e71756172616e74696e65120e736563726574732e6d616e616765120e736563726574732e72657665' ||
    '616c0a1e0a10756e72656c617465642d726561646572120a666c6565742e726561641a0c616374696f6e732e6c6f636b' ||
    '1a0e736563726574732e72657665616c',
    'hex'),
  revision = 3;

INSERT INTO principals (id, issuer, subject, display_name, authorization_role)
SELECT account.id, 'urn:lindm:local:' || deployment.deployment_id, account.id::text, account.username, account.role
FROM deployment_identity deployment,
  (VALUES ('3d0c1f4e-7a2b-4c51-9e8d-1b6f2a7c9e01'::uuid, 'helpdesk-1', 'legacy-assistance'),
          ('3d0c1f4e-7a2b-4c51-9e8d-1b6f2a7c9e02'::uuid, 'operations-1', 'legacy-mixed')) AS account(id, username, role);

INSERT INTO local_accounts (id, username, role, scope_binding) VALUES
  ('3d0c1f4e-7a2b-4c51-9e8d-1b6f2a7c9e01', 'helpdesk-1', 'legacy-assistance', '{"scopes":[{"labels":["department/helpdesk"]}]}'),
  ('3d0c1f4e-7a2b-4c51-9e8d-1b6f2a7c9e02', 'operations-1', 'legacy-mixed', '{}');
