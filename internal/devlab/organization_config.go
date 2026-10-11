package devlab

import (
	"context"
	"errors"
	"os"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/config"
)

// ConfigureOrganizationAuthorization changes only this controller-owned local
// fixture's server configuration and restarts lindmd. It is not a product API
// mutation and cannot configure an external/connected server.
func (f *AuthorityFixture) ConfigureOrganizationAuthorization(ctx context.Context, policy *authv1.AuthorizationPolicy) error {
	if f == nil || f.closed || f.local == nil || f.database == nil || f.directory == "" || f.binary == "" || f.process == nil || f.ha != nil {
		return errors.New("organization authorization requires a running controller-owned local fixture")
	}
	if policy == nil {
		return errors.New("organization authorization policy is required")
	}
	if err := protovalidate.Validate(policy); err != nil {
		return err
	}
	document, err := config.Load(f.configPath())
	if err != nil {
		return err
	}
	document.Proto.Authorization = proto.CloneOf(policy)
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		return err
	}
	if err := os.WriteFile(f.configPath(), encoded, 0600); err != nil {
		return err
	}
	return f.Restart(ctx)
}
