// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"context"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	"lindm/internal/config"
)

// ConfigurePool changes only the disposable server's explicit connection budget.
func (f *AuthorityFixture) ConfigurePool(ctx context.Context, connections uint32) error {
	document, err := config.Load(f.configPath())
	if err != nil {
		return err
	}
	document.Proto.Database.MaxConnections = connections
	validator, err := protovalidate.New()
	if err != nil {
		return err
	}
	if err := validator.Validate(document.Proto); err != nil {
		return err
	}
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		return err
	}
	if err := f.writeConfig(encoded); err != nil {
		return err
	}
	return f.Restart(ctx)
}
