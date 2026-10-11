package devlab

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
)

func (f *AuthorityFixture) transportTrustDirectory() string {
	if f.persistent {
		return f.directory
	}
	return FixturePath(f.repository)
}

func (f *AuthorityFixture) snapshotPersistentTrust(shared string, cfg *configv1.ServerConfig) error {
	for _, name := range []string{"transport-ca.crt", "device-ca.crt", "device-ca.key", "postgres-password"} {
		data, err := readOwned(filepath.Join(shared, name))
		if err != nil {
			return err
		}
		err = writeSplitPrivateFile(filepath.Join(f.directory, name), data)
		clear(data)
		if err != nil {
			return err
		}
	}
	address, err := netip.ParseAddr(cfg.GetDeviceListener().GetAddress())
	if err != nil {
		return err
	}
	// Named demos retain the same leaf through stops; its validity is bounded by
	// the development CA. Do not silently rotate a resumed demo's identity.
	if err := writeFixtureCertificate(shared, f.directory, address, 365*24*time.Hour); err != nil {
		return err
	}
	cfg.Tls.CertificateFile = filepath.Join(f.directory, "split-server.crt")
	cfg.Tls.PrivateKeyFile = filepath.Join(f.directory, "split-server.key")
	cfg.DeviceCa.CertificateFile = filepath.Join(f.directory, "device-ca.crt")
	cfg.DeviceCa.PrivateKeyFile = filepath.Join(f.directory, "device-ca.key")
	cfg.TrustedCaFile = filepath.Join(f.directory, "transport-ca.crt")
	path := filepath.Join(f.directory, "database-url")
	data, err := readOwned(path)
	if err != nil {
		return err
	}
	dsn, err := url.Parse(strings.TrimSpace(string(data)))
	clear(data)
	if err != nil {
		return err
	}
	query := dsn.Query()
	for _, key := range []string{"sslrootcert", "sslcert", "sslkey"} {
		source := query.Get(key)
		if source == "" || source == "system" {
			continue
		}
		data, err := readOwned(source)
		if err != nil {
			return err
		}
		destination := filepath.Join(f.directory, "database-"+key)
		err = writeSplitPrivateFile(destination, data)
		clear(data)
		if err != nil {
			return err
		}
		query.Set(key, destination)
	}
	dsn.RawQuery = query.Encode()
	return os.WriteFile(path, []byte(dsn.String()), 0600)
}

// ConfigureAuthorization applies runtime policy through the ordinary owner
// AdminService session. Configuration stays bootstrap-only and no restart occurs.
func (f *AuthorityFixture) ConfigureAuthorization(ctx context.Context, policy *authv1.AuthorizationPolicy) (result error) {
	if f.closed || f.connected != nil {
		return errors.New("authorization update requires an open controller fixture")
	}
	owner, err := f.OpenOwnerSession(ctx)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, owner.Close(context.WithoutCancel(ctx))) }()
	current, err := owner.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		return err
	}
	if current.Msg.GetAuthorization().GetRuntime() && proto.Equal(current.Msg.GetAuthorization().GetPolicy(), policy) {
		return nil
	}
	_, err = owner.Admin.UpdateAuthorization(ctx, connect.NewRequest(&adminv1.UpdateAuthorizationRequest{
		RequestId: uuid.NewString(), ExpectedRevision: current.Msg.GetAuthorization().GetRevision(),
		Policy: policy, Reason: "Configure laboratory organization access",
	}))
	return err
}
