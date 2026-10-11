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

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
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

// ConfigureAuthorization restarts only lindmd on the same database. Sessions,
// enrollment and device state remain product-owned PostgreSQL data. A no-op
// policy update does not restart the process.
func (f *AuthorityFixture) ConfigureAuthorization(ctx context.Context, policy *authv1.AuthorizationPolicy) error {
	if f.closed || f.connected != nil {
		return errors.New("authorization configuration requires an open controller fixture")
	}
	document, err := config.Load(f.configPath())
	if err != nil {
		return err
	}
	if proto.Equal(document.Proto.GetAuthorization(), policy) {
		return nil
	}
	document.Proto.Authorization = proto.CloneOf(policy)
	resources, err := document.Resolve()
	if err != nil {
		return err
	}
	resources.HTTPClient.CloseIdleConnections()
	data, err := protojson.Marshal(document.Proto)
	if err != nil {
		return err
	}
	if err := f.writeConfig(data); err != nil {
		return err
	}
	return f.Restart(ctx)
}
