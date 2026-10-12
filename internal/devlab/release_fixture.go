package devlab

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/gen/lindm/integrations/v1/integrationsv1connect"
	releasemanagementv1 "lindm/gen/lindm/releasemanagement/v1"
	"lindm/gen/lindm/releasemanagement/v1/releasemanagementv1connect"
	updatev1 "lindm/gen/lindm/update/v1"
	"lindm/internal/packaging"
	"lindm/internal/releaseupdate"
	"lindm/internal/trust"
)

// NativeReleasePackages publishes the actual signed update fixture packages
// through lindmd's native repository before its immutable file snapshot opens.
type NativeReleasePackages struct {
	Format packaging.Format
	Paths  []string
	Signer packaging.SigningKey
}

// OpenReleaseAuthorityFixture owns a local-auth control plane, fresh five-role
// TUF repository and replacement signed bootstrap. Shared .cache/dev material
// is only read; no production key generation or bootstrap trust fallback occurs.
// The publisher is a lab release-authority handle, not a server authorization bypass.
func OpenReleaseAuthorityFixture(ctx context.Context, repository, binary string, native *NativeReleasePackages) (*AuthorityFixture, *releaseupdate.Publisher, error) {
	fixture, err := openAuthorityFixtureWithOptions(ctx, repository, binary, authorityReleaseUpdates, LoadAuthorityOptions{nativeReleasePackages: native})
	if err != nil {
		return nil, nil, err
	}
	return fixture, fixture.releasePublisher, nil
}

// PublishRecoveryArtifact makes this exact signed UKI an authenticated offline
// targets-role release. Its length is measured by the publisher, never supplied
// by the action requester or inferred from guest inventory.
func (f *AuthorityFixture) PublishRecoveryArtifact(ctx context.Context, source string, digest []byte) error {
	if f.releasePublisher == nil || len(digest) != 32 {
		return errors.New("recovery artifact requires an isolated release authority and SHA-256")
	}
	return f.releasePublisher.PublishArtifact(ctx, "recovery/"+hex.EncodeToString(digest)+".efi", source)
}

// PublishMeasuredRecoveryArtifact publishes a measured-BLS initramfs and then
// its companion vendor-kernel descriptor under the same offline targets role.
func (f *AuthorityFixture) PublishMeasuredRecoveryArtifact(ctx context.Context, initrd string, digest []byte, kernel string) error {
	if f.releasePublisher == nil || len(digest) != 32 {
		return errors.New("recovery artifact requires an isolated release authority and SHA-256")
	}
	initrdName, err := releaseupdate.RecoveryInitrdTargetPath(digest)
	if err != nil {
		return err
	}
	if err := f.releasePublisher.PublishArtifact(ctx, initrdName, initrd); err != nil {
		return err
	}
	kernelName, err := releaseupdate.RecoveryKernelTargetPath(digest)
	if err != nil {
		return err
	}
	return f.releasePublisher.PublishArtifact(ctx, kernelName, kernel)
}

func (s *OwnerSession) ReleaseManagement() releasemanagementv1connect.ReleaseManagementServiceClient {
	return releasemanagementv1connect.NewReleaseManagementServiceClient(s.client, s.origin, s.consoleOption())
}

// Integrations and Reports reach the optional services with this session's cookie and CSRF token.
func (s *OwnerSession) Integrations() integrationsv1connect.IntegrationServiceClient {
	return integrationsv1connect.NewIntegrationServiceClient(s.client, s.origin, s.consoleOption())
}

func (s *OwnerSession) Reports() integrationsv1connect.ReportServiceClient {
	return integrationsv1connect.NewReportServiceClient(s.client, s.origin, s.consoleOption())
}

func (s *OwnerSession) consoleOption() connect.ClientOption {
	return connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set("Origin", s.origin)
			req.Header().Set("X-CSRF-Token", s.csrf)
			return next(ctx, req)
		}
	}))
}

func closeReleaseSession(owner *OwnerSession) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return owner.Close(ctx)
}

// RegisterRelease records the actual version under test through authenticated,
// freshly authorized audited RPC. Unknown/development stamps are never inferred.
func (f *AuthorityFixture) RegisterRelease(ctx context.Context, version string) (resultErr error) {
	owner, err := f.OpenOwnerSession(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, closeReleaseSession(owner)) }()
	return registerFixtureRelease(ctx, owner.ReleaseManagement(), version)
}

// RegisterRelease also supports explicitly owned shared development sessions.
func (s *OwnerSession) RegisterRelease(ctx context.Context, version string) error {
	return registerFixtureRelease(ctx, s.ReleaseManagement(), version)
}

// ReleaseIdentity reads the actual running server's stamp/protocol. Synthetic
// load clients may model this registered series; it is not native agent evidence.
func (f *AuthorityFixture) ReleaseIdentity(ctx context.Context) (version string, protocol uint32, resultErr error) {
	owner, err := f.OpenOwnerSession(ctx)
	if err != nil {
		return "", 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeReleaseSession(owner)) }()
	response, err := owner.ReleaseManagement().GetCompatibility(ctx, connect.NewRequest(&releasemanagementv1.GetCompatibilityRequest{}))
	if err != nil {
		return "", 0, err
	}
	return response.Msg.GetServerRelease(), response.Msg.GetServerProtocol(), nil
}

func registerFixtureRelease(ctx context.Context, client releasemanagementv1connect.ReleaseManagementServiceClient, version string) error {
	view, err := client.GetCompatibility(ctx, connect.NewRequest(&releasemanagementv1.GetCompatibilityRequest{}))
	if err != nil {
		return err
	}
	if version == "" {
		version = view.Msg.GetServerRelease()
	}
	parsed, err := releaseupdate.ParseVersion(version)
	if err != nil {
		return fmt.Errorf("native fixture requires a real x.y.z linker release stamp (got %q): build with -X lindm/internal/agent/buildinfo.Version=<release>: %w", version, err)
	}
	for _, series := range view.Msg.GetSeries() {
		if uint64(series.GetMajor()) == parsed[0] && uint64(series.GetMinor()) == parsed[1] {
			return nil
		}
	}
	now := time.Now().UTC()
	_, err = client.RegisterReleaseSeries(ctx, connect.NewRequest(&releasemanagementv1.RegisterReleaseSeriesRequest{RequestId: uuid.NewString(), Reason: "Register actual isolated laboratory release under test", Series: &releasemanagementv1.ReleaseSeries{Major: uint32(parsed[0]), Minor: uint32(parsed[1]), ReleasedAt: timestamppb.New(now.Add(-time.Minute)), SupportUntil: timestamppb.New(now.Add(91 * 24 * time.Hour)), MinimumProtocol: view.Msg.GetServerProtocol(), MaximumProtocol: view.Msg.GetServerProtocol()}}))
	return err
}

// SetRollout uses the maintained audited management surface. Preserve the same
// request ID for an ambiguous response; published state is never inferred here.
func (f *AuthorityFixture) SetRollout(ctx context.Context, request *releasemanagementv1.SetRolloutRequest) (channel *updatev1.AgentUpdateChannel, resultErr error) {
	owner, err := f.OpenOwnerSession(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeReleaseSession(owner)) }()
	response, err := owner.ReleaseManagement().SetRollout(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	return response.Msg.GetChannel(), nil
}

// This hook runs before the first lindmd process and before execution authority
// is initialized. Replacing an already pinned live trust domain is not supported.
func (f *AuthorityFixture) configureReleaseRepository(ctx context.Context, cfg *configv1.ServerConfig, material *AgentFixture, native *NativeReleasePackages) error {
	directory := filepath.Join(f.directory, "release-repository")
	custody := filepath.Join(f.directory, "release-custody")
	onlineCustody := filepath.Join(f.directory, "release-online-custody")
	for _, path := range []string{directory, custody} {
		if err := os.Mkdir(path, 0700); err != nil {
			return err
		}
	}
	if err := releaseupdate.GenerateDevelopmentKeys(custody); err != nil {
		return err
	}
	if err := createReleaseOnlineCustody(custody, onlineCustody); err != nil {
		return err
	}
	signers, err := releaseupdate.LoadRoleSigners(custody, true)
	if err != nil {
		return err
	}
	publisher, err := releaseupdate.CreateRepository(ctx, releaseupdate.PublisherConfig{Directory: directory, Signers: signers, Now: time.Now})
	if err != nil {
		return err
	}
	releaseRoot, err := os.ReadFile(filepath.Join(directory, "metadata", "1.root.json"))
	if err != nil {
		return err
	}
	envelope, err := f.releaseBootstrap(ctx, material, releaseRoot)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(f.directory, "bootstrap.dsse.json"), envelope, 0600); err != nil {
		return err
	}
	cfg.ReleaseRepository = &configv1.ReleaseRepositoryConfig{Directory: directory, Signing: &configv1.ReleaseRepositorySigning{Directory: onlineCustody}, VerificationStateDirectory: proto.String(filepath.Join(f.directory, "release-verification"))}
	if native != nil {
		output := filepath.Join(directory, "repo")
		if err := os.Mkdir(output, 0o700); err != nil {
			return err
		}
		// lindmd serves a native repository only under its configured signer
		// pin; without it every /repo/<family> path was 404 (zypper: "Repository
		// type can't be determined").
		pins := &configv1.NativeRepositoriesConfig{}
		switch native.Format {
		case packaging.FormatArch:
			if _, err := packaging.PublishArch(ctx, packaging.ArchRequest{OutputDir: output, Packages: native.Paths, Signer: native.Signer}); err != nil {
				return err
			}
			pins.ArchSigningKeyFingerprint = proto.String(native.Signer.Fingerprint)
		case packaging.FormatRPM:
			if _, err := packaging.PublishRPM(ctx, packaging.RPMRequest{OutputDir: output, RPMs: native.Paths, Signer: native.Signer}); err != nil {
				return err
			}
			pins.RpmSigningKeyFingerprint = proto.String(native.Signer.Fingerprint)
		default:
			return errors.New("native release fixture requires signed pacman or RPM packages")
		}
		cfg.ReleaseRepository.NativeRepositories = pins
	}
	f.releasePublisher = publisher
	return nil
}

// Copy only the generated online roles into the server's private directory.
// Full offline custody stays at release-custody for explicit lab publication and
// adversarial helpers; neither root nor top-level targets is a server dependency.
func createReleaseOnlineCustody(custody, online string) error {
	if err := os.Mkdir(online, 0700); err != nil {
		return err
	}
	for _, name := range []string{"rollout.pem", "snapshot.pem", "timestamp.pem"} {
		key, err := os.ReadFile(filepath.Join(custody, name))
		if err != nil {
			return err
		}
		err = os.WriteFile(filepath.Join(online, name), key, 0600)
		clear(key)
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *AuthorityFixture) releaseBootstrap(ctx context.Context, material *AgentFixture, rootJSON []byte) (envelope []byte, resultErr error) {
	resultErr = locked(ctx, f.repository, func(root string) error {
		directory := filepath.Join(FixturePath(root), "agent-trust")
		authority, err := trust.New()
		if err != nil {
			return err
		}
		if err := verifyDevelopmentTrust(ctx, authority, directory); err != nil {
			return err
		}
		verified, err := authority.VerifyBootstrap(ctx, material.ExecutionRootJSON, material.BootstrapEnvelope, time.Now())
		if err != nil {
			return err
		}
		keys := make([]ed25519.PrivateKey, 0, verified.Root.GetThreshold())
		defer func() {
			for _, key := range keys {
				clear(key)
			}
		}()
		for i := range verified.Root.GetThreshold() {
			encoded, err := os.ReadFile(filepath.Join(directory, fmt.Sprintf("execution-key-%d.pem", i)))
			if err != nil {
				return err
			}
			key, err := developmentPrivateKey(encoded)
			clear(encoded)
			if err != nil {
				return err
			}
			keys = append(keys, key)
		}
		bundle := proto.CloneOf(verified.Bundle)
		bundle.BundleId = uuid.NewString()
		bundle.ReleaseRootJson = rootJSON
		envelope, err = authority.Sign(ctx, bundle, keys...)
		if err != nil {
			return err
		}
		_, err = authority.VerifyBootstrap(ctx, material.ExecutionRootJSON, envelope, time.Now())
		return err
	})
	return envelope, resultErr
}
