package releaseupdate

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	updatev1 "lindm/gen/lindm/update/v1"
)

type targetFlags map[string]string

func (t targetFlags) String() string { return "logical-target=local-file" }
func (t targetFlags) Set(value string) error {
	name, file, ok := strings.Cut(value, "=")
	if !ok || !safePath(name) || file == "" {
		return errors.New("target must be logical-target=local-file")
	}
	if _, exists := t[name]; exists {
		return errors.New("duplicate target")
	}
	t[name] = file
	return nil
}
func readCLIFile(filename string, limit int64) (data []byte, err error) {
	root, err := os.OpenRoot(filepath.Dir(filename))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	return readBounded(root, filepath.Base(filename), limit)
}

// RunCLI is the focused publisher command surface. Product composition owns
// top-level dispatch. All keys and inputs are explicit; no ambient key fallback.
func RunCLI(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("release repository command required: development-keys, init, publish, publish-artifact, promote, rollout, rotate, mirror")
	}
	flags := flag.NewFlagSet("release repository "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("repository", "", "published repository directory")
	keyDir := flags.String("keys", "", "explicit private role key directory (outside repository)")
	nextKeys := flags.String("new-keys", "", "new root and online role key directory")
	channelPath := flags.String("channel", "", "strict protobuf JSON AgentUpdateChannel")
	ring := flags.String("ring", "", "channel ring")
	paused := flags.Bool("paused", false, "pause channel")
	percentage := flags.Uint("percentage", 100, "deterministic eligible percentage")
	expected := flags.Uint64("expected-generation", 0, "required predecessor generation for audited rollout")
	requestID := flags.String("request-id", "", "durable rollout intent identity")
	source := flags.String("source", "", "air-gap source repository directory")
	bootstrap := flags.String("root", "", "authenticated bootstrap root JSON file")
	files := targetFlags{}
	flags.Var(files, "target", "logical-target=local-file (repeatable)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if args[0] == "development-keys" {
		return writeDevelopmentKeys(*keyDir, stdout)
	}
	if *directory == "" {
		return errors.New("-repository required")
	}
	absolute, err := filepath.Abs(*directory)
	if err != nil {
		return err
	}
	if args[0] == "mirror" {
		if *source == "" || *bootstrap == "" {
			return errors.New("mirror requires -source and authenticated -root")
		}
		root, err := readCLIFile(*bootstrap, MaxMetadataBytes)
		if err != nil {
			return err
		}
		return Mirror(ctx, MirrorConfig{Directory: absolute, BootstrapRoot: root, Fetch: DirectoryFetch(*source), OpenTarget: directoryOpenTarget(*source)})
	}
	if *keyDir == "" {
		return errors.New("explicit -keys required")
	}
	keysAbsolute, err := custodyOutside(absolute, *keyDir, "private key custody cannot be within published repository")
	if err != nil {
		return err
	}
	var signers RoleSigners
	if args[0] == "rollout" || args[0] == "promote" {
		signers, err = LoadOnlineSigners(keysAbsolute)
	} else {
		signers, err = LoadRoleSigners(keysAbsolute, args[0] == "init" || args[0] == "rotate")
	}
	if err != nil {
		return err
	}
	cfg := PublisherConfig{Directory: absolute, Signers: signers}
	if args[0] == "init" {
		_, err = CreateRepository(ctx, cfg)
		return err
	}
	publisher, err := NewPublisher(cfg)
	if err != nil {
		return err
	}
	switch args[0] {
	case "publish-artifact":
		if len(files) != 1 {
			return errors.New("publish-artifact requires exactly one -target logical-target=local-file")
		}
		for name, source := range files {
			return publisher.PublishArtifact(ctx, name, source)
		}
		return errors.New("publish-artifact requires a target")
	case "publish", "promote":
		return publishChannel(ctx, publisher, args[0] == "promote", *channelPath, files)
	case "rollout":
		if *percentage > 100 {
			return errors.New("percentage must be 0 through 100")
		}
		channel, err := publisher.SetRolloutRequest(ctx, *ring, *paused, uint32(*percentage), *expected, *requestID)
		if err != nil {
			return err
		}
		data, err := protojson.Marshal(channel)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, string(data))
		return err
	case "rotate":
		if *nextKeys == "" {
			return errors.New("rotate requires -new-keys")
		}
		nextAbsolute, err := custodyOutside(absolute, *nextKeys, "new private custody cannot be within published repository")
		if err != nil {
			return err
		}
		next, err := LoadRoleSigners(nextAbsolute, true)
		if err != nil {
			return err
		}
		return publisher.RotateRoot(ctx, next)
	default:
		return errors.New("unknown release repository command")
	}
}

// writeDevelopmentKeys generates development-only role keys in keyDir and says
// so on stdout.
func writeDevelopmentKeys(keyDir string, stdout io.Writer) error {
	if keyDir == "" {
		return errors.New("-keys required")
	}
	absolute, err := filepath.Abs(keyDir)
	if err != nil {
		return err
	}
	if err = GenerateDevelopmentKeys(absolute); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "DEVELOPMENT ONLY: generated five independent local role keys; not production custody")
	return err
}

// custodyOutside resolves the private key directory and rejects one at or within
// the published repository, reporting violation.
func custodyOutside(repository, keyDir, violation string) (string, error) {
	keysAbsolute, err := filepath.Abs(keyDir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(repository, keysAbsolute)
	if err != nil {
		return "", err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return "", errors.New(violation)
	}
	return keysAbsolute, nil
}

// directoryOpenTarget opens mirrored target files from the air-gap source
// directory, never following a path outside it.
func directoryOpenTarget(source string) OpenTargetFunc {
	return func(ctx context.Context, name string) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sourceRoot, err := os.OpenRoot(source)
		if err != nil {
			return nil, err
		}
		file, openErr := openRegular(sourceRoot, name)
		closeErr := sourceRoot.Close()
		if openErr != nil || closeErr != nil {
			if file != nil {
				return nil, errors.Join(openErr, closeErr, file.Close())
			}
			return nil, errors.Join(openErr, closeErr)
		}
		return file, nil
	}
}

// publishChannel publishes the strict protobuf JSON channel with new targets,
// or promotes it using only already published targets.
func publishChannel(ctx context.Context, publisher *Publisher, promote bool, channelPath string, files targetFlags) error {
	if channelPath == "" {
		return errors.New("publish requires -channel")
	}
	data, err := readCLIFile(channelPath, MaxCatalogBytes)
	if err != nil {
		return err
	}
	channel := new(updatev1.AgentUpdateChannel)
	if err = protojson.Unmarshal(data, channel); err != nil {
		return err
	}
	if promote {
		if len(files) != 0 {
			return errors.New("promote cannot accept new package targets")
		}
		return publisher.Promote(ctx, channel)
	}
	return publisher.Publish(ctx, channel, files)
}
