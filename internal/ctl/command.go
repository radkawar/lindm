package ctl

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/orgapply"
)

const usage = "usage: lindmctl {login|logout|whoami|apply -f FILE [-dry-run] [-secrets-out NEW_FILE]|devices list|get|device revoke|enrollment grant create|revoke|profiles list|get|publish|assignments set|clear|get|audit list|execution delegation sign|bundle export|verify|development-key} [flags]"

// Run executes one command. Secret-issuing operations are never retried.
// Apply writes secrets only to its exclusive private output file; other issuance
// commands print once to stdout. Browser invocation is injected by main.
func Run(ctx context.Context, args []string, stdout io.Writer, openBrowser func(context.Context, string) error) (resultErr error) {
	if stdout == nil {
		return errors.New("stdout is required")
	}
	if len(args) == 0 {
		return errors.New(usage)
	}
	if args[0] == "execution" {
		return runOwnerDelegation(ctx, args[1:], stdout, time.Now)
	}
	if args[0] == "bundle" {
		// Flag errors are discarded like other commands: paths may be private.
		return runBundle(ctx, args[1:], stdout, io.Discard, time.Now)
	}
	command, args, err := commandName(args)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("lindmctl", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // Flag errors may contain user-supplied secrets.
	configPath := flags.String("config", "", "protected configuration path (default XDG)")
	output := flags.String("o", "table", "output: table or json")
	var values commandFlags
	if err := values.register(flags, command); err != nil {
		return err
	}
	if err := flags.Parse(args); err != nil {
		return errors.New("invalid command flags; use the documented command syntax")
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments; use named flags")
	}
	if *output != "table" && *output != "json" {
		return errors.New("-o must be table or json")
	}
	if *configPath == "" {
		path, err := DefaultConfigPath()
		if err != nil {
			return err
		}
		*configPath = path
	}
	var cfg *authv1.CLIConfig
	if values.server != "" || values.ca != "" {
		if values.server == "" || values.ca == "" {
			return errors.New("--server and --ca must be supplied together")
		}
		pem, err := readDocument(values.ca)
		if err != nil {
			return errors.New("read CA file failed")
		}
		cfg = &authv1.CLIConfig{ServerOrigin: values.server, CaPem: string(pem)}
	}
	client, err := New(*configPath, cfg)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, client.Close()) }()
	if command == "login" {
		return client.Login(ctx, openBrowser)
	}
	if command == "logout" {
		return client.Logout(ctx)
	}
	if command == "apply" {
		return values.applyOrganization(ctx, client.Admin(), stdout, *output, applyEngine{plan: orgapply.Plan, apply: orgapply.Apply})
	}
	if values.mutation && values.requestID == "" {
		values.requestID = uuid.NewString()
	}
	message, err := values.call(ctx, client, command)
	if err != nil {
		return err
	}
	return printMessage(stdout, message, *output)
}

// commandName joins multi-word commands ("devices list", "enrollment grant
// create") and returns the remaining flag arguments.
func commandName(args []string) (string, []string, error) {
	command, args := args[0], args[1:]
	switch command {
	case "enrollment":
		if len(args) < 2 || args[0] != "grant" {
			return "", nil, errors.New(usage)
		}
		command += " grant " + args[1]
		args = args[2:]
	case "devices", "device", "profiles", "assignments", "audit":
		if len(args) == 0 {
			return "", nil, errors.New(usage)
		}
		command += " " + args[0]
		args = args[1:]
	}
	return command, args, nil
}

// commandFlags holds the per-command flag values; mutation marks commands that
// take an audit reason and idempotency request ID.
type commandFlags struct {
	server, ca, device, grant, profile, revision, expected, reason, file, pageToken, requestID string
	pageSize, lifetime, interval                                                               uint
	mutation                                                                                   bool
	secretsOut                                                                                 string
	dryRun                                                                                     bool
}

// register defines exactly the flags command accepts; unknown commands are a
// usage error.
func (f *commandFlags) register(flags *flag.FlagSet, command string) error {
	switch command {
	case "login":
		flags.StringVar(&f.server, "server", "", "HTTPS origin (first use)")
		flags.StringVar(&f.ca, "ca", "", "PEM CA file (first use)")
	case "logout", "whoami":
	case "apply":
		flags.StringVar(&f.file, "f", "", "strict Organization protobuf JSON file")
		flags.BoolVar(&f.dryRun, "dry-run", false, "plan without mutations")
		flags.StringVar(&f.secretsOut, "secrets-out", "", "new mode-0600 file for issued secrets; never stdout")
	case "devices list", "profiles list", "audit list":
		flags.UintVar(&f.pageSize, "page-size", 50, "page size")
		flags.StringVar(&f.pageToken, "page-token", "", "continuation token")
	case "devices get", "device revoke", "assignments get", "assignments set", "assignments clear":
		flags.StringVar(&f.device, "device-id", "", "device UUID")
		f.mutation = command == "device revoke" || command == "assignments set" || command == "assignments clear"
		if command == "assignments set" || command == "assignments clear" {
			flags.StringVar(&f.expected, "expected-assignment-id", "", "current assignment UUID; omit only for first assignment")
		}
		if command == "assignments set" {
			flags.StringVar(&f.profile, "profile-id", "", "profile UUID")
			flags.StringVar(&f.revision, "revision-id", "", "exact retained revision UUID")
			flags.UintVar(&f.interval, "interval-seconds", 900, "reconciliation interval")
		}
	case "enrollment grant create":
		f.mutation = true
		flags.UintVar(&f.lifetime, "lifetime-seconds", 600, "grant lifetime")
	case "enrollment grant revoke":
		f.mutation = true
		flags.StringVar(&f.grant, "grant-id", "", "grant UUID")
	case "profiles get", "profiles publish":
		flags.StringVar(&f.profile, "profile-id", "", "profile UUID")
		if command == "profiles get" {
			flags.StringVar(&f.revision, "revision-id", "", "retained revision UUID; omit for catalog head")
		} else {
			f.mutation = true
			flags.StringVar(&f.expected, "expected-revision-id", "", "current head UUID; omit for new profile")
			flags.StringVar(&f.file, "file", "", "strict ResourceProfile protobuf JSON file")
		}
	default:
		return errors.New(usage)
	}
	if f.mutation {
		flags.StringVar(&f.reason, "reason", "", "audit reason")
		flags.StringVar(&f.requestID, "request-id", "", "idempotency UUID; generated if omitted")
	}
	return nil
}

// call issues the authenticated RPC for command once and returns its response.
func (f *commandFlags) call(ctx context.Context, client *Client, command string) (proto.Message, error) {
	page, err := protocolUint32(f.pageSize)
	if err != nil {
		return nil, err
	}
	life, err := protocolUint32(f.lifetime)
	if err != nil {
		return nil, err
	}
	seconds, err := protocolUint32(f.interval)
	if err != nil {
		return nil, err
	}
	switch command {
	case "whoami":
		return client.Whoami(ctx)
	case "devices list":
		return rpcMessage(ctx, &adminv1.ListDevicesRequest{PageSize: page, PageToken: f.pageToken}, client.Admin().ListDevices)
	case "devices get":
		return rpcMessage(ctx, &adminv1.GetDeviceRequest{DeviceId: f.device}, client.Admin().GetDevice)
	case "device revoke":
		return rpcMessage(ctx, &adminv1.RevokeDeviceRequest{RequestId: f.requestID, DeviceId: f.device, Reason: f.reason}, client.Admin().RevokeDevice)
	case "enrollment grant create":
		return rpcMessage(ctx, &adminv1.CreateEnrollmentGrantRequest{RequestId: f.requestID, LifetimeSeconds: life, Reason: f.reason}, client.Admin().CreateEnrollmentGrant)
	case "enrollment grant revoke":
		return rpcMessage(ctx, &adminv1.RevokeEnrollmentGrantRequest{RequestId: f.requestID, GrantId: f.grant, Reason: f.reason}, client.Admin().RevokeEnrollmentGrant)
	case "profiles list":
		return rpcMessage(ctx, &adminv1.ListProfilesRequest{PageSize: page, PageToken: f.pageToken}, client.Admin().ListProfiles)
	case "profiles get":
		return rpcMessage(ctx, &adminv1.GetProfileRevisionRequest{ProfileId: f.profile, RevisionId: optionalString(f.revision)}, client.Admin().GetProfileRevision)
	case "profiles publish":
		data, readErr := readDocument(f.file)
		if readErr != nil {
			return nil, errors.New("read profile file failed")
		}
		spec := &policyv1.ResourceProfile{}
		if err := protojson.Unmarshal(data, spec); err != nil {
			return nil, errors.New("profile file must be strict ResourceProfile protobuf JSON")
		}
		return rpcMessage(ctx, &adminv1.PublishProfileRevisionRequest{RequestId: f.requestID, ProfileId: f.profile, ExpectedRevisionId: optionalString(f.expected), Spec: spec, Reason: f.reason}, client.Admin().PublishProfileRevision)
	case "assignments set", "assignments clear":
		request := &adminv1.SetResourceAssignmentRequest{RequestId: f.requestID, DeviceId: f.device, ExpectedAssignmentId: optionalString(f.expected), Reason: f.reason, Clear: command == "assignments clear"}
		if !request.Clear {
			request.Target = &adminv1.ResourceAssignmentTarget{ProfileId: f.profile, RevisionId: f.revision}
			request.ReconcileIntervalSeconds = &seconds
		}
		return rpcMessage(ctx, request, client.Admin().SetResourceAssignment)
	case "assignments get":
		return rpcMessage(ctx, &adminv1.GetDeviceResourceStateRequest{DeviceId: f.device}, client.Admin().GetDeviceResourceState)
	case "audit list":
		return rpcMessage(ctx, &adminv1.ListAuditEventsRequest{PageSize: page, PageToken: f.pageToken}, client.Admin().ListAuditEvents)
	}
	return nil, nil
}

// protocolUint32 rejects integer representation overflow before protobuf rules
// apply.
func protocolUint32(value uint) (uint32, error) {
	if uint64(value) > uint64(^uint32(0)) {
		return 0, errors.New("integer flag cannot be represented by the protocol")
	}
	return uint32(value), nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func rpcMessage[Request, Response any](ctx context.Context, request *Request, call func(context.Context, *connect.Request[Request]) (*connect.Response[Response], error)) (proto.Message, error) {
	response, err := call(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	message, ok := any(response.Msg).(proto.Message)
	if !ok {
		return nil, errors.New("RPC response is not a protobuf message")
	}
	return message, nil
}

func printMessage(out io.Writer, message proto.Message, format string) error {
	if format == "json" {
		data, err := (protojson.MarshalOptions{Indent: "  "}).Marshal(message)
		if err != nil {
			return errors.New("encode command response")
		}
		_, err = out.Write(append(data, '\n'))
		return err
	}
	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "FIELD\tVALUE"); err != nil {
		return err
	}
	var printFields func(string, protoreflect.Message) error
	printFields = func(prefix string, m protoreflect.Message) error {
		fields := m.Descriptor().Fields()
		for i := range fields.Len() {
			field := fields.Get(i)
			name := prefix + string(field.Name())
			value := m.Get(field)
			if field.IsList() {
				list := value.List()
				for n := range list.Len() {
					itemName := fmt.Sprintf("%s[%d]", name, n)
					if field.Message() != nil {
						if err := printFields(itemName+".", list.Get(n).Message()); err != nil {
							return err
						}
					} else if _, err := fmt.Fprintf(writer, "%s\t%s\n", itemName, terminalValue(list.Get(n))); err != nil {
						return err
					}
				}
			} else if field.IsMap() {
				data, err := protojson.Marshal(m.Interface())
				if err != nil {
					return errors.New("encode table map")
				}
				if _, err := fmt.Fprintf(writer, "%s\t%s\n", name, strconv.Quote(string(data))); err != nil {
					return err
				}
			} else if field.Message() != nil {
				if m.Has(field) {
					if err := printFields(name+".", value.Message()); err != nil {
						return err
					}
				}
			} else if _, err := fmt.Fprintf(writer, "%s\t%s\n", name, terminalValue(value)); err != nil {
				return err
			}
		}
		return nil
	}
	if err := printFields("", message.ProtoReflect()); err != nil {
		return err
	}
	return writer.Flush()
}

func terminalValue(value protoreflect.Value) string {
	// Quote control characters so a server-controlled hostname cannot inject
	// terminal escapes or additional table rows.
	return strings.TrimSuffix(strings.TrimPrefix(strconv.QuoteToASCII(value.String()), "\""), "\"")
}
