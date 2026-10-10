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

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
)

const usage = "usage: lindmctl {login|logout|whoami|devices list|get|device revoke|enrollment grant create|revoke|profiles list|get|publish|assignments set|clear|get|audit list} [flags]"

// Run executes one command. Secret-issuing operations write their response only
// once to stdout and are never retried. Browser invocation is injected by main.
func Run(ctx context.Context, args []string, stdout io.Writer, openBrowser func(context.Context, string) error) (resultErr error) {
	if stdout == nil {
		return errors.New("stdout is required")
	}
	if len(args) == 0 {
		return errors.New(usage)
	}
	command, args := args[0], args[1:]
	switch command {
	case "enrollment":
		if len(args) < 2 || args[0] != "grant" {
			return errors.New(usage)
		}
		command += " grant " + args[1]
		args = args[2:]
	case "devices", "device", "profiles", "assignments", "audit":
		if len(args) == 0 {
			return errors.New(usage)
		}
		command += " " + args[0]
		args = args[1:]
	}
	flags := flag.NewFlagSet("lindmctl", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // Flag errors may contain user-supplied secrets.
	configPath := flags.String("config", "", "protected configuration path (default XDG)")
	output := flags.String("o", "table", "output: table or json")
	var server, ca, device, grant, profile, revision, expected, reason, file, pageToken, requestID string
	var pageSize, lifetime, interval uint
	mutation := false
	switch command {
	case "login":
		flags.StringVar(&server, "server", "", "HTTPS origin (first use)")
		flags.StringVar(&ca, "ca", "", "PEM CA file (first use)")
	case "logout", "whoami":
	case "devices list", "profiles list", "audit list":
		flags.UintVar(&pageSize, "page-size", 50, "page size")
		flags.StringVar(&pageToken, "page-token", "", "continuation token")
	case "devices get", "device revoke", "assignments get", "assignments set", "assignments clear":
		flags.StringVar(&device, "device-id", "", "device UUID")
		mutation = command == "device revoke" || command == "assignments set" || command == "assignments clear"
		if command == "assignments set" || command == "assignments clear" {
			flags.StringVar(&expected, "expected-assignment-id", "", "current assignment UUID; omit only for first assignment")
		}
		if command == "assignments set" {
			flags.StringVar(&profile, "profile-id", "", "profile UUID")
			flags.StringVar(&revision, "revision-id", "", "exact retained revision UUID")
			flags.UintVar(&interval, "interval-seconds", 900, "reconciliation interval")
		}
	case "enrollment grant create":
		mutation = true
		flags.UintVar(&lifetime, "lifetime-seconds", 600, "grant lifetime")
	case "enrollment grant revoke":
		mutation = true
		flags.StringVar(&grant, "grant-id", "", "grant UUID")
	case "profiles get", "profiles publish":
		flags.StringVar(&profile, "profile-id", "", "profile UUID")
		if command == "profiles get" {
			flags.StringVar(&revision, "revision-id", "", "retained revision UUID; omit for catalog head")
		} else {
			mutation = true
			flags.StringVar(&expected, "expected-revision-id", "", "current head UUID; omit for new profile")
			flags.StringVar(&file, "file", "", "strict ResourceProfile protobuf JSON file")
		}
	default:
		return errors.New(usage)
	}
	if mutation {
		flags.StringVar(&reason, "reason", "", "audit reason")
		flags.StringVar(&requestID, "request-id", "", "idempotency UUID; generated if omitted")
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
	if server != "" || ca != "" {
		if server == "" || ca == "" {
			return errors.New("--server and --ca must be supplied together")
		}
		pem, err := readDocument(ca)
		if err != nil {
			return errors.New("read CA file failed")
		}
		cfg = &authv1.CLIConfig{ServerOrigin: server, CaPem: string(pem)}
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
	if mutation && requestID == "" {
		requestID = uuid.NewString()
	}
	// Reject integer representation overflow before applying protobuf rules.
	uint32Value := func(value uint) (uint32, error) {
		if uint64(value) > uint64(^uint32(0)) {
			return 0, errors.New("integer flag cannot be represented by the protocol")
		}
		return uint32(value), nil
	}
	page, err := uint32Value(pageSize)
	if err != nil {
		return err
	}
	life, err := uint32Value(lifetime)
	if err != nil {
		return err
	}
	seconds, err := uint32Value(interval)
	if err != nil {
		return err
	}
	var message proto.Message
	switch command {
	case "whoami":
		message, err = client.Whoami(ctx)
	case "devices list":
		message, err = rpcMessage(ctx, &adminv1.ListDevicesRequest{PageSize: page, PageToken: pageToken}, client.Admin().ListDevices)
	case "devices get":
		message, err = rpcMessage(ctx, &adminv1.GetDeviceRequest{DeviceId: device}, client.Admin().GetDevice)
	case "device revoke":
		message, err = rpcMessage(ctx, &adminv1.RevokeDeviceRequest{RequestId: requestID, DeviceId: device, Reason: reason}, client.Admin().RevokeDevice)
	case "enrollment grant create":
		message, err = rpcMessage(ctx, &adminv1.CreateEnrollmentGrantRequest{RequestId: requestID, LifetimeSeconds: life, Reason: reason}, client.Admin().CreateEnrollmentGrant)
	case "enrollment grant revoke":
		message, err = rpcMessage(ctx, &adminv1.RevokeEnrollmentGrantRequest{RequestId: requestID, GrantId: grant, Reason: reason}, client.Admin().RevokeEnrollmentGrant)
	case "profiles list":
		message, err = rpcMessage(ctx, &adminv1.ListProfilesRequest{PageSize: page, PageToken: pageToken}, client.Admin().ListProfiles)
	case "profiles get":
		message, err = rpcMessage(ctx, &adminv1.GetProfileRevisionRequest{ProfileId: profile, RevisionId: optionalString(revision)}, client.Admin().GetProfileRevision)
	case "profiles publish":
		data, readErr := readDocument(file)
		if readErr != nil {
			return errors.New("read profile file failed")
		}
		spec := &policyv1.ResourceProfile{}
		if err := protojson.Unmarshal(data, spec); err != nil {
			return errors.New("profile file must be strict ResourceProfile protobuf JSON")
		}
		message, err = rpcMessage(ctx, &adminv1.PublishProfileRevisionRequest{RequestId: requestID, ProfileId: profile, ExpectedRevisionId: optionalString(expected), Spec: spec, Reason: reason}, client.Admin().PublishProfileRevision)
	case "assignments set", "assignments clear":
		request := &adminv1.SetResourceAssignmentRequest{RequestId: requestID, DeviceId: device, ExpectedAssignmentId: optionalString(expected), Reason: reason, Clear: command == "assignments clear"}
		if !request.Clear {
			request.Target = &adminv1.ResourceAssignmentTarget{ProfileId: profile, RevisionId: revision}
			request.ReconcileIntervalSeconds = &seconds
		}
		message, err = rpcMessage(ctx, request, client.Admin().SetResourceAssignment)
	case "assignments get":
		message, err = rpcMessage(ctx, &adminv1.GetDeviceResourceStateRequest{DeviceId: device}, client.Admin().GetDeviceResourceState)
	case "audit list":
		message, err = rpcMessage(ctx, &adminv1.ListAuditEventsRequest{PageSize: page, PageToken: pageToken}, client.Admin().ListAuditEvents)
	}
	if err != nil {
		return err
	}
	return printMessage(stdout, message, *output)
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
