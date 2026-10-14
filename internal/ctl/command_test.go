// SPDX-License-Identifier: Apache-2.0

package ctl

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	adminv1connect "lindm/gen/lindm/admin/v1/adminv1connect"
)

type commandServer struct {
	adminv1connect.UnimplementedAdminServiceHandler
	token       string
	secret      string
	fail        bool
	calls       atomic.Int32
	grants      chan *adminv1.CreateEnrollmentGrantRequest
	assignments chan *adminv1.SetResourceAssignmentRequest
}

func (s *commandServer) CreateEnrollmentGrant(_ context.Context, req *connect.Request[adminv1.CreateEnrollmentGrantRequest]) (*connect.Response[adminv1.CreateEnrollmentGrantResponse], error) {
	s.calls.Add(1)
	if req.Header().Get("Authorization") != "Bearer "+s.token {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing bearer"))
	}
	if s.fail {
		return nil, connect.NewError(connect.CodeInternal, errors.New(s.secret))
	}
	s.grants <- req.Msg
	return connect.NewResponse(&adminv1.CreateEnrollmentGrantResponse{GrantId: "fdbf4608-fffe-4a6e-9ab3-284e2ac81a94", Secret: s.secret}), nil
}

func (s *commandServer) SetResourceAssignment(_ context.Context, req *connect.Request[adminv1.SetResourceAssignmentRequest]) (*connect.Response[adminv1.SetResourceAssignmentResponse], error) {
	s.calls.Add(1)
	if req.Header().Get("Authorization") != "Bearer "+s.token {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing bearer"))
	}
	s.assignments <- req.Msg
	return connect.NewResponse(&adminv1.SetResourceAssignmentResponse{Assignment: &adminv1.ResourceAssignment{AssignmentId: "132304a5-a9b5-43dd-a81f-1f280b533319"}}), nil
}

func (s *commandServer) ListDevices(_ context.Context, req *connect.Request[adminv1.ListDevicesRequest]) (*connect.Response[adminv1.ListDevicesResponse], error) {
	s.calls.Add(1)
	if req.Header().Get("Authorization") != "Bearer "+s.token {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing bearer"))
	}
	return connect.NewResponse(&adminv1.ListDevicesResponse{Devices: []*adminv1.Device{{Id: "132304a5-a9b5-43dd-a81f-1f280b533319", Hostname: "host\x1b[31m\ninjected"}}, NextPageToken: "next-page"}), nil
}

func setupCommands(t *testing.T, fail bool) (*commandServer, string) {
	t.Helper()
	service := &commandServer{token: testToken(t), secret: "one-time-enrollment-secret", fail: fail, grants: make(chan *adminv1.CreateEnrollmentGrantRequest, 1), assignments: make(chan *adminv1.SetResourceAssignmentRequest, 2)}
	path, handler := adminv1connect.NewAdminServiceHandler(service)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	client, configPath, config := testClient(t, mux)
	config.SessionToken = service.token
	if err := client.store.save(config); err != nil {
		t.Fatal(err)
	}
	return service, configPath
}

func TestEnrollmentSecretPrintedOnceAndNotRetried(t *testing.T) {
	for _, output := range []string{"table", "json"} {
		t.Run(output, func(t *testing.T) {
			service, path := setupCommands(t, false)
			var out bytes.Buffer
			err := Run(context.Background(), []string{"enrollment", "grant", "create", "--config", path, "--reason", "new lab device", "--lifetime-seconds", "120", "-o", output}, &out, nil)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(out.String(), service.secret) != 1 || service.calls.Load() != 1 {
				t.Fatal("secret was not delivered exactly once")
			}
			request := <-service.grants
			if request.GetLifetimeSeconds() != 120 || request.GetReason() != "new lab device" || request.GetRequestId() == "" {
				t.Fatal("grant request lost mutation fields")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), service.secret) {
				t.Fatal("enrollment secret persisted")
			}
		})
	}
	service, path := setupCommands(t, true)
	var out bytes.Buffer
	err := Run(context.Background(), []string{"enrollment", "grant", "create", "--config", path, "--reason", "new lab device"}, &out, nil)
	if err == nil || strings.Contains(err.Error(), service.secret) || out.Len() != 0 || service.calls.Load() != 1 {
		t.Fatalf("unsafe failed secret delivery: err=%v calls=%d", err, service.calls.Load())
	}
}

func TestAssignmentsPreserveOptimisticConcurrencyAndClear(t *testing.T) {
	service, path := setupCommands(t, false)
	device, profile, revision, expected := "132304a5-a9b5-43dd-a81f-1f280b533319", "485fdd7c-c260-44dd-8611-03653d13beec", "1cf23dc9-7c08-4c74-9fc7-6cfec12832dd", "71207bfc-6bb4-4b7b-85f4-18d76e3c6c54"
	for _, command := range []string{"set", "clear"} {
		args := []string{"assignments", command, "--config", path, "--device-id", device, "--expected-assignment-id", expected, "--reason", "operator change"}
		if command == "set" {
			args = append(args, "--profile-id", profile, "--revision-id", revision, "--interval-seconds", "600")
		}
		var out bytes.Buffer
		if err := Run(context.Background(), args, &out, nil); err != nil {
			t.Fatal(err)
		}
		request := <-service.assignments
		if request.GetExpectedAssignmentId() != expected || request.GetDeviceId() != device {
			t.Fatal("assignment lost concurrency fence")
		}
		if command == "clear" {
			if !request.GetClear() || request.GetTarget() != nil {
				t.Fatal("clear did not remove target")
			}
		} else if request.GetClear() || request.GetTarget().GetRevisionId() != revision || request.GetReconcileIntervalSeconds() != 600 {
			t.Fatal("set did not pin exact revision")
		}
	}
}

func TestStrictProfileAndSchemaFailuresStayLocal(t *testing.T) {
	service, path := setupCommands(t, false)
	file := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(file, []byte(`{"name":"test","unknownSecurityField":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	commands := [][]string{
		{"profiles", "publish", "--file", file, "--profile-id", "485fdd7c-c260-44dd-8611-03653d13beec", "--reason", "strict profile"},
		{"devices", "list", "--page-size", "201"},
		{"enrollment", "grant", "create", "--lifetime-seconds", "59", "--reason", "short lifetime"},
		{"assignments", "clear", "--device-id", "invalid", "--reason", "invalid device"},
	}
	for _, args := range commands {
		var out bytes.Buffer
		if err := Run(context.Background(), append(args, "--config", path), &out, nil); err == nil {
			t.Fatalf("invalid command accepted: %s", args[0])
		}
		if out.Len() != 0 {
			t.Fatal("failed command emitted output")
		}
	}
	if service.calls.Load() != 0 {
		t.Fatal("invalid schema reached server")
	}
}

func TestDeviceOutputIsProtobufJSONOrTerminalSafeTable(t *testing.T) {
	_, path := setupCommands(t, false)
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"devices", "list", "--config", path, "-o", "json"}, &out, nil); err != nil {
		t.Fatal(err)
	}
	response := &adminv1.ListDevicesResponse{}
	if err := protojson.Unmarshal(out.Bytes(), response); err != nil {
		t.Fatal(err)
	}
	if response.GetNextPageToken() != "next-page" || len(response.GetDevices()) != 1 {
		t.Fatal("JSON response lost pagination or devices")
	}
	out.Reset()
	if err := Run(context.Background(), []string{"devices", "list", "--config", path}, &out, nil); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(out.String(), '\x1b') || strings.Contains(out.String(), "\ninjected") || !strings.Contains(out.String(), "next-page") {
		t.Fatal("unsafe or incomplete human table")
	}
}
