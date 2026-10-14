// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/rpcreason"
)

func TestIntegrationHandlersUnconfigured(t *testing.T) {
	plane := &controlPlane{}
	deliveryPath, deliveryHandler, reportPath, reportHandler := plane.integrationHandlers()
	mux := http.NewServeMux()
	mux.Handle(deliveryPath, deliveryHandler)
	mux.Handle(reportPath, reportHandler)
	// Reproduce the console fallback: an unmapped POST must fail instead of
	// accidentally satisfying the regression with another RPC handler.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte("console"))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	services := []protoreflect.ServiceDescriptor{
		integrationsv1.File_lindm_integrations_v1_delivery_proto.Services().ByName("IntegrationService"),
		integrationsv1.File_lindm_integrations_v1_reports_proto.Services().ByName("ReportService"),
	}
	for _, service := range services {
		if service == nil {
			t.Fatal("missing generated integration service descriptor")
		}
		methods := service.Methods()
		if methods.Len() == 0 {
			t.Fatalf("service %s has no methods", service.FullName())
		}
		for i := range methods.Len() {
			method := methods.Get(i)
			procedure := "/" + string(service.FullName()) + "/" + string(method.Name())
			t.Run(procedure, func(t *testing.T) {
				if method.IsStreamingClient() || method.IsStreamingServer() {
					t.Fatal("optional integration refusal needs coverage for the new streaming method")
				}
				for _, protocol := range []struct {
					name    string
					options []connect.ClientOption
				}{
					{name: "protobuf"},
					{name: "json", options: []connect.ClientOption{connect.WithProtoJSON()}},
				} {
					t.Run(protocol.name, func(t *testing.T) {
						options := append([]connect.ClientOption{connect.WithSchema(method)}, protocol.options...)
						client := connect.NewClient[dynamicpb.Message, dynamicpb.Message](server.Client(), server.URL+procedure, options...)
						_, err := client.CallUnary(t.Context(), connect.NewRequest(dynamicpb.NewMessage(method.Input())))
						if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
							t.Fatalf("%s: code = %v, want %v (error: %v)", procedure, got, connect.CodeFailedPrecondition, err)
						}
						if got := rpcreason.Get(err); got != "integrations_unconfigured" {
							t.Fatalf("%s: reason = %q, want integrations_unconfigured (error: %v)", procedure, got, err)
						}
					})
				}
			})
		}
	}
}
