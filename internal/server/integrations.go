// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"

	"connectrpc.com/connect"

	"lindm/gen/lindm/integrations/v1/integrationsv1connect"
	"lindm/internal/rpcreason"
)

// Keep optional APIs on their normal Connect routes even before setup. The
// session guard still runs first; authenticated callers get a definite setup
// refusal, never the console's GET-only fallback.
func (p *controlPlane) integrationHandlers() (string, http.Handler, string, http.Handler) {
	if p.deliveries != nil {
		deliveryPath, deliveryHandler := p.deliveries.AdminHandler()
		reportPath, reportHandler := p.reporting.AdminHandler()
		return deliveryPath, deliveryHandler, reportPath, reportHandler
	}
	guard := connect.WithInterceptors(connect.UnaryInterceptorFunc(func(connect.UnaryFunc) connect.UnaryFunc {
		return func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
			return nil, rpcreason.Error(connect.CodeFailedPrecondition, "integrations_unconfigured")
		}
	}))
	deliveryPath, deliveryHandler := integrationsv1connect.NewIntegrationServiceHandler(integrationsv1connect.UnimplementedIntegrationServiceHandler{}, guard)
	reportPath, reportHandler := integrationsv1connect.NewReportServiceHandler(integrationsv1connect.UnimplementedReportServiceHandler{}, guard)
	return deliveryPath, deliveryHandler, reportPath, reportHandler
}
