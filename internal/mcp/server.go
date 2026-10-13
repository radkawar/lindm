package mcp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"lindm/internal/identity"
)

// Auditor is the identity audit boundary; audit failure prevents API admission
// and prevents returned evidence from being exposed.
type Auditor interface {
	AuditMCP(context.Context, string, string) error
	AuditMCPResult(context.Context, string, string, string) error
}

// New creates the stateless transport. The composition root MUST additionally
// wrap it in identity.RequireMCP so purpose-bound credentials and browser CSRF
// are checked before transport admission. Principal absence is denied here too.
func New(admin http.Handler, audit Auditor) (http.Handler, error) {
	if admin == nil || audit == nil {
		return nil, errors.New("mcp: admin handler and auditor required")
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "lindm", Version: "1"}, &mcp.ServerOptions{Instructions: untrustedWarning})
	addTools(server, admin)
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
			tool := ""
			if call, ok := request.GetParams().(*mcp.CallToolParamsRaw); ok {
				tool = boundedAuditName(call.Name)
				if strings.Contains(tool, "/") {
					tool = "unknown"
				}
			}
			methodTag := boundedAuditName(method)
			if err := audit.AuditMCP(ctx, methodTag, tool); err != nil {
				return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "Audit unavailable. Request refused."}
			}
			result, err := next(ctx, method, request)
			outcome := "success"
			if err != nil {
				outcome = "failed"
			} else if call, ok := result.(*mcp.CallToolResult); ok && call.IsError {
				outcome = "denied"
			}
			if auditErr := audit.AuditMCPResult(ctx, methodTag, tool, outcome); auditErr != nil {
				return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "Audit unavailable. Outcome unconfirmed; retain any proposal requestId."}
			}
			return result, err
		}
	})
	transport := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	limits := &principalLimits{clock: time.Now, entries: make(map[uuid.UUID]principalWindow)}
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		principal, ok := identity.PrincipalFromContext(request.Context())
		if !ok || principal.ID == uuid.Nil {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		if err := audit.AuditMCP(request.Context(), "http", ""); err != nil {
			http.Error(w, "Audit unavailable", http.StatusServiceUnavailable)
			return
		}
		response := &boundedResponse{header: make(http.Header), limit: 2*maxResultBytes + maxRequestBytes}
		if !limits.allow(principal.ID) {
			response.Header().Set("Retry-After", "60")
			http.Error(response, "Request limit reached", http.StatusTooManyRequests)
		} else {
			ctx, cancel := context.WithTimeout(request.Context(), 25*time.Second)
			defer cancel()
			request = request.WithContext(ctx)
			request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
			transport.ServeHTTP(response, request)
		}
		outcome := "success"
		if response.status >= http.StatusBadRequest {
			outcome = "denied"
		}
		if response.overflow {
			outcome = "failed"
		}
		if err := audit.AuditMCPResult(request.Context(), "http", "", outcome); err != nil {
			http.Error(w, "Audit unavailable. Outcome unconfirmed; retain any proposal requestId.", http.StatusServiceUnavailable)
			return
		}
		if response.overflow {
			http.Error(w, "Result too large. Narrow the query.", http.StatusRequestEntityTooLarge)
			return
		}
		for name, values := range response.header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		status := response.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		if _, err := w.Write(response.body.Bytes()); err != nil {
			slog.Warn("write MCP response", "error", err)
		}
	}), nil
}

func boundedAuditName(value string) string {
	if value == "" {
		return ""
	}
	if len(value) > 64 {
		return "unknown"
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && !strings.ContainsRune("_./-", char) {
			return "unknown"
		}
	}
	return value
}

type principalWindow struct {
	start time.Time
	calls int
}
type principalLimits struct {
	mu      sync.Mutex
	clock   func() time.Time
	entries map[uuid.UUID]principalWindow
}

func (l *principalLimits) allow(principal uuid.UUID) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	window, exists := l.entries[principal]
	if !exists || now.Sub(window.start) >= time.Minute {
		if !exists && len(l.entries) >= 4096 {
			for id, entry := range l.entries {
				if now.Sub(entry.start) >= time.Minute {
					delete(l.entries, id)
				}
			}
			if len(l.entries) >= 4096 {
				return false
			}
		}
		window = principalWindow{start: now}
	}
	window.calls++
	l.entries[principal] = window
	return window.calls <= 60
}
