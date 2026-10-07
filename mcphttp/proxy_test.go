package mcphttp

import (
	"net/http"
	"testing"
)

func TestTransportFromEnvUsesExplicitProxy(t *testing.T) {
	t.Setenv("ARTEX_MCP_PROXY", "http://proxy.internal:8080")
	transport, err := transportFromEnv(false)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://mcp.example.test/sse", nil)
	got, err := transport.Proxy(req)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.String() != "http://proxy.internal:8080" {
		t.Fatalf("proxy=%v", got)
	}
}

func TestTransportFromEnvRejectsUnsupportedScheme(t *testing.T) {
	t.Setenv("ARTEX_MCP_PROXY", "socks5://proxy.internal:1080")
	if _, err := transportFromEnv(false); err == nil {
		t.Fatal("expected invalid proxy error")
	}
}
