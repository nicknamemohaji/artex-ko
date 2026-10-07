package server

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestGetEgressLogsTailsAndFilters(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "egress-proxy", "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := "{\"event\":\"request\",\"host\":\"one.test\"}\n{\"event\":\"response\",\"host\":\"two.test\"}\n"
	if err := os.WriteFile(filepath.Join(logDir, "egress.jsonl"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{dir: dir}}
	w := httptest.NewRecorder()
	s.getEgressLogs(w, httptest.NewRequest("GET", "/api/egress-logs?q=two&limit=1", nil))
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Items     []map[string]any `json:"items"`
		Available bool             `json:"available"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Available || len(got.Items) != 1 || got.Items[0]["host"] != "two.test" {
		t.Fatalf("unexpected response: %#v", got)
	}
}
