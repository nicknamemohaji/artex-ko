package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	defaultEgressLogLimit = 200
	maxEgressLogLimit     = 500
	maxEgressLogLine      = 256 * 1024
)

type egressLogRow map[string]any

// getEgressLogs exposes the already-redacted sidecar audit file through the
// authenticated API. It deliberately has no raw-file/download mode: one bad or
// unexpectedly huge line must not bypass paging and the response-size cap.
func (s *Server) getEgressLogs(w http.ResponseWriter, r *http.Request) {
	limit := defaultEgressLogLimit
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = min(n, maxEgressLogLimit)
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	dir := filepath.Join(s.m.dir, "egress-proxy", "logs")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusOK, map[string]any{"items": []egressLogRow{}, "available": false})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && (name == "egress.jsonl" || strings.HasPrefix(name, "egress.jsonl.")) {
			names = append(names, name)
		}
	}
	// RotatingFileHandler uses .1 as the newest archive; lexical reverse puts the
	// active file last, which is the chronological order needed before tailing.
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	var rows []egressLogRow
	for _, name := range names {
		file, openErr := os.Open(filepath.Join(dir, name))
		if openErr != nil {
			continue
		}
		scanner := bufio.NewScanner(io.LimitReader(file, 128*1024*1024))
		scanner.Buffer(make([]byte, 64*1024), maxEgressLogLine)
		for scanner.Scan() {
			line := scanner.Bytes()
			if query != "" && !strings.Contains(strings.ToLower(string(line)), query) {
				continue
			}
			var row egressLogRow
			if json.Unmarshal(line, &row) == nil {
				rows = append(rows, row)
				if len(rows) > limit {
					rows = rows[len(rows)-limit:]
				}
			}
		}
		_ = file.Close()
	}
	if rows == nil {
		rows = []egressLogRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows, "available": true})
}
