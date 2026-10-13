package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"-format", "csv", "https://example.com"}, {"-workers", "0", "https://example.com"}, {"-targets", "missing.json"}, {"-targets", "targets.json", "https://example.com"}} {
		var out, err bytes.Buffer
		if code := run(context.Background(), args, &out, &err); code != 2 || err.Len() == 0 {
			t.Fatalf("unexpected usage result: code=%d, error=%s", code, err.String())
		}
	}
}

func TestJSONOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	var out, err bytes.Buffer
	code := run(context.Background(), []string{"-allow-http", "-allow-private", "-format", "json", server.URL}, &out, &err)
	var results []map[string]any
	if code != 0 || json.Unmarshal(out.Bytes(), &results) != nil || len(results) != 1 || results[0]["status"] != "ok" {
		t.Fatalf("invalid JSON report: %s, error=%s", out.String(), err.String())
	}
}

func TestFailedCheckExitCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	var out, err bytes.Buffer
	if code := run(context.Background(), []string{"-allow-http", "-allow-private", server.URL}, &out, &err); code != 1 {
		t.Fatalf("expected failed check code, got %d", code)
	}
}
