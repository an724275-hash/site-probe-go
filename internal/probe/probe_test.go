package probe

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func localChecker(t *testing.T, change func(*Options)) *Checker {
	t.Helper()
	options := DefaultOptions()
	options.AllowHTTP, options.AllowPrivate = true, true
	if change != nil {
		change(&options)
	}
	checker, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return checker
}

func TestHTTPStatuses(t *testing.T) {
	for _, test := range []struct {
		code   int
		status string
	}{{200, "ok"}, {204, "ok"}, {403, "restricted"}, {429, "restricted"}, {500, "http_error"}} {
		t.Run(http.StatusText(test.code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(test.code) }))
			defer server.Close()
			result := localChecker(t, nil).Check(context.Background(), Target{URL: server.URL})
			if result.Status != test.status || result.StatusCode != test.code {
				t.Fatalf("unexpected result: %+v", result)
			}
			if result.Timings.TTFBMS == nil || result.Timings.TotalMS < 0 {
				t.Fatalf("missing timings: %+v", result.Timings)
			}
		})
	}
}

func TestRedirectAndQueryRedaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/end?token=secret", http.StatusFound)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	result := localChecker(t, nil).Check(context.Background(), Target{URL: server.URL + "/start?token=secret"})
	if result.Status != "ok" || len(result.Redirects) != 1 || !strings.HasSuffix(result.FinalURL, "/end") {
		t.Fatalf("unexpected redirect: %+v", result)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "token=") {
		t.Fatal("query leaked into report")
	}
}

func TestRedirectLoop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", 302) }))
	defer server.Close()
	result := localChecker(t, func(o *Options) { o.MaxRedirects = 2 }).Check(context.Background(), Target{URL: server.URL})
	if result.ErrorKind != "redirect" || len(result.Redirects) != 2 {
		t.Fatalf("loop not stopped: %+v", result)
	}
}

func TestPrivateAddressBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("private server was contacted") }))
	defer server.Close()
	result := localChecker(t, func(o *Options) { o.AllowPrivate = false }).Check(context.Background(), Target{URL: server.URL})
	if result.ErrorKind != "private_address" {
		t.Fatalf("private address not blocked: %+v", result)
	}
}

func TestPrivateHTTPSBlocked(t *testing.T) {
	options := DefaultOptions()
	checker, _ := New(options)
	result := checker.Check(context.Background(), Target{URL: "https://127.0.0.1/"})
	if result.ErrorKind != "private_address" {
		t.Fatalf("private HTTPS not blocked: %+v", result)
	}
}

func TestInvalidURLs(t *testing.T) {
	checker, _ := New(DefaultOptions())
	for _, target := range []string{"", "file:///tmp/test", "https://user:secret@example.com", "http://example.com", "https://example.com:bad"} {
		result := checker.Check(context.Background(), Target{URL: target})
		if result.ErrorKind != "invalid_url" || strings.Contains(result.URL, "secret") {
			t.Fatalf("invalid URL accepted: %+v", result)
		}
	}
}

func TestTimeoutAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	checker := localChecker(t, func(o *Options) { o.Timeout = 30 * time.Millisecond })
	result := checker.Check(context.Background(), Target{URL: server.URL})
	if result.ErrorKind != "timeout" {
		t.Fatalf("unexpected timeout: %+v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = checker.Check(ctx, Target{URL: server.URL})
	if result.ErrorKind != "canceled" {
		t.Fatalf("unexpected cancel: %+v", result)
	}
}

func TestTLSValidation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	result := localChecker(t, nil).Check(context.Background(), Target{URL: server.URL})
	if result.ErrorKind != "tls" {
		t.Fatalf("untrusted certificate accepted: %+v", result)
	}
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	result = localChecker(t, func(o *Options) { o.RootCAs = pool }).Check(context.Background(), Target{URL: server.URL})
	if result.Status != "ok" || result.Certificate == nil || result.Timings.TLSMS == nil {
		t.Fatalf("trusted TLS failed: %+v", result)
	}
}

func TestHTTPSDowngradeBlocked(t *testing.T) {
	var contacted atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { contacted.Store(true) }))
	defer destination.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	result := localChecker(t, func(o *Options) { o.RootCAs = pool }).Check(context.Background(), Target{URL: server.URL})
	if result.ErrorKind != "redirect_policy" || contacted.Load() {
		t.Fatalf("HTTPS downgrade was allowed: %+v", result)
	}
}

func TestWorkersAndResultOrder(t *testing.T) {
	var active, maximum atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); count > old && !maximum.CompareAndSwap(old, count); old = maximum.Load() {
		}
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer server.Close()
	targets := []Target{{Name: "one", URL: server.URL}, {Name: "two", URL: server.URL}, {Name: "three", URL: server.URL}, {Name: "four", URL: server.URL}}
	results := localChecker(t, func(o *Options) { o.Workers = 2 }).Run(context.Background(), targets)
	if maximum.Load() > 2 {
		t.Fatalf("worker limit exceeded: %d", maximum.Load())
	}
	for index, result := range results {
		if result.Name != targets[index].Name || result.Status != "ok" {
			t.Fatalf("result order lost: %+v", results)
		}
	}
}

func TestPublicAddressPolicy(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.0.1", "169.254.169.254", "100.64.0.1", "::1", "::ffff:127.0.0.1", "2001:db8::1"} {
		if publicAddress(net.ParseIP(ip)) {
			t.Errorf("reserved address accepted: %s", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if !publicAddress(net.ParseIP(ip)) {
			t.Errorf("public address blocked: %s", ip)
		}
	}
}

func TestOptionValidation(t *testing.T) {
	for _, change := range []func(*Options){func(o *Options) { o.Workers = 0 }, func(o *Options) { o.Workers = 33 }, func(o *Options) { o.Timeout = 0 }, func(o *Options) { o.MaxRedirects = 11 }} {
		options := DefaultOptions()
		change(&options)
		if _, err := New(options); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
}
