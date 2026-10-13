package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Target struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url"`
}

type Options struct {
	Timeout      time.Duration
	Workers      int
	MaxRedirects int
	AllowHTTP    bool
	AllowPrivate bool
	RootCAs      *x509.CertPool
}

func DefaultOptions() Options {
	return Options{Timeout: 10 * time.Second, Workers: 4, MaxRedirects: 5}
}

type Timings struct {
	DNSMS   *float64 `json:"dns_ms,omitempty"`
	TCPMS   *float64 `json:"tcp_ms,omitempty"`
	TLSMS   *float64 `json:"tls_ms,omitempty"`
	TTFBMS  *float64 `json:"ttfb_ms,omitempty"`
	TotalMS float64  `json:"total_ms"`
}

type Hop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

type Result struct {
	Name        string     `json:"name,omitempty"`
	URL         string     `json:"url"`
	FinalURL    string     `json:"final_url,omitempty"`
	Status      string     `json:"status"`
	StatusCode  int        `json:"status_code,omitempty"`
	ErrorKind   string     `json:"error_kind,omitempty"`
	Error       string     `json:"error,omitempty"`
	RemoteIP    string     `json:"remote_ip,omitempty"`
	Protocol    string     `json:"protocol,omitempty"`
	Certificate *time.Time `json:"certificate_expires,omitempty"`
	Redirects   []Hop      `json:"redirects,omitempty"`
	Timings     Timings    `json:"timings"`
}

type Checker struct{ options Options }

var errPrivate = errors.New("private or reserved address is blocked")
var errRedirect = errors.New("redirect limit reached")
var errRedirectPolicy = errors.New("redirect policy rejected the destination")

func New(options Options) (*Checker, error) {
	if options.Timeout <= 0 || options.Timeout > 2*time.Minute {
		return nil, errors.New("timeout must be between 0 and 2 minutes")
	}
	if options.Workers < 1 || options.Workers > 32 {
		return nil, errors.New("workers must be between 1 and 32")
	}
	if options.MaxRedirects < 0 || options.MaxRedirects > 10 {
		return nil, errors.New("redirect limit must be between 0 and 10")
	}
	return &Checker{options}, nil
}

func validateURL(raw string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid URL")
	}
	if u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return nil, errors.New("URL must contain a host and no credentials")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return nil, errors.New("HTTPS is required; use -allow-http for HTTP targets")
	}
	return u, nil
}

func redactedURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid URL]"
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}

var reserved = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
}

func publicAddress(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range reserved {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func milliseconds(start time.Time) float64 {
	return float64(time.Since(start)) / float64(time.Millisecond)
}

func errorKind(err error) string {
	var dnsError *net.DNSError
	var certificateError *tls.CertificateVerificationError
	var networkError net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &networkError) && networkError.Timeout():
		return "timeout"
	case errors.Is(err, errPrivate):
		return "private_address"
	case errors.Is(err, errRedirect):
		return "redirect"
	case errors.Is(err, errRedirectPolicy):
		return "redirect_policy"
	case errors.As(err, &certificateError):
		return "tls"
	case errors.As(err, &dnsError):
		return "dns"
	default:
		return "network"
	}
}

func (c *Checker) Check(parent context.Context, target Target) Result {
	start := time.Now()
	result := Result{Name: target.Name, URL: redactedURL(target.URL), Status: "network_error"}
	u, err := validateURL(target.URL, c.options.AllowHTTP)
	if err != nil {
		result.ErrorKind, result.Error = "invalid_url", err.Error()
		return result
	}
	ctx, cancel := context.WithTimeout(parent, c.options.Timeout)
	defer cancel()
	var mu sync.Mutex
	var timings Timings
	var remoteIP string
	var certificate *time.Time
	var tlsStart time.Time
	connectStart := make(map[string]time.Time)
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, address string) { mu.Lock(); connectStart[address] = time.Now(); mu.Unlock() },
		ConnectDone: func(_, address string, err error) {
			mu.Lock()
			defer mu.Unlock()
			if began, ok := connectStart[address]; ok && err == nil {
				value := milliseconds(began)
				timings.TCPMS = &value
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			mu.Lock()
			defer mu.Unlock()
			remoteIP, _, _ = net.SplitHostPort(info.Conn.RemoteAddr().String())
		},
		TLSHandshakeStart: func() { mu.Lock(); tlsStart = time.Now(); mu.Unlock() },
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			mu.Lock()
			defer mu.Unlock()
			value := milliseconds(tlsStart)
			timings.TLSMS = &value
			if err == nil && len(state.PeerCertificates) > 0 {
				expires := state.PeerCertificates[0].NotAfter.UTC()
				certificate = &expires
			}
		},
		GotFirstResponseByte: func() { mu.Lock(); value := milliseconds(start); timings.TTFBMS = &value; mu.Unlock() },
	}
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.options.RootCAs},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			dnsStart := time.Now()
			addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			mu.Lock()
			value := milliseconds(dnsStart)
			timings.DNSMS = &value
			mu.Unlock()
			if err != nil {
				return nil, err
			}
			if len(addresses) == 0 {
				return nil, &net.DNSError{Name: host, Err: "no addresses"}
			}
			for _, address := range addresses {
				if !c.options.AllowPrivate && !publicAddress(address.IP) {
					return nil, errPrivate
				}
			}
			var failures []error
			for _, address := range addresses {
				connection, err := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
				if err == nil {
					return connection, nil
				}
				failures = append(failures, err)
			}
			return nil, errors.Join(failures...)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme == "http" {
			return fmt.Errorf("%w: HTTPS to HTTP downgrade", errRedirectPolicy)
		}
		if _, err := validateURL(req.URL.String(), c.options.AllowHTTP); err != nil {
			return fmt.Errorf("%w: %s", errRedirectPolicy, err)
		}
		if len(via) > c.options.MaxRedirects {
			return errRedirect
		}
		mu.Lock()
		result.Redirects = append(result.Redirects, Hop{redactedURL(via[len(via)-1].URL.String()), req.Response.StatusCode})
		mu.Unlock()
		return nil
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, u.String(), nil)
	if err != nil {
		result.ErrorKind, result.Error = "invalid_url", "could not build HTTP request"
		return result
	}
	req.Header.Set("User-Agent", "SiteProbe/0.1 (+https://github.com/an724275-hash/site-probe-go)")
	response, err := client.Do(req)
	if response != nil {
		response.Body.Close()
		result.StatusCode, result.Protocol = response.StatusCode, response.Proto
		result.FinalURL = redactedURL(response.Request.URL.String())
	}
	mu.Lock()
	result.Timings, result.RemoteIP, result.Certificate = timings, remoteIP, certificate
	mu.Unlock()
	result.Timings.TotalMS = milliseconds(start)
	if err != nil {
		result.ErrorKind = errorKind(err)
		var urlError *url.Error
		if errors.As(err, &urlError) {
			err = urlError.Err
		}
		result.Error = err.Error()
		return result
	}
	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		result.Status = "ok"
	case response.StatusCode == 401 || response.StatusCode == 403 || response.StatusCode == 429:
		result.Status = "restricted"
	default:
		result.Status = "http_error"
	}
	return result
}

func (c *Checker) Run(ctx context.Context, targets []Target) []Result {
	results := make([]Result, len(targets))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for i := 0; i < c.options.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				results[index] = c.Check(ctx, targets[index])
			}
		}()
	}
	for index := range targets {
		jobs <- index
	}
	close(jobs)
	workers.Wait()
	return results
}

func Summary(result Result) string {
	if result.ErrorKind != "" {
		return fmt.Sprintf("%s: %s", result.ErrorKind, strings.ReplaceAll(result.Error, "\n", " "))
	}
	return fmt.Sprintf("HTTP %d", result.StatusCode)
}
