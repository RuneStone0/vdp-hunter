// Package probe fetches /.well-known/security.txt for a list of domains.
//
// Two design rules, both learned the hard way on the Python crawler:
//
//  1. A transport failure is not evidence of absence. DNS and connect errors are
//     collected and retried at lower concurrency instead of being counted as
//     "no security.txt", which silently undercounts by a third under load.
//  2. Throughput is not the metric. Pushing concurrency until the rate looks
//     good saturates the link, times out handshakes and drops real hits. The
//     prober reports hits per thousand so the operator can see that.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RuneStone0/vdp-hunter/go/internal/sec"
)

// UserAgent identifies the crawler and the project. Registries and CDNs are
// entitled to know who is probing them.
var UserAgent = "vdp-hunter/1.0 (RFC 9116 discovery; +https://github.com/RuneStone0/vdp-hunter)"

const (
	pathWellKnown = "/.well-known/security.txt"
	pathLegacy    = "/security.txt"
	maxBody       = 32 * 1024
)

// Result is one domain's outcome, serialised as JSONL for the merge pipeline.
// Field names match the Python crawler's records so both feed the same dataset.
type Result struct {
	Domain       string   `json:"domain"`
	CheckedAt    string   `json:"checked_at"`
	FoundAt      string   `json:"found_at,omitempty"`
	TLSVerified  *bool    `json:"tls_verified,omitempty"`
	HTTPStatus   int      `json:"http_status,omitempty"`
	Expiry       string   `json:"expiry,omitempty"`
	ExpiresOn    string   `json:"expires_on,omitempty"`
	Policy       string   `json:"policy,omitempty"`
	Emails       []string `json:"emails"`
	ContactURLs  []string `json:"contact_urls"`
	OffersBounty string   `json:"offers_bounty,omitempty"`
	InScope      []string `json:"in_scope_domains,omitempty"`
	Source       string   `json:"source,omitempty"`
	Errors       []string `json:"errors,omitempty"`
}

// Found reports whether the domain served a usable security.txt.
func (r Result) Found() bool { return r.FoundAt != "" }

// TransportError reports whether the failure was at the network layer, which is
// the only kind worth retrying.
func (r Result) TransportError() bool { return len(r.Errors) > 0 && !r.Found() }

// Options tunes a Prober.
type Options struct {
	Workers   int
	Timeout   time.Duration
	Retries   int
	RateLimit int // requests per second across all workers, 0 = unlimited
	Client    *http.Client
	Now       func() time.Time
	Source    string // provenance label written into each result, e.g. "czds"
}

// Prober is safe for concurrent use.
type Prober struct {
	opts  Options
	http  *http.Client
	plain *http.Client // TLS verification off, used only after a verified attempt fails
	lim   *limiter
	reqs  atomic.Int64
}

// New builds a Prober with sane defaults.
func New(opts Options) *Prober {
	if opts.Workers <= 0 {
		opts.Workers = 100
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 12 * time.Second
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Client == nil {
		tr := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   8 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   8 * time.Second,
			ResponseHeaderTimeout: 8 * time.Second,
			MaxIdleConns:          opts.Workers * 4,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       30 * time.Second,
			ForceAttemptHTTP2:     true,
		}
		opts.Client = &http.Client{Transport: tr, Timeout: opts.Timeout}
	}
	plainTr := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 8 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // deliberate: records tls_verified=false
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		MaxIdleConnsPerHost:   2,
	}
	return &Prober{
		opts:  opts,
		http:  opts.Client,
		plain: &http.Client{Transport: plainTr, Timeout: opts.Timeout},
		lim:   newLimiter(opts.RateLimit),
	}
}

// Requests returns how many HTTP requests have been issued, including retries.
func (p *Prober) Requests() int64 { return p.reqs.Load() }

// Probe checks one domain: verified TLS first, then the legacy path on 404, then
// an unverified TLS attempt, then plain http as a last resort.
func (p *Prober) Probe(ctx context.Context, domain string) Result {
	res := Result{
		Domain:      domain,
		Source:      p.opts.Source,
		CheckedAt:   p.opts.Now().UTC().Format(time.RFC3339),
		Emails:      []string{},
		ContactURLs: []string{},
	}
	attempts := 1 + p.opts.Retries
	for i := 0; i < attempts; i++ {
		if i > 0 {
			// jittered backoff: retries are for transient failures, not for
			// hammering a host that is down
			time.Sleep(time.Duration(150+rand.Intn(400)) * time.Millisecond)
		}
		if r, ok := p.try(ctx, &res, "https://"+domain+pathWellKnown, "verified"); ok {
			return r
		}
		if res.HTTPStatus == http.StatusNotFound {
			if r, ok := p.try(ctx, &res, "https://"+domain+pathLegacy, "verified"); ok {
				return r
			}
		}
		if res.TransportOK() {
			break // the host answered, retrying will not change the answer
		}
	}
	if !res.TransportOK() {
		if r, ok := p.try(ctx, &res, "https://"+domain+pathWellKnown, "unverified"); ok {
			return r
		}
		if r, ok := p.try(ctx, &res, "http://"+domain+pathWellKnown, "plain"); ok {
			return r
		}
	}
	return res
}

// TransportOK reports whether any attempt reached the host over TLS or HTTP.
func (r *Result) TransportOK() bool { return r.HTTPStatus != 0 }

func (p *Prober) try(ctx context.Context, res *Result, raw, mode string) (Result, bool) {
	if p.lim != nil {
		if err := p.lim.wait(ctx); err != nil {
			res.Errors = append(res.Errors, "limiter:"+err.Error())
			return *res, false
		}
	}
	p.reqs.Add(1)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		res.Errors = append(res.Errors, "request:"+err.Error())
		return *res, false
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "text/plain,*/*;q=0.5")

	client := p.http
	if mode != "verified" {
		client = p.plain
	}
	resp, err := client.Do(req)
	if err != nil {
		res.Errors = append(res.Errors, classifyErr(err))
		return *res, false
	}
	defer resp.Body.Close()

	res.HTTPStatus = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		return *res, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		res.Errors = append(res.Errors, "read:"+err.Error())
		return *res, false
	}
	fields := sec.Parse(string(body))
	if len(fields["contact"]) == 0 {
		return *res, false // 200 but not a security.txt
	}

	verified := mode == "verified"
	final := resp.Request.URL.String()
	state, on := sec.ExpiryState(fields, p.opts.Now())
	res.FoundAt = final
	res.TLSVerified = &verified
	res.Expiry = state
	res.ExpiresOn = on
	res.Policy = first(fields["policy"])
	res.Emails = uniq(append(res.Emails, fields.Emails()...))
	res.ContactURLs = uniq(append(res.ContactURLs, fields.URLs()...))
	res.OffersBounty = fields.OffersBounty()
	res.InScope = uniq(fields["scope"])
	res.Errors = nil
	return *res, true
}

func classifyErr(err error) string {
	var (
		dnsErr *net.DNSError
		urlErr *url.Error
	)
	switch {
	case errors.As(err, &dnsErr):
		return "dns:" + dnsErr.Err
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &urlErr) && urlErr.Timeout():
		return "timeout"
	case strings.Contains(err.Error(), "connection refused"):
		return "refused"
	case strings.Contains(err.Error(), "no such host"):
		return "dns"
	case strings.Contains(err.Error(), "certificate"):
		return "tls:certificate"
	case strings.Contains(err.Error(), "EOF"):
		return "eof"
	default:
		return "transport:" + err.Error()
	}
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func uniq(v []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(v))
	for _, s := range v {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// limiter is a token bucket shared by all workers.
type limiter struct {
	mu       sync.Mutex
	perSec   int
	next     time.Time
}

func newLimiter(perSec int) *limiter {
	if perSec <= 0 {
		return nil
	}
	return &limiter{perSec: perSec}
}

func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	gap := time.Second / time.Duration(l.perSec)
	slot := l.next
	l.next = l.next.Add(gap)
	l.mu.Unlock()
	if d := time.Until(slot); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}

// Run probes every domain from in with opts.Workers goroutines, calling emit for
// each result. Transport failures are collected and retried once at a quarter of
// the concurrency before being reported as misses.
func Run(ctx context.Context, p *Prober, in <-chan string, emit func(Result)) (stats Stats, retry []string) {
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		st   Stats
		fail []string
	)
	jobs := in
	for i := 0; i < p.opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				if ctx.Err() != nil {
					return
				}
				res := p.Probe(ctx, domain)
				mu.Lock()
				st.Checked++
				if res.Found() {
					st.Hits++
					if res.Expiry == "valid" {
						st.Valid++
					}
				} else if res.TransportError() {
					st.Transport++
					fail = append(fail, domain)
				}
				mu.Unlock()
				emit(res)
			}
		}()
	}
	wg.Wait()
	return st, fail
}

// Stats counts one pass.
type Stats struct {
	Checked   int64
	Hits      int64
	Valid     int64
	Transport int64
}

// String renders a compact progress line.
func (s Stats) String() string {
	rate := 0.0
	if s.Checked > 0 {
		rate = float64(s.Hits) / float64(s.Checked) * 1000
	}
	return fmt.Sprintf("checked=%d hits=%d valid=%d transport_err=%d hits_per_1k=%.1f",
		s.Checked, s.Hits, s.Valid, s.Transport, rate)
}
