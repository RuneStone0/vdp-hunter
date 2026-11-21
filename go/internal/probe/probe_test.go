package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const body = "Contact: mailto:security@test.example\n" +
	"Contact: https://test.example/report\n" +
	"Expires: 2099-01-01T00:00:00Z\n" +
	"Policy: https://test.example/policy\n"

func newProber(srv *httptest.Server, retries int) *Prober {
	return New(Options{Workers: 2, Timeout: 5 * time.Second, Retries: retries,
		Client: srv.Client()})
}

func TestProbeHit(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/security.txt" {
			atomic.AddInt32(&hits, 1)
			w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	p := newProber(srv, 1)
	res := p.Probe(context.Background(), strings.TrimPrefix(srv.URL, "https://"))
	if !res.Found() {
		t.Fatalf("expected a hit, got %+v", res)
	}
	if res.Expiry != "valid" || res.ExpiresOn != "2099-01-01" {
		t.Fatalf("expiry = %q %q", res.Expiry, res.ExpiresOn)
	}
	if len(res.Emails) != 1 || len(res.ContactURLs) != 1 {
		t.Fatalf("contacts = %v %v", res.Emails, res.ContactURLs)
	}
	if res.TLSVerified == nil || !*res.TLSVerified {
		t.Fatal("TLS should be marked verified")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly one request, got %d", hits)
	}
}

func TestProbeLegacyPathAfter404(t *testing.T) {
	var legacy int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/security.txt" {
			atomic.AddInt32(&legacy, 1)
			w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res := newProber(srv, 1).Probe(context.Background(), strings.TrimPrefix(srv.URL, "https://"))
	if !res.Found() || !strings.HasSuffix(res.FoundAt, "/security.txt") {
		t.Fatalf("legacy path not followed: %+v", res)
	}
	if atomic.LoadInt32(&legacy) != 1 {
		t.Fatal("legacy path should be requested once")
	}
}

func TestProbe404IsNotTransportError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res := newProber(srv, 1).Probe(context.Background(), strings.TrimPrefix(srv.URL, "https://"))
	if res.Found() {
		t.Fatal("404 is not a hit")
	}
	if res.TransportError() {
		t.Fatalf("a clean 404 must not be treated as a transport failure: %+v", res)
	}
	if !res.TransportOK() {
		t.Fatal("host answered, TransportOK should be true")
	}
}

func TestProbeRetriesTransportFailure(t *testing.T) {
	var calls int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			// drop the connection without a response: the classic transient
			// failure that used to be recorded as "no security.txt"
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					conn.Close()
					return
				}
			}
			http.Error(w, "boom", 500)
			return
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()

	res := newProber(srv, 1).Probe(context.Background(), strings.TrimPrefix(srv.URL, "https://"))
	if !res.Found() {
		t.Fatalf("retry should have recovered the hit: %+v", res)
	}
	if atomic.LoadInt32(&calls) < 2 {
		t.Fatal("expected a retry")
	}
}

func TestProbe200WithoutContactIsNotAHit(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>welcome</html>"))
	}))
	defer srv.Close()

	res := newProber(srv, 0).Probe(context.Background(), strings.TrimPrefix(srv.URL, "https://"))
	if res.Found() {
		t.Fatal("a 200 that is not a security.txt must not count")
	}
	if res.TransportError() {
		t.Fatal("an answered request is not a transport error")
	}
}

func TestRunCollectsTransportFailuresForRetry(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")

	in := make(chan string, 4)
	in <- host
	in <- "127.0.0.1:1" // closed port: transport failure
	close(in)

	var emitted int
	p := newProber(srv, 0)
	stats, retry := Run(context.Background(), p, in, func(r Result) {
		if r.Found() {
			emitted++
		}
	})
	if stats.Hits != 1 || emitted != 1 {
		t.Fatalf("stats = %+v emitted=%d", stats, emitted)
	}
	if len(retry) != 1 || retry[0] != "127.0.0.1:1" {
		t.Fatalf("retry list = %v", retry)
	}
}
