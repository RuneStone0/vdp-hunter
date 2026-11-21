// Command probe scans a domain list for RFC 9116 security.txt.
//
//	go run ./cmd/probe -in data/domains-com.txt -out data/hits-czds.jsonl -workers 100
//
// Output is JSONL in the same shape as the Python crawler, so bin/build_dataset.py
// merges it without special-casing.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/RuneStone0/vdp-hunter/go/internal/probe"
)

func main() {
	in := flag.String("in", "", "file of domains, one per line")
	out := flag.String("out", "", "JSONL output (hits appended)")
	workers := flag.Int("workers", 100, "concurrent probes")
	rate := flag.Int("rate", 0, "global requests per second (0 = unlimited)")
	timeout := flag.Duration("timeout", 12*time.Second, "per-request timeout")
	retries := flag.Int("retries", 1, "retries on transport failure")
	limit := flag.Int("limit", 0, "probe at most N domains (0 = all)")
	resume := flag.Bool("resume", true, "skip domains already in -out")
	source := flag.String("source", "czds", "provenance label for emitted rows")
	flag.Parse()
	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: probe -in domains.txt -out hits.jsonl")
		os.Exit(2)
	}

	domains, err := readDomains(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	seen := map[string]bool{}
	if *resume {
		if fh, err := os.Open(*out); err == nil {
			sc := bufio.NewScanner(fh)
			sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
			for sc.Scan() {
				var rec struct{ Domain string }
				if json.Unmarshal(sc.Bytes(), &rec) == nil && rec.Domain != "" {
					seen[rec.Domain] = true
				}
			}
			fh.Close()
		}
	}
	queue := make([]string, 0, len(domains))
	for _, d := range domains {
		if !seen[d] {
			queue = append(queue, d)
		}
	}
	if *limit > 0 && len(queue) > *limit {
		queue = queue[:*limit]
	}
	fmt.Printf("%d domains loaded, %d already done, %d to probe\n",
		len(domains), len(seen), len(queue))

	fh, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open out:", err)
		os.Exit(1)
	}
	defer fh.Close()

	var writeMu sync.Mutex
	var checked atomic.Int64
	enc := json.NewEncoder(fh)
	emit := func(r probe.Result) {
		checked.Add(1)
		if !r.Found() {
			return // only hits are stored, same as the Python crawler
		}
		writeMu.Lock()
		_ = enc.Encode(r)
		writeMu.Unlock()
	}

	p := probe.New(probe.Options{Workers: *workers, Timeout: *timeout, Retries: *retries,
		RateLimit: *rate, Source: *source})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ch := make(chan string)
	go func() {
		defer close(ch)
		for _, d := range queue {
			select {
			case <-ctx.Done():
				return
			case ch <- d:
			}
		}
	}()

	start := time.Now()
	done := make(chan struct{})
	go func() {
		tk := time.NewTicker(10 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-done:
				return
			case <-tk.C:
				el := time.Since(start).Seconds()
				n := checked.Load()
				fmt.Fprintf(os.Stderr, "probing %d in %.0fs (%.0f/s)\n", n, el, float64(n)/el)
			}
		}
	}()

	stats, retry := probe.Run(ctx, p, ch, emit)
	if len(retry) > 0 && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "retry pass: %d transport failures at %d workers\n",
			len(retry), max(4, *workers/4))
		retryProber := probe.New(probe.Options{Workers: max(4, *workers/4), Timeout: *timeout,
			Retries: 1, RateLimit: *rate, Source: *source})
		rch := make(chan string)
		go func() {
			defer close(rch)
			for _, d := range retry {
				select {
				case <-ctx.Done():
					return
				case rch <- d:
				}
			}
		}()
		more, _ := probe.Run(ctx, retryProber, rch, emit)
		stats.Checked += more.Checked
		stats.Hits += more.Hits
		stats.Valid += more.Valid
	}
	close(done)

	fmt.Printf("%s requests=%d seconds=%.1f\n", stats, p.Requests(),
		time.Since(start).Seconds())
}

func readDomains(path string) ([]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var out []string
	seen := map[string]bool{}
	for sc.Scan() {
		d := strings.ToLower(strings.TrimSpace(sc.Text()))
		if d == "" || strings.HasPrefix(d, "#") || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, sc.Err()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
