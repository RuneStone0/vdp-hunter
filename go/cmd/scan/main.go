// Command scan runs the three-stage zone sweep: does the name resolve, is a web
// port open, does it publish a security.txt.
//
// The point of the stages is to make the fourth honest pass cheap. A .com zone is
// ~160M names; asking each of them for a security.txt every month is not possible.
// Asking each of them whether they resolve is, and in steady state roughly a
// third of them are parked (no answer) and drop out immediately.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RuneStone0/vdp-hunter/go/internal/dnsq"
	"github.com/RuneStone0/vdp-hunter/go/internal/park"
	"github.com/RuneStone0/vdp-hunter/go/internal/probe"
)

func main() {
	var (
		zoneFile  = flag.String("zone", "", "file of names, one per line")
		tld       = flag.String("tld", "", "tld label used for the park state directory")
		stateDir  = flag.String("state", "state", "directory holding parked sets")
		hitsFile  = flag.String("hits", "hits.jsonl", "append hits here")
		maxMin    = flag.Float64("max-minutes", 0, "stop after this many minutes, 0 = no limit")
		dnsW      = flag.Int("dns-workers", 2000, "concurrent DNS queries")
		portW     = flag.Int("port-workers", 2000, "concurrent port connects")
		httpW     = flag.Int("http-workers", 600, "concurrent security.txt fetches")
		dnsTO     = flag.Duration("dns-timeout", 2*time.Second, "per DNS query")
		portTO    = flag.Duration("port-timeout", 1500*time.Millisecond, "per port connect")
		httpTO    = flag.Duration("http-timeout", 4*time.Second, "per security.txt request")
		parkEmpty = flag.Int("park-days", 90, "park a name with no DNS or no open port this many days")
		parkClean = flag.Int("park-clean-days", 30, "park a reachable name that publishes no policy")
		limit     = flag.Int("limit", 0, "cap names read, for testing")
		shardSpec = flag.String("shards", "", "shard range like 0-127 or a single number, empty = all")
		resolvers = flag.String("resolvers", "1.1.1.1:53,1.0.0.1:53,8.8.8.8:53", "comma separated DNS servers")
		batchSize = flag.Int("batch", 20000, "names per batch, sets the cost of a pool pass")
		portCheck = flag.Bool("port-check", false,
			"dial 443/80 before asking for security.txt; off by default because the request itself is the port check")
	)
	flag.Parse()
	if *zoneFile == "" || *tld == "" {
		fmt.Fprintln(os.Stderr, "need -zone and -tld")
		os.Exit(2)
	}
	if err := os.MkdirAll(*stateDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	names, err := readNames(*zoneFile, *limit)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	byShard := make([][]string, park.Shards)
	for _, n := range names {
		s := park.Shard(park.Hash(n))
		byShard[s] = append(byShard[s], n)
	}
	shards := parseShards(*shardSpec)

	ctx := context.Background()
	if *maxMin > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(*maxMin*float64(time.Minute)))
		defer cancel()
	}

	dns := dnsq.New(strings.Split(*resolvers, ","), *dnsTO)
	prober := probe.New(probe.Options{
		Workers: *httpW, Timeout: *httpTO, Retries: 0, Source: "czds",
	})

	hits, err := os.OpenFile(*hitsFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer hits.Close()
	var hitMu sync.Mutex

	today := uint32(time.Now().Unix() / 86400)
	var checked, skipped, noDNS, noPort, live, found, parkedOut int64
	start := time.Now()

	// Batching by name count, not by shard: a small TLD has ~8 names per shard, and
	// spinning 4600 goroutines per shard spends all the time on setup. A batch of
	// 20k names means one pool pass per stage, and the park sets for the shards it
	// touches are loaded once.
	type batch struct {
		shards []int
		names  []string
	}
	var batches []batch
	cur := batch{}
	for _, shard := range shards {
		if len(byShard[shard]) == 0 {
			continue
		}
		cur.shards = append(cur.shards, shard)
		cur.names = append(cur.names, byShard[shard]...)
		if len(cur.names) >= *batchSize {
			batches = append(batches, cur)
			cur = batch{}
		}
	}
	if len(cur.names) > 0 {
		batches = append(batches, cur)
	}

	for _, b := range batches {
		if ctx.Err() != nil {
			break
		}
		sets := make(map[int]*park.Set, len(b.shards))
		var todo []string
		for _, shard := range b.shards {
			set, err := park.Load(*stateDir, *tld, shard)
			if err != nil {
				fmt.Fprintln(os.Stderr, "load park:", err)
				continue
			}
			sets[shard] = set
			for _, n := range byShard[shard] {
				atomic.AddInt64(&checked, 1)
				if set.Active(park.Hash(n), today) {
					atomic.AddInt64(&skipped, 1)
					continue
				}
				todo = append(todo, n)
			}
		}
		if len(todo) == 0 {
			continue
		}

		// stage 1: does it resolve at all
		var resolved []host
		var mu sync.Mutex
		runPool(ctx, *dnsW, todo, func(n string) {
			ip, ok, err := dns.Resolve(n)
			if err != nil || !ok {
				atomic.AddInt64(&noDNS, 1)
				parkIn(sets, n, dayPlus(today, *parkEmpty))
				return
			}
			mu.Lock()
			resolved = append(resolved, host{name: n, ip: ip})
			mu.Unlock()
		})

		// stage 2 is optional: a failed security.txt request already proves the port
		// is closed, so dialling first doubles the network round trips for nothing
		var reachable []string
		if *portCheck && len(resolved) > 0 {
			runPoolHosts(ctx, *portW, resolved, func(h host) {
				if !dialAny(h.ip, *portTO, "443", "80") {
					atomic.AddInt64(&noPort, 1)
					parkIn(sets, h.name, dayPlus(today, *parkEmpty))
					return
				}
				mu.Lock()
				reachable = append(reachable, h.name)
				mu.Unlock()
			})
		} else {
			for _, h := range resolved {
				reachable = append(reachable, h.name)
			}
		}

		// stage 3: does it publish a policy
		if len(reachable) > 0 {
			in := make(chan string)
			go func() {
				defer close(in)
				for _, n := range reachable {
					select {
					case in <- n:
					case <-ctx.Done():
						return
					}
				}
			}()
			probe.Run(ctx, prober, in, func(res probe.Result) {
				hitMu.Lock()
				if res.Found() {
					atomic.AddInt64(&found, 1)
					_ = json.NewEncoder(hits).Encode(res)
				} else {
					parkIn(sets, res.Domain, dayPlus(today, *parkClean))
				}
				hitMu.Unlock()
			})
			atomic.AddInt64(&live, int64(len(reachable)))
		}

		for shard, set := range sets {
			_ = set.Save(*stateDir, *tld, shard, today)
		}
		if ctx.Err() != nil {
			parkedOut++
		}
	}

	elapsed := time.Since(start).Seconds()
	fmt.Printf("names=%d checked=%d parked_skip=%d no_dns=%d no_port=%d reachable=%d hits=%d seconds=%.1f rate=%.0f/s shards_stopped_early=%d\n",
		len(names), checked, skipped, noDNS, noPort, live, found, elapsed, float64(checked)/elapsed, parkedOut)
}

func dayPlus(today uint32, days int) uint32 { return today + uint32(days) }

// parkIn parks a name in the set that owns its shard.
func parkIn(sets map[int]*park.Set, name string, until uint32) {
	h := park.Hash(name)
	if set, ok := sets[park.Shard(h)]; ok {
		set.Park(h, until)
	}
}

// runPool runs fn over items with n workers, stopping when ctx is done.
func runPool(ctx context.Context, n int, items []string, fn func(string)) {
	if n <= 0 {
		n = 1
	}
	ch := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range ch {
				fn(item)
			}
		}()
	}
	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		ch <- item
	}
	close(ch)
	wg.Wait()
}

type host struct{ name, ip string }

// runPoolHosts is runPool for the host list the DNS stage produced.
func runPoolHosts(ctx context.Context, n int, items []host, fn func(host)) {
	if n <= 0 {
		n = 1
	}
	ch := make(chan host)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range ch {
				fn(item)
			}
		}()
	}
	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		ch <- item
	}
	close(ch)
	wg.Wait()
}

func dialAny(host string, timeout time.Duration, ports ...string) bool {
	var wg sync.WaitGroup
	var ok atomic.Bool
	for _, p := range ports {
		wg.Add(1)
		go func(port string) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
			if err == nil {
				ok.Store(true)
				_ = c.Close()
			}
		}(p)
	}
	wg.Wait()
	return ok.Load()
}

func readNames(path string, limit int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		n := strings.TrimSpace(sc.Text())
		if n == "" || strings.HasPrefix(n, ";") {
			continue
		}
		out = append(out, strings.ToLower(n))
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, sc.Err()
}

func parseShards(spec string) []int {
	all := make([]int, park.Shards)
	for i := range all {
		all[i] = i
	}
	if spec == "" {
		return all
	}
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			var a, b int
			if _, err := fmt.Sscanf(part, "%d-%d", &a, &b); err == nil {
				for i := a; i <= b && i < park.Shards; i++ {
					out = append(out, i)
				}
			}
			continue
		}
		var v int
		if _, err := fmt.Sscanf(part, "%d", &v); err == nil && v >= 0 && v < park.Shards {
			out = append(out, v)
		}
	}
	sort.Ints(out)
	_ = filepath.Separator
	return out
}
