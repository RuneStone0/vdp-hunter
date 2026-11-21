// Command zonex extracts apex names from a CZDS zone file.
//
//	go run ./cmd/zonex -in zones/com.zone.gz -tld com -out data/domains-com.txt
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/RuneStone0/vdp-hunter/go/internal/zone"
)

func main() {
	in := flag.String("in", "", "zone file (.zone or .zone.gz)")
	tld := flag.String("tld", "", "TLD the zone belongs to, e.g. com")
	out := flag.String("out", "", "output file, one apex domain per line")
	limit := flag.Int("limit", 0, "stop after N names (0 = all)")
	flag.Parse()
	if *in == "" || *tld == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: zonex -in zone.gz -tld com -out domains.txt")
		os.Exit(2)
	}

	r, err := zone.Open(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	defer r.Close()

	fh, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create:", err)
		os.Exit(1)
	}
	defer fh.Close()
	w := bufio.NewWriterSize(fh, 1<<20)

	start := time.Now()
	var written int
	n, err := zone.Names(r, *tld, func(name string) error {
		if _, err := w.WriteString(name + "\n"); err != nil {
			return err
		}
		written++
		if *limit > 0 && written >= *limit {
			return fmt.Errorf("limit reached")
		}
		if written%2_000_000 == 0 {
			fmt.Fprintf(os.Stderr, "%d names, %.0f/s\n", written,
				float64(written)/time.Since(start).Seconds())
		}
		return nil
	})
	if err != nil && err.Error() != "limit reached" {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, "flush:", err)
		os.Exit(1)
	}
	fmt.Printf("tld=%s scanned_lines=%d written=%d seconds=%.1f out=%s\n",
		*tld, n, written, time.Since(start).Seconds(), *out)
}
