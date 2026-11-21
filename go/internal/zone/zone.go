// Package zone streams DNS master-file (RFC 1035) zone files and yields the
// apex names inside them.
//
// A gTLD zone file is the authoritative list of every registered name under that
// TLD: hundreds of millions of lines for .com, a few hundred thousand for a
// small gTLD. Nothing else gives a complete, sanctioned picture of what exists,
// which is what makes it the right source for finding disclosure programs that
// no aggregator lists.
package zone

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"
)

// Open opens a zone file, transparently gunzipping it.
func Open(path string) (io.ReadCloser, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	magic := make([]byte, 2)
	if n, _ := io.ReadFull(fh, magic); n == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		if _, err := fh.Seek(0, io.SeekStart); err != nil {
			fh.Close()
			return nil, err
		}
		gz, err := gzip.NewReader(fh)
		if err != nil {
			fh.Close()
			return nil, err
		}
		return &readCloser{r: gz, closers: []io.Closer{gz, fh}}, nil
	}
	if _, err := fh.Seek(0, io.SeekStart); err != nil {
		fh.Close()
		return nil, err
	}
	return fh, nil
}

type readCloser struct {
	r       io.Reader
	closers []io.Closer
}

func (rc *readCloser) Read(p []byte) (int, error) { return rc.r.Read(p) }

func (rc *readCloser) Close() error {
	var first error
	for _, c := range rc.closers {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Names walks a zone file for one TLD and calls fn with each apex name, once,
// lowercased and without the trailing dot. Emission is in file order, which for
// real zone files is close to sorted; duplicates are suppressed by comparing
// against the previous name, so memory stays flat regardless of zone size.
//
// Apex means "exactly one label under the TLD": delegated subdomains and host
// records are skipped, because a security.txt is published at the apex.
func Names(r io.Reader, tld string, fn func(string) error) (int, error) {
	tld = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(tld, "."), "."))
	if tld == "" {
		return 0, fmt.Errorf("zone: empty tld")
	}
	suffix := "." + tld
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	prev := ""
	count := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "$") {
			continue
		}
		// strip trailing comments, then take the owner field
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.ToLower(fields[0])
		name = strings.TrimSuffix(name, ".")
		if name == "" || name == prev {
			continue
		}
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		label := strings.TrimSuffix(name, suffix)
		if label == "" || strings.Contains(label, ".") {
			continue
		}
		if strings.HasPrefix(label, "_") || strings.HasPrefix(label, "*") {
			continue
		}
		prev = name
		count++
		if err := fn(name); err != nil {
			return count, err
		}
	}
	return count, sc.Err()
}
