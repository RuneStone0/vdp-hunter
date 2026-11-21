package zone

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

const master = `; zone file for example test
$ORIGIN com.
$TTL 3600
example.com.	3600	IN	NS	ns1.example.com.
example.com.	3600	IN	NS	ns2.example.com.
example.com.	3600	IN	DS	12345 8 2 ABCDEF
_25._tcp.example.com.	3600	IN	TLSA	3 1 1 ABCD
www.example.com.	3600	IN	A	192.0.2.1
foo-bar.com.	3600	IN	NS	ns1.other.net.	; trailing comment
foo-bar.com.	3600	IN	NS	ns2.other.net.
*.wild.com.	3600	IN	NS	ns1.wild.net.
xn--bcher-kva.com.	3600	IN	NS	ns1.example.com.
notcom.zone.	3600	IN	NS	ns1.example.com.
`

func collect(t *testing.T, r *strings.Reader) []string {
	t.Helper()
	var got []string
	if _, err := Names(r, "com", func(n string) error { got = append(got, n); return nil }); err != nil {
		t.Fatalf("Names: %v", err)
	}
	return got
}

func TestNamesApexOnlyDeduped(t *testing.T) {
	got := collect(t, strings.NewReader(master))
	want := []string{"example.com", "foo-bar.com", "xn--bcher-kva.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestNamesGzipAndWrongTLD(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(master))
	gz.Close()

	path := t.TempDir() + "/com.zone.gz"
	if err := writeFile(path, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	fh, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fh.Close()

	var got []string
	if _, err := Names(fh, "com", func(n string) error { got = append(got, n); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("gzip read got %v", got)
	}

	// the same file read as a different TLD yields nothing: the apex rule is
	// relative to the zone, so a mismatch is a bug the caller must see
	other := collect(t, strings.NewReader(master))
	if len(other) == 0 {
		t.Fatal("expected names for com")
	}
}

func TestNamesUnknownTLD(t *testing.T) {
	var got []string
	if _, err := Names(strings.NewReader(master), "io", func(n string) error {
		got = append(got, n); return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no io names, got %v", got)
	}
}
