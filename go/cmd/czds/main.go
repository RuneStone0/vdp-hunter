// Command czds downloads zone files from ICANN's Centralized Zone Data Service.
//
// Credentials come from -user, else CZDS_USER, and -pass, else CZDS_PASS. The
// account must already be approved for the TLDs on the CZDS portal; this tool
// does not request access, it only downloads what the account is entitled to.
//
//	export CZDS_USER=you@example.com CZDS_PASS='...'
//	go run ./cmd/czds -tlds com,io,dev -out zones
//
// API shape follows ICANN's published sample clients: POST {auth}/api/authenticate
// returns an access token, GET {czds}/czds/downloads/links returns one signed URL
// per approved TLD, and the URL itself needs the same bearer token.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultAuthBase = "https://account-api.icann.org"
const defaultCZDSBase = "https://czds-api.icann.org"

type client struct {
	authBase, czdsBase string
	user, pass         string
	token              string
	http               *http.Client
}

func main() {
	user := flag.String("user", os.Getenv("CZDS_USER"), "ICANN account email")
	pass := flag.String("pass", os.Getenv("CZDS_PASS"), "ICANN account password")
	authBase := flag.String("auth-base", defaultAuthBase, "authentication base URL")
	czdsBase := flag.String("czds-base", defaultCZDSBase, "CZDS base URL")
	tlds := flag.String("tlds", "", "comma separated TLDs to fetch (default: all approved)")
	out := flag.String("out", "zones", "directory for downloaded zone files")
	skipExisting := flag.Bool("skip-existing", true, "do not re-download files already on disk")
	flag.Parse()

	if *user == "" || *pass == "" {
		fmt.Fprintln(os.Stderr, "need CZDS_USER and CZDS_PASS (or -user/-pass)")
		os.Exit(2)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		os.Exit(1)
	}

	c := &client{authBase: *authBase, czdsBase: *czdsBase, user: *user, pass: *pass,
		http: &http.Client{Timeout: 60 * time.Minute}}
	ctx := context.Background()

	if err := c.authenticate(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "auth:", err)
		os.Exit(1)
	}
	links, err := c.links(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "links:", err)
		os.Exit(1)
	}
	want := map[string]bool{}
	for _, t := range strings.Split(*tlds, ",") {
		if t = strings.TrimSpace(strings.ToLower(t)); t != "" {
			want[t] = true
		}
	}
	fetched := 0
	for _, link := range links {
		tld := tldOf(link)
		if len(want) > 0 && !want[tld] {
			continue
		}
		path := filepath.Join(*out, tld+".zone.gz")
		if *skipExisting {
			if st, err := os.Stat(path); err == nil && st.Size() > 0 {
				fmt.Printf("skip %s (%d MB already on disk)\n", tld, st.Size()>>20)
				continue
			}
		}
		n, err := c.download(ctx, link, path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "download %s: %v\n", tld, err)
			continue
		}
		fetched++
		fmt.Printf("saved %s %d MB\n", path, n>>20)
	}
	fmt.Printf("done: %d zone files written to %s\n", fetched, *out)
}

func tldOf(link string) string {
	base := filepath.Base(link)
	base = strings.TrimSuffix(base, ".gz")
	base = strings.TrimSuffix(base, ".zone")
	return strings.ToLower(base)
}

func (c *client) authenticate(ctx context.Context) error {
	body, _ := json.Marshal(map[string]string{"username": c.user, "password": c.pass})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.authBase+"/api/authenticate", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("decode token: %w", err)
	}
	if out.AccessToken == "" {
		return errors.New("empty access token")
	}
	c.token = out.AccessToken
	return nil
}

func (c *client) links(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.czdsBase+"/czds/downloads/links", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var links []string
	if err := json.Unmarshal(raw, &links); err != nil {
		return nil, fmt.Errorf("decode links: %w", err)
	}
	return links, nil
}

func (c *client) download(ctx context.Context, link, path string) (int64, error) {
	if _, err := url.Parse(link); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	tmp := path + ".part"
	fh, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(fh, resp.Body)
	cerr := fh.Close()
	if err != nil || cerr != nil {
		os.Remove(tmp)
		if err == nil {
			err = cerr
		}
		return n, err
	}
	return n, os.Rename(tmp, path)
}
