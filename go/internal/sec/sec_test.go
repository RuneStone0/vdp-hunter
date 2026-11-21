package sec

import (
	"testing"
	"time"
)

const sample = "Contact: mailto:security@example.com\r\n" +
	"Contact: https://example.com/report\r\n" +
	"Contact: mailto:psirt@example.com\r\n" +
	"# a comment line\r\n" +
	"Expires: 2027-01-01T00:00:00Z\r\n" +
	"Policy: https://example.com/policy\r\n" +
	"Preferred-Languages: en\r\n" +
	"  continued value\r\n" +
	"Unknown-Field: ignored\r\n" +
	"Bounty: yes\r\n"

func TestParse(t *testing.T) {
	f := Parse(sample)
	if got := len(f["contact"]); got != 3 {
		t.Fatalf("contact values = %d, want 3 (%v)", got, f["contact"])
	}
	if got := f["preferred-languages"][0]; got != "en continued value" {
		t.Fatalf("folding = %q", got)
	}
	if _, ok := f["unknown-field"]; ok {
		t.Fatal("unknown field should be dropped")
	}
	if got := f.Emails(); len(got) != 2 || got[0] != "security@example.com" {
		t.Fatalf("emails = %v", got)
	}
	if got := f.URLs(); len(got) != 1 || got[0] != "https://example.com/report" {
		t.Fatalf("urls = %v", got)
	}
	if got := f.OffersBounty(); got != "yes" {
		t.Fatalf("bounty = %q", got)
	}
}

func TestExpiryStates(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name, body, state, on string
	}{
		{"future", "Contact: mailto:a@b.c\nExpires: 2027-06-01T00:00:00Z\n", "valid", "2027-06-01"},
		{"past", "Contact: mailto:a@b.c\nExpires: 2025-06-01T00:00:00Z\n", "expired", "2025-06-01"},
		{"absent", "Contact: mailto:a@b.c\n", "missing", ""},
		{"garbage", "Contact: mailto:a@b.c\nExpires: soon\n", "invalid", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, on := ExpiryState(Parse(tc.body), now)
			if state != tc.state || on != tc.on {
				t.Fatalf("got (%q,%q) want (%q,%q)", state, on, tc.state, tc.on)
			}
		})
	}
}
