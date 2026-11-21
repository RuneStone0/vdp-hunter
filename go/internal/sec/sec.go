// Package sec parses RFC 9116 security.txt files.
package sec

import (
	"strings"
	"time"
)

// Allowed are the field names RFC 9116 defines. Anything else is ignored, the
// same way the Python crawler does, so both scanners produce identical rows.
var Allowed = map[string]bool{
	"contact": true, "expires": true, "policy": true, "hiring": true,
	"acknowledgments": true, "preferred-languages": true, "canonical": true,
	"encryption": true, "csaf": true, "permissions-policy": true,
	"bounty": true, "rewards": true, "scope": true, "acknowledgement": true,
}

// Fields maps a lowercased field name to its values in file order.
type Fields map[string][]string

// Parse reads a security.txt body. Continuation lines (leading space or tab)
// extend the previous value, blank lines and # comments end a field.
func Parse(text string) Fields {
	out := Fields{}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	last := ""
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			last = ""
			continue
		}
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && last != "" {
			vals := out[last]
			if n := len(vals); n > 0 {
				vals[n-1] += " " + trimmed
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if !Allowed[name] {
			continue
		}
		out[name] = append(out[name], strings.TrimSpace(value))
		last = name
	}
	return out
}

// Emails returns every mailto: contact without the scheme.
func (f Fields) Emails() []string {
	var out []string
	for _, c := range f["contact"] {
		if strings.HasPrefix(strings.ToLower(c), "mailto:") {
			addr := strings.TrimSpace(c[len("mailto:"):])
			if addr != "" {
				out = append(out, addr)
			}
		}
	}
	return out
}

// URLs returns every http(s) contact plus the policy URL.
func (f Fields) URLs() []string {
	var out []string
	for _, c := range f["contact"] {
		lc := strings.ToLower(c)
		if strings.HasPrefix(lc, "http://") || strings.HasPrefix(lc, "https://") {
			out = append(out, c)
		}
	}
	return out
}

// ExpiryState classifies the Expires field: valid, expired, missing or invalid.
// A security.txt without Expires is still served, it just cannot be trusted to
// be current, so the states are distinct rather than collapsed into a bool.
func ExpiryState(f Fields, now time.Time) (state, on string) {
	vals := f["expires"]
	if len(vals) == 0 {
		return "missing", ""
	}
	for _, v := range vals {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(v))
		if err != nil {
			continue
		}
		on = t.UTC().Format("2006-01-02")
		if t.Before(now) {
			return "expired", on
		}
		return "valid", on
	}
	return "invalid", ""
}

// OffersBounty reports whether the file advertises a reward. The field is not
// standardised, so both the RFC draft field and a plain mention count.
func (f Fields) OffersBounty() string {
	if len(f["bounty"]) > 0 || len(f["rewards"]) > 0 {
		return "yes"
	}
	for _, v := range f["contact"] {
		if strings.Contains(strings.ToLower(v), "bounty") {
			return "yes"
		}
	}
	return ""
}
