// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// issuedTokenTTL is how long a token's series is exported after the token
// was issued. GitHub installation tokens expire after one hour; the extra
// hour covers API-usage records about the token that arrive late.
const issuedTokenTTL = 2 * time.Hour

var issuedTokens = newIssuedTokenCollector(issuedTokenTTL, time.Now)

func init() {
	prometheus.MustRegister(issuedTokens)
}

// observeIssuedToken records a token issued by Exchange. err is the error
// Exchange returns; nothing is recorded for a failed exchange.
func observeIssuedToken(e Event, err error) {
	if err != nil || e.TokenSHA256 == "" {
		return
	}
	issuedTokens.add(e.TokenSHA256, e.Scope, e.Identity, strconv.FormatInt(e.InstallationID, 10), e.Time)
}

// issuedTokenCollector exports octo_sts_token_issued_timestamp_seconds: one
// series per token issued in the last ttl, keyed by the token's SHA-256
// (hex) and labelled with the trust policy (scope and identity) it was issued
// under. GitHub's audit log records the same hash for every API request made
// with the token (hashed_token, base64-encoded), so per-token request counts
// can be attributed to the trust policy that issued the token. Entries older
// than ttl are dropped, so the number of series is bounded by the tokens
// issued in that window.
type issuedTokenCollector struct {
	mu      sync.Mutex
	ttl     time.Duration
	now     func() time.Time
	entries map[string]issuedToken
	desc    *prometheus.Desc
}

type issuedToken struct {
	scope        string
	identity     string
	installation string
	issued       time.Time
}

func newIssuedTokenCollector(ttl time.Duration, now func() time.Time) *issuedTokenCollector {
	return &issuedTokenCollector{
		ttl:     ttl,
		now:     now,
		entries: map[string]issuedToken{},
		desc: prometheus.NewDesc(
			"octo_sts_token_issued_timestamp_seconds",
			"Issue time of each token issued recently, by the SHA-256 of the token (hex) and the trust policy it was issued under.",
			[]string{"token_sha256", "scope", "identity", "installation_id"}, nil),
	}
}

func (c *issuedTokenCollector) add(hash, scope, identity, installation string, issued time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune()
	c.entries[hash] = issuedToken{scope: scope, identity: identity, installation: installation, issued: issued}
}

// prune drops entries older than ttl. The caller holds mu.
func (c *issuedTokenCollector) prune() {
	cutoff := c.now().Add(-c.ttl)
	for hash, t := range c.entries {
		if t.issued.Before(cutoff) {
			delete(c.entries, hash)
		}
	}
}

// Describe implements prometheus.Collector.
func (c *issuedTokenCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

// Collect implements prometheus.Collector.
func (c *issuedTokenCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune()
	for hash, t := range c.entries {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue,
			float64(t.issued.Unix()), hash, t.scope, t.identity, t.installation)
	}
}
