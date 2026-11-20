// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/status"
)

// unknownIdentity labels exchanges whose identity did not resolve to a trust
// policy. The requested identity is caller-supplied, so it becomes a label
// only once a policy file by that name was found; anything else would let a
// caller create metric series at will.
const unknownIdentity = "unknown"

// tokenInfoTTL is how long a token's info series is exported after it was
// issued. GitHub installation tokens expire after one hour; the extra hour
// covers audit events that arrive late and range queries over the token's
// whole life.
const tokenInfoTTL = 2 * time.Hour

var exchangesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "octo_sts_exchanges_total",
	Help: "Token exchanges by trust policy identity, installation and gRPC status code.",
}, []string{"identity", "installation_id", "code"})

var issuedTokens = newTokenInfo(tokenInfoTTL, time.Now)

func init() {
	prometheus.MustRegister(exchangesTotal, issuedTokens)
}

// observeExchange records one exchange: a structured log line with the
// event's fields, the exchange counter, and, for an issued token, its info
// series. err is the error Exchange returns.
func observeExchange(ctx context.Context, e Event, err error) {
	logExchange(ctx, e)

	identity := unknownIdentity
	if e.TrustPolicy != nil {
		identity = e.Identity
	}
	installation := ""
	if e.InstallationID != 0 {
		installation = strconv.FormatInt(e.InstallationID, 10)
	}
	exchangesTotal.WithLabelValues(identity, installation, status.Code(err).String()).Inc()

	if err == nil && e.TokenSHA256 != "" {
		issuedTokens.add(e.TokenSHA256, identity, installation, e.Time)
	}
}

// logExchange writes one line per exchange with the Event's fields.
// token_sha256 is a one-way hash of a short-lived token (GitHub's audit log
// records the same hash as hashed_token, base64-encoded), so it is safe to log
// and lets the token's activity on GitHub be traced back to this exchange.
func logExchange(ctx context.Context, e Event) {
	args := []any{
		"scope", e.Scope,
		"identity", e.Identity,
		"issuer", e.Actor.Issuer,
		"subject", e.Actor.Subject,
		"installation_id", e.InstallationID,
		"user_agent", e.UserAgent,
		"token_sha256", e.TokenSHA256,
	}
	if e.Error != "" {
		args = append(args, "error", e.Error)
	}
	clog.FromContext(ctx).Info("exchange", args...)
}

// tokenInfo exports octo_sts_token_issued_timestamp_seconds, one series per
// token issued in the last ttl, labelled with the token's SHA-256 (hex) and
// the identity it was issued to. Joined on token_sha256 with a per-token
// count of GitHub API calls (from the audit log), it gives each identity's
// call rate. Series expire after ttl, so the number exported is bounded by
// the tokens issued in that window.
type tokenInfo struct {
	mu      sync.Mutex
	ttl     time.Duration
	now     func() time.Time
	entries map[string]tokenEntry
	desc    *prometheus.Desc
}

type tokenEntry struct {
	identity     string
	installation string
	issued       time.Time
}

func newTokenInfo(ttl time.Duration, now func() time.Time) *tokenInfo {
	return &tokenInfo{
		ttl:     ttl,
		now:     now,
		entries: map[string]tokenEntry{},
		desc: prometheus.NewDesc(
			"octo_sts_token_issued_timestamp_seconds",
			"Issue time of each token issued in the last two hours, by SHA-256 of the token (hex) and trust policy identity.",
			[]string{"token_sha256", "identity", "installation_id"}, nil),
	}
}

func (t *tokenInfo) add(hash, identity, installation string, issued time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune()
	t.entries[hash] = tokenEntry{identity: identity, installation: installation, issued: issued}
}

// prune drops entries older than ttl. The caller holds mu.
func (t *tokenInfo) prune() {
	cutoff := t.now().Add(-t.ttl)
	for hash, entry := range t.entries {
		if entry.issued.Before(cutoff) {
			delete(t.entries, hash)
		}
	}
}

// Describe implements prometheus.Collector.
func (t *tokenInfo) Describe(ch chan<- *prometheus.Desc) {
	ch <- t.desc
}

// Collect implements prometheus.Collector.
func (t *tokenInfo) Collect(ch chan<- prometheus.Metric) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune()
	for hash, entry := range t.entries {
		ch <- prometheus.MustNewConstMetric(t.desc, prometheus.GaugeValue,
			float64(entry.issued.Unix()), hash, entry.identity, entry.installation)
	}
}
