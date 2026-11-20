// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestTokenInfoExpires(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	info := newTokenInfo(2*time.Hour, func() time.Time { return now })

	info.add("aaa", "policy-a", "181763887", now.Add(-90*time.Minute))
	info.add("bbb", "policy-b", "182767618", now.Add(-3*time.Hour))

	want := `
# HELP octo_sts_token_issued_timestamp_seconds Issue time of each token issued in the last two hours, by SHA-256 of the token (hex) and trust policy identity.
# TYPE octo_sts_token_issued_timestamp_seconds gauge
octo_sts_token_issued_timestamp_seconds{identity="policy-a",installation_id="181763887",token_sha256="aaa"} 1.7951706e+09
`
	if err := testutil.CollectAndCompare(info, strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}

	// Once past the TTL, the series is gone and the entry is freed.
	now = now.Add(time.Hour)
	if n := testutil.CollectAndCount(info); n != 0 {
		t.Errorf("series after TTL = %d, want 0", n)
	}
	if len(info.entries) != 0 {
		t.Errorf("entries after TTL = %d, want 0", len(info.entries))
	}
}

func TestTokenInfoPrunesOnAdd(t *testing.T) {
	now := time.Now()
	info := newTokenInfo(time.Hour, func() time.Time { return now })
	info.add("old", "p", "1", now.Add(-2*time.Hour))
	info.add("new", "p", "1", now)
	if _, ok := info.entries["old"]; ok {
		t.Error("add did not prune an expired entry")
	}
}

func TestObserveExchangeLabels(t *testing.T) {
	saved := issuedTokens
	issuedTokens = newTokenInfo(tokenInfoTTL, time.Now)
	t.Cleanup(func() { issuedTokens = saved })

	ctx := context.Background()

	// A matched policy: identity is a label, and the token's info series is
	// exported.
	ok := Event{Identity: "policy-a", TrustPolicy: &OrgTrustPolicy{}, InstallationID: 42, TokenSHA256: "abc", Time: time.Now()}
	before := testutil.ToFloat64(exchangesTotal.WithLabelValues("policy-a", "42", "OK"))
	observeExchange(ctx, ok, nil)
	if got := testutil.ToFloat64(exchangesTotal.WithLabelValues("policy-a", "42", "OK")) - before; got != 1 {
		t.Errorf("exchanges_total{policy-a,42,OK} increased by %v, want 1", got)
	}
	if e, found := issuedTokens.entries["abc"]; !found || e.identity != "policy-a" || e.installation != "42" {
		t.Errorf("token info entry = %+v, %v; want policy-a/42", e, found)
	}

	// No policy found: the caller-supplied identity never becomes a label,
	// and no token was issued.
	bad := Event{Identity: "made-up-by-caller", Time: time.Now()}
	denied := status.Error(codes.NotFound, "unable to find trust policy")
	before = testutil.ToFloat64(exchangesTotal.WithLabelValues(unknownIdentity, "", "NotFound"))
	observeExchange(ctx, bad, denied)
	if got := testutil.ToFloat64(exchangesTotal.WithLabelValues(unknownIdentity, "", "NotFound")) - before; got != 1 {
		t.Errorf("exchanges_total{unknown,,NotFound} increased by %v, want 1", got)
	}
	ch := make(chan prometheus.Metric, 100)
	exchangesTotal.Collect(ch)
	close(ch)
	for m := range ch {
		if strings.Contains(m.Desc().String(), "made-up-by-caller") {
			t.Fatal("a caller-supplied identity became a label")
		}
	}
	if len(issuedTokens.entries) != 1 {
		t.Errorf("token info entries = %d, want 1 (failed exchange added one)", len(issuedTokens.entries))
	}
}
