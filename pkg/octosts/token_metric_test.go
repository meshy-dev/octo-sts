// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestIssuedTokenCollectorExpires(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	c := newIssuedTokenCollector(2*time.Hour, func() time.Time { return now })

	c.add("aaa", "org-a", "policy-a", "181763887", now.Add(-90*time.Minute))
	c.add("bbb", "org-b", "policy-b", "182767618", now.Add(-3*time.Hour))

	want := `
# HELP octo_sts_token_issued_timestamp_seconds Issue time of each token issued recently, by the SHA-256 of the token (hex) and the trust policy it was issued under.
# TYPE octo_sts_token_issued_timestamp_seconds gauge
octo_sts_token_issued_timestamp_seconds{identity="policy-a",installation_id="181763887",scope="org-a",token_sha256="aaa"} 1.7951706e+09
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}

	// Past the TTL, the series is gone and the entry is freed.
	now = now.Add(time.Hour)
	if n := testutil.CollectAndCount(c); n != 0 {
		t.Errorf("series after TTL = %d, want 0", n)
	}
	if len(c.entries) != 0 {
		t.Errorf("entries after TTL = %d, want 0", len(c.entries))
	}
}

func TestIssuedTokenCollectorPrunesOnAdd(t *testing.T) {
	now := time.Now()
	c := newIssuedTokenCollector(time.Hour, func() time.Time { return now })
	c.add("old", "org", "p", "1", now.Add(-2*time.Hour))
	c.add("new", "org", "p", "1", now)
	if _, ok := c.entries["old"]; ok {
		t.Error("add did not prune an expired entry")
	}
}

func TestObserveIssuedTokenOnlyOnSuccess(t *testing.T) {
	saved := issuedTokens
	issuedTokens = newIssuedTokenCollector(issuedTokenTTL, time.Now)
	t.Cleanup(func() { issuedTokens = saved })

	issued := Event{Scope: "org/repo", Identity: "policy-a", InstallationID: 42, TokenSHA256: "abc", Time: time.Now()}
	observeIssuedToken(issued, nil)
	got, ok := issuedTokens.entries["abc"]
	if !ok || got.scope != "org/repo" || got.identity != "policy-a" || got.installation != "42" {
		t.Errorf("entry = %+v, %v; want org/repo, policy-a, 42", got, ok)
	}

	// A failed exchange, or one that issued no token, records nothing.
	observeIssuedToken(Event{Identity: "made-up", TokenSHA256: "def", Time: time.Now()}, errors.New("denied"))
	observeIssuedToken(Event{Identity: "policy-b", Time: time.Now()}, nil)
	if len(issuedTokens.entries) != 1 {
		t.Errorf("entries = %d, want 1", len(issuedTokens.entries))
	}
}
