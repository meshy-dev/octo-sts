// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	v1 "chainguard.dev/sdk/proto/platform/oidc/v1"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/octo-sts/app/pkg/provider"
)

// orgPolicyOnlyAuthContext returns a context carrying a bearer token that
// verifies against a test key set for the GitHub Actions issuer, so an Exchange
// reaches scope validation without real OIDC discovery. The token's subject,
// issuer and audience match testdata/org/.github/foo.sts.yaml and
// testdata/org/repo/foo.sts.yaml, so a request that is not refused proceeds to a
// real policy read.
func orgPolicyOnlyAuthContext(t *testing.T) context.Context {
	t.Helper()

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() = %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: pk}, nil)
	if err != nil {
		t.Fatalf("jose.NewSigner() = %v", err)
	}

	const iss = "https://token.actions.githubusercontent.com"
	token, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Subject:  "foo",
		Issuer:   iss,
		Audience: josejwt.Audience{"octosts"},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
	}).Serialize()
	if err != nil {
		t.Fatalf("Serialize() = %v", err)
	}
	provider.AddTestKeySetVerifier(t, iss, &oidc.StaticKeySet{
		PublicKeys: []crypto.PublicKey{pk.Public()},
	})
	return metadata.NewIncomingContext(context.Background(), metadata.MD{
		"authorization": []string{"Bearer " + token},
	})
}

// TestExchangeOrgPolicyOnlyRefusesRepoScope pins the fix: with OrgPolicyOnly on,
// a repo-scoped exchange ("owner/repo") is refused with PermissionDenied before
// any GitHub call, so no policy is read from the scoped repository and no token
// is minted.
func TestExchangeOrgPolicyOnlyRefusesRepoScope(t *testing.T) {
	ctx := orgPolicyOnlyAuthContext(t)

	// Any request reaching GitHub means the refusal came too late: the whole
	// point is that a repo-scoped exchange never reads a policy or mints a token.
	var hits atomic.Int32
	gh := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotImplemented)
	})
	atr := newAppsTransport(t, gh)
	pool := &ghinstall.OrgPool{M: &fakeInstallMgr{atr: atr}, AppCount: 1}
	router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})
	s := &sts{router: router, orgPolicyOnly: true}

	_, err := s.Exchange(ctx, &v1.ExchangeRequest{
		Identity: "foo",
		Scopes:   []string{"org/repo"},
	})
	if err == nil {
		t.Fatal("Exchange() succeeded, wanted a refusal")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Exchange() error is not a gRPC status: %T", err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("Exchange() code = %v, wanted %v", st.Code(), codes.PermissionDenied)
	}
	if got, want := st.Message(), "repo-scoped exchanges are disabled; policies are read only from the org policy repo"; got != want {
		t.Errorf("Exchange() message = %q, wanted %q", got, want)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("GitHub received %d requests, wanted 0: a repo-scoped exchange read a policy or minted a token", got)
	}
}

// TestExchangeOrgPolicyOnlyAllowsOrgScope is the counterpart: with OrgPolicyOnly
// on, a bare-org scope ("owner") is not refused by this check and the exchange
// succeeds against the org policy repo.
func TestExchangeOrgPolicyOnlyAllowsOrgScope(t *testing.T) {
	key := cacheTrustPolicyKey{owner: "org", repo: ".github", identity: "foo"}
	trustPolicies.Remove(key)
	t.Cleanup(func() { trustPolicies.Remove(key) })

	ctx := orgPolicyOnlyAuthContext(t)
	atr := newAppsTransport(t, newFakeGitHub())
	pool := &ghinstall.OrgPool{M: &fakeInstallMgr{atr: atr}, AppCount: 1}
	router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})
	s := &sts{router: router, orgPolicyOnly: true}

	if _, err := s.Exchange(ctx, &v1.ExchangeRequest{
		Identity: "foo",
		Scopes:   []string{"org"},
	}); err != nil {
		t.Fatalf("Exchange() for a bare-org scope failed: %v", err)
	}
}

// TestExchangeRepoScopeDefaultProceeds pins the default-off behavior: with
// OrgPolicyOnly unset, a repo-scoped exchange still proceeds past this check and
// reads the scoped repository's policy, so an existing deployment is unchanged.
func TestExchangeRepoScopeDefaultProceeds(t *testing.T) {
	key := cacheTrustPolicyKey{owner: "org", repo: "repo", identity: "foo"}
	trustPolicies.Remove(key)
	t.Cleanup(func() { trustPolicies.Remove(key) })

	ctx := orgPolicyOnlyAuthContext(t)
	atr := newAppsTransport(t, newFakeGitHub())
	pool := &ghinstall.OrgPool{M: &fakeInstallMgr{atr: atr}, AppCount: 1}
	router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{"org": pool})
	s := &sts{router: router} // orgPolicyOnly defaults to false

	if _, err := s.Exchange(ctx, &v1.ExchangeRequest{
		Identity: "foo",
		Scopes:   []string{"org/repo"},
	}); err != nil {
		t.Fatalf("Exchange() for a repo-scoped request was not served with the option off: %v", err)
	}
}
