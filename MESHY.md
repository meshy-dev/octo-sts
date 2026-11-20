# Meshy's octo-sts fork

`meshy-dev/octo-sts` is octo-sts/app plus a small patch that lets us see each
client's GitHub API usage. Meshy runs the image built here
(`ghcr.io/meshy-dev/octo-sts`), deployed from `taichi-dev/deployments`
`k8s/apps/octo-sts/values.yaml`.

## What the patch adds

All of it is in `pkg/octosts/exchange_observe.go`, called from one deferred
call in `Exchange`.

- **A log line per exchange**: `exchange scope=… identity=… issuer=… subject=…
  installation_id=… user_agent=… token_sha256=… [error=…]`.
- **`octo_sts_exchanges_total{identity, installation_id, code}`**: exchanges by
  trust policy and gRPC status. An identity with no policy file is labelled
  `unknown`, because the requested identity is caller-supplied.
- **`octo_sts_token_issued_timestamp_seconds{token_sha256, identity,
  installation_id}`**: one series per token issued in the last two hours.

GitHub's audit log records the SHA-256 of the token behind every API call
(`hashed_token`, base64). The SIEM's audit collector exports those calls as
`github_audit_api_requests_total{actor, token_sha256}` (hex). Joining the two
on `token_sha256` gives each client's call rate:

```promql
sum by (identity) (
  rate(github_audit_api_requests_total{actor=~"meshy-octo-sts.*"}[1h])
  * on (token_sha256) group_left (identity)
  group by (token_sha256, identity) (octo_sts_token_issued_timestamp_seconds)
) * 3600
```

## Keeping up with upstream

Rebase `main` onto `octo-sts/app` `main`, run `go test ./pkg/octosts/...`, and
merge. The `Meshy image` workflow builds and pushes on every push to `main`;
bump the digest in `taichi-dev/deployments`.
