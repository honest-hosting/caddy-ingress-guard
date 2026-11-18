# caddy-ingress-guard

A Caddy module that enforces signed policy bundles. A local agent pushes each bundle to the
module's loopback endpoint; the module verifies it, builds a new WAF instance in the background
and swaps it in atomically, without a Caddy reload.

> **Status: spike prototype (S2).** Not for production. Site and multi modes accept bundles;
> multi-site host selection and the access-stage controls aren't implemented yet.

## Pieces

| Path | What |
|---|---|
| `proto/ingressguard/v1/bundle.proto` | The bundle format: the module's public contract |
| `bundle/` | Build, sign and verify bundles (producers and the module share it) |
| `app.go`, `runtime.go`, `compose.go`, `push.go` | The `ingress_guard` Caddy app: state kept across reloads, verification, layer composition, push endpoint |
| `handler.go` | The `ingress_guard` HTTP handler (`access` and `inspect` stages) |
| `cmd/ingress-guard-bundle` | Keys, keysets, bundles, push, and the S2 load tools (`flip`, `junk`) |

## Caddyfile

```caddyfile
{
	order ingress_guard_access before sidekick
	order ingress_guard_inspect before php_server

	ingress_guard {
		mode site
		target layer:global layer:dc:{$NOMAD_DC} site:{$INGRESS_GUARD_SITE_UUID}
		root_key root <base64 Ed25519 public key>
		push_listen 127.0.0.1:2020
	}
}
```

- **Modes:** `site` (FrankenWP), `multi` (ingress tier, `ingress:<pool>`), `static` (rules from
  `static_directives` / `static_file`, no push endpoint).
- **`stale_bootstrap`:** accepts an expired bundle when nothing is active for its target (the
  ingress agent's last-known-good). Never enable it where tenant code runs.

## Push endpoint

- `PUT /v1/bundle` with a `SignedBundle` body; the response is an `Ack`.
- `GET /v1/status`.
- Loopback only; 10 requests/s, burst 20. Send `Accept: application/json` for JSON.
- Verification order: size → target → sequence → keyset and signature → time → payload hash →
  decompress → sections → build → swap. A rejected or failed bundle leaves the active one in
  place.

## Build

```bash
make vet test        # vet both build-tag variants; unit tests
make caddy           # bin/caddy (Caddy 2.11.7 + module)
make caddy-panic     # with -tags ingressguard_panicinject (S2)
make caddy-race      # with the race detector (S2)
make tool            # bin/ingress-guard-bundle
make proto           # regenerate bundle/bundlepb
```

The module requires Go 1.26 (Caddy 2.11.7). Builds pin their toolchain; they must not inherit a
floating builder Go.
