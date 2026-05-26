# Changelog

All notable changes to dne are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] — 2026-05-24

### Added
- JKS / JCEKS Java KeyStore detection. Reuses the existing `dne.k8s.io/pkcs12-passwords` annotation for password lookup — operators don't need to know the format, the cascade dispatches on magic bytes.
- `--skip-cert-manager` flag (Helm value `skipCertManager`, default `false`). When on, Secrets bearing `cert-manager.io/certificate-name` are filtered out and any previously-emitted series are cleared via `Tracker.DropSecret` on the next reconcile.
- New `dne_reconcile_total{result="skipped"}` label value, incremented every time the cert-manager filter drops a Secret.
- `internal/testutil`: `NewJKS`, `NewJKSChain`, `NewJKSTruststore` helpers built on `github.com/pavlo-v-chernykh/keystore-go/v4`.

### Changed
- Detection cascade is now four steps: PEM → DER → PKCS#12 → JKS. Existing values that already match earlier steps are unaffected.

## [0.2.1] — 2026-05-24

### Fixed
- Grafana dashboard JSON failed to import because the threshold values used arithmetic expressions (`14 * 86400`) — pre-computed to literals.
- "Top 25 closest to expiry" panel used `topk` (furthest from expiry) instead of `bottomk` (closest), so it surfaced root CAs with decades of validity instead of the leaf certs operators actually care about.

## [0.2.0] — 2026-05-23

### Added
- Raw X.509 DER detection — values that are bare DER bytes (no PEM envelope) are now picked up.
- PKCS#12 / PFX detection, including encrypted bundles. Passwords are sourced from a separate data key in the same Secret via the new `dne.k8s.io/pkcs12-passwords` annotation: `dne.k8s.io/pkcs12-passwords: "cert.p12=cert-password"`. The leaf cert lands at `cert_index="0"`, with any CA chain at incrementing indexes.
- New metric `dne_secret_locked_total{namespace,secret,key,reason}` for values that look like PKCS#12 bundles but couldn't be opened. `reason` ∈ `{pkcs12_no_password, pkcs12_wrong_password, pkcs12_decode_error}`.
- New bundled alert `DNESecretLocked` that fires when any Secret has locked PKCS#12 values for over 30m.
- `internal/testutil`: `NewDER`, `NewPKCS12`, `NewPKCS12Chain` helpers built on `software.sslmate.com/src/go-pkcs12`.

### Changed
- `cert.ParseAll` now takes a `ParseOptions` struct and returns a third value, a slice of `LockedBlob`. Existing PEM behaviour is unchanged.

## [0.1.0] — 2026-05-20

### Added
- Initial controller implementation: watches every `Secret` and exposes Prometheus metrics for the X.509 certificates inside.
- Metrics: `dne_certificate_not_after_seconds`, `dne_certificate_not_before_seconds`, `dne_certificate_info`, `dne_secret_parse_errors_total`, `dne_reconcile_total`.
- Scope filters: `--namespaces` and `--label-selector`, both applied at the watch layer.
- Per-Secret metric lifecycle: cert rotation removes the stale series; Secret deletion clears everything via `DeletePartialMatch`.
- Helm chart under `deploy/helm/dne` with optional `ServiceMonitor`, `PrometheusRule`, and Grafana dashboard `ConfigMap`.
- Standalone Grafana dashboard (`deploy/grafana/dne.json`) and PrometheusRule (`deploy/prometheus/dne-rules.yaml`) for non-Helm installs.
- Documentation under `docs/`: metrics reference, alerts reference, dashboard walkthrough, configuration reference, development guide.
- GitHub Actions: PR CI (golangci-lint, go test with race + coverage, helm lint, container build) and tag-driven release (multi-arch image to ghcr.io, chart via chart-releaser to gh-pages).
