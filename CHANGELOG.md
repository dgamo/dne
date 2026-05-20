# Changelog

All notable changes to dne are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
