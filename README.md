# dne — Do-Not-Expire

[![CI](https://github.com/dgamo/dne/actions/workflows/ci.yaml/badge.svg)](https://github.com/dgamo/dne/actions/workflows/ci.yaml)
[![Release](https://img.shields.io/github/v/release/dgamo/dne?sort=semver)](https://github.com/dgamo/dne/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/dgamo/dne)](https://goreportcard.com/report/github.com/dgamo/dne)

dne is a tiny Kubernetes controller that watches every `Secret` in the cluster, parses any X.509 certificate it finds (in any value, not just `tls.crt`), and exports Prometheus metrics for the certificates' validity windows. Pair it with the bundled Grafana dashboard and PrometheusRule to get a single pane of glass for "which TLS materials are about to expire."

## Highlights

- **Zero configuration to get useful output**: install the chart and you have `dne_certificate_not_after_seconds` for every cert in the cluster.
- **Four formats supported**: PEM (`-----BEGIN CERTIFICATE-----`), raw X.509 DER, PKCS#12 / PFX bundles, and JKS / JCEKS Java keystores (encrypted bundles use a password from the same Secret via annotation — see [docs/configuration.md](docs/configuration.md#pkcs12-password-mapping)).
- **cert-manager interop**: `--skip-cert-manager` filters out Secrets cert-manager already manages, so dne raises alerts only on the rest.
- **Multi-cert chains** via a `cert_index` label.
- **Stable metric lifecycle**: when a cert rotates, the previous series with the old subject/serial/SANs are removed; when a Secret is deleted, all its series are removed. No accumulating stale series.
- **Optional namespace and label-selector filtering** at the watch layer, so large clusters can scope the controller to a subset.
- **Bundled Grafana dashboard and PrometheusRule**, both gated by chart values and discoverable by the kube-prometheus-stack sidecar / operator out of the box.

## Quickstart

```bash
helm repo add dne https://dgamo.github.io/dne
helm repo update

helm install dne dne/dne \
  --namespace dne-system --create-namespace \
  --set serviceMonitor.enabled=true \
  --set prometheusRule.enabled=true \
  --set grafanaDashboard.enabled=true
```

Then in Prometheus:

```promql
# Seconds until each cert expires, joined with identifying labels.
(dne_certificate_not_after_seconds - time())
  * on(namespace, secret, key, cert_index) group_left(subject, issuer, dns_names)
    dne_certificate_info
```

## How it works

dne uses controller-runtime to watch `Secret` objects. For each one it walks every value and tries four formats in sequence, stopping at the first that produces certs:

1. **PEM** — `pem.Decode` in a loop, `x509.ParseCertificate` for each `CERTIFICATE` block.
2. **Raw DER** — `x509.ParseCertificate` directly on the bytes.
3. **PKCS#12** — `pkcs12.DecodeChain` with the password (if any) looked up from the `dne.k8s.io/pkcs12-passwords` annotation; falls back to the empty password for unencrypted bundles.
4. **JKS / JCEKS** — Java KeyStore decoded with the same annotation-supplied password; certificates emitted in alphabetical alias order with sequential `cert_index`.

Values that match none of those are skipped silently. Multi-cert chains produce one metric series per cert, distinguished by a `cert_index` label.

If `--skip-cert-manager` (`skipCertManager: true` in Helm) is on, Secrets bearing `cert-manager.io/certificate-name` are filtered out entirely — their reconciles count toward `dne_reconcile_total{result="skipped"}` and any previously-emitted series are cleared.

Two `Gauge` collectors carry the numeric data (`dne_certificate_not_after_seconds`, `dne_certificate_not_before_seconds`) with a small label set; a companion `dne_certificate_info` gauge carries the identifying labels (subject, issuer, serial, DNS SANs) at value `1`, following the kube-state-metrics pattern. This keeps the queryable gauges low-cardinality while letting dashboards join in the human-readable fields.

A small per-Secret tracker remembers exactly which label combinations were emitted last time, so cert rotation and Secret deletion drop the stale series instead of accumulating them.

## Configuration

See **[docs/configuration.md](docs/configuration.md)** for the full reference. Most-asked-about settings:

| Flag / value             | Default     | Meaning                                                                 |
|--------------------------|-------------|-------------------------------------------------------------------------|
| `namespaces`             | `[]`        | Comma-separated list of namespaces to watch; empty = cluster-wide.      |
| `labelSelector`          | `""`        | Standard k8s label selector applied to Secrets at the watch layer.       |
| `replicaCount`           | `1`         | Run a single replica; enable `leaderElection.enabled` if you want >1.    |
| `serviceMonitor.enabled` | `false`     | Emit a `monitoring.coreos.com/v1 ServiceMonitor` for kube-prometheus.    |
| `prometheusRule.enabled` | `false`     | Emit a `PrometheusRule` with sensible default alert thresholds.          |
| `grafanaDashboard.enabled` | `false`   | Emit a `ConfigMap` labelled `grafana_dashboard=1` for the sidecar.       |

## Metrics

See **[docs/metrics.md](docs/metrics.md)** for the full reference, including the recommended PromQL.

## Alerts

The bundled `PrometheusRule` covers warning / critical expiry, already-expired, not-yet-valid (clock skew), controller-down, and parse errors. See **[docs/alerts.md](docs/alerts.md)**.

## Dashboard

See **[docs/dashboard.md](docs/dashboard.md)**. The dashboard JSON lives at [`deploy/grafana/dne.json`](deploy/grafana/dne.json) and is importable manually if you don't use the sidecar.

## Development

See **[docs/development.md](docs/development.md)**. Short version:

```bash
make test          # unit + envtest, race detector on
make lint          # golangci-lint
make helm-lint     # helm lint + several template combinations
make kind-up
make kind-load IMG=dne:dev
```

## FAQ

**Why a ClusterRole instead of per-namespace Roles?**
Even with `--namespaces` set, dne uses a `ClusterRole` (`secrets: [get,list,watch]`). Per-namespace `Role` objects would be unwieldy in the chart with no real security gain — the controller still authenticates as a single ServiceAccount. If you need strict isolation, deploy dne separately in each namespace.

**Does dne ever write to Secrets?**
No. dne is a read-only observer.

## Contributing

See **[CONTRIBUTING.md](CONTRIBUTING.md)**.

## License

Apache 2.0. See [LICENSE](LICENSE).
