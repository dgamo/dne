# Metrics reference

All metrics are exposed on `:8080/metrics` (override with `--metrics-bind-address`). The controller-runtime registry also exposes its standard collectors (`controller_runtime_*`, `workqueue_*`, `rest_client_*`, plus Go and process metrics).

## `dne_certificate_not_after_seconds`

- **Type**: gauge
- **Value**: Unix timestamp (seconds) of the certificate's `NotAfter` field.
- **Labels**: `namespace`, `secret`, `key`, `cert_index`.

This is the primary metric. Compute remaining lifetime in Prometheus with `value - time()`.

## `dne_certificate_not_before_seconds`

- **Type**: gauge
- **Value**: Unix timestamp (seconds) of the certificate's `NotBefore` field.
- **Labels**: `namespace`, `secret`, `key`, `cert_index`.

Useful for catching certificates that are not yet valid (clock skew, misissue).

## `dne_certificate_info`

- **Type**: gauge (always `1`)
- **Labels**: `namespace`, `secret`, `key`, `cert_index`, `subject`, `issuer`, `serial`, `dns_names`.

Companion metric carrying identifying information. Following the kube-state-metrics `_info` pattern, the value is always `1`; the metric exists to make subject/issuer/SAN labels available for joins:

```promql
(dne_certificate_not_after_seconds - time())
  * on(namespace, secret, key, cert_index) group_left(subject, issuer, dns_names)
    dne_certificate_info
```

`serial` and `dns_names` are high-cardinality by nature but bounded by the actual number of certs in your cluster. `dns_names` is a comma-joined list of the cert's `Subject Alternative Name` DNS entries.

## `dne_secret_parse_errors_total`

- **Type**: counter
- **Labels**: `namespace`, `secret`, `key`.

Increments when a value contained a `BEGIN CERTIFICATE` block but the DER content could not be parsed (corrupted, truncated, or not actually X.509). Other values in the same Secret are processed normally — the parser is not aborted by one bad block.

## `dne_reconcile_total`

- **Type**: counter
- **Labels**: `result` — one of `success`, `error`, `notfound`.

Useful as a smoke test (`rate(dne_reconcile_total{result="success"}[5m])`) and to alert on rising error rates.

## Label cardinality

The slim metrics carry four labels: `namespace`, `secret`, `key`, `cert_index`. For a cluster with 5,000 Secrets averaging 1.2 certs each, that's roughly 6,000 series per slim gauge, and the same per `dne_certificate_info` (with the additional identifying labels). This is well within typical Prometheus limits.

If your cluster is unusually large and you want to constrain the series count, scope dne with `--label-selector` so it only watches the Secrets you care about.

## Recommended dashboards / queries

- **Top 25 closest to expiry**: see the bundled Grafana dashboard, panel "Top 25 closest to expiry."
- **Already expired**: `count((dne_certificate_not_after_seconds - time()) < 0)`.
- **Reconcile error rate**: `sum(rate(dne_reconcile_total{result="error"}[5m]))`.
- **Parse error rate by secret**: `sum by (namespace, secret) (rate(dne_secret_parse_errors_total[5m]))`.
