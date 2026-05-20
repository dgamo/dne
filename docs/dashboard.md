# Grafana dashboard

The bundled dashboard lives at [`deploy/grafana/dne.json`](../deploy/grafana/dne.json) (UID `dne-overview`). It is intentionally minimal — a one-screen overview, not a deep operational console.

## Importing

### Via the Helm chart (kube-prometheus-stack)

```bash
helm upgrade dne dne/dne --reuse-values --set grafanaDashboard.enabled=true
```

The chart renders a `ConfigMap` labelled `grafana_dashboard=1`, which the standard kube-prometheus-stack sidecar picks up automatically. By default the ConfigMap goes into the release namespace; override with `grafanaDashboard.namespace` if your sidecar watches a different namespace.

### Manual import

In Grafana → Dashboards → Import → "Upload JSON file" → select `deploy/grafana/dne.json`.

Or via the Grafana API:

```bash
curl -X POST -H "Authorization: Bearer $GRAFANA_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"dashboard\": $(cat deploy/grafana/dne.json), \"overwrite\": true}" \
  https://grafana.example.com/api/dashboards/db
```

## Panels

1. **Certificates tracked** — total cert count after the namespace/secret filters.
2. **Expiring within 30 days** — quick "how big is the rotation backlog" stat.
3. **Already expired** — should be `0`. If not, you have an active outage in waiting.
4. **Reconcile success rate** — health of the controller itself.
5. **Top 25 closest to expiry** — table sorted ascending by time-until-expiry, with subject/issuer/DNS columns. This is the panel you'll spend most of your time on.
6. **Parse error rate** — surfaces Secrets where dne is finding PEM-shaped data it can't parse.
7. **Reconcile rate by result** — useful for spotting elevated `error` results that don't make it to `_total`-style alerts.

## Variables

- `datasource` — Prometheus datasource picker.
- `namespace` — multi-select, populated from `label_values(dne_certificate_not_after_seconds, namespace)`.
- `secret` — multi-select, filtered by the selected namespace(s).

The default refresh is `1m`. Time range is `now-6h..now`; expiry timestamps are absolute, so changing the range has no effect on the cert-expiry panels — only on the rate-based ones (parse errors, reconciles).
