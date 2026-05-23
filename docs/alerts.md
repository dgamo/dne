# Alerts reference

dne ships a `PrometheusRule` (also available standalone at [`deploy/prometheus/dne-rules.yaml`](../deploy/prometheus/dne-rules.yaml)) with two groups: certificate-validity alerts and operational alerts.

When installed via Helm with `--set prometheusRule.enabled=true`, the same alerts are rendered with thresholds taken from `prometheusRule.thresholds.warning` (days) and `prometheusRule.thresholds.critical` (days). The standalone file ships hard-coded defaults of `14` and `3` days.

## Certificate alerts

### `DNECertificateExpiringSoon`

- **Severity**: warning
- **For**: 15m
- **Expression**:
  ```
  (dne_certificate_not_after_seconds - time()) < (warning * 24 * 3600)
  and (dne_certificate_not_after_seconds - time()) > (critical * 24 * 3600)
  ```
- **Meaning**: cert expires inside the warning window but not yet inside the critical window.
- **How to silence**: rotate the certificate (cert-manager, manual reissue, or external automation) or, if you need a temporary silence, label the Secret out of dne's selector.

### `DNECertificateExpiringCritical`

- **Severity**: critical
- **For**: 5m
- **Expression**:
  ```
  (dne_certificate_not_after_seconds - time()) < (critical * 24 * 3600)
  and (dne_certificate_not_after_seconds - time()) > 0
  ```
- **Meaning**: cert expires inside the critical window.
- **How to silence**: same as above — rotate the cert. If something is intentionally short-lived and you don't want it to alert, exclude it via the controller's `--label-selector`.

### `DNECertificateExpired`

- **Severity**: critical
- **For**: 1m
- **Expression**: `(dne_certificate_not_after_seconds - time()) < 0`
- **Meaning**: cert is already past `NotAfter`. Any client doing TLS verification against this cert will fail.

### `DNECertificateNotYetValid`

- **Severity**: warning
- **For**: 15m
- **Expression**: `(dne_certificate_not_before_seconds - time()) > 0`
- **Meaning**: cert's `NotBefore` is in the future. Usually one of:
  - Clock skew on the cluster nodes.
  - A pre-provisioned cert that isn't supposed to be active yet (sometimes intentional during a planned rotation).
- **How to silence**: fix node clocks (`ntp`/`chrony`) or wait for `NotBefore`.

## Operational alerts

### `DNEControllerDown`

- **Severity**: critical
- **For**: 5m
- **Expression**: `up{job=~".*dne.*"} == 0`
- **Meaning**: Prometheus isn't successfully scraping dne. The cert metrics are stale; the rest of the alerts may not fire reliably.

### `DNEParseErrorsRising`

- **Severity**: warning
- **For**: 30m
- **Expression**: `sum by (namespace, secret) (rate(dne_secret_parse_errors_total[15m])) > 0`
- **Meaning**: dne found PEM `CERTIFICATE` blocks it couldn't parse as X.509 in some Secret. Usually a corrupted cert or a value that happens to start with `-----BEGIN CERTIFICATE-----` but is malformed.

### `DNESecretLocked`

- **Severity**: warning
- **For**: 30m
- **Expression**: `sum by (namespace, secret) (dne_secret_locked_total) > 0`
- **Meaning**: dne found at least one value in this Secret that looks like a PKCS#12 / PFX bundle but couldn't open it (no password supplied, wrong password, or a decode error). These certs are not being tracked.
- **How to silence**: add the `dne.k8s.io/pkcs12-passwords` annotation pointing each encrypted data key to the data key holding its password (same Secret). See `docs/configuration.md` for the annotation contract. If the bundle is genuinely something you don't want to track (e.g. a test fixture), label the Secret out of dne's selector instead.

## Routing tips

These alerts include the labels `namespace` and `secret` — route them to the team that owns the Secret. If you label your Secrets with team ownership, add a relabeling step in your Alertmanager config to project the team label onto the alert.

## Tuning thresholds

The default `warning=14, critical=3` is conservative for a cluster that uses cert-manager or short-lived service mesh certs. If your environment relies heavily on long-lived certs that you renew on a quarterly cadence, raise `warning` to `30` and `critical` to `7`:

```bash
helm upgrade dne dne/dne --reuse-values \
  --set prometheusRule.thresholds.warning=30 \
  --set prometheusRule.thresholds.critical=7
```
