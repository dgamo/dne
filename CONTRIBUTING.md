# Contributing to dne

Thanks for considering a contribution! dne aims to stay a small, focused tool — please open an issue first if you're planning anything beyond a fix or a small enhancement.

## Local setup

Requirements:

- Go 1.26+ (the repo pins `1.26.3` in `go.mod`).
- Docker and a local Kubernetes (kind, minikube, or k3d) for end-to-end checks.
- Helm 3.

Install the envtest binaries used by the integration tests:

```bash
make envtest
```

## The development loop

```bash
make test          # unit + envtest, race detector on
make lint          # golangci-lint
make helm-lint     # helm lint + helm template across several values combinations
make build         # produce ./bin/dne
```

End-to-end against a local kind cluster:

```bash
make kind-up
make kind-load IMG=dne:dev
helm install dne ./deploy/helm/dne \
  --set image.repository=dne --set image.tag=dev --set image.pullPolicy=Never \
  --set serviceMonitor.enabled=true \
  --set prometheusRule.enabled=true \
  --set grafanaDashboard.enabled=true
kubectl port-forward svc/dne 8080:8080
curl localhost:8080/metrics | grep dne_certificate_
```

## Code conventions

- Wrap errors with `fmt.Errorf("...: %w", err)`. Don't swallow errors silently.
- Production code uses `controller-runtime`'s `logr` (via `log.FromContext(ctx)`); tests can use `t.Logf`.
- No new shared mutable state without a mutex and a `-race` test.
- Avoid adding new dependencies unless they pay for themselves in lines of code removed.
- Keep `internal/...` actually internal — no exported types that don't need to be exported.

## Testing conventions

- Every package in `internal/` should have unit tests next to it.
- Test helpers belong in `internal/testutil`. The cert generator there is preferred over checked-in `.pem` testdata that goes stale.
- The reconciler is exercised with envtest (a real `kube-apiserver` + `etcd` provided by `setup-envtest`). Tests that need envtest must skip cleanly when `KUBEBUILDER_ASSETS` is unset.

## Helm chart conventions

- `deploy/grafana/dne.json` and `deploy/prometheus/dne-rules.yaml` are the source of truth for the dashboard and the standalone-applicable rules. The chart consumes a build-time copy under `deploy/helm/dne/files/` via `make helm-sync`.
- Any change to the dashboard or the rules requires running `make helm-sync` and committing the synced copy. CI fails otherwise.
- Touch `deploy/helm/dne/values.schema.json` if you add new values — the schema is what guards users from typos in their values files.

## Submitting changes

1. Branch from `main`, push, open a PR.
2. PR title in present tense, prefixed by scope when useful (`controller:`, `helm:`, `docs:`).
3. Update `CHANGELOG.md` under `## [Unreleased]` for any user-visible change.
4. Make sure `make lint test helm-lint` passes locally.
5. Maintainers will respond within a week. Be patient — this is a side project.

## Releasing

Maintainers only:

1. Move `## [Unreleased]` entries into a new `## [vX.Y.Z]` section in `CHANGELOG.md`. Commit.
2. Tag the release: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. CI builds and pushes the multi-arch image to `ghcr.io/dgamo/dne:vX.Y.Z` (and `:latest`), then publishes the chart to the `gh-pages` branch via `chart-releaser`.
4. Verify the chart shows up at `https://dgamo.github.io/dne/index.yaml`.

## Code of conduct

Be kind. Assume good faith. Disagree on technical specifics, not on people.
