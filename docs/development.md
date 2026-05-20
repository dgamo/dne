# Development guide

## Toolchain

- Go 1.26.3 (matches `go.mod`).
- `golangci-lint` v2.0+.
- `helm` v3.
- `docker` with buildx (for multi-arch builds).
- `kind` (or `minikube`/`k3d`) for end-to-end testing.

## Layout

```
cmd/dne/main.go                 # entrypoint, flag parsing, manager wiring
internal/cert/                  # PEM scanning, X.509 summary
internal/config/                # flag parsing into a typed Config
internal/metrics/               # Prometheus collectors + per-Secret tracker
internal/controller/            # Reconciler
internal/testutil/              # cert generator for tests (no production deps)
deploy/grafana/dne.json         # standalone dashboard (source of truth)
deploy/prometheus/dne-rules.yaml# standalone PrometheusRule (source of truth)
deploy/helm/dne/                # chart; files/ is build-time copies of the above
docs/                           # this directory
.github/workflows/              # CI + release
```

## Common tasks

```bash
make test          # all tests with race detector; uses envtest
make test-unit     # only the packages that don't need envtest
make lint          # golangci-lint
make build         # build ./bin/dne
make docker IMG=dne:dev
make helm-sync     # copy dashboard + rules into the chart
make helm-lint     # helm lint + helm template across values combinations
make kind-up       # create a local kind cluster named dne-test
make kind-load IMG=dne:dev
make kind-down
```

## Running against your local cluster

```bash
go run ./cmd/dne --namespaces=default --log-level=debug
```

dne will pick up your current kubectl context via `controller-runtime`'s `ctrl.GetConfigOrDie()`. The metrics endpoint will be `localhost:8080/metrics`.

Useful: create a small playground:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj "/CN=demo.test" -addext "subjectAltName=DNS:demo.test" \
  -keyout /tmp/tls.key -out /tmp/tls.crt
kubectl create secret tls demo --cert=/tmp/tls.crt --key=/tmp/tls.key
curl -s localhost:8080/metrics | grep demo
```

## Debugging

The reconciler logs at `V(1)` for every parse error and every "secret removed; cleared metrics" event. Run with `--log-level=debug` to see those.

For deeper traces, add temporary `t.Logf` or `setupLog.V(2).Info(...)` calls — controller-runtime ships a verbose logger by default at `V(2+)`. Don't ship those in PRs.

## Profiling

dne does not expose `pprof` by default. If you need it:

```go
// in main.go, behind a hidden flag
import _ "net/http/pprof"
import "net/http"
go func() { _ = http.ListenAndServe("localhost:6060", nil) }()
```

This is a temporary measure for investigating — don't merge it as a permanent feature without a discussion about exposing pprof in production.

## Releasing

See [CONTRIBUTING.md](../CONTRIBUTING.md#releasing).
