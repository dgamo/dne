FROM --platform=$BUILDPLATFORM golang:1.26.3-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o /out/dne ./cmd/dne

FROM gcr.io/distroless/static:nonroot

ARG VERSION=dev
LABEL org.opencontainers.image.title="dne" \
      org.opencontainers.image.description="Do-Not-Expire — Prometheus metrics for every certificate stored in Kubernetes Secrets." \
      org.opencontainers.image.source="https://github.com/dgamo/dne" \
      org.opencontainers.image.url="https://github.com/dgamo/dne" \
      org.opencontainers.image.documentation="https://github.com/dgamo/dne#readme" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /out/dne /dne
USER 65532:65532
EXPOSE 8080 8081
ENTRYPOINT ["/dne"]
