# syntax=docker/dockerfile:1.7
# Krivy controller image. Multi-arch via buildx (TARGETOS/TARGETARCH).

ARG GO_VERSION=1.27

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build
WORKDIR /src

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown

ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=readonly

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags "-s -w -X github.com/l4r-s/krivy/internal/version.Version=${VERSION} -X github.com/l4r-s/krivy/internal/version.Commit=${COMMIT}" \
      -o /out/krivy ./cmd/krivy

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="krivy" \
      org.opencontainers.image.description="Kubernetes CVE-scanning controller using ephemeral Trivy Jobs" \
      org.opencontainers.image.source="https://github.com/l4r-s/krivy" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/krivy /krivy

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/krivy"]
