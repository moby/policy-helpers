# syntax=docker/dockerfile:1

ARG ALPINE_VERSION=3.22
ARG GOLANG_VERSION=1.25
ARG XX_VERSION=1.8.0

ARG ROOT_SIGNING_VERSION=975f28e3597a34098a7c0c07edc16f47420b9aa3

ARG DOCKER_HARDENED_IMAGES_KEYRING_VERSION=04ae44966821da8e5cdcb4c51137dee69297161a

FROM --platform=$BUILDPLATFORM tonistiigi/xx:${XX_VERSION} AS xx

FROM alpine:${ALPINE_VERSION} AS base
RUN apk add --no-cache file git

FROM scratch AS sigstore-root-signing
ARG ROOT_SIGNING_VERSION
ADD --keep-git-dir=true "https://www.github.com/sigstore/root-signing.git#${ROOT_SIGNING_VERSION}" /

FROM scratch AS tuf-root
COPY --from=sigstore-root-signing metadata/root.json metadata/snapshot.json metadata/timestamp.json metadata/targets.json /
COPY --parents --from=sigstore-root-signing targets/trusted_root.json /

FROM base AS tuf-root-update-work
RUN --mount=type=bind,target=/src \
    --mount=type=bind,from=sigstore-root-signing,target=/sigstore-root-signing \
    --mount=type=bind,from=tuf-root,target=/a \
    --mount=type=bind,source=roots/tuf-root,target=/b <<EOT
  set -eu
  if ! diff -ruN /a /b; then
    mkdir -p /out/roots/tuf-root
    cp /src/Dockerfile /out/Dockerfile
    cp -R /a/. /out/roots/tuf-root
    sha="$(git -C /sigstore-root-signing log -n1 --format=%H -- metadata/root.json metadata/snapshot.json metadata/timestamp.json metadata/targets.json targets/trusted_root.json)"
    echo "Updating ROOT_SIGNING_VERSION in Dockerfile to ${sha}"
    sed -i -E 's|^ARG ROOT_SIGNING_VERSION=.*$|ARG ROOT_SIGNING_VERSION='"${sha}"'|' /out/Dockerfile
  fi
EOT

FROM scratch AS tuf-root-update
COPY --from=tuf-root-update-work /out /

FROM base AS validate-tuf-root
RUN --mount=type=bind,from=tuf-root,target=/a \
    --mount=type=bind,source=roots/tuf-root,target=/b \
    diff -ruN /a /b

FROM scratch AS dhi-keyring
ARG DOCKER_HARDENED_IMAGES_KEYRING_VERSION
ADD https://www.github.com/docker-hardened-images/keyring.git#${DOCKER_HARDENED_IMAGES_KEYRING_VERSION} /

FROM scratch AS dhi-pubkey
COPY --from=dhi-keyring /publickey/dhi-latest.pub /dhi.pub

FROM alpine:${ALPINE_VERSION} AS validate-dhi-pubkey
RUN --mount=type=bind,from=dhi-pubkey,target=/a \
    --mount=type=bind,source=roots/dhi,target=/b \
    diff -u /a/dhi-latest.pub /b/dhi.pub

FROM --platform=$BUILDPLATFORM golang:${GOLANG_VERSION}-alpine${ALPINE_VERSION} AS build
COPY --from=xx / /
WORKDIR /go/src/github.com/moby/policy-helpers
ARG TARGETPLATFORM
RUN --mount=target=. xx-go build -o /out/policy-helper ./cmd/policy-helper

FROM scratch AS binary
COPY --from=build /out/policy-helper /
