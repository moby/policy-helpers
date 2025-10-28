# syntax=docker/dockerfile:1.19-labs

ARG ALPINE_VERSION=3.20
ARG ROOT_SIGNING_VERSION=main

FROM scratch AS sigstore-root-signing
ARG ROOT_SIGNING_VERSION
ADD https://www.github.com/sigstore/root-signing.git#${ROOT_SIGNING_VERSION} /

FROM scratch AS tuf-root
COPY --from=sigstore-root-signing metadata/root.json metadata/snapshot.json metadata/timestamp.json metadata/targets.json /
COPY --parents --from=sigstore-root-signing targets/trusted_root.json /

FROM alpine:${ALPINE_VERSION} AS validate-tuf-root
RUN --mount=type=bind,from=tuf-root,target=/a \
    --mount=type=bind,source=roots/tuf-root,target=/b \
    diff -ruN /a /b
