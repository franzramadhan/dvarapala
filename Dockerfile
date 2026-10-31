# Built by .github/workflows/release.yml from static musl binaries with every
# feature (job image-binary) in dist/<arch>/dvarapala, so
# the image compiles nothing and needs no QEMU for arm64. Locally:
#   cargo build --release --target x86_64-unknown-linux-musl -p dvarapala --all-features
#   mkdir -p dist/amd64 && cp target/x86_64-unknown-linux-musl/release/dvarapala dist/amd64/
#   docker build --platform linux/amd64 -t dvarapala .
# Root CAs from Alpine at the path the system root lookup reads, so OIDC
# discovery (RFC 0018), https:// upstreams and TLS stores verify without a
# mounted bundle. ca_file still replaces them. Only files are copied: no
# emulation for the other arch.
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS certs

# RFC 0019: the operator, from the same job (dist/<arch>/dvarapala-operator).
# Build it with --target operator; the default target is the gateway below.
# No CA bundle: it only talks to the API server, whose CA comes with the
# service account.
FROM scratch AS operator
ARG TARGETARCH
COPY --chmod=0755 dist/${TARGETARCH}/dvarapala-operator /dvarapala-operator
USER 10001:10001
ENTRYPOINT ["/dvarapala-operator"]
CMD ["run"]

FROM scratch
ARG TARGETARCH
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chmod=0755 dist/${TARGETARCH}/dvarapala /dvarapala
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/dvarapala"]
CMD ["serve"]
