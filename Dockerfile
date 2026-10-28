# Built by .github/workflows/release.yml from the static musl release
# binaries in dist/<arch>/dvarapala, so the image compiles nothing and needs
# no QEMU for arm64. Locally:
#   cargo build --release --target x86_64-unknown-linux-musl -p dvarapala
#   mkdir -p dist/amd64 && cp target/x86_64-unknown-linux-musl/release/dvarapala dist/amd64/
#   docker build --platform linux/amd64 -t dvarapala .
# No CA bundle in the image: for an https:// upstream, mount one and set
# upstream_tls.ca_file.
FROM scratch
ARG TARGETARCH
COPY --chmod=0755 dist/${TARGETARCH}/dvarapala /dvarapala
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/dvarapala"]
CMD ["serve"]
