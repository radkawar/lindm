# Build the embedded console first, then a Linux CGO_ENABLED=0 lindmd binary.
# The build context must contain only that release binary as ./lindmd; never
# send configuration, credentials or the checkout to the image builder.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --chmod=0555 lindmd /usr/bin/lindmd
USER 65532:65532
WORKDIR /
EXPOSE 18444 18445
ENTRYPOINT ["/usr/bin/lindmd"]
CMD ["serve", "-config", "/etc/lindm/server.json"]
