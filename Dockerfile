# Runtime image for the senselb controller.
#
# GoReleaser cross-compiles the binaries and lays them out in a temporary build
# context as $TARGETPLATFORM/senselb-controller. Building the Go code again here
# would duplicate that work, so this file only assembles the runtime layer: a
# static, non-root image with the pre-built binary. Keeping the base distroless
# also supplies the CA bundle the controller needs for the OPNsense HTTPS API.
#
# It is therefore not a standalone `docker build .` file: use
# `mise run docker-build`, which drives goreleaser and populates the context.

FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETPLATFORM

COPY $TARGETPLATFORM/senselb-controller /senselb-controller

# The controller reads its ConfigMap and Secret at startup, then serves metrics
# on 8080 and the health probes on 8081.
USER nonroot:nonroot
EXPOSE 8080 8081

ENTRYPOINT ["/senselb-controller"]
