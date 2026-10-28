# The image only adds poppler-utils (pdftotext, for the MCP read_document tool)
# to a binary built outside of Docker: `make image` cross-compiles it, which is
# much faster than compiling modernc.org/sqlite on a Raspberry Pi. See the
# README.
FROM alpine:3.22
RUN apk add --no-cache ca-certificates poppler-utils
ARG TARGETARCH
COPY dist/foncia-linux-${TARGETARCH} /usr/local/bin/foncia
ENTRYPOINT ["/usr/local/bin/foncia"]
