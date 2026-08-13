# Build multi-arch: docker buildx build --platform linux/arm/v7 -t wg-portal .
# (linux/arm/v7 = MikroTik serie ARM 32-bit come L009; linux/arm64 per hAP ax/RB5009; linux/amd64 per CHR/x86)
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags="-s -w" -o /wg-portal .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /wg-portal /wg-portal
EXPOSE 8080
ENTRYPOINT ["/wg-portal"]
