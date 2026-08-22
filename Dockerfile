FROM golang:1.26-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /kong-jwt-keycloak ./cmd/kong-jwt-keycloak

FROM busybox:1.37
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /kong-jwt-keycloak /kong-jwt-keycloak
ENTRYPOINT ["/kong-jwt-keycloak"]
