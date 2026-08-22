package main

import (
	"github.com/Kong/go-pdk/server"

	"github.com/open-source-cloud/kong-jwt-keycloak/internal/plugin"
)

const (
	Version  = "0.3.0" // x-release-please-version
	Priority = 1000
)

func New() interface{} {
	return &plugin.Config{}
}

func main() {
	_ = server.StartServer(New, Version, Priority)
}
