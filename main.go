package main

import (
	"github.com/Kong/go-pdk/server"
)

const (
	Version  = "0.2.0"
	Priority = 1000 // Runs before most plugins but after rate-limiting/cors
)

func New() interface{} {
	return &Config{}
}

func main() {
	_ = server.StartServer(New, Version, Priority)
}
