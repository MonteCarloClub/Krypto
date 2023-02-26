package main

import (
	"github.com/MonteCarloClub/Krypto/network"
)

func main() {
	server := network.NewServer(":8080")
	server.Start()
}