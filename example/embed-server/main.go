// embed-server demonstrates using github.com/queasy-ma/dns-tunnel/tunnel as a library
// to embed a DNS tunnel server into your own application.
//
// Build:  go build -o embed-server .
// Run:    sudo ./embed-server   (port 53 requires root)
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/queasy-ma/dns-tunnel/tunnel"
)

func main() {
	dnsListen := "0.0.0.0:53"
	tcpDest := "127.0.0.1:22"
	domain := "t.example.com" // empty string for direct mode
	debug := true

	server := tunnel.NewDNSServer(dnsListen, tcpDest, debug, tunnel.DefaultKey, domain, false)

	// Start in background goroutine (Start() blocks)
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	fmt.Printf("DNS tunnel server running, DNS %s -> TCP %s\n", dnsListen, tcpDest)

	// Graceful shutdown on SIGINT/SIGTERM
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sig:
		fmt.Println("Shutting down...")
		server.Close()
	case err := <-errCh:
		log.Fatalf("server error: %v", err)
	}

	fmt.Println("Done.")
}
