// embed-client demonstrates using github.com/queasy-ma/dns-tunnel/tunnel as a library
// to embed a DNS tunnel client into your own application.
//
// Build:  go build -o embed-client .
// Run:    ./embed-client
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/queasy-ma/dns-tunnel/tunnel"
)

func main() {
	listenAddr := "127.0.0.1:8080"
	dnsServer := "8.8.8.8:53"
	domain := "t.example.com" // empty string for direct mode
	debug := true

	client, err := tunnel.NewDNSClient(listenAddr, dnsServer, debug, tunnel.DefaultKey, domain, false)
	if err != nil {
		log.Fatalf("NewDNSClient: %v", err)
	}

	// Start in background goroutine (Start() blocks)
	go func() {
		if err := client.Start(); err != nil {
			log.Printf("client stopped: %v", err)
		}
	}()

	// Wait for tunnel to be ready
	for i := 0; i < 30; i++ {
		if client.IsRunning() {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !client.IsRunning() {
		log.Fatal("client failed to start")
	}
	fmt.Printf("DNS tunnel client running, TCP %s -> DNS %s\n", listenAddr, dnsServer)

	// Graceful shutdown on SIGINT/SIGTERM
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("Shutting down...")
	client.Close()

	// Wait for IsRunning() to become false
	for i := 0; i < 50; i++ {
		if !client.IsRunning() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("Done.")
}
