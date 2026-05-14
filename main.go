package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"dns-tunnel/tunnel"
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
Usage: %s [options]

Server Mode Options:
  -server-listen string    Address to listen for DNS requests (e.g., "0.0.0.0:53")
  -server-dest string      Destination address to forward traffic (e.g., "10.0.0.1:22")

Client Mode Options:
  -client-listen string    Local address to listen for TCP connections (e.g., "127.0.0.1:2222")
  -client-dest string      DNS server address to tunnel through (e.g., "8.8.8.8:53")

Common Options:
  -domain string          Domain for NS delegation mode (e.g., "t.example.com")
  -debug                  Enable debug logging
  -h                      Show this help message

Examples:
  # Direct mode - server listening on UDP port 53, forwarding to SSH server:
  sudo %s -server-listen 0.0.0.0:53 -server-dest 10.0.0.1:22

  # Direct mode - client tunneling through DNS server:
  %s -client-listen 127.0.0.1:2222 -client-dest dns.example.com:53

  # NS delegation mode - server with domain:
  sudo %s -server-listen 0.0.0.0:53 -server-dest 10.0.0.1:22 -domain t.example.com

  # NS delegation mode - client through local DNS:
  %s -client-listen 127.0.0.1:2222 -client-dest 192.168.1.1:53 -domain t.example.com

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
	}
}

func main() {
	// Client flags
	clientListen := flag.String("client-listen", "", "(e.g., 127.0.0.1:8080) Local TCP port to listen on")
	clientDest := flag.String("client-dest", "", "(e.g., 10.0.0.1:53) Remote DNS server address")

	// Server flags
	serverListen := flag.String("server-listen", "", "(e.g., 0.0.0.0:53) DNS listen address")
	serverDest := flag.String("server-dest", "", "(e.g., 127.0.0.1:80) Destination TCP address to forward to")

	domain := flag.String("domain", "", "(e.g., t.example.com) Domain for NS delegation mode")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	// Server mode if server flags are set
	if *serverListen != "" || *serverDest != "" {
		if *serverListen == "" || *serverDest == "" {
			fmt.Println("Error: both server-listen and server-dest are required for server mode")
			fmt.Println("Example: ./dns-tunnel -server-listen 0.0.0.0:53 -server-dest 127.0.0.1:80")
			flag.Usage()
			os.Exit(1)
		}
		server := tunnel.NewDNSServer(*serverListen, *serverDest, *debug, tunnel.DefaultKey, *domain)
		log.Printf("Starting DNS tunnel server:")
		log.Printf("  DNS listening on: %s", *serverListen)
		log.Printf("  Forwarding to: %s", *serverDest)
		log.Printf("  Encryption: enabled")
		if *domain != "" {
			log.Printf("  NS delegation domain: %s", *domain)
		} else {
			log.Printf("  Mode: direct")
		}
		log.Fatal(server.Start())
	}

	// Client mode if client flags are set
	if *clientListen != "" || *clientDest != "" {
		if *clientListen == "" || *clientDest == "" {
			fmt.Println("Error: both client-listen and client-dest are required for client mode")
			fmt.Println("Example: ./dns-tunnel -client-listen 127.0.0.1:8080 -client-dest 10.0.0.1:53")
			flag.Usage()
			os.Exit(1)
		}
		client, err := tunnel.NewDNSClient(*clientListen, *clientDest, *debug, tunnel.DefaultKey, *domain)
		if err != nil {
			log.Fatalf("Failed to create DNS client: %v", err)
		}
		log.Printf("Starting DNS tunnel client:")
		log.Printf("  TCP listening on: %s", *clientListen)
		log.Printf("  Tunneling to DNS server: %s", *clientDest)
		log.Printf("  Encryption: enabled")
		if *domain != "" {
			log.Printf("  NS delegation domain: %s", *domain)
		} else {
			log.Printf("  Mode: direct")
		}
		log.Fatal(client.Start())
	}

	// If no mode selected, show usage
	fmt.Println("Error: must specify either client or server mode")
	fmt.Println("\nServer mode example:")
	fmt.Println("  ./dns-tunnel -server-listen 0.0.0.0:53 -server-dest 127.0.0.1:80")
	fmt.Println("\nClient mode example:")
	fmt.Println("  ./dns-tunnel -client-listen 127.0.0.1:8080 -client-dest 10.0.0.1:53")
	flag.Usage()
	os.Exit(1)
}
