// dns-tunnel 命令行入口。
//
// 单一可执行,通过命令行 flag 区分 client / server：
//   - 提供 -server-listen / -server-dest    → 服务端模式（监听 UDP/53,把数据转给真实 TCP 目标）
//   - 提供 -client-listen / -client-dest    → 客户端模式（监听本地 TCP,把流量编进 DNS 查询）
//
// 部署形态：
//   - 直连模式（default）：客户端把 DNS 查询直接发给服务端 IP,FQDN 尾巴用占位 TLD "edu"。
//   - NS 委派模式（-domain t.example.com）：把权威 NS 指到服务端,客户端通过企业内 DNS 解析器走递归链路。
//
// 协议设计 / 实现细节请看 DESIGN.md；快速 onboarding 看 CLAUDE.md。
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/queasy-ma/dns-tunnel/tunnel"
)

// init 自定义 -h / --help 的输出格式,把两种模式 + 两种部署形态的例子都列出来,
// 让首次使用的人不需要看 README 就能跑起来。
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
  -log                    Write log to <exe-dir>/YYYY-MM-DD.log (append mode)
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
	// 客户端 flag：本地 TCP 监听地址 + 上游 DNS 服务器地址。
	clientListen := flag.String("client-listen", "", "(e.g., 127.0.0.1:8080) Local TCP port to listen on")
	clientDest := flag.String("client-dest", "", "(e.g., 10.0.0.1:53) Remote DNS server address")

	// 服务端 flag：DNS 监听地址 + 真实 TCP 目标地址。
	serverListen := flag.String("server-listen", "", "(e.g., 0.0.0.0:53) DNS listen address")
	serverDest := flag.String("server-dest", "", "(e.g., 127.0.0.1:80) Destination TCP address to forward to")

	// -domain 同时影响两端：客户端把 FQDN 尾巴换成它；服务端用它判断 NS 委派下的标准查询。
	domain := flag.String("domain", "", "(e.g., t.example.com) Domain for NS delegation mode")
	debug := flag.Bool("debug", false, "Enable debug logging")
	logToFile := flag.Bool("log", false, "Write log to <exe-dir>/YYYY-MM-DD.log (append mode)")
	flag.Parse()

	// 顶层先打开文件日志,这样后面的 "Starting DNS tunnel..." 几行也能落盘;
	// 再传 false 给 NewDNS* 避免重复调用 EnableFileLog（其本身是 idempotent,
	// 这里传 false 只是少一次锁开销,语义不影响）。
	if *logToFile {
		f, err := tunnel.EnableFileLog()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to enable file log: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Logging to %s\n", f.Name())
	}

	// 任一 server flag 出现就进入服务端模式。两个必须同时出现,否则报错退出。
	if *serverListen != "" || *serverDest != "" {
		if *serverListen == "" || *serverDest == "" {
			fmt.Println("Error: both server-listen and server-dest are required for server mode")
			fmt.Println("Example: ./dns-tunnel -server-listen 0.0.0.0:53 -server-dest 127.0.0.1:80")
			flag.Usage()
			os.Exit(1)
		}
		server := tunnel.NewDNSServer(*serverListen, *serverDest, *debug, tunnel.DefaultKey, *domain, false)
		log.Printf("Starting DNS tunnel server:")
		log.Printf("  DNS listening on: %s", *serverListen)
		log.Printf("  Forwarding to: %s", *serverDest)
		log.Printf("  Encryption: enabled")
		if *domain != "" {
			log.Printf("  NS delegation domain: %s", *domain)
		} else {
			log.Printf("  Mode: direct")
		}
		// server.Start 阻塞执行（监听 UDP/53）,正常情况不会返回；返回即代表致命错误。
		log.Fatal(server.Start())
	}

	// 任一 client flag 出现就进入客户端模式。两个必须同时出现。
	if *clientListen != "" || *clientDest != "" {
		if *clientListen == "" || *clientDest == "" {
			fmt.Println("Error: both client-listen and client-dest are required for client mode")
			fmt.Println("Example: ./dns-tunnel -client-listen 127.0.0.1:8080 -client-dest 10.0.0.1:53")
			flag.Usage()
			os.Exit(1)
		}
		client, err := tunnel.NewDNSClient(*clientListen, *clientDest, *debug, tunnel.DefaultKey, *domain, false)
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
		// client.Start 阻塞执行（监听本地 TCP + 维持隧道）。
		log.Fatal(client.Start())
	}

	// 两种模式都没指定,打印帮助退出。
	fmt.Println("Error: must specify either client or server mode")
	fmt.Println("\nServer mode example:")
	fmt.Println("  ./dns-tunnel -server-listen 0.0.0.0:53 -server-dest 127.0.0.1:80")
	fmt.Println("\nClient mode example:")
	fmt.Println("  ./dns-tunnel -client-listen 127.0.0.1:8080 -client-dest 10.0.0.1:53")
	flag.Usage()
	os.Exit(1)
}
