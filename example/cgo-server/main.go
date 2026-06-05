// cgo-server —— 把 dns-tunnel 服务端封装成可被 C / 其它语言调用的静态库 / 共享库。
//
// 公开 C ABI:
//
//	int  StartDnsServer(const char* dnsListen, const char* tcpDest,
//	                    int debug, const char* key, const char* domain,
//	                    int logToFile);
//	     // 返回 0 成功 / -2 已有 server 在跑。Start 走后台 goroutine,本调用不阻塞。
//	     // logToFile=1 时把日志追加写到 <宿主可执行文件目录>/<YYYY-MM-DD>.log,
//	     // =0 时保持默认 stderr。文件打开失败会 fallback 回 stderr,不影响启动。
//	void StopDnsServer(void);
//	int  IsDnsServerRunning(void);
//	     // 1 = 运行中,0 = 未启动 / 已停止 / 致命错误退出。
//
// 编译为静态库 (Linux / macOS):
//
//	CGO_ENABLED=1 go build -buildmode=c-archive -o libdnstunnel_server.a .
//	# 产物: libdnstunnel_server.a + libdnstunnel_server.h
//
// 编译为共享库 (Linux .so / macOS .dylib):
//
//	CGO_ENABLED=1 go build -buildmode=c-shared -o libdnstunnel_server.so .
//
// 编译为 Windows DLL (MinGW 工具链):
//
//	set CGO_ENABLED=1
//	set CC=x86_64-w64-mingw32-gcc
//	go build -buildmode=c-shared -o dnstunnel_server.dll .
//
// 编译为 Windows 静态库 (MinGW):
//
//	set CGO_ENABLED=1
//	set CC=x86_64-w64-mingw32-gcc
//	go build -buildmode=c-archive -o libdnstunnel_server.a .
//
// 注意:
//  1. 服务端需要监听 UDP/53,Linux 上要 root 或 CAP_NET_BIND_SERVICE。
//  2. buildmode=c-archive / c-shared 必须是 package main 且保留空的 main()。
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"sync"

	"github.com/queasy-ma/dns-tunnel/tunnel"
)

var (
	dnsServer *tunnel.DNSServer
	serverMu  sync.Mutex
)

// 创建并在后台启动 DNS 隧道服务端。
//
// 参数:
//
//	dnsListen  DNS 监听地址,例 "0.0.0.0:53"。
//	tcpDest    转发的 TCP 目标,例 "127.0.0.1:22"。每个 stream 建立时 dial 它。
//	debug      非零启用 debug 日志。
//	key        Vigenère 密钥;传 NULL / "" 使用 tunnel.DefaultKey。
//	domain     NS 委派域,例 "t.example.com";空表示直连模式。
//	logToFile  非零时把日志追加写到 <宿主可执行文件目录>/<YYYY-MM-DD>.log,
//	           =0 时保持默认 stderr。多次调用 idempotent（沿用首次打开的文件）。
//
// 返回:
//
//	 0  成功
//	-2  已有 server 在跑（先 Stop 再 Start）
//
// 行为：不阻塞,Start 在后台 goroutine。
//
//export StartDnsServer
func StartDnsServer(dnsListen *C.char, tcpDest *C.char,
	debug C.int, key *C.char, domain *C.char, logToFile C.int) C.int {

	keyStr := C.GoString(key)
	if keyStr == "" {
		keyStr = tunnel.DefaultKey
	}

	// logToFile 透传给 NewDNSServer,失败时 fallback 到 stderr。
	server := tunnel.NewDNSServer(
		C.GoString(dnsListen),
		C.GoString(tcpDest),
		debug != 0,
		keyStr,
		C.GoString(domain),
		logToFile != 0,
	)

	serverMu.Lock()
	if dnsServer != nil {
		serverMu.Unlock()
		return -2
	}
	// MarkRunning 在 go Start 之前调用,消除外部 IsDnsServerRunning 查询的
	// 假阴性窗口（Start goroutine 还没跑到 s.running=true 那一刻）。
	server.MarkRunning()
	dnsServer = server
	serverMu.Unlock()

	go func() {
		_ = server.Start()
		serverMu.Lock()
		if dnsServer == server {
			dnsServer = nil
		}
		serverMu.Unlock()
	}()
	return 0
}

// 优雅停止服务端：Shutdown miekg/dns + close quit（cleanupSessions 退出）。
// 多次调用安全。会话 map 不被显式清空（由 cleanupSessions 自然回收过期项;
// 调用方若需彻底清理,丢掉 dnsServer 指针即可,GC 会收）。
//
//export StopDnsServer
func StopDnsServer() {
	serverMu.Lock()
	s := dnsServer
	dnsServer = nil
	serverMu.Unlock()
	if s != nil {
		s.Close()
	}
}

// 返回 1 表示服务端正在运行;0 表示尚未 Start / 已停止 / Start 内部退出。
//
//export IsDnsServerRunning
func IsDnsServerRunning() C.int {
	serverMu.Lock()
	s := dnsServer
	serverMu.Unlock()
	if s != nil && s.IsRunning() {
		return 1
	}
	return 0
}

// main 必须存在但留空——c-archive / c-shared 不会执行它,只用于满足 package main。
func main() {}
