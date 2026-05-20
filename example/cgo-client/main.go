// cgo-client —— 把 dns-tunnel 客户端封装成可被 C / 其它语言调用的静态库 / 共享库。
//
// 公开 C ABI:
//
//	int  StartDnsClient(const char* listenAddr, const char* dnsServerAddr,
//	                    int debug, const char* key, const char* domain,
//	                    int logToFile);
//	     // 返回 0 成功 / -1 NewDNSClient 失败 / -2 已有 client 在跑。
//	     // Start 走后台 goroutine,此调用本身**不阻塞**。
//	     // logToFile=1 时把日志追加写入 <宿主可执行文件目录>/<YYYY-MM-DD>.log,
//	     // =0 时保持默认 stderr。文件打开失败会 fallback 回 stderr,不影响启动。
//	void StopDnsClient(void);
//	     // 优雅关闭。多次调用安全（第二次起 no-op）。
//	int  IsDnsClientRunning(void);
//	     // 1 = 运行中,0 = 未启动 / 已停止。
//
// 编译为静态库 (Linux / macOS):
//
//	CGO_ENABLED=1 go build -buildmode=c-archive -o libdnstunnel_client.a .
//	# 产物: libdnstunnel_client.a + libdnstunnel_client.h
//
// 编译为共享库 (Linux .so / macOS .dylib):
//
//	CGO_ENABLED=1 go build -buildmode=c-shared -o libdnstunnel_client.so .
//
// 编译为 Windows DLL (MinGW 工具链):
//
//	set CGO_ENABLED=1
//	set CC=x86_64-w64-mingw32-gcc
//	go build -buildmode=c-shared -o dnstunnel_client.dll .
//
// 编译为 Windows 静态库 (MinGW):
//
//	set CGO_ENABLED=1
//	set CC=x86_64-w64-mingw32-gcc
//	go build -buildmode=c-archive -o libdnstunnel_client.a .
//
// 注意：buildmode=c-archive / c-shared 必须是 package main 且**必须**保留空的
// main() 函数（即使永远不被调用）。runtime 会用它做初始化点。
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"sync"

	"github.com/queasy-ma/dns-tunnel/tunnel"
)

// 模块级单例 + 互斥保护。同一进程同时只允许一个客户端实例。
// 想要多实例需要改成 ID → *tunnel.DNSClient 的 map（同时 C 侧接口要返回 handle）。
var (
	dnsClient *tunnel.DNSClient
	clientMu  sync.Mutex
)

// 创建并在后台启动 DNS 隧道客户端。
//
// 参数:
//
//	listenAddr     本地 TCP 监听地址,例 "127.0.0.1:2222"。
//	dnsServerAddr  上游 DNS 服务器,例 "192.168.1.1:53"。直连模式可填服务端 IP:53。
//	debug          非零启用 debug 日志（与 server 同等粒度,会打每个 DNS 查询）。
//	key            Vigenère 密钥;传 NULL / "" 使用 tunnel.DefaultKey。
//	domain         NS 委派域,例 "t.example.com";空表示直连模式。
//	logToFile      非零时把日志追加写到 <宿主可执行文件目录>/<YYYY-MM-DD>.log,
//	               =0 时保持默认 stderr。多次调用 idempotent（沿用首次打开的文件）。
//
// 返回:
//
//	 0  成功
//	-1  NewDNSClient 构造失败
//	-2  已有客户端在跑（先 Stop 再 Start）
//
// 行为：本调用**不阻塞**,Start 在后台 goroutine 里跑。调用后可立即用
// IsDnsClientRunning 查询。
//
//export StartDnsClient
func StartDnsClient(listenAddr *C.char, dnsServerAddr *C.char,
	debug C.int, key *C.char, domain *C.char, logToFile C.int) C.int {

	// logToFile 透传给 NewDNSClient,由它内部决定要不要打开文件。
	// 失败时 NewDNSClient 会 fallback 到 stderr 并继续构造,所以这里没有 -3 错误码,
	// 文件日志是 best-effort 而不是阻塞性需求。
	keyStr := C.GoString(key)
	if keyStr == "" {
		keyStr = tunnel.DefaultKey
	}

	client, err := tunnel.NewDNSClient(
		C.GoString(listenAddr),
		C.GoString(dnsServerAddr),
		debug != 0,
		keyStr,
		C.GoString(domain),
		logToFile != 0,
	)
	if err != nil {
		return -1
	}

	clientMu.Lock()
	if dnsClient != nil {
		clientMu.Unlock()
		return -2
	}
	// MarkRunning 必须在 go Start 之前调用,消除 "Start goroutine 还没跑到
	// running=true 而外部已经在轮询 IsRunning" 的竞态窗口。
	client.MarkRunning()
	dnsClient = client
	clientMu.Unlock()

	go func() {
		// Start 返回错误时,defer 内部会把 running 置回 false,
		// IsDnsClientRunning 之后会返回 0。
		_ = client.Start()
	}()
	return 0
}

// 优雅停止客户端。多次调用安全。
//
//export StopDnsClient
func StopDnsClient() {
	clientMu.Lock()
	c := dnsClient
	dnsClient = nil
	clientMu.Unlock()
	if c != nil {
		c.Close()
	}
}

// 返回 1 表示客户端正在运行;0 表示尚未 Start 或已退出。
//
//export IsDnsClientRunning
func IsDnsClientRunning() C.int {
	clientMu.Lock()
	c := dnsClient
	clientMu.Unlock()
	if c != nil && c.IsRunning() {
		return 1
	}
	return 0
}

// main 必须存在但留空——c-archive / c-shared 不会执行它,只用于满足 package main。
func main() {}
