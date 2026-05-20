# dns-tunnel

把任意 TCP 流量封进 DNS 查询 / 应答的隧道。典型场景:**只能解析 DNS 的网络环境**里跑 SSH、SCP、HTTP 代理等,只依赖 [`miekg/dns`](https://github.com/miekg/dns)。

---

## 特性

- **单二进制双角色**:`./dns-tunnel` 通过 flag 切换 client / server
- **多 stream 复用**:同一 DNS 会话上最多 254 条并发 TCP 流
- **TXT / NULL 记录自适应**:握手期探测,选择负载更大的记录类型
- **Base32 / Base64url 编码自适应**:握手期探测大小写保留能力
- **Fragsize 探测**:二分握手得到链路实际能承载的下行最大长度
- **lazy hold**:服务端把空 poll 挂住最多 1s 再回,空闲期发包频率 ~1Hz
- **zlib 压缩**(payload > 16 字节时启用)
- **Vigenère 反 IDS 关键字扰动**(混淆而非加密,详见 DESIGN.md §4.2)
- **两种部署模式**:直连(`-client-dest` 指向 server IP)/ NS 委派(`-domain` 子域走递归解析)

---

## 构建

```bash
go build -o dns-tunnel .
```

依赖见 `go.mod`,仅 `github.com/miekg/dns`。Go 1.23+。

---

## 快速上手:SSH-over-DNS

最常见的两段直连示例 —— SSH 客户端连到本地 2222,通过 DNS 隧道打到远端 SSH 服务。

**服务端**(需要 root 绑定 53):

```bash
sudo ./dns-tunnel \
  -server-listen 0.0.0.0:53 \
  -server-dest 127.0.0.1:22 \
  -debug
```

**客户端**:

```bash
./dns-tunnel \
  -client-listen 127.0.0.1:2222 \
  -client-dest <SERVER_IP>:53 \
  -debug
```

**使用**:

```bash
ssh user@127.0.0.1 -p 2222
```

`-debug` 打开协议级日志。**调试这个项目几乎全靠 debug 日志**,任何反馈最好附上两端的 debug 输出。

---

## NS 委派模式

如果隧道客户端只能解析受限网络里的 DNS,可以通过权威 NS 委派把子域 `t.example.com` 指向你控制的 `dns-tunnel` server,这样查询经由递归 DNS 转发抵达。需要在你的CND配置NS委派：

```
t   IN  NS    ns1.example.com.
ns1 IN  A     <SERVER_PUBLIC_IP> (不走CND代理，即cloudeflare的灰云)
```

启动时两端都加 `-domain t.example.com`:

```bash
# server (公网,需占 53):
sudo ./dns-tunnel -server-listen 0.0.0.0:53 -server-dest 127.0.0.1:22 -domain t.example.com

# client (受限网):
./dns-tunnel -client-listen 127.0.0.1:2222 -client-dest 192.168.1.1:53 -domain t.example.com
```

---

## 命令行参数

| flag | 作用 |
|---|---|
| `-server-listen` | server 监听的 DNS 地址,如 `0.0.0.0:53` |
| `-server-dest` | server 把流量转发到的 TCP 地址,如 `127.0.0.1:22` |
| `-client-listen` | client 本地 TCP 监听地址,如 `127.0.0.1:2222` |
| `-client-dest` | client 要走的 DNS 服务器,如 `192.168.1.1:53` |
| `-domain` | NS 委派模式的子域,如 `t.example.com`;不传则用 `edu` 占位走直连 |
| `-debug` | 打印协议级日志 |
| `-log` | 把日志追加写到 `<可执行文件目录>/<YYYY-MM-DD>.log`（不指定路径,文件名为启动当日日期） |

`-server-*` 与 `-client-*` 二选一,各自的两个参数必须成对出现。

日志默认输出到 stderr,时间戳精度为微秒(便于和 server 端 tcpdump 对齐)。加 `-log` 后切换为文件追加写,跨午夜不滚动 —— 文件名固定为启动当日日期。

---

## 作为库使用

`tunnel` 包导出了完整的 API,可以直接嵌入到你自己的 Go 程序中,无需通过命令行启动。

### 导出 API

| 类型/函数 | 说明 |
|---|---|
| `tunnel.NewDNSClient(listenAddr, dnsServer string, debug bool, key string, domain string)` | 创建客户端实例,`domain` 为空则直连模式 |
| `tunnel.NewDNSServer(dnsListen, tcpDest string, debug bool, key string, domain string)` | 创建服务端实例 |
| `client.Start() error` | 启动客户端 (阻塞),开始监听 TCP 并通过 DNS 隧道转发 |
| `client.Close()` | 优雅关闭客户端,断开所有连接 |
| `client.IsRunning() bool` | 查询客户端是否正在运行 (线程安全) |
| `server.Start() error` | 启动服务端 (阻塞),监听 DNS 请求并转发到目标 TCP |
| `server.Close()` | 优雅关闭服务端 |
| `tunnel.DefaultKey` | 内置的 Vigenere 混淆密钥,客户端和服务端必须一致 |

### 嵌入客户端

```go
package main

import (
    "log"
    "github.com/queasy-ma/dns-tunnel/tunnel"
)

func main() {
    client, err := tunnel.NewDNSClient(
        "127.0.0.1:8080",      // 本地 TCP 监听
        "8.8.8.8:53",          // DNS 服务器
        false,                 // debug
        tunnel.DefaultKey,     // 加密密钥
        "t.example.com",       // domain, 空串则直连
    )
    if err != nil {
        log.Fatal(err)
    }

    // Start() 阻塞, 放到 goroutine 里
    go func() {
        if err := client.Start(); err != nil {
            log.Printf("client stopped: %v", err)
        }
    }()

    // 通过 IsRunning() 判断隧道是否就绪
    // ...

    // 需要关闭时调用 Close(), Start() 会返回
    client.Close()
}
```

### 嵌入服务端

```go
server := tunnel.NewDNSServer(
    "0.0.0.0:53",          // DNS 监听
    "127.0.0.1:22",        // 转发目标
    false,                 // debug
    tunnel.DefaultKey,     // 密钥, 须与客户端一致
    "t.example.com",       // domain
)

go func() {
    if err := server.Start(); err != nil {
        log.Fatal(err)
    }
}()

// 关闭
server.Close()
```

### CGO 静态库

也可以编译为 C 静态库, 供 C/C++ 程序调用:

```go
// main.go (package main, import "C")
//export StartDnsClient
func StartDnsClient(listenAddr *C.char, dnsServer *C.char, debug C.int, key *C.char, domain *C.char, logToFile C.int) C.int {
    if logToFile != 0 {
        if _, err := tunnel.EnableFileLog(); err != nil { return -3 }
    }
    client, err := tunnel.NewDNSClient(C.GoString(listenAddr), C.GoString(dnsServer), debug != 0, C.GoString(key), C.GoString(domain))
    if err != nil { return -1 }
    go client.Start()
    return 0
}
```

`logToFile=1` 时把日志追加写到宿主可执行文件目录下的 `<YYYY-MM-DD>.log`,适合 host 进程的 stderr 被吞 / 重定向 / 重定向不到屏幕的场景（Windows 服务、systemd、被 GUI 程序加载等）。`logToFile=0` 时维持默认 stderr 输出。

```bash
CGO_ENABLED=1 go build -buildmode=c-archive -o libdnstunnel.a .
# 生成 libdnstunnel.a + libdnstunnel.h
```

完整示例见 `example/` 目录：

- `example/embed-client/`  纯 Go 嵌入 client 的最小示例
- `example/embed-server/`  纯 Go 嵌入 server 的最小示例
- `example/cgo-client/`    cgo 静态库 / 共享库形式封装 client（导出 `StartDnsClient` / `StopDnsClient` / `IsDnsClientRunning`）
- `example/cgo-server/`    cgo 静态库 / 共享库形式封装 server（导出 `StartDnsServer` / `StopDnsServer` / `IsDnsServerRunning`）

每个 cgo example 的文件头注释里写了 Linux / macOS / Windows 三平台的 `-buildmode=c-archive` 和 `-buildmode=c-shared` 命令。
