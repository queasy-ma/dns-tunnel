# dns-tunnel

把任意 TCP 流量封进 DNS 查询 / 应答的隧道，适用于网络环境复杂、仅 DNS 协议可达的合法授权场景（如自有基础设施上的 SSH、SCP、HTTP 代理等），只依赖 [`miekg/dns`](https://github.com/miekg/dns)。

> **使用声明**：本工具仅适用于使用者对两端网络基础设施均具有合法授权的场景，包括自有服务器、经网络管理员授权的内部网络、以及授权的网络测试与研究环境。在未经授权的网络环境中使用可能违反当地法律法规；使用者须自行承担相应法律责任，作者不对任何未经授权的使用行为承担责任。

---

## 特性

- **单二进制双角色**:`./dns-tunnel` 通过 flag 切换 client / server
- **多 stream 复用**:同一 DNS 会话上最多 254 条并发 TCP 流
- **TXT / NULL 记录自适应**:握手期探测,选择负载更大的记录类型
- **Base32 / Base64url 编码自适应**:握手期探测大小写保留能力
- **Fragsize 探测**:二分握手得到链路实际能承载的下行最大长度
- **小窗口流水线**:握手期自动探测初始窗口，运行期按 data timeout/ack 自动降窗/升窗
- **lazy hold**:服务端把空 poll 挂住最多 1s 再回,空闲期发包频率 ~1Hz
- **poll / data 统一背压**:总 DNS 查询在途受当前运行窗口限制；有上行 backlog 时停止补 poll,避免上传被拉取请求挤占
- **zlib 压缩**(payload > 16 字节时启用)
- **Vigenère 字节扰动**(降低字节特征，非加密，详见 DESIGN.md §4.2)
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

如果隧道客户端处于仅 DNS 协议可达的合法授权网络环境（如自有内网或经管理员授权的场景），可以通过权威 NS 委派把子域 `t.example.com` 指向你控制的 `dns-tunnel` server，这样查询经由递归 DNS 转发抵达。需要在你的 DNS/CDN 控制台配置 NS 委派：

```
t   IN  NS    ns1.example.com.
ns1 IN  A     <SERVER_PUBLIC_IP>  # 不走 CDN 代理，例如 Cloudflare 灰云
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

client 会在握手期从自动上限开始突发探测；CLI 上限为当前 1 字节 seq 空间的安全上限 127，库默认上限为 64。某档失败后按约 1/2 降档继续探测，每档最多 3 轮，选择当前 DNS 路径稳定承载的初始窗口后通过 `cmdWindow` 提交给 server。若所有探测档都失败，会 fallback 到最多 4 的小窗口而不是永久锁死为 1。

运行期使用 AIMD 风格调窗：连续 3 次 data timeout 会自动减半降窗；稳定收到 `max(16, runtime_window*4)` 个 data ack 且距离上次增窗至少 10s 后，保守 `+1` 增窗。握手窗口只是初始值，运行期在链路稳定且持续满载时可以继续升到协议硬上限 127。空闲时只保留 1 个 poll pending；下行活跃且无上行 backlog 时 poll 最多 `min(runtime_window, 16)` 个在途；一旦存在上行 backlog，新的 poll credit 会压到 0，把窗口让给 data。

---

## 作为库使用

`tunnel` 包导出了完整的 API,可以直接嵌入到你自己的 Go 程序中,无需通过命令行启动。

### 导出 API

| 类型/函数 | 说明 |
|---|---|
| `tunnel.NewDNSClient(listenAddr, dnsServer string, debug bool, key string, domain string, logToFile bool)` | 创建客户端实例,`domain` 为空则直连模式;`logToFile=true` 把日志追加写入 `<exe目录>/<YYYY-MM-DD>.log` |
| `tunnel.NewDNSServer(dnsListen, tcpDest string, debug bool, key string, domain string, logToFile bool)` | 创建服务端实例;`logToFile` 同 client 含义 |
| `client.MarkRunning()` / `server.MarkRunning()` | 异步 `Start` 前预先标记运行中,避免调用方立刻查询 `IsRunning()` 时遇到 goroutine 调度竞态 |
| `client.Start() error` | 启动客户端 (阻塞),开始监听 TCP 并通过 DNS 隧道转发 |
| `client.Close()` | 优雅关闭客户端,断开所有连接 |
| `client.IsRunning() bool` | 查询客户端是否正在运行 (线程安全) |
| `client.StatusString() string` | 返回多行 `key=value` 状态,包含记录类型、编码、payload 上限、运行窗口、DNS/poll/upstream 在途数和 stream 数 |
| `server.Start() error` | 启动服务端 (阻塞),监听 DNS 请求并转发到目标 TCP |
| `server.Close()` | 优雅关闭服务端 |
| `tunnel.EnableFileLog() (*os.File, error)` | 手动把日志重定向到 `<exe目录>/<YYYY-MM-DD>.log`;多次调用 idempotent |
| `tunnel.DefaultKey` | 内置的 Vigenere 混淆密钥,客户端和服务端必须一致 |
| `tunnel.DefaultWindow` / `tunnel.MaxWindow` | 库默认窗口探测上限 / 协议硬上限 |

使用约束：

- 同一实例只支持 `Start` 一次；`Close` 后如需重启,请丢弃旧实例并重新 `NewDNSClient` / `NewDNSServer`。
- 同进程可以创建多个 client；server 使用私有 `dns.ServeMux`,也支持多个实例监听不同端口。
- `debug=false` 时库模式只保留少量关键日志；`debug=true` 会输出每个 DNS 查询、ack、stream I/O 等协议级日志。
- Vigenere 只是字节扰动,不是安全加密；生产场景如需机密性应在外层协议或后续 AEAD 改造中处理。

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
        tunnel.DefaultKey,     // Vigenere 扰动密钥
        "t.example.com",       // domain, 空串则直连
        false,                 // logToFile: true 时把日志落到 <exe目录>/<YYYY-MM-DD>.log
    )
    if err != nil {
        log.Fatal(err)
    }

    // Start() 阻塞,放到 goroutine 里。异步启动前先 MarkRunning(),
    // 避免外部马上查询 IsRunning() 时遇到 goroutine 尚未调度的假阴性窗口。
    client.MarkRunning()
    go func() {
        if err := client.Start(); err != nil {
            log.Printf("client stopped: %v", err)
        }
    }()

    // 通过 IsRunning() 判断实例是否仍在运行。
    // 通过 StatusString() 查看运行窗口 / DNS 在途 / poll / upstream 等状态。
    log.Print(client.StatusString())
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
    tunnel.DefaultKey,     // Vigenere 扰动密钥,须与客户端一致
    "t.example.com",       // domain
    false,                 // logToFile
)

server.MarkRunning()
go func() {
    if err := server.Start(); err != nil {
        log.Fatal(err)
    }
}()

// 关闭
server.Close()
```

### CGO 静态库 / 共享库

也可以编译为 C 静态库或共享库,供 C/C++ 程序调用:

```go
// main.go (package main, import "C")
//export StartDnsClient
func StartDnsClient(listenAddr *C.char, dnsServer *C.char, debug C.int, key *C.char, domain *C.char, logToFile C.int) C.int {
    client, err := tunnel.NewDNSClient(C.GoString(listenAddr), C.GoString(dnsServer), debug != 0, C.GoString(key), C.GoString(domain), logToFile != 0)
    if err != nil { return -1 }
    client.MarkRunning()
    go client.Start()
    return 0
}
```

`logToFile=1` 时把日志追加写到宿主可执行文件目录下的 `<YYYY-MM-DD>.log`,适合 host 进程的 stderr 被吞 / 重定向 / 重定向不到屏幕的场景（Windows 服务、systemd、被 GUI 程序加载等）。`logToFile=0` 时维持默认 stderr 输出。文件打开失败会自动 fallback 回 stderr,不会让 NewDNS* 失败。

客户端参考封装还导出 `GetDnsClientStatus()` 和 `FreeDnsTunnelString()`。状态字符串示例：

```text
record_type=NULL
encoding=base64url
max_up_payload=156
max_down_payload=1193
runtime_window=32
dns_inflight=17/32
upstream=1/32
poll=15/0
stream_count=7
```

字段含义：

- `runtime_window`: 当前运行窗口,降窗/升窗都会反映在这里。
- `dns_inflight`: 当前总 DNS 查询在途数 / 当前运行窗口。
- `upstream`: 当前上行 data frame 在途数 / 当前运行窗口。
- `poll`: 当前 poll 在途数 / 当前 poll credit。出现 `poll=15/0` 表示已有旧 poll 在途,但当前因为上行 backlog 已不再允许补新 poll。
- `stream_count`: 当前 client 侧 TCP stream 数。

完整示例见 `example/` 目录：

- `example/embed-client/`  纯 Go 嵌入 client 的最小示例
- `example/embed-server/`  纯 Go 嵌入 server 的最小示例
- `example/cgo-client/`    cgo 静态库 / 共享库形式封装 client（导出 `StartDnsClient` / `StopDnsClient` / `IsDnsClientRunning` / `GetDnsClientStatus` / `FreeDnsTunnelString`）
- `example/cgo-server/`    cgo 静态库 / 共享库形式封装 server（导出 `StartDnsServer` / `StopDnsServer` / `IsDnsServerRunning`）

每个 cgo example 的文件头注释里写了 Linux / macOS / Windows 三平台的 `-buildmode=c-archive` 和 `-buildmode=c-shared` 命令。
