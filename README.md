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

`-server-*` 与 `-client-*` 二选一,各自的两个参数必须成对出现。
