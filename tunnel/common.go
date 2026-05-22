// Package tunnel 实现一个 TCP-over-DNS 隧道。
//
// 本文件汇集协议无关的基础设施：
//   - 全局常量（包大小上限、超时、序列号空间等）；
//   - DNS-safe 的 Base32 / Base64 编解码；
//   - Vigenère 流式混淆（注意：**不是**加密，详见 §4.2 DESIGN.md）；
//   - 上行净载估算；
//   - CMC / sessionID / 探测包等小工具；
//   - 简易线程安全的 DataBuf，用于客户端 stream 的上 / 下行字节队列。
//
// 这些原语对 client / server 两侧都通用，跨文件复用时只读、不持有锁。
package tunnel

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 把标准 log 的时间戳精度提到微秒,方便和 server 端 tcpdump（默认微秒）以及
// 客户端 / 服务端两侧之间做时间对齐。秒级精度看不到一秒内多条 poll 的顺序,
// 调 storm 类 bug 时基本没法用。Embedders 想自定义可以在 NewDNS* 之后再覆写。
func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}

// logFileMu 防并发重入 EnableFileLog 时把 log 输出反复切换 / 文件句柄泄漏。
// 重复调用是 no-op：发现 currentLogFile 非 nil 直接返回它本身。
var (
	logFileMu      sync.Mutex
	currentLogFile *os.File
)

// EnableFileLog 把标准 log 包的输出重定向到 <可执行文件所在目录>/<YYYY-MM-DD>.log,
// 追加打开;返回打开的文件句柄。多次调用安全（第二次起返回已经打开的句柄,不再切换输出）。
//
// 设计取舍:
//   - 路径用 os.Executable() 的目录,不用 CWD —— CGO 共享库 / Windows 服务 / systemd
//     之类的场景 CWD 经常是 /(或 C:\Windows\System32),不可写也不直观;
//     "程序目录" 对 CLI 二进制和 c-archive (静态链入业务程序) 都对得上。
//   - 文件名只取启动时的日期,**不滚动**。跨午夜继续写同一个文件;真要按天分割
//     请重启进程或外接 logrotate。
//   - 不与 stderr 复用(不用 io.MultiWriter): 用户传 -log / logToFile=true 的语义
//     通常是 "host 进程的 stderr 不能用,需要落盘",MultiWriter 反而会污染 host stderr。
//     需要两路输出的场景请在外面包 tee。
func EnableFileLog() (*os.File, error) {
	logFileMu.Lock()
	defer logFileMu.Unlock()
	if currentLogFile != nil {
		return currentLogFile, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("os.Executable: %w", err)
	}
	dir := filepath.Dir(exe)
	name := filepath.Join(dir, time.Now().Format("2006-01-02")+".log")
	f, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open log file %s: %w", name, err)
	}
	log.SetOutput(f)
	currentLogFile = f
	return f, nil
}

// 协议级常量。改这些值之前请先看 DESIGN.md §12，里面记录了为什么取这些数字。
const (
	maxDNSNameLen = 250 // 整条 QNAME 长度上限（含 dot）。多数递归解析器对 >255 字节的 name 会拒绝。
	maxLabelSize  = 63  // 单个 label 长度上限（DNS RFC 硬性规定）。编码超过 63 字符要切段。
	maxRetries    = 10  // 握手 / 控制类同步 DNS 请求的最大重试次数。
	retryDelay    = 1 * time.Second
	dnsTimeout    = 5 * time.Second
	// lazyTimeout 是服务端 lazy hold 模式下"一个查询最多挂多久等下行数据"。
	// 这同时也是客户端空闲发包节拍的事实下限——客户端是"收响应立刻发下一个"，
	// 服务端 hold 多久就决定了空闲 QPS 上限（~1Hz）。
	lazyTimeout = 1 * time.Second
	// minLazyHold 是 lazy 模式被关掉时的兜底 hold 时间。
	// 即使 client 或某条配置异常把 lazyMode 关了，handlePollWithAck 也至少
	// 阻塞 minLazyHold 才回空包，把上行 QPS 上限钉在 ~10/s，避免 RTT⁻¹ 死循环。
	minLazyHold = 100 * time.Millisecond
	pollDelay   = 50 * time.Millisecond // 保留常量，目前未直接使用。

	sessionIDLength = 7     // sessionID 字符数（Base32 字符集）。
	cmcLength       = 4     // CMC（Client Message Counter）的 hex 字符长度，即 2 字节随机熵。
	defaultTLD      = "edu" // 直连模式下用作 FQDN 尾巴的占位 TLD；只为让形态像合法域名。
	metaLength      = 6     // 元数据 hex 字符长度（3 字节：seq / frag-last / ack）。

	maxDownPayloadTXT  = 200 // TXT 模式下行 payload 默认上限（握手后可被探测改大）。
	maxDownPayloadNULL = 500 // NULL 模式下行 payload 默认上限。

	// dnsRespOverhead 是 DNS 响应中除 "QNAME 字符数 + rdata 字节" 之外的固定开销估值,
	// 用于 cmdRespSize 探测把 (qnameLen, rdataLen) 折算成 "总响应字节"。
	// 拆解：DNS header 12 + QNAME 包头/null/QTYPE/QCLASS 共 ~6 + RR header ~12
	//      （含 name compression 指针 2B）+ EDNS OPT ~11 + 余量 ~9 = ~50。
	// 略大于实测值即可，保留余量比贴线探测安全（链路上的 MTU / EDNS 阈值往往有抖动）。
	dnsRespOverhead = 50

	// DefaultKey 是 Vigenère 默认密钥。仅用于字节扰动（降低字节特征与已知协议头
	// 的相关性）,不提供机密性保障。要真正加密请换 AEAD（AES-GCM / ChaCha20-Poly1305）+ KDF。
	DefaultKey = "!QAZ@WSX#EDC$RFV%TGB^YHN"

	EncBase32 = 0 // 默认编码：6 段大小写不敏感,扛 0x20 随机化。
	EncBase64 = 1 // 握手协商成功后切到 Base64URL,上行净载提升 ~50%。

	maxStreams = 254 // 单 session 最大并发 TCP 流（streamID 是 uint8,排除 0 用作"无流"哨兵）。
)

var (
	// 不带 padding 的 Base32 / Base64：DNS label 不允许 '=' 之类的填充字符,
	// 用 NoPadding 后字符数恰好对齐 5 bit / 6 bit 切分。
	dnsBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)
	dnsBase64 = base64.URLEncoding.WithPadding(base64.NoPadding)
)

// generateCMC 给每条上行查询生成一个随机的 hex 计数器,塞进 QNAME 第一段。
//
// 作用：让"逻辑上相同"的请求每次 QNAME 都不同,避免上游递归解析器命中本地
// 缓存（缓存 NXDOMAIN / 同名应答会让流量永远到不了我们）。**必须**用
// crypto/rand,math/rand 输出可预测的话会让递归缓存照样命中。
func generateCMC() string {
	b := make([]byte, cmcLength/2)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// encodeDNSSafe 把二进制 data 编进可放进 DNS label 的字符串。
//
// 流程：按 enc 选 Base32 / Base64URL → 按 maxLabelSize 切段 → 用 "." 连接。
// 空 data 返回 "AA"（不是有效编码,但 decode 端识别为空）；保证返回值至少是
// 一个合法 label,不会触发上游对"空 label"的拒绝。
func encodeDNSSafe(data []byte, enc int) string {
	if len(data) == 0 {
		return "AA"
	}
	var encoded string
	switch enc {
	case EncBase64:
		encoded = dnsBase64.EncodeToString(data)
	default:
		encoded = dnsBase32.EncodeToString(data)
	}
	var labels []string
	for i := 0; i < len(encoded); i += maxLabelSize {
		end := i + maxLabelSize
		if end > len(encoded) {
			end = len(encoded)
		}
		labels = append(labels, encoded[i:end])
	}
	return strings.Join(labels, ".")
}

// decodeDNSSafe 与 encodeDNSSafe 反向：去掉段分隔符,按 enc 解码。
// "AA" 和空串都视为空数据（与 encodeDNSSafe 的特殊返回值对齐）。
// Base32 端强制 ToUpper,因为路径上的递归解析器可能用 0x20-bit 随机化大小写。
func decodeDNSSafe(s string, enc int) ([]byte, error) {
	s = strings.ReplaceAll(s, ".", "")
	if s == "" || s == "AA" {
		return []byte{}, nil
	}
	switch enc {
	case EncBase64:
		return dnsBase64.DecodeString(s)
	default:
		return dnsBase32.DecodeString(strings.ToUpper(s))
	}
}

// generateSessionID 生成 7 字符 Base32 字符集的随机 sessionID。
// Base32 字符集（A-Z2-7）天然 case-insensitive,避免 0x20 改写破坏 sessionID。
func generateSessionID() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	result := make([]byte, sessionIDLength)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[n.Int64()]
	}
	return string(result)
}

// maxUpPayload 根据 tld 长度 + 编码方式估算"上行数据段最多能塞多少字节明文"。
//
// 上行 FQDN 形态：
//
//	<CMC>.<DATA>.<META>.<SESSION>.<TLD>
//	4hex + dot + DATA + dot + 6hex + dot + 7字符 + dot + tld + dot
//
// avail 是 DATA 段总字符数,然后再扣掉 label 切分导致的额外 dot 字符,
// 最后按编码膨胀比换算回明文字节数。膨胀比：
//   - Base32：8 字符表示 5 字节,即明文字节 = 字符数 × 5/8。
//   - Base64：4 字符表示 3 字节,即明文字节 = 字符数 × 3/4。
func maxUpPayload(tld string, enc int) int {
	return maxUpPayloadWithBudget(tld, enc, maxDNSNameLen)
}

// maxUpPayloadWithBudget 同 maxUpPayload，但用调用方给的 QNAME 字符预算
// （而不是常量 maxDNSNameLen）。客户端探测出运行时实际可用 QNAME 长度后用这个。
func maxUpPayloadWithBudget(tld string, enc int, nameBudget int) int {
	overhead := cmcLength + 1 + metaLength + 1 + sessionIDLength + 1 + len(tld) + 1 + 2
	avail := nameBudget - overhead
	if avail < 0 {
		return 0
	}
	dataChars := avail - avail/maxLabelSize
	switch enc {
	case EncBase64:
		return dataChars * 3 / 4
	default:
		return dataChars * 5 / 8
	}
}

// makeFixedLengthLabels 构造一段总字符长度恰好为 charLen 的 DNS-safe 字符串，
// 按 maxLabelSize (63) 切分用 "." 连接。用于 QNAME 长度探测——服务端不解 dataStr，
// 我们只关心 QNAME 总长。
//
// **填充字符使用 base64url 字母表**（含 `_`、`-`、数字、混合大小写）：必须和真实
// 数据帧的字符集一致，否则探测会**假阳性**——某些递归链对长 QNAME 含 `_` / `-` 的
// 才会触发过滤，全 'A' 字符的探测包反而过得了，导致探测出的上限比实际能用的大。
//
// label 第一个字符强制不取 `-`（开头是 `-` 违反 RFC 952 hostname 规约，部分递归会
// 直接拒绝）；base64url 字母表里 `-` 排在最末位（index 63）所以从 offset=1 开始
// 取就能保证 label[0] 总是字母。
//
// 算法保证：strings.Join 之后的字符串长度 == charLen，且每个 label 都 1..63 长。
func makeFixedLengthLabels(charLen int) string {
	if charLen <= 0 {
		return ""
	}
	// 64-char base64url-style alphabet; index 62='_', 63='-'.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	fill := func(n int) string {
		b := make([]byte, n)
		for i := 0; i < n; i++ {
			// offset+1 让 label[0]='B'（避开 '-' / '_' 开头）。
			b[i] = alphabet[(i+1)%64]
		}
		return string(b)
	}
	if charLen <= maxLabelSize {
		return fill(charLen)
	}
	var parts []string
	chars := charLen
	for chars > maxLabelSize {
		parts = append(parts, fill(maxLabelSize))
		chars -= maxLabelSize + 1
	}
	if chars == 0 {
		last := parts[len(parts)-1]
		parts[len(parts)-1] = last[:len(last)-1]
		parts = append(parts, fill(1))
	} else if chars > 0 {
		parts = append(parts, fill(chars))
	}
	return strings.Join(parts, ".")
}

// vigenereEncrypt 用 key 做按字节加法混淆。
//
// 作用范围：让明文上下行字节不再是连续 ASCII / 已知协议头,降低字节特征
// 比"裸 base32 + 控制字符"强一些。**不要**把这当机密性保障：
//   - 长度泄露：密文长度 == 明文长度；
//   - 无认证：攻击者翻转任意 bit 不会被检测；
//   - 密钥短：DefaultKey 24 字节,容易被已知明文还原。
//
// 生产环境一定要换成 AEAD（AES-GCM / ChaCha20-Poly1305）+ KDF。
func vigenereEncrypt(data []byte, key string) []byte {
	if len(key) == 0 {
		return data
	}
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = byte((int(b) + int(key[i%len(key)])) % 256)
	}
	return result
}

// vigenereDecrypt 是 vigenereEncrypt 的逆操作。+256 防止 int 减法出现负数。
func vigenereDecrypt(data []byte, key string) []byte {
	if len(key) == 0 {
		return data
	}
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = byte((int(b) - int(key[i%len(key)]) + 256) % 256)
	}
	return result
}

// DataBuf 是带锁的字节队列,client 侧每个 stream 用两个：
//   - upBuf  ：本地 TCP read 来的字节,等待写进 DNS 上行 QNAME；
//   - downBuf：DNS 下行 payload 解出来的字节,等待写进本地 TCP socket。
//
// 与裸 channel 比的优势：可以 Take 任意长度（DNS 上行 payload 上限是动态的）,
// 不会被定长块分割。Write / Take 都持锁,可并发使用。
type DataBuf struct {
	mu   sync.Mutex
	data []byte
}

// Write 追加字节。注意：调用方应当对 DataBuf 不持有 stream 锁,避免与读路径死锁。
func (b *DataBuf) Write(d []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, d...)
}

// Take 取出最多 max 字节,返回新分配的 copy（让调用方可以放心修改）。
// 没数据时返回 nil（而不是空切片）,便于调用方用 if data != nil 区分。
func (b *DataBuf) Take(max int) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.data) == 0 {
		return nil
	}
	n := max
	if n > len(b.data) {
		n = len(b.data)
	}
	chunk := make([]byte, n)
	copy(chunk, b.data[:n])
	b.data = b.data[n:]
	return chunk
}

// Len 返回当前缓冲字节数。仅用于调度判断"有没有数据要送"。
func (b *DataBuf) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.data)
}

// testEncodingRoundtrip 验证一份测试数据能否在指定编码下 encode → decode 还原。
// 握手期 Base64URL 探测时用,如果路径上有把 +/= 改写、把大小写翻乱的"乖巧"递归
// 解析器,这里就会失败,客户端回退到 Base32。
func testEncodingRoundtrip(data []byte, enc int) bool {
	encoded := encodeDNSSafe(data, enc)
	decoded, err := decodeDNSSafe(encoded, enc)
	if err != nil {
		return false
	}
	if len(decoded) != len(data) {
		return false
	}
	for i := range data {
		if data[i] != decoded[i] {
			return false
		}
	}
	return true
}

// generateFragSizeProbe 造一段 size 字节的"可预测内容"探测数据。
//
// 用于 fragsize 二分探测：服务端按客户端要的 size 造一份这种数据回去,
// 客户端检查回包长度 ≥ size 即认为该 size 在链路上能稳定承载。内容用
// 递增 byte（i & 0xFF）只是为了好看,完全可以是任意确定字节。
func generateFragSizeProbe(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i & 0xFF)
	}
	return data
}

// generateNULLFragSizeProbe 造一段 size 字节的随机探测数据并用 key 做 Vigenère 加密。
//
// NULL 记录直接承载原始字节，固定递增内容（0x00, 0x01, ...）在链路上特征明显；
// 用随机字节 + 加密让探测包和正常数据包在字节分布上无法区分。
// 客户端只校验回包长度 ≥ size，加密不影响判断。
func generateNULLFragSizeProbe(size int, key string) []byte {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		// crypto/rand 失败极罕见；退化为递增字节保证探测能继续。
		for i := range data {
			data[i] = byte(i & 0xFF)
		}
	}
	return vigenereEncrypt(data, key)
}

// buildFQDN 用 "." 把 parts 串成 FQDN。单独抽出来仅为了语义清晰。
func buildFQDN(parts ...string) string {
	return strings.Join(parts, ".")
}

// formatSize 把整数 size 编码为 4 位小写 hex,放进 FQDN 的 size 段。
// 控制字段都用定长 hex,方便服务端按位置切片。
func formatSize(size int) string {
	return fmt.Sprintf("%04x", size)
}

// parseSize 是 formatSize 的逆操作。手写 hex 解析（不调 strconv）是为了
// 接受大小写混合（路径上 0x20 改写后,'A'..'F' 可能变成 'a'..'f'）。
func parseSize(s string) (int, error) {
	if len(s) != 4 {
		return 0, fmt.Errorf("bad size: %s", s)
	}
	var v int
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int(c - '0')
		case c >= 'a' && c <= 'f':
			v |= int(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v |= int(c - 'A' + 10)
		default:
			return 0, fmt.Errorf("bad hex: %c", c)
		}
	}
	return v, nil
}
