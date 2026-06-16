// 本文件实现 dns-tunnel 的客户端侧。
//
// 角色：监听本地 TCP,把每个连接映射成一条 stream,数据编进 DNS 查询 QNAME 发给服务端；
// DNS 应答解码后写回本地 TCP socket。
//
// 关键组件：
//   - DNSClient        ：客户端运行态,管理监听 socket + sessionID + stream 表。
//   - dataLoop         ：唯一负责"发上行 + 收下行"的 goroutine；空闲 1 pending,
//     活跃时使用 session 级小窗口；active-down poll 另有较小上限。
//   - dnsRecvLoop      ：唯一负责底层 socket 读的 goroutine,解出 DNS 响应送入 recvCh。
//   - streamReader     ：每个 stream 一个,本地 TCP read → 入 upBuf,唤醒 dataLoop。
//   - streamWriter     ：每个 stream 一个,从 downBuf 异步写本地 TCP,不阻塞 dataLoop。
//   - 握手 sendDNS*    ：用独立的 c.dnsClient（同步 Exchange）完成版本协商、编码探测等。
//
// 设计取舍 / 关键不变量（详见 DESIGN.md §6.1）：
//   - **空闲 1 pending**：没有上行数据时只保留 1 个 poll 查询在途,避免 idle QPS
//     随窗口翻倍；活跃上行时允许小窗口填充。
//   - **空闲发包节拍由 server 控制**：客户端"收响应立刻发下一个",自己不加 idle gap；
//     server 端 lazy hold (~1s) 决定空闲 QPS。
//   - **dataLoop 不阻塞本地 TCP I/O**：上行写入 upBuf、下行写入 downBuf,真正的 TCP 读 / 写
//     在 streamReader / streamWriter 里跑。任何一个 stream 卡住都不会拖死整个隧道。
package tunnel

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type upFlight struct {
	active bool
	seq    uint8
	sid    uint8
	data   []byte
	sentAt time.Time
	retry  int
}

type dnsResponse struct {
	raw    []byte
	isPoll bool
}

const (
	runtimeWindowDownshiftTimeouts   = 3
	runtimeWindowIncreaseMinInterval = 10 * time.Second
	runtimeWindowIncreaseCooldown    = 15 * time.Second
	windowProbeRounds                = 3
)

// clientStream —— 客户端侧一条 stream 的运行态。
//
// 字段语义：
//   - id      ：1..254 的 streamID,与服务端 Stream.id 对齐；0 是哨兵值,不用。
//   - conn    ：本地 TCP socket（应用如 ssh client 连上来的那个）。
//   - upBuf   ：本地 TCP 读出的字节,等 selectUpstream 取去打包成 DNS 查询。
//   - downBuf ：DNS 响应 payload 解出的字节,等 streamWriter 写回本地 TCP。
//   - downSig ：streamWriter 阻塞等数据的唤醒信号；非阻塞写,容量 1。
//   - closed  ：硬关闭。一旦置 true,reader / writer 看到就立刻退出,不再写本地 TCP。
//   - closing ：软关闭。服务端 EOF 时设置；writer 先把 downBuf 残留写完再关 conn,
//     防止 SCP 等场景丢尾字节（见 §14 修复演进 #4）。
type clientStream struct {
	id      uint8
	conn    net.Conn
	upBuf   *DataBuf // 本地 TCP → 隧道上行
	downBuf *DataBuf // 隧道下行 → 本地 TCP
	downSig chan struct{}
	closed  bool // 硬关闭：reader / writer 立刻退出
	closing bool // 软关闭：writer 排完队再关 socket
}

// DNSClient —— 客户端总状态。
//
// 锁规约：
//   - mu     ：保护 streams / nextSID / lastUpSched / 各 stream 的 closed / closing 字段。
//   - runMu  ：保护 running 标志,允许外部并发查询 IsRunning。
//   - 字段如 maxFrag / encoding / lazyMode 等握手协商出来的"会话级配置",
//     只在握手期写一次、之后只读,**不**需要锁；dataLoop 直接读。
type DNSClient struct {
	listenAddr string      // 本地 TCP 监听地址（"127.0.0.1:2222" 之类）
	dnsServer  string      // 上游 DNS 服务器地址（直连模式 = 本服务端；委派模式 = 企业内 DNS）
	sessionID  string      // 7 字符 Base32 sessionID,每次 setupTunnel 重新生成
	tld        string      // FQDN 尾巴：直连用 "edu",委派模式用 -domain
	dnsClient  *dns.Client // 同步 Exchange 用的客户端（握手 / 控制命令走这条）
	debug      bool
	key        string // Vigenère key

	// 握手协商出的会话级配置。握手完成后只读,无需锁。
	lazyMode    bool
	compression bool
	useNULL     bool
	maxFrag     int // 下行单包 payload 上限（影响服务端切片）
	encoding    int // EncBase32 / EncBase64,影响 upPayload
	upPayload   int // 上行单包能塞的明文字节上限
	qnameBudget int // probeMaxQName 探测出的 QNAME 字符总长上限,0 = 未探或失败
	respTotal   int // probeRespTotal 探测出的总响应字节预算,0 = 未探或失败
	window      int // session 级当前运行窗口
	reqWindow   int // client-requested session window, clamped by the server
	windowMax   int // handshake-negotiated window; status denominator, runtime changes do not mutate it

	// 受 mu 保护：
	mu          sync.Mutex
	streams     map[uint8]*clientStream
	nextSID     uint8 // 下一次 allocStreamIDLocked 的起点
	lastUpSched uint8 // selectUpstream 的 round-robin 游标
	upNotify    chan struct{}

	// tunnelUp：隧道存活,多 goroutine 读写,用 atomic.Bool 消除 data race。
	//   - Start 握手成功后 Store(true)；
	//   - dnsRecvLoop / processDown 致命错误 Store(false)；
	//   - dataLoop / Accept 循环按 Load() 决定是否退出/惰性重连。
	tunnelUp atomic.Bool

	// dataLoop 发布的轻量运行态,供嵌入式 / CGO 查询状态使用。
	statusQueryInFlight atomic.Int64
	statusPollInFlight  atomic.Int64
	statusPollCredit    atomic.Int64
	statusUpInFlight    atomic.Int64

	// 进程级生命周期管理。**runMu 同时保护 running / closed / quit / listener** 四个字段——
	// 缺一不可,否则 "Close 在 Start 还没跑到时打进来" 这种竞态会让 Start 后续
	// 重建一个永远没人关的 listener 和 quit channel,造成 goroutine 永久泄漏。
	//
	// 不变量：
	//   - closed=true 表示已经 Close 过；Close 后再 Start 直接返回 error,
	//     **不支持重启同一实例**（要重启,丢掉旧 *DNSClient,用 NewDNSClient 建新的）。
	//   - quit / listener 字段的读和"Close + closed 检查"必须在同一个临界区内
	//     做完,否则会出现 Close 拿到的是旧值、Start 又写了新值的撕裂情景。
	runMu    sync.RWMutex
	running  bool
	closed   bool
	quit     chan struct{}
	listener net.Listener
}

// NewDNSClient 构造但不启动客户端。listenAddr 是本地 TCP 监听地址,
// dnsServer 是上游 DNS 服务器（含端口）；debug 打开协议级日志。
//
// 初始默认：lazy + compression 开启、Base32 编码、TXT 记录。这些值在握手时
// 可能被协商关 / 升级,但默认开启避免"还没握手成功 dataLoop 就先按错配置发包"。
//
// logToFile=true 时调用 EnableFileLog() 把日志重定向到
// <可执行文件目录>/<YYYY-MM-DD>.log。失败只在 stderr 打一行警告,不影响构造
// (文件日志失败时降级回 stderr 仍可用)。
func NewDNSClient(listenAddr, dnsServer string, debug bool, key string, domain string, logToFile bool) (*DNSClient, error) {
	if logToFile {
		if _, err := EnableFileLog(); err != nil {
			log.Printf("NewDNSClient: EnableFileLog failed: %v (falling back to stderr)", err)
		}
	}
	suffix := defaultTLD
	if domain != "" {
		suffix = domain
	}
	enc := EncBase32
	c := &DNSClient{
		listenAddr:  listenAddr,
		dnsServer:   dnsServer,
		sessionID:   generateSessionID(),
		tld:         suffix,
		dnsClient:   &dns.Client{Net: "udp", ReadTimeout: dnsTimeout, WriteTimeout: dnsTimeout},
		debug:       debug,
		key:         key,
		lazyMode:    true,
		compression: true,
		useNULL:     false,
		maxFrag:     maxDownPayloadTXT,
		encoding:    enc,
		upPayload:   maxUpPayload(suffix, enc),
		window:      1,
		reqWindow:   defaultWindow,
		windowMax:   1,
		streams:     make(map[uint8]*clientStream),
		nextSID:     1,
		upNotify:    make(chan struct{}, 1),
		quit:        make(chan struct{}),
	}
	return c, nil
}

// SetWindow overrides the requested DNS pipeline window for future handshakes.
// The server still clamps the final value to its supported range.
func (c *DNSClient) SetWindow(window int) {
	if window < 1 {
		window = 1
	}
	if window > maxWindow {
		window = maxWindow
	}
	c.reqWindow = window
}

// MarkRunning 由外部嵌入式使用者调用,把 running 标记成 true。
// 普通命令行模式下 Start 内部会自己设,无需手动调用。
func (c *DNSClient) MarkRunning() {
	c.runMu.Lock()
	c.running = true
	c.runMu.Unlock()
}

// Close 优雅关闭客户端：tunnel down + close quit + close listener。多次调用安全。
//
// 在 runMu 内**同时**置 closed=true + 快照 quit / listener,之后释放锁再做 IO。
// 这保证了即使 Close 与一个还在 scheduled 状态的 Start goroutine 撞车,Start
// 也会在 runMu.Lock 内看到 closed=true 然后立即退出,不会建出一个永远没人关的
// listener / quit 一直泄漏（CGO 场景下的典型"Start 后立即 Stop"路径）。
func (c *DNSClient) Close() {
	c.runMu.Lock()
	c.closed = true
	c.running = false
	quit := c.quit
	listener := c.listener
	c.runMu.Unlock()

	c.tunnelUp.Store(false)
	if quit != nil {
		select {
		case <-quit:
		default:
			close(quit)
		}
	}
	if listener != nil {
		listener.Close()
	}
}

// IsRunning 用 RLock 允许并发查询;runMu 写者只在 MarkRunning / Close / Start 启停时短暂持有。
func (c *DNSClient) IsRunning() bool {
	c.runMu.RLock()
	defer c.runMu.RUnlock()
	return c.running
}

// StatusString returns a stable, human-readable snapshot of the client tunnel state.
// It intentionally does not include the Vigenere key.
func (c *DNSClient) StatusString() string {
	if c == nil {
		return "record_type=\nencoding=\nmax_up_payload=0\nmax_down_payload=0\nwindow=0/0\npoll=0/0\nupstream=0/0\nstream_count=0\n"
	}

	c.mu.Lock()
	streamCount := len(c.streams)
	c.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "record_type=%s\n", recordTypeName(c.useNULL))
	fmt.Fprintf(&b, "encoding=%s\n", encodingName(c.encoding))
	fmt.Fprintf(&b, "max_up_payload=%d\n", c.upPayload)
	fmt.Fprintf(&b, "max_down_payload=%d\n", c.maxFrag)
	windowMax := c.windowMax
	if windowMax < 1 {
		windowMax = c.window
	}
	fmt.Fprintf(&b, "window=%d/%d\n", c.statusQueryInFlight.Load(), windowMax)
	fmt.Fprintf(&b, "poll=%d/%d\n", c.statusPollInFlight.Load(), c.statusPollCredit.Load())
	fmt.Fprintf(&b, "upstream=%d/%d\n", c.statusUpInFlight.Load(), windowMax)
	fmt.Fprintf(&b, "stream_count=%d\n", streamCount)
	return b.String()
}

func encodingName(enc int) string {
	switch enc {
	case EncBase64:
		return "base64url"
	case EncBase32:
		return "base32"
	default:
		return fmt.Sprintf("unknown(%d)", enc)
	}
}

func recordTypeName(useNULL bool) string {
	if useNULL {
		return "NULL"
	}
	return "TXT"
}

// Start 是阻塞主循环：监听 TCP、setupTunnel 握手、启动 dataLoop,
// 然后在 Accept 循环里把每个 TCP 连接挂成新 stream。
//
// 错误恢复：dataLoop 发现 tunnelUp=false 后退出；下一个 Accept 时会触发
// setupTunnel 重新握手 + 重启 dataLoop（"惰性重连"）。
//
// 生命周期：
//   - 同一 *DNSClient 实例**最多 Start 一次**。Close 后再 Start 直接返回 error,
//     需要重启请用 NewDNSClient 建新实例。
//   - Start 内对 quit / listener 的写入都在 runMu 临界区内完成,且会立即检查
//     closed 标志,确保 "Close 抢先" 的场景下不会建出永远没人关的资源。
func (c *DNSClient) Start() error {
	// 第 1 道闸：注册 quit + running。如果已被 Close 过,直接拒绝。
	c.runMu.Lock()
	if c.closed {
		c.runMu.Unlock()
		return fmt.Errorf("client has been closed; create a new DNSClient to restart")
	}
	if c.quit == nil {
		c.quit = make(chan struct{})
	}
	quit := c.quit
	c.running = true
	c.runMu.Unlock()
	defer func() {
		c.runMu.Lock()
		c.running = false
		c.runMu.Unlock()
	}()

	listener, err := net.Listen("tcp", c.listenAddr)
	if err != nil {
		return fmt.Errorf("listen failed: %v", err)
	}

	// 第 2 道闸：listen 成功后 publish 之前再检查一次 closed。
	// 如果 Close 在 net.Listen 期间打进来（看到 listener=nil 而跳过 listener.Close）,
	// 这里我们自己关掉刚建出来的 listener,避免泄漏。
	c.runMu.Lock()
	if c.closed {
		c.runMu.Unlock()
		listener.Close()
		return nil
	}
	c.listener = listener
	c.runMu.Unlock()
	defer listener.Close()

	if c.debug {
		log.Printf("Listening on %s, DNS server %s, max upstream %d bytes", c.listenAddr, c.dnsServer, c.upPayload)
	}

	if err := c.setupTunnel(); err != nil {
		return fmt.Errorf("tunnel setup failed: %v", err)
	}

	go c.dataLoop()

	for {
		// 每次 Accept 前先检查 quit,防止 listener.Close 后还在傻 Accept。
		// 用本地 `quit` 而不是 c.quit,避免与并发 Start 的写竞争（虽然现在
		// Start 不允许重入,但本地变量更可读且未来更鲁棒）。
		select {
		case <-quit:
			return nil
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			// Close() 走的就是 listener.Close()→Accept 返回 err 的路径。
			select {
			case <-quit:
				return nil
			default:
			}
			if c.debug {
				log.Printf("Accept error: %v", err)
			}
			continue
		}

		// 上一次 dataLoop 退出（tunnel 死）后,这里惰性重建。
		if !c.tunnelUp.Load() {
			if c.debug {
				log.Printf("Tunnel down, re-establishing...")
			}
			if err := c.setupTunnel(); err != nil {
				if c.debug {
					log.Printf("Tunnel re-setup failed: %v", err)
				}
				conn.Close()
				continue
			}
			go c.dataLoop()
		}

		// 分配 streamID：必须用 allocStreamIDLocked 扫描空闲 slot,
		// 不能裸 nextSID++（254 回绕后会复用未关的 ID,数据串错流）。
		c.mu.Lock()
		sid, ok := c.allocStreamIDLocked()
		if !ok {
			c.mu.Unlock()
			if c.debug {
				log.Printf("Stream IDs exhausted (%d in use), rejecting connection", len(c.streams))
			}
			conn.Close()
			continue
		}

		stream := &clientStream{
			id:      sid,
			conn:    conn,
			upBuf:   &DataBuf{},
			downBuf: &DataBuf{},
			downSig: make(chan struct{}, 1),
		}
		c.streams[sid] = stream
		c.mu.Unlock()

		if c.debug {
			log.Printf("New TCP connection → stream %d", sid)
		}

		// cmdOpenStream 走同步 sendDNS（带 10 次重试）,服务端 dial 远端 TCP
		// 可能耗时（最长 dialer.Timeout=10s）。失败立即 close 本地 conn。
		if err := c.cmdOpenStream(sid); err != nil {
			if c.debug {
				log.Printf("Stream %d open failed: %v", sid, err)
			}
			c.mu.Lock()
			delete(c.streams, sid)
			c.mu.Unlock()
			conn.Close()
			continue
		}

		go c.streamReader(stream)
		go c.streamWriter(stream)
	}
}

// streamWriter —— 把 downBuf 的字节异步写进本地 TCP socket。
//
// 为什么独立 goroutine？dataLoop 的 processDown 只把 payload Write 进 downBuf
// 就立刻返回；真正的 syscall.Write 由这里来做。任何一条 stream 的本地 TCP
// 写慢（消费者堵塞、kernel buffer 满）都不会卡 dataLoop,其它 stream 照常工作。
//
// 关闭语义：
//   - closed=true：硬关,立刻 return,不再写。
//   - closing=true 且 downBuf 空：服务端已发 StreamClosed,把残留写完后关 socket。
//   - downBuf 空且没 closing：阻塞等 downSig 或 2s 超时（轮询用,防止真的死锁）。
func (c *DNSClient) streamWriter(stream *clientStream) {
	for {
		data := stream.downBuf.Take(64 * 1024)
		if len(data) > 0 {
			stream.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			n, err := stream.conn.Write(data)
			stream.conn.SetWriteDeadline(time.Time{})
			if err != nil {
				if c.debug {
					log.Printf("stream %d: TCP write error after %d/%d bytes: %v",
						stream.id, n, len(data), err)
				}
				c.mu.Lock()
				stream.closed = true
				delete(c.streams, stream.id)
				c.mu.Unlock()
				stream.conn.Close()
				// 通知服务端别再发数据。后台异步发,不阻塞本 goroutine 退出。
				go c.cmdCloseStream(stream.id)
				return
			}
			if c.debug {
				log.Printf("stream %d: TCP wrote %d bytes (downBuf remaining=%d)",
					stream.id, n, stream.downBuf.Len())
			}
			continue
		}
		c.mu.Lock()
		closed := stream.closed
		closing := stream.closing
		c.mu.Unlock()
		if closed {
			if c.debug {
				log.Printf("stream %d: writer exiting (closed=true)", stream.id)
			}
			return
		}
		if closing {
			// 缓冲已经空了,且服务端已经发过 EOF,可以真正关 socket。
			if c.debug {
				log.Printf("stream %d: writer drained, closing-then-close → close TCP", stream.id)
			}
			c.mu.Lock()
			stream.closed = true
			c.mu.Unlock()
			stream.conn.Close()
			return
		}
		select {
		case <-stream.downSig:
		case <-time.After(2 * time.Second):
		}
	}
}

// allocStreamIDLocked 在 c.streams 里扫一遍找空闲 streamID。
//
// **必须**持有 c.mu。返回 (0, false) 表示 254 个槽位全占用,拒绝新连接。
//
// 历史 bug（DESIGN.md §14 #6）：早期实现就是 `sid = nextSID++`,uint8 滚到 254
// 后回到 1,如果旧 stream 还没关就会复用 ID,新连接的数据被写到旧 conn 上。
func (c *DNSClient) allocStreamIDLocked() (uint8, bool) {
	for tries := 0; tries < maxStreams; tries++ {
		sid := c.nextSID
		c.nextSID++
		if c.nextSID == 0 {
			c.nextSID = 1
		}
		if _, exists := c.streams[sid]; !exists {
			return sid, true
		}
	}
	return 0, false
}

// setupTunnel 重置会话级状态 + 执行 5 步握手。
//
// 重置内容：sessionID（新生成）、encoding 回到 Base32、maxFrag 回到默认、
// streams map 清空、nextSID 复位。重连场景下旧 stream 仍然指向旧 conn,
// 但 dataLoop 已经退出,旧 stream 的 reader/writer 在 conn 关后自然退出。
//
// 注意：握手包走的是 c.dnsClient（同步 Exchange）,不经过 dataLoop。
func (c *DNSClient) setupTunnel() error {
	c.sessionID = generateSessionID()
	c.useNULL = false
	c.encoding = EncBase32
	c.upPayload = maxUpPayload(c.tld, EncBase32)
	c.maxFrag = maxDownPayloadTXT
	c.lazyMode = true
	c.compression = true
	c.window = 1
	c.windowMax = 1

	c.mu.Lock()
	c.streams = make(map[uint8]*clientStream)
	c.nextSID = 1
	c.mu.Unlock()

	if err := c.handshake(); err != nil {
		return err
	}

	c.tunnelUp.Store(true)

	if c.debug {
		log.Printf("Tunnel ready: lazy=%v compress=%v null=%v maxfrag=%d enc=%d window=%d",
			c.lazyMode, c.compression, c.useNULL, c.maxFrag, c.encoding, c.window)
	}
	return nil
}

// streamReader —— 把本地 TCP read 来的字节塞进 upBuf,唤醒 dataLoop。
//
// 本 goroutine 阻塞在 conn.Read,有数据就 Write 入 upBuf,再非阻塞通知
// dataLoop。Read 出错（包括 EOF）→ 标记 stream.closed + 通知服务端关流 + 退出。
func (c *DNSClient) streamReader(stream *clientStream) {
	buf := make([]byte, 4096)
	for {
		for stream.upBuf.Len() >= maxStreamBuffer {
			c.mu.Lock()
			closed := stream.closed
			c.mu.Unlock()
			if closed {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		n, err := stream.conn.Read(buf)
		if n > 0 {
			stream.upBuf.Write(buf[:n])
			if c.debug {
				log.Printf("stream %d: TCP read %d bytes → upBuf (now=%d)",
					stream.id, n, stream.upBuf.Len())
			}
			select {
			case c.upNotify <- struct{}{}:
			default:
			}
		}
		if err != nil {
			if c.debug {
				log.Printf("stream %d: TCP read error/EOF: %v (sending cmdCloseStream)", stream.id, err)
			}
			c.mu.Lock()
			stream.closed = true
			delete(c.streams, stream.id)
			c.mu.Unlock()
			stream.conn.Close()
			go c.cmdCloseStream(stream.id)
			return
		}
	}
}

// selectUpstream —— round-robin 选一个有数据可发的 stream,取出最多 upPayload-1 字节。
//
// 返回值：(streamID, payload)。没有任何 stream 有数据时返回 (0, nil)。
//
// **公平调度算法**（DESIGN.md §8.3）：从 lastUpSched+1 开始循环 maxStreams+1 次,
// 让一个重负载 stream（大文件上传）不会霸占单一上行窗口、把其它 stream 的
// keepalive 饿死。`maxStreams+1` 而不是 `maxStreams` 是为了让循环回到 start
// 自己——少一次就漏掉 start。**0 是哨兵 streamID,直接 continue 跳过**。
func (c *DNSClient) selectUpstream() (uint8, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 上行 payload 第 0 字节是 streamID,所以实际数据空间是 upPayload-1。
	maxData := c.upPayload - 1
	if maxData < 1 {
		return 0, nil
	}

	start := c.lastUpSched
	for i := 1; i <= maxStreams+1; i++ {
		sid := uint8((int(start) + i) % (maxStreams + 1))
		if sid == 0 {
			continue
		}
		stream, ok := c.streams[sid]
		if !ok || stream.closed {
			continue
		}
		if stream.upBuf.Len() > 0 {
			data := stream.upBuf.Take(maxData)
			c.lastUpSched = sid
			if c.debug {
				log.Printf("selectUpstream: picked sid=%d len=%d (start=%d, upBuf remaining=%d)",
					sid, len(data), start, stream.upBuf.Len())
			}
			return sid, data
		}
	}
	return 0, nil
}

// dataLoop —— 唯一的"发上行 + 收下行"调度 goroutine。
//
// 规约：
//   - 与 dnsRecvLoop 共用一个 UDP socket（net.Dial("udp", server) 后只用这一条）。
//   - Phase 2 session 小窗口：最多当前运行窗口个 data frame 未 ack。
//   - 没有上行数据时，idle 只保留 1 个 poll pending；下行活跃时补到 active poll 上限。
//   - 收到响应就尽量补窗口（不加 idle gap,见 §14 修复演进 #5）。
//   - tunnelUp=false 就退出；外层 Accept 循环会触发重连。
func (c *DNSClient) dataLoop() {
	conn, err := net.Dial("udp", c.dnsServer)
	if err != nil {
		if c.debug {
			log.Printf("DNS dial failed: %v", err)
		}
		c.tunnelUp.Store(false)
		c.statusQueryInFlight.Store(0)
		c.statusPollInFlight.Store(0)
		c.statusPollCredit.Store(0)
		c.statusUpInFlight.Store(0)
		return
	}
	defer conn.Close()
	defer func() {
		c.statusQueryInFlight.Store(0)
		c.statusPollInFlight.Store(0)
		c.statusPollCredit.Store(0)
		c.statusUpInFlight.Store(0)
	}()

	recvCh := make(chan dnsResponse, maxWindow*2)
	go c.dnsRecvLoop(conn, recvCh)
	windowNotifyCh := make(chan int, 4)
	go func() {
		for n := range windowNotifyCh {
			c.notifyWindow(n)
		}
	}()
	defer close(windowNotifyCh)

	var upNextSeq uint8 // 下一次新上行帧的 seq
	var downAck uint8   // 要捎带给服务端的"最近收到的下行 seq"
	window := c.window
	if window < 1 {
		window = 1
	}
	if window > maxWindow {
		window = maxWindow
	}
	// 握手探测出的窗口只作为初始保守值；运行期如果持续稳定满载,允许继续增窗到协议硬上限。
	windowCap := maxWindow
	var upFlights [maxWindow]upFlight
	downInited := false   // 是否已经收到过下行,用于 lastDownSeq 初始化
	var lastDownSeq uint8 // 上次收到的下行 seq,用于去重（同 seq 重传）
	downDeliveredSeq := uint8(0)
	downReorder := make(map[uint8]*DownPkt)
	queryInFlight := 0 // 总 DNS 查询在途数；data/poll 都必须受它背压。
	pollInFlight := 0  // 只统计 poll 查询,用于 idle/active-down credit。
	downActiveUntil := time.Time{}
	dataTimeouts := 0
	stableDataAcks := 0
	nextWindowIncreaseAt := time.Now().Add(runtimeWindowIncreaseMinInterval)

	// lazy 降级跟踪（参考 iodine client.c send_query）：
	// windowSent/windowRecv 统计 dataLoop 启动后的发送/接收量。
	// 如果 windowSent > 6 且 windowRecv == 0，说明解析器吃掉了所有 lazy 响应，
	// 主动关闭 lazy 模式并通知服务端。
	windowSent := 0
	windowRecv := 0

	countUpFlights := func() int {
		n := 0
		for i := range upFlights {
			if upFlights[i].active {
				n++
			}
		}
		return n
	}
	firstFreeUpSlot := func() int {
		for i := range upFlights {
			if !upFlights[i].active {
				return i
			}
		}
		return -1
	}
	oldestUpFlight := func() *upFlight {
		var oldest *upFlight
		for i := range upFlights {
			f := &upFlights[i]
			if !f.active {
				continue
			}
			if oldest == nil || f.sentAt.Before(oldest.sentAt) {
				oldest = f
			}
		}
		return oldest
	}
	hasBufferedUpstream := func() bool {
		c.mu.Lock()
		streams := make([]*clientStream, 0, len(c.streams))
		for _, stream := range c.streams {
			streams = append(streams, stream)
		}
		c.mu.Unlock()
		for _, stream := range streams {
			if stream.upBuf.Len() > 0 {
				return true
			}
		}
		return false
	}
	hasUpstreamBacklog := func() bool {
		return countUpFlights() > 0 || hasBufferedUpstream()
	}
	notifyRuntimeWindow := func(n int) {
		select {
		case windowNotifyCh <- n:
		default:
			select {
			case <-windowNotifyCh:
			default:
			}
			select {
			case windowNotifyCh <- n:
			default:
			}
		}
	}
	isDownActive := func() bool {
		return !downActiveUntil.IsZero() && time.Now().Before(downActiveUntil)
	}
	markDownActive := func() {
		downActiveUntil = time.Now().Add(2 * lazyTimeout)
	}
	publishStatus := func() {
		active := isDownActive()
		upBacklog := hasUpstreamBacklog()
		c.statusQueryInFlight.Store(int64(queryInFlight))
		c.statusPollInFlight.Store(int64(pollInFlight))
		c.statusPollCredit.Store(int64(pollCredit(active, upBacklog, window)))
		c.statusUpInFlight.Store(int64(countUpFlights()))
	}
	maybeIncreaseWindow := func(released int) {
		if released <= 0 {
			return
		}
		dataTimeouts = 0
		if window >= windowCap {
			stableDataAcks = 0
			return
		}
		if !hasUpstreamBacklog() {
			stableDataAcks = 0
			return
		}
		stableDataAcks += released
		target := windowIncreaseAckTarget(window)
		if stableDataAcks < target || time.Now().Before(nextWindowIncreaseAt) {
			return
		}
		oldWindow := window
		window++
		if window > windowCap {
			window = windowCap
		}
		c.window = window
		stableDataAcks = 0
		nextWindowIncreaseAt = time.Now().Add(runtimeWindowIncreaseMinInterval)
		if c.debug {
			log.Printf("runtime window increase: %d -> %d after %d stable data acks (cap=%d)",
				oldWindow, window, target, windowCap)
		}
		notifyRuntimeWindow(window)
	}
	sendNewData := func() bool {
		slot := firstFreeUpSlot()
		if slot < 0 {
			return false
		}
		sid, data := c.selectUpstream()
		if data == nil {
			return false
		}
		buf := make([]byte, len(data))
		copy(buf, data)
		upFlights[slot] = upFlight{
			active: true,
			seq:    upNextSeq,
			sid:    sid,
			data:   buf,
			sentAt: time.Now(),
		}
		if c.debug {
			log.Printf("send: new data sid=%d seq=%d len=%d ack=%d upInFlight=%d/%d queries=%d",
				sid, upNextSeq, len(buf), downAck, countUpFlights(), window, queryInFlight+1)
		}
		c.asyncSendStreamData(conn, sid, buf, upNextSeq, downAck)
		upNextSeq = nextSeq(upNextSeq)
		queryInFlight++
		windowSent++
		publishStatus()
		return true
	}
	sendRetransmit := func() bool {
		f := oldestUpFlight()
		if f == nil {
			return false
		}
		f.sentAt = time.Now()
		f.retry++
		if c.debug {
			log.Printf("send: retransmit sid=%d seq=%d len=%d ack=%d retry=%d upInFlight=%d/%d queries=%d",
				f.sid, f.seq, len(f.data), downAck, f.retry, countUpFlights(), window, queryInFlight+1)
		}
		c.asyncSendStreamData(conn, f.sid, f.data, f.seq, downAck)
		queryInFlight++
		windowSent++
		publishStatus()
		return true
	}
	sendPoll := func() bool {
		active := isDownActive()
		upBacklog := hasUpstreamBacklog()
		if !canSendPoll(pollInFlight, queryInFlight, active, upBacklog, window) {
			return false
		}
		if c.debug {
			mode := "idle"
			if active {
				mode = "active-down"
			}
			if upBacklog {
				mode = "upstream-backlog"
			}
			log.Printf("send: poll (%s, no upstream data) ack=%d polls=%d/%d queries=%d",
				mode, downAck, pollInFlight+1, pollCredit(active, upBacklog, window), queryInFlight+1)
		}
		c.asyncSendPoll(conn, downAck)
		pollInFlight++
		queryInFlight++
		windowSent++
		publishStatus()
		return true
	}
	releaseAcked := func(ack uint8) int {
		released := 0
		for i := range upFlights {
			f := &upFlights[i]
			if !f.active {
				continue
			}
			if ackCovers(ack, f.seq) {
				if c.debug {
					log.Printf("  ack accepted: seq=%d covered by ack=%d (slot=%d)", f.seq, ack, i)
				}
				upFlights[i] = upFlight{}
				released++
			}
		}
		return released
	}
	deliverDown := func(pkt *DownPkt) bool {
		c.processDown(pkt, &downAck, &downInited, &lastDownSeq)
		return len(pkt.Payload) > 0 || (pkt.StreamClosed && pkt.StreamID > 0)
	}
	handleDown := func(pkt *DownPkt) bool {
		if pkt.Closed {
			deliverDown(pkt)
			return false
		}
		ordered := len(pkt.Payload) > 0 || (pkt.StreamClosed && pkt.StreamID > 0)
		if !ordered {
			deliverDown(pkt)
			return false
		}
		expected := nextSeq(downDeliveredSeq)
		if pkt.Seq == expected {
			active := deliverDown(pkt)
			downDeliveredSeq = pkt.Seq
			for {
				next := nextSeq(downDeliveredSeq)
				queued, ok := downReorder[next]
				if !ok {
					break
				}
				delete(downReorder, next)
				active = deliverDown(queued) || active
				downDeliveredSeq = next
			}
			return active
		} else if seqInWindow(pkt.Seq, expected, window) {
			downReorder[pkt.Seq] = pkt
			if c.debug {
				log.Printf("  down reorder: cached future seq=%d expected=%d delivered=%d",
					pkt.Seq, expected, downDeliveredSeq)
			}
		} else if c.debug {
			log.Printf("  down reorder: drop old/far seq=%d expected=%d delivered=%d",
				pkt.Seq, expected, downDeliveredSeq)
		}
		return false
	}
	pump := func() {
		sentData := false
		for canSendUpData(countUpFlights(), queryInFlight, window) {
			if !sendNewData() {
				break
			}
			sentData = true
		}
		if sentData {
			return
		}
		if countUpFlights() > 0 {
			if queryInFlight == 0 {
				sendRetransmit()
			}
			return
		}
		active := isDownActive()
		upBacklog := hasBufferedUpstream()
		clampedPolls := clampPollInFlight(pollInFlight, active, upBacklog, window)
		if clampedPolls != pollInFlight {
			if c.debug {
				log.Printf("poll credit clamp: polls=%d -> %d credit=%d",
					pollInFlight, clampedPolls, pollCredit(active, upBacklog, window))
			}
			pollInFlight = clampedPolls
			publishStatus()
		}
		for {
			if !sendPoll() {
				break
			}
		}
		publishStatus()
	}

	publishStatus()
	pump()

	for c.tunnelUp.Load() {
		timeout := 5 * time.Second
		if c.lazyMode {
			// lazy 模式下,服务端会 hold 最多 lazyTimeout(1s),所以客户端 2s 仍未
			// 收到响应基本就是丢包/远端死了。
			timeout = 2 * time.Second
		}

		select {
		case resp := <-recvCh:
			windowRecv++
			if queryInFlight > 0 {
				queryInFlight--
			}
			if resp.isPoll && pollInFlight > 0 {
				pollInFlight--
			}
			publishStatus()
			pkt := c.decodeResponse(resp.raw)
			if pkt == nil {
				if c.debug {
					log.Printf("recv: decode failed (len=%d), skip", len(resp.raw))
				}
			} else {
				if c.debug {
					log.Printf("recv: pkt seq=%d ack=%d sid=%d payload=%d flags=%s polls=%d/%d queries=%d upInFlight=%d/%d",
						pkt.Seq, pkt.Ack, pkt.StreamID, len(pkt.Payload), pktFlags(pkt),
						pollInFlight, pollCredit(isDownActive(), hasUpstreamBacklog(), window), queryInFlight, countUpFlights(), window)
				}
				if handleDown(pkt) {
					markDownActive()
				}
				maybeIncreaseWindow(releaseAcked(pkt.Ack))
				publishStatus()
			}

			// processDown 里如果收到 Closed 标志会把 tunnelUp 置 false。
			if !c.tunnelUp.Load() {
				if c.debug {
					log.Printf("recv: tunnelUp=false after processDown, dataLoop exiting")
				}
				return
			}

			pump()

		case <-c.upNotify:
			pump()

		case <-time.After(timeout):
			// lazy 降级检测（参考 iodine）：发了 >6 个查询却收不到任何响应，
			// 说明解析器不转发 lazy 延迟响应。关闭 lazy 让服务端立即回包。
			if c.lazyMode && windowSent > 6 && windowRecv == 0 {
				c.lazyMode = false
				if c.debug {
					log.Printf("lazy degradation: %d sent / %d recv, disabling lazy mode", windowSent, windowRecv)
				}
				go func() {
					meta := CtrlMeta(cmdLazy, 0)
					fqdn := buildFQDN("L", meta, c.sessionID, c.tld)
					c.sendDNSRetries(fqdn, 2)
				}()
			}

			if queryInFlight > 0 {
				if c.debug {
					log.Printf("timeout(%v): suspect response lost (polls=%d queries=%d upInFlight=%d/%d)",
						timeout, pollInFlight, queryInFlight, countUpFlights(), window)
				}
				if countUpFlights() > 0 {
					dataTimeouts++
					stableDataAcks = 0
					if dataTimeouts >= runtimeWindowDownshiftTimeouts && window > 1 {
						oldWindow := window
						window = window / 2
						if window < 1 {
							window = 1
						}
						c.window = window
						dataTimeouts = 0
						nextWindowIncreaseAt = time.Now().Add(runtimeWindowIncreaseCooldown)
						if c.debug {
							log.Printf("runtime window downshift: %d -> %d after %d consecutive data timeouts (cap=%d)",
								oldWindow, window, runtimeWindowDownshiftTimeouts, windowCap)
						}
						notifyRuntimeWindow(window)
					}
				}
				queryInFlight = 0
				pollInFlight = 0
				publishStatus()
				if !sendRetransmit() {
					pump()
				}
			} else {
				if c.debug {
					log.Printf("timeout(%v): no queries in flight, pump", timeout)
				}
				pump()
			}
		}
	}
}

// pktFlags —— 把 DownPkt 标志拼成易读字符串,只给日志用。
func pktFlags(p *DownPkt) string {
	var flags []string
	if p.LastFrag {
		flags = append(flags, "LF")
	}
	if p.Compressed {
		flags = append(flags, "Z")
	}
	if p.Closed {
		flags = append(flags, "CLOSED")
	}
	if p.StreamClosed {
		flags = append(flags, "SCLOSED")
	}
	if len(flags) == 0 {
		return "[-]"
	}
	return "[" + strings.Join(flags, " ") + "]"
}

// processDown —— 处理一个解码好的 DownPkt：更新 ack、把 payload 塞进对应 stream 的 downBuf。
//
// 状态机字段通过指针传入,避免 dataLoop 维护一份、processDown 又维护一份。
//
// 流程：
//  1. Closed flag → tunnelUp=false,dataLoop 退出。
//  2. StreamClosed → 标记 stream.closing,writer 排空 downBuf 后关 socket。
//  3. payload / StreamClosed + 新 seq → 有序交付并更新 downAck/lastDownSeq。
//
// **去重**：pkt.Seq == lastDownSeq 表示同 seq 重传,跳过 payload 处理（避免重复写）。
func (c *DNSClient) processDown(pkt *DownPkt, downAck *uint8, downInited *bool, lastDownSeq *uint8) {
	if pkt.Closed {
		if c.debug {
			log.Printf("  Closed flag set: session ended by server, tearing down")
		}
		c.tunnelUp.Store(false)
		return
	}

	if pkt.StreamClosed && pkt.StreamID > 0 {
		c.mu.Lock()
		stream, ok := c.streams[pkt.StreamID]
		if ok {
			// closing-then-close（DESIGN.md §14 #4）：writer 排空 downBuf 再关 conn,
			// 避免 SCP 大文件传输丢尾字节。
			stream.closing = true
			delete(c.streams, pkt.StreamID)
		}
		c.mu.Unlock()
		if ok {
			select {
			case stream.downSig <- struct{}{}:
			default:
			}
		}
		if c.debug {
			log.Printf("  StreamClosed sid=%d (closing-then-close, found=%v)", pkt.StreamID, ok)
		}
		if !*downInited || pkt.Seq != *lastDownSeq {
			if !*downInited {
				*downInited = true
			}
			*downAck = pkt.Seq
			*lastDownSeq = pkt.Seq
		}
	}

	if len(pkt.Payload) > 0 && pkt.StreamID > 0 {
		// 新 seq 才处理；同 seq 是 DNS 重传或 UDP 重复,跳过 payload。
		if !*downInited || pkt.Seq != *lastDownSeq {
			firstTime := !*downInited
			if firstTime {
				*downInited = true
			}
			c.mu.Lock()
			stream, ok := c.streams[pkt.StreamID]
			c.mu.Unlock()
			if ok && !stream.closed {
				// 把 payload 交给 per-stream writer goroutine,dataLoop 不阻塞在本地 TCP。
				stream.downBuf.Write(pkt.Payload)
				select {
				case stream.downSig <- struct{}{}:
				default:
				}
				if c.debug {
					log.Printf("  payload → stream %d (%d bytes, downAck %d → %d%s)",
						pkt.StreamID, len(pkt.Payload), *downAck, pkt.Seq,
						map[bool]string{true: ", first downpkt"}[firstTime])
				}
			} else if c.debug {
				log.Printf("  payload dropped: stream %d not found or closed (%d bytes lost)",
					pkt.StreamID, len(pkt.Payload))
			}
			*downAck = pkt.Seq
			*lastDownSeq = pkt.Seq
		} else if c.debug {
			log.Printf("  dedup: same downSeq=%d, skip payload (%d bytes)", pkt.Seq, len(pkt.Payload))
		}
	} else if c.debug && pkt.StreamID == 0 && len(pkt.Payload) > 0 {
		log.Printf("  payload on sid=0 (control response, %d bytes), ignored in dataLoop path", len(pkt.Payload))
	}
}

// dnsRecvLoop —— 唯一的底层 UDP socket 读 goroutine。
//
// 流程：阻塞 Read → 解 DNS msg → 抽 RDATA → 写 recvCh。
//
// **容错策略**：
//   - 短暂 ICMP 错误（ECONNREFUSED / EHOSTUNREACH / ENETUNREACH）忽略：
//     Linux 在对端 reply socket 短暂消失时会回这些,但下一次 Exchange 通常
//     就恢复了。让 dataLoop 的 timeout 路径自己重传即可。
//   - FormatError / ServerFailure / Refused：服务端不再认这个 session
//     （可能重启了、或者编码协商失败）。直接 tunnelUp=false,Start 循环会重连。
//   - 其它致命错误（i/o 永久错）：tunnelUp=false。
//
// **背压**：recvCh 容量随 maxWindow 放大,写入时给 100ms 超时；超时丢包并打日志。
// 历史 bug（DESIGN.md §14 #8）：早期 `default` 直接丢,dataLoop 偶尔卡一下就静默丢响应,
// 看似稳定但偶现死锁。
func (c *DNSClient) dnsRecvLoop(conn net.Conn, ch chan<- dnsResponse) {
	buf := make([]byte, 65536)
	for c.tunnelUp.Load() {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// 容忍 ICMP 派生的瞬态错误：Linux 在 reply socket 暂时
			// 不存在 / 内核发陈旧 unreachable 时会冒这些。隧道不应
			// 因一个 ICMP 弹回就完全垮掉——dataLoop 的 timeout 会自己重传。
			if errors.Is(err, syscall.ECONNREFUSED) ||
				errors.Is(err, syscall.EHOSTUNREACH) ||
				errors.Is(err, syscall.ENETUNREACH) {
				if c.debug {
					log.Printf("DNS recv loop transient error: %v (continuing)", err)
				}
				continue
			}
			if c.debug {
				log.Printf("DNS recv loop fatal: %v", err)
			}
			c.tunnelUp.Store(false)
			return
		}
		if n > 0 {
			msg := new(dns.Msg)
			if err := msg.Unpack(buf[:n]); err != nil {
				if c.debug {
					log.Printf("DNS recv: unpack error: %v (raw %d bytes)", err, n)
				}
				continue
			}
			qname := ""
			if len(msg.Question) > 0 {
				qname = msg.Question[0].Name
			}
			if c.debug {
				log.Printf("DNS recv: %d bytes id=%d rcode=%d answers=%d qname=%s",
					n, msg.Id, msg.Rcode, len(msg.Answer), qname)
			}
			if msg.Rcode != dns.RcodeSuccess {
				// FormErr / ServFail / Refused 意味着服务端已经不认这个
				// session 了（重启了、或者编码协商出现不一致）。立刻拆
				// tunnel 让 dataLoop 退出,外层重连。
				if msg.Rcode == dns.RcodeFormatError ||
					msg.Rcode == dns.RcodeServerFailure ||
					msg.Rcode == dns.RcodeRefused {
					if c.debug {
						log.Printf("DNS recv loop: fatal rcode %d, tearing down", msg.Rcode)
					}
					c.tunnelUp.Store(false)
					return
				}
				// 其它非 success rcode（如 NXDOMAIN）忽略,等下次响应。
				if c.debug {
					log.Printf("  non-success rcode %d, ignoring", msg.Rcode)
				}
				continue
			}
			raw, err := c.extractAnswer(msg)
			if err != nil {
				if c.debug {
					log.Printf("  extractAnswer error: %v", err)
				}
				continue
			}
			if raw == nil {
				if c.debug {
					log.Printf("  empty answer (no NULL/TXT record), drop")
				}
				continue
			}
			if c.debug {
				log.Printf("  rdata %d bytes → recvCh", len(raw))
			}
			// 复制一份,避免下次 Read 复用 buf 时把数据覆盖了。
			data := make([]byte, len(raw))
			copy(data, raw)
			resp := dnsResponse{raw: data, isPoll: responseIsPoll(qname)}
			select {
			case ch <- resp:
			case <-time.After(100 * time.Millisecond):
				if c.debug {
					log.Printf("recv channel backpressure, dropping packet")
				}
			}
		}
	}
}

func responseIsPoll(qname string) bool {
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	return len(labels) >= 2 && strings.EqualFold(labels[1], "P")
}

// asyncSendPoll —— 发一个 P 命令空查询,纯粹捎带 downAck 收下行。
// 走的是 dataLoop 持有的 conn（不是 c.dnsClient）,fire-and-forget,响应由 dnsRecvLoop 收。
func (c *DNSClient) asyncSendPoll(conn net.Conn, downAck uint8) {
	meta := CtrlMeta(cmdPoll, downAck)
	fqdn := buildFQDN("P", meta, c.sessionID, c.tld)
	if c.debug {
		log.Printf("  poll meta=%s downAck=%d", meta, downAck)
	}
	c.asyncSendDNS(conn, fqdn)
}

// asyncSendStreamData —— 把一段 stream payload 编进 DNS 查询发出去。
//
// payload 布局：[streamID(1)] + [raw bytes]
//   - 先拼字节,再 Vigenère,再按编码 DNS-safe 编码,再切 label 拼 FQDN。
//
// meta 用 DataMeta：seq + LastFrag(true) + ack。
func (c *DNSClient) asyncSendStreamData(conn net.Conn, sid uint8, data []byte, seq, downAck uint8) {
	payload := make([]byte, 1+len(data))
	payload[0] = sid
	copy(payload[1:], data)

	encrypted := vigenereEncrypt(payload, c.key)
	encoded := encodeDNSSafe(encrypted, c.encoding)
	meta := DataMeta(seq, 0, downAck, true)
	fqdn := buildFQDN(encoded, meta, c.sessionID, c.tld)
	if c.debug {
		log.Printf("  data meta=%s sid=%d seq=%d ack=%d len=%d enc=%d",
			meta, sid, seq, downAck, len(data), c.encoding)
	}
	c.asyncSendDNS(conn, fqdn)
}

// asyncSendDNS —— 最底层"打包 + 发 UDP"。
//
// 每次都重新生成 CMC（让 QNAME 唯一,避开递归解析器本地缓存）。
// 选 qtype（TXT or NULL）;加 EDNS OPT 把 UDP 大小提到 4096,避免大下行被截。
// 不等响应（fire-and-forget）,响应由 dnsRecvLoop 收。
func (c *DNSClient) asyncSendDNS(conn net.Conn, fqdn string) {
	qtype := dns.TypeTXT
	if c.useNULL {
		qtype = dns.TypeNULL
	}
	fqdn = generateCMC() + "." + fqdn

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), qtype)
	msg.RecursionDesired = true
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, opt)

	data, err := msg.Pack()
	if err != nil {
		if c.debug {
			log.Printf("  pack error: %v", err)
		}
		return
	}
	if c.debug {
		log.Printf("DNS send: %s type=%d to=%s len=%d", fqdn, qtype, c.dnsServer, len(data))
	}
	if _, err := conn.Write(data); err != nil {
		if c.debug {
			log.Printf("  UDP write error: %v", err)
		}
	}
}

// cmdOpenStream —— 通知服务端给指定 streamID dial 真实 TCP 目标。
// 同步等响应,服务端 dial 最长 10s（dialer Timeout）。响应非 "OK" 即视为失败。
func (c *DNSClient) cmdOpenStream(sid uint8) error {
	meta := CtrlMeta(cmdOpenStream, sid)
	fqdn := buildFQDN("O", meta, c.sessionID, c.tld)
	if c.debug {
		log.Printf("cmdOpenStream %d: meta=%s sending...", sid, meta)
	}
	resp, err := c.sendDNS(fqdn)
	if err != nil {
		if c.debug {
			log.Printf("cmdOpenStream %d: send error: %v", sid, err)
		}
		return fmt.Errorf("stream open: %v", err)
	}
	if resp == nil || string(resp) != "OK" {
		if c.debug {
			log.Printf("cmdOpenStream %d: server rejected: %q", sid, string(resp))
		}
		return fmt.Errorf("stream open rejected: %s", string(resp))
	}
	if c.debug {
		log.Printf("cmdOpenStream %d: server OK", sid)
	}
	return nil
}

// cmdCloseStream —— 通知服务端关 stream。fire-and-forget（不重试,丢了无所谓）。
// 走独立的 c.dnsClient 而不是 dataLoop 的 socket,避免和 dataLoop 抢 socket。
func (c *DNSClient) cmdCloseStream(sid uint8) {
	meta := CtrlMeta(cmdCloseStream, sid)
	fqdn := buildFQDN("X", meta, c.sessionID, c.tld)
	if c.debug {
		log.Printf("cmdCloseStream %d: meta=%s (fire-and-forget)", sid, meta)
	}
	c.sendDNSOnce(fqdn)
}

// handshake —— 5 步握手,详见 DESIGN.md §5。
//
// 每一步用同步 sendDNS 等响应；任一步失败导致 setupTunnel 失败。
//
// 步骤：
//  1. cmdVersion           : 拿到服务端默认 maxFrag。
//  2. testNULLRecord       : 探测 NULL 记录支持（成功则升级 maxFrag 到 maxDownPayloadNULL）。
//  3. testEncoding(Base64) : 探测 Base64URL 上行（成功则升级 encoding,扩大 upPayload）。
//  4. probeFragSize        : 二分探测下行 fragsize,然后 commitFragSize 通知服务端。
//  5. cmdLazy + cmdCompress: 启用 lazy hold + zlib 压缩；任一失败仅打印,不致命。
func (c *DNSClient) handshake() error {
	meta := CtrlMeta(cmdVersion, protoVersion)
	fqdn := buildFQDN("V", meta, c.sessionID, c.tld)
	resp, err := c.sendDNS(fqdn)
	if err != nil {
		return fmt.Errorf("version failed: %v", err)
	}
	if c.debug {
		log.Printf("Version response: %q", string(resp))
	}
	// 服务端正常返回 "V,<ver>,<maxFragHex>"；版本不匹配返回 "VERR,<server_ver>"。
	// 这两种格式之外的任何回包（含 nil / 空 / 前缀错）都视作非法,握手失败。
	respStr := string(resp)
	if strings.HasPrefix(respStr, "VERR,") {
		return fmt.Errorf("server rejected protocol version: client=%d, server=%s", protoVersion, strings.TrimPrefix(respStr, "VERR,"))
	}
	parts := strings.Split(respStr, ",")
	if len(parts) < 3 || parts[0] != "V" {
		return fmt.Errorf("malformed version response: %q", respStr)
	}
	serverVer, e := strconv.Atoi(parts[1])
	if e != nil {
		return fmt.Errorf("bad server version field %q: %v", parts[1], e)
	}
	if serverVer != protoVersion {
		return fmt.Errorf("protocol version mismatch: client=%d server=%d", protoVersion, serverVer)
	}
	if size, e := parseSize(parts[2]); e == nil && size > 0 {
		c.maxFrag = size
	}

	if c.testNULLRecord() {
		c.useNULL = true
		c.maxFrag = maxDownPayloadNULL
		if c.debug {
			log.Printf("NULL records supported, maxfrag=%d", c.maxFrag)
		}
	} else if c.debug {
		log.Printf("NULL records not supported, using TXT")
	}

	if c.testEncoding(EncBase64) {
		c.encoding = EncBase64
		c.upPayload = maxUpPayload(c.tld, EncBase64)
		if c.debug {
			log.Printf("Base64url supported, upstream payload=%d", c.upPayload)
		}
	} else if c.debug {
		log.Printf("Base64url not supported, using Base32")
	}

	c.runContentCoverage()

	budget := c.probeMaxQName()
	c.qnameBudget = budget
	if budget > 0 && budget < maxDNSNameLen {
		newUp := maxUpPayloadWithBudget(c.tld, c.encoding, budget)
		if newUp > 0 && newUp < c.upPayload {
			if c.debug {
				log.Printf("QName budget probed: %d chars (was %d), upstream payload %d → %d",
					budget, maxDNSNameLen, c.upPayload, newUp)
			}
			c.upPayload = newUp
		} else if c.debug {
			log.Printf("QName budget probed: %d chars, keeping upstream payload %d", budget, c.upPayload)
		}
	} else if c.debug {
		if budget == 0 {
			log.Printf("QName probe failed, keeping upstream payload %d", c.upPayload)
		} else {
			log.Printf("QName budget probed at max (%d), no shrink needed", budget)
		}
	}

	probed := c.probeFragSize()
	if probed > 0 {
		// commit 用的 maxFrag 要扣掉 downPktHeaderSize（5 字节）。
		c.maxFrag = probed - downPktHeaderSize
		if c.maxFrag < 100 {
			c.maxFrag = probed
		}
		if c.debug {
			log.Printf("Probed fragsize: %d (payload max %d)", probed, c.maxFrag)
		}
		// commit 失败不致命,服务端按默认 maxFrag 切片,只是吞吐少一点。
		if err := c.commitFragSize(probed); err != nil && c.debug {
			log.Printf("Fragsize commit failed: %v (server will use default maxfrag)", err)
		}
	}

	// 探测"长 QNAME + 大 rdata"组合下的总响应预算。fragsize 单维度过得了 1198 字节、
	// QName 单维度过得了 228 字符,但二维同时撞上时部分递归会静默丢响应——是 POST
	// 失败的根因（log-0521 实测）。返回 0 = 单维度即足够,无需在服务端额外收紧。
	if budget > 0 {
		respTotal := c.probeRespTotal(budget)
		if respTotal > 0 {
			c.respTotal = respTotal
			if c.debug {
				log.Printf("Response total budget probed: %d bytes (qname=%d) → server will clamp per-query chunk",
					respTotal, budget)
			}
			if err := c.commitRespTotal(respTotal); err != nil && c.debug {
				log.Printf("respTotal commit failed: %v (server will use static maxFrag only)", err)
			}
		} else if c.debug {
			log.Printf("Response total budget: no extra shrink needed beyond fragsize")
		}
	}

	lmeta := CtrlMeta(cmdLazy, 1)
	lfqdn := buildFQDN("L", lmeta, c.sessionID, c.tld)
	lresp, err := c.sendDNS(lfqdn)
	if err == nil && lresp != nil && string(lresp) == "OK" {
		c.lazyMode = true
	} else {
		c.lazyMode = false
	}

	cmeta := CtrlMeta(cmdCompress, 1)
	cfqdn := buildFQDN("C", cmeta, c.sessionID, c.tld)
	cresp, err := c.sendDNS(cfqdn)
	if err == nil && cresp != nil && string(cresp) == "OK" {
		c.compression = true
	} else {
		c.compression = false
	}

	selectedWindow := c.probeWindow(c.reqWindow)
	if err := c.commitWindow(selectedWindow); err != nil {
		return err
	}

	return nil
}

func (c *DNSClient) probeWindow(requested int) int {
	candidates := windowProbeCandidates(requested)
	for _, candidate := range candidates {
		if c.testWindow(candidate) {
			if c.debug {
				log.Printf("Window probe selected: requested=%d actual=%d", requested, candidate)
			}
			return candidate
		}
		if c.debug {
			log.Printf("Window probe: n=%d failed, trying lower window", candidate)
		}
	}
	best := windowProbeFallback(requested)
	if c.debug {
		log.Printf("Window probe fallback: requested=%d actual=%d (all probe rounds failed)", requested, best)
	}
	return best
}

func (c *DNSClient) testWindow(n int) bool {
	if n < 1 {
		n = 1
	}
	for round := 1; round <= windowProbeRounds; round++ {
		if c.testWindowRound(n, round) {
			return true
		}
	}
	return false
}

func (c *DNSClient) testWindowRound(n, round int) bool {
	var wg sync.WaitGroup
	results := make(chan bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results <- c.testWindowProbeOnce(n, round, idx)
		}(i)
	}
	wg.Wait()
	close(results)

	ok := 0
	for result := range results {
		if result {
			ok++
		}
	}
	if c.debug {
		log.Printf("Window probe n=%d round=%d/%d: %d/%d ok", n, round, windowProbeRounds, ok, n)
	}
	return ok == n
}

func (c *DNSClient) testWindowProbeOnce(n, round, idx int) bool {
	meta := CtrlMeta(cmdWindow, 0)
	data := fmt.Sprintf("W%02x%02x%02x", n, round, idx)
	fqdn := generateCMC() + "." + buildFQDN(data, meta, c.sessionID, c.tld)
	qtype := dns.TypeTXT
	if c.useNULL {
		qtype = dns.TypeNULL
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), qtype)
	msg.RecursionDesired = true
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, opt)

	probeClient := &dns.Client{Net: "udp", ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second}
	r, _, err := probeClient.Exchange(msg, c.dnsServer)
	if err != nil {
		if c.debug {
			log.Printf("  window probe n=%d round=%d idx=%d: %v", n, round, idx, err)
		}
		return false
	}
	if r.Rcode != dns.RcodeSuccess {
		if c.debug {
			log.Printf("  window probe n=%d round=%d idx=%d: rcode %d", n, round, idx, r.Rcode)
		}
		return false
	}
	ans, err := c.extractAnswer(r)
	if err != nil {
		if c.debug {
			log.Printf("  window probe n=%d round=%d idx=%d: answer error %v", n, round, idx, err)
		}
		return false
	}
	resp := string(ans)
	if !strings.HasPrefix(resp, "OK,") {
		if c.debug {
			log.Printf("  window probe n=%d round=%d idx=%d: unexpected resp %q", n, round, idx, resp)
		}
		return false
	}
	return true
}

func (c *DNSClient) commitWindow(requested int) error {
	if requested < 1 {
		requested = 1
	}
	if requested > maxWindow {
		requested = maxWindow
	}
	meta := CtrlMeta(cmdWindow, uint8(requested))
	fqdn := buildFQDN("W", meta, c.sessionID, c.tld)
	resp, err := c.sendDNS(fqdn)
	if err != nil {
		return fmt.Errorf("window commit failed: %v", err)
	}
	respStr := string(resp)
	parts := strings.Split(respStr, ",")
	if len(parts) != 2 || parts[0] != "OK" {
		return fmt.Errorf("malformed window response: %q", respStr)
	}
	actual, err := strconv.Atoi(parts[1])
	if err != nil || actual < 1 {
		return fmt.Errorf("bad window response: %q", respStr)
	}
	if actual > maxWindow {
		actual = maxWindow
	}
	c.window = actual
	c.windowMax = actual
	if c.debug {
		log.Printf("Window committed: requested=%d actual=%d", requested, actual)
	}
	return nil
}

func (c *DNSClient) notifyWindow(window int) {
	if window < 1 {
		window = 1
	}
	if window > maxWindow {
		window = maxWindow
	}
	meta := CtrlMeta(cmdWindow, uint8(window))
	fqdn := buildFQDN("W", meta, c.sessionID, c.tld)
	resp, err := c.sendDNSRetries(fqdn, 3)
	if c.debug {
		if err != nil {
			log.Printf("runtime window notify failed: window=%d err=%v", window, err)
		} else {
			log.Printf("runtime window notify: window=%d resp=%q", window, string(resp))
		}
	}
}

// testNULLRecord —— 用一个 NULL 类型查询试探链路是否支持 NULL 记录。
//
// 直接走 c.dnsClient.Exchange,不走 sendDNSRetries（NULL 失败不需要重试,
// 失败就是失败,回退到 TXT）。返回 true 表示服务端用 dns.NULL 类型成功回复了。
func (c *DNSClient) testNULLRecord() bool {
	meta := CtrlMeta(cmdRecType, 1)
	fqdn := generateCMC() + "." + buildFQDN("N", meta, c.sessionID, c.tld)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeNULL)
	msg.RecursionDesired = true
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, opt)

	r, _, err := c.dnsClient.Exchange(msg, c.dnsServer)
	if err != nil {
		return false
	}
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) == 0 {
		return false
	}
	// 必须是 NULL 类型,不能是 TXT。
	if _, ok := r.Answer[0].(*dns.NULL); ok {
		return true
	}
	return false
}

// testEncoding —— 测试递归链路对 Base64URL 编码的"忠实度"。
//
// 把固定的 8 字节模式 {0x00,0x55,0xAA,0xFF,0x01,0x7F,0x80,0xFE} 编进 QNAME,
// 服务端按 Base64 解码后逐字节比对。如果递归解析器做了 0x20 大小写改写、
// 把 +/= 改写为 -_、或者把全 0 / 全 1 字节做 ASCII 处理,这里都会失败。
// 失败就保留 Base32。
func (c *DNSClient) testEncoding(enc int) bool {
	testData := []byte{0x00, 0x55, 0xAA, 0xFF, 0x01, 0x7F, 0x80, 0xFE}
	encoded := encodeDNSSafe(testData, enc)

	meta := CtrlMeta(cmdRecType, 0)
	fqdn := buildFQDN(encoded, meta, c.sessionID, c.tld)

	resp, err := c.sendDNSFew(fqdn)
	if err != nil {
		return false
	}

	if resp != nil && string(resp) == "ENCOK" {
		return true
	}
	return false
}

// contentTestPatterns 是 runContentCoverage 跑的字符集探测样本（仿 iodine 的
// handshake_upenc_autodetect 几个 pat* 串）。每条要求是单个合法 DNS label：
//
//	1..63 字符、由 [A-Za-z0-9_-] 组成、不以 '-' 开头。
//
// 设计：
//   - 都以 "aA" 开头：用来检测路径上的 0x20-bit case 随机化（如果链路把首字符
//     强制大小写化, "aA" 会变 "AA" 或 "aa"）。
//   - "case-mixed" 只含字母大小写交替, 用来隔离"是不是单纯 case 被吞了"。
//   - "b64url-full" 加上 base64url 字符集特有的 '_' / 数字 / 末尾 '-',
//     这俩字符是 base32 字母表里没有的;它们如果被改/丢了, 说明 Base64url
//     在这条递归上不稳定, 客户端应该降级到 Base32（case-insensitive 的）。
//
// 失败诊断更准: 哪个字符在哪个位置被改了, debug 日志单独打。
var contentTestPatterns = []struct {
	name string
	body string
}{
	{"case-mixed", "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ"},
	{"b64url-full", "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ_0129-"},
}

// testContentPattern 用 cmdContentProbe 把 body 当 DATA 段发上去, 服务端原样
// echo 回来。任何 sent != recv 都说明递归路径上有人改了字符。
//
// 失败模式比对照表（iodine 文档说的几种典型）：
//
//	'a' → 'A' / 'A' → 'a'         链路在做全大写/全小写转换
//	'aA' → 'AA' 但其他位 OK        0x20-bit 案例随机化（更隐蔽,但 base64 也死）
//	'_' / '-' → 其它字符或被剥    base64url 不可用,必须 fallback Base32
//	长度不匹配（截短/补字节）       链路对长 label 有过滤,需要降级总长
func (c *DNSClient) testContentPattern(body string) (string, error) {
	meta := CtrlMeta(cmdContentProbe, 0)
	fqdn := buildFQDN(body, meta, c.sessionID, c.tld)
	resp, err := c.sendDNSFew(fqdn)
	if err != nil {
		return "", err
	}
	return string(resp), nil
}

// runContentCoverage 顺序跑所有 contentTestPatterns, 逐字节比对发送 vs 收到,
// debug 日志详细打出"哪个字符被改成了什么"。
//
// 副作用: 如果当前选了 Base64url, 但任一 base64-特有字符（'_'/'-' 或字母大小写）
// 在路上被改/丢了, **降级回 Base32**, 并按 base32 重算 c.upPayload。
//
// 这一步不会让握手失败——只是缩窄能力。所有 pattern 都过返回 true; 任一不过
// 返回 false（让调用方知道这条链路"不太干净"）。
func (c *DNSClient) runContentCoverage() bool {
	allOk := true
	caseSwapped := false
	b64CharLost := false

	for _, p := range contentTestPatterns {
		echo, err := c.testContentPattern(p.body)
		if err != nil {
			if c.debug {
				log.Printf("content probe %q: send error: %v", p.name, err)
			}
			allOk = false
			continue
		}
		if echo == p.body {
			if c.debug {
				log.Printf("content probe %q: ok (%d chars round-trip clean)", p.name, len(p.body))
			}
			continue
		}

		allOk = false
		// 找第一个不一致的位置, 报具体哪个字符变成了哪个。
		minLen := len(p.body)
		if len(echo) < minLen {
			minLen = len(echo)
		}
		diff := -1
		for i := 0; i < minLen; i++ {
			if p.body[i] != echo[i] {
				diff = i
				break
			}
		}

		if c.debug {
			log.Printf("content probe %q: FAIL (sent %d chars, recv %d chars)", p.name, len(p.body), len(echo))
			log.Printf("  sent: %s", p.body)
			log.Printf("  recv: %s", echo)
		}
		if diff >= 0 {
			sCh, rCh := p.body[diff], echo[diff]
			if c.debug {
				log.Printf("  first diff at idx %d: %q (0x%02X) → %q (0x%02X)",
					diff, string(sCh), sCh, string(rCh), rCh)
			}
			// case swap: 同字母不同 case。
			if (sCh >= 'A' && sCh <= 'Z' && rCh == sCh+32) ||
				(sCh >= 'a' && sCh <= 'z' && rCh == sCh-32) {
				caseSwapped = true
			}
			// base64-特有字符（base32 字母表里没有）被改/丢。
			if sCh == '_' || sCh == '-' {
				b64CharLost = true
			}
		} else if len(echo) != len(p.body) {
			// 完全前缀匹配但长度不同 = 链路把字串截短或者补了字节。
			if c.debug {
				log.Printf("  length mismatch only (no char swap); path is truncating or padding")
			}
		}
	}

	if (caseSwapped || b64CharLost) && c.encoding == EncBase64 {
		oldUp := c.upPayload
		c.encoding = EncBase32
		c.upPayload = maxUpPayload(c.tld, EncBase32)
		reason := ""
		switch {
		case caseSwapped && b64CharLost:
			reason = "case + base64 special chars both mangled"
		case caseSwapped:
			reason = "0x20-bit case randomization on path"
		case b64CharLost:
			reason = "base64 special char (_/-) mangled on path"
		}
		if c.debug {
			log.Printf("Content coverage: downgrading Base64url → Base32 (%s); upstream payload %d → %d",
				reason, oldUp, c.upPayload)
		}
	}

	return allOk
}

// probeMaxQName —— 二分探测上行 QNAME 字符长度上限。
//
// 背景：NS 委派路径上的某些中间递归对长 QNAME（>200 字符）会直接 SERVFAIL。
// 不探测的话客户端按 maxDNSNameLen=250 切 QNAME,一旦命中阈值整个 chunk
// 都得等递归 ~10s 超时才放弃,触发上层 fatal rcode tear down。
//
// 算法：
//  1. 先在 floor (100) 上探一次,floor 都过不去说明链路坏了,返回 0。
//  2. 在 softCeil (= maxDNSNameLen) 上探一次,过了就直接用 softCeil（绝大多数情况）。
//  3. 否则在 [floor, softCeil-1] 二分,找最大可用 char-len。
//
// 探测成本：每次 ~2 秒（dedicated 短超时 + 单 attempt）。最坏 10 次 ≈ 20 秒。
// 返回值是 QNAME 总字符长度（含 dot,不含 dns.Fqdn 加的 trailing dot）；0 表示探测失败。
func (c *DNSClient) probeMaxQName() int {
	const safeFloor = 100
	softCeil := maxDNSNameLen

	if c.probeQNameLen(softCeil) {
		return softCeil
	}
	if !c.probeQNameLen(safeFloor) {
		return 0
	}

	lo, hi := safeFloor, softCeil-1
	best := safeFloor
	for lo <= hi {
		mid := (lo + hi) / 2
		if c.probeQNameLen(mid) {
			best = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return best
}

// probeQNameLen —— 构造一条 QNAME 总长 = targetCharLen 的探测查询发出,
// 服务端 cmdQNameProbe 回 "OK"。
//
// 使用独立的 dns.Client（短超时 + 单 attempt）避免和后续二分探测互相拖时间。
// 任何 error / 非 "OK" 回包都视为该长度不可用。
func (c *DNSClient) probeQNameLen(targetCharLen int) bool {
	fqdn, ok := c.buildProbeFQDN(targetCharLen)
	if !ok {
		return false
	}
	qtype := dns.TypeTXT
	if c.useNULL {
		qtype = dns.TypeNULL
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), qtype)
	msg.RecursionDesired = true
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, opt)

	probeClient := &dns.Client{Net: "udp", ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second}
	if c.debug {
		log.Printf("probeQNameLen target=%d actual=%d", targetCharLen, len(fqdn))
	}
	r, _, err := probeClient.Exchange(msg, c.dnsServer)
	if err != nil {
		if c.debug {
			log.Printf("  probe len=%d: %v", targetCharLen, err)
		}
		return false
	}
	if r.Rcode != dns.RcodeSuccess {
		if c.debug {
			log.Printf("  probe len=%d: rcode %d", targetCharLen, r.Rcode)
		}
		return false
	}
	ans, err := c.extractAnswer(r)
	if err != nil || string(ans) != "OK" {
		if c.debug {
			log.Printf("  probe len=%d: unexpected resp %q", targetCharLen, string(ans))
		}
		return false
	}
	return true
}

// buildProbeFQDN —— 构造完整 FQDN <CMC>.<DATA>.<META>.<SESSION>.<TLD>,
// 字符总长（不含 dns.Fqdn 加的 trailing dot）恰好为 targetTotalLen。
//
// CMC 每次重新生成,避免上游递归缓存把不同长度的探测混在一起。
func (c *DNSClient) buildProbeFQDN(targetTotalLen int) (string, bool) {
	suffix := CtrlMeta(cmdQNameProbe, 0) + "." + c.sessionID + "." + c.tld
	// final = "<CMC><dot><DATA><dot><suffix>" = cmcLength + 1 + dataLen + 1 + len(suffix)
	dataLen := targetTotalLen - cmcLength - 1 - 1 - len(suffix)
	if dataLen < 1 {
		return "", false
	}
	data := makeFixedLengthLabels(dataLen)
	if len(data) != dataLen {
		return "", false
	}
	return generateCMC() + "." + data + "." + suffix, true
}

// probeFragSize —— 二分查找下行 fragsize 上限。
//
// 范围 [100, 1200]（TXT 收窄到 [100, 300]）;每次 testFragSize 让服务端
// 造对应大小的 probe 数据返回,客户端比对长度是否 >= size。
//
// 返回值 = 探到的最大稳定大小 - 2（留点裕度,避免边界波动）；< 100 视为探测失败。
func (c *DNSClient) probeFragSize() int {
	lo, hi := 100, 1200
	if c.useNULL {
		hi = 1200
	} else {
		hi = 300
	}
	best := 0

	for lo <= hi {
		mid := (lo + hi) / 2
		if c.testFragSize(mid) {
			best = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}

	if best < 100 {
		return 0
	}
	return best - 2
}

// testFragSize —— 让服务端造一段 size 字节的 probe 数据,看回包是否真有那么大。
// 失败可能是路径上 EDNS UDP 阈值小于 size,或者中间设备截断了大 UDP。
func (c *DNSClient) testFragSize(size int) bool {
	sizeStr := formatSize(size)
	meta := CtrlMeta(cmdFragSize, 0)
	fqdn := buildFQDN(sizeStr, meta, c.sessionID, c.tld)

	resp, err := c.sendDNSFew(fqdn)
	if err != nil {
		return false
	}
	return len(resp) >= size
}

// commitFragSize —— 把探测到的 size commit 到服务端 session.maxFrag。
// param=1 是 commit 的标记（param=0 是 probe）。漏发这一步会让服务端按
// 默认 500 切片,客户端二分白做,下行吞吐被卡——这是 DESIGN.md §14 #9 的 bug。
func (c *DNSClient) commitFragSize(size int) error {
	sizeStr := formatSize(size)
	meta := CtrlMeta(cmdFragSize, 1)
	fqdn := buildFQDN(sizeStr, meta, c.sessionID, c.tld)
	resp, err := c.sendDNSFew(fqdn)
	if err != nil {
		return err
	}
	if resp == nil || string(resp) != "OK" {
		return fmt.Errorf("unexpected commit response: %q", string(resp))
	}
	return nil
}

// buildRespSizeProbeFQDN —— 构造 cmdRespSize probe 的完整 FQDN：
//
//	<CMC>.<sizeHex>.<padding>.<meta=ff0B00>.<session>.<tld>
//
// 整个 QNAME 字符总长（不含 dns.Fqdn 加的 trailing dot）= targetTotalLen。
// 服务端只取 dataStr 首段 4 hex 作为 size,padding 段仅用来撑长 QNAME。
//
// 这是 cmdFragSize 之外的"组合"探测：固定 QNAME 长度 ≈ 实际数据查询的最坏长,
// 同时让服务端返回 size 字节 rdata,二分找到稳定上限,推算出总响应预算。
func (c *DNSClient) buildRespSizeProbeFQDN(size int, targetTotalLen int) (string, bool) {
	cmc := generateCMC()
	sizeStr := formatSize(size)
	meta := CtrlMeta(cmdRespSize, 0)
	suffix := meta + "." + c.sessionID + "." + c.tld
	// 布局: <cmc>.<sizeStr>.<padding>.<suffix>
	// 字符数 = len(cmc) + 1 + len(sizeStr) + 1 + padLen + 1 + len(suffix)
	padLen := targetTotalLen - len(cmc) - 1 - len(sizeStr) - 1 - 1 - len(suffix)
	if padLen < 1 {
		return "", false
	}
	pad := makeFixedLengthLabels(padLen)
	if len(pad) != padLen {
		return "", false
	}
	return cmc + "." + sizeStr + "." + pad + "." + suffix, true
}

// testRespSize —— 在 targetQName 字符长度下让服务端回 size 字节 probe rdata,
// 看回包是否完整。任一步失败（i/o timeout / rcode != 0 / 长度不够）即认为
// 当前 (qname, size) 组合在递归路径上不可用。
func (c *DNSClient) testRespSize(size int, targetQNameLen int) bool {
	fqdn, ok := c.buildRespSizeProbeFQDN(size, targetQNameLen)
	if !ok {
		return false
	}
	qtype := dns.TypeTXT
	if c.useNULL {
		qtype = dns.TypeNULL
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), qtype)
	msg.RecursionDesired = true
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, opt)

	probeClient := &dns.Client{Net: "udp", ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second}
	r, _, err := probeClient.Exchange(msg, c.dnsServer)
	if err != nil {
		if c.debug {
			log.Printf("  respSize probe qname=%d size=%d: %v", targetQNameLen, size, err)
		}
		return false
	}
	if r.Rcode != dns.RcodeSuccess {
		if c.debug {
			log.Printf("  respSize probe qname=%d size=%d: rcode %d", targetQNameLen, size, r.Rcode)
		}
		return false
	}
	ans, err := c.extractAnswer(r)
	if err != nil {
		return false
	}
	return len(ans) >= size
}

// probeRespTotal —— 在"长 QNAME"下二分探测 rdata 上限,折算出 DNS 总响应字节预算。
//
// 输入 qnameLen 一般传 probeMaxQName 探出来的 budget（最坏情况下数据查询会到的字符长）。
// 二分范围 [100, maxRdata]：maxRdata 取 c.maxFrag + downPktHeaderSize（已 commit 的上限,
// 单维度下能过）。若组合下仍能过 maxRdata,说明本链路不卡总长,返回 0 表示"无需收紧"。
// 否则返回 (qnameLen + bestRdata + dnsRespOverhead) 作为总响应预算。
func (c *DNSClient) probeRespTotal(qnameLen int) int {
	if qnameLen <= 0 {
		return 0
	}
	maxRdata := c.maxFrag + downPktHeaderSize
	if maxRdata < 200 {
		return 0
	}

	// 先在 maxRdata 上探一次,过了说明本链路在"长 QNAME + 当前 fragsize"下毫无压力,
	// 不需要再压一档；直接返回 0 让服务端走静态 maxFrag。
	if c.testRespSize(maxRdata, qnameLen) {
		if c.debug {
			log.Printf("respSize probe at qname=%d rdata=%d ok; no total-budget shrink needed",
				qnameLen, maxRdata)
		}
		return 0
	}

	// floor 也过不去 → 链路不支持长 QNAME + 任何数据 rdata 组合,放弃。
	const floor = 100
	if !c.testRespSize(floor, qnameLen) {
		if c.debug {
			log.Printf("respSize probe failed at floor (qname=%d rdata=%d)", qnameLen, floor)
		}
		return 0
	}

	lo, hi := floor, maxRdata-1
	best := floor
	for lo <= hi {
		mid := (lo + hi) / 2
		if c.testRespSize(mid, qnameLen) {
			best = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	// best 是稳定的最大 rdata；总预算保守加上估计的固定开销。
	return qnameLen + best + dnsRespOverhead
}

// commitRespTotal —— 把探到的总响应字节预算告诉服务端,后续按当前查询的
// QNAME 长度动态收紧 chunk 上限。dataStr 形如 "<budgetHex>"（4 hex）。
func (c *DNSClient) commitRespTotal(budget int) error {
	sizeStr := formatSize(budget)
	meta := CtrlMeta(cmdRespSize, 1)
	fqdn := buildFQDN(sizeStr, meta, c.sessionID, c.tld)
	resp, err := c.sendDNSFew(fqdn)
	if err != nil {
		return err
	}
	if resp == nil || string(resp) != "OK" {
		return fmt.Errorf("unexpected commit response: %q", string(resp))
	}
	return nil
}

// sendDNSFew —— 重试 3 次的同步发送（用于握手探测,失败容忍度高）。
func (c *DNSClient) sendDNSFew(fqdn string) ([]byte, error) {
	return c.sendDNSRetries(fqdn, 3)
}

// sendDNS —— 重试 maxRetries (10) 次的同步发送（用于 cmdOpenStream 等关键命令）。
func (c *DNSClient) sendDNS(fqdn string) ([]byte, error) {
	return c.sendDNSRetries(fqdn, maxRetries)
}

// sendDNSRetries —— 通用同步 DNS 发送 + 重试。
//
// 每次重试都重新生成 CMC（让 QNAME 不同,绕开递归解析器缓存）。
// 仅对 i/o timeout 做 sleep retry,其它错误立即返回。
func (c *DNSClient) sendDNSRetries(fqdn string, retries int) ([]byte, error) {
	qtype := dns.TypeTXT
	if c.useNULL {
		qtype = dns.TypeNULL
	}

	for attempt := 1; attempt <= retries; attempt++ {
		retryFQDN := generateCMC() + "." + fqdn

		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(retryFQDN), qtype)
		msg.RecursionDesired = true
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(4096)
		msg.Extra = append(msg.Extra, opt)

		if c.debug {
			log.Printf("sendDNS attempt %d/%d: %s type=%d", attempt, retries, retryFQDN, qtype)
		}
		r, _, err := c.dnsClient.Exchange(msg, c.dnsServer)
		if err != nil {
			if strings.Contains(err.Error(), "i/o timeout") && attempt < retries {
				if c.debug {
					log.Printf("  attempt %d timeout, sleep %v and retry", attempt, retryDelay)
				}
				time.Sleep(retryDelay)
				continue
			}
			if c.debug {
				log.Printf("  attempt %d error: %v (giving up)", attempt, err)
			}
			return nil, err
		}
		if r.Rcode != dns.RcodeSuccess {
			if attempt < retries {
				if c.debug {
					log.Printf("  attempt %d rcode=%d, sleep %v and retry", attempt, r.Rcode, retryDelay)
				}
				time.Sleep(retryDelay)
				continue
			}
			if c.debug {
				log.Printf("  attempt %d rcode=%d (giving up)", attempt, r.Rcode)
			}
			return nil, fmt.Errorf("DNS error %d", r.Rcode)
		}
		ans, err := c.extractAnswer(r)
		if c.debug {
			log.Printf("  attempt %d ok: rdata=%d bytes", attempt, len(ans))
		}
		return ans, err
	}
	return nil, fmt.Errorf("max retries")
}

// sendDNSOnce —— 同步发一次,不重试。用于 cmdCloseStream 这种"丢了无所谓"的通知。
func (c *DNSClient) sendDNSOnce(fqdn string) ([]byte, error) {
	qtype := dns.TypeTXT
	if c.useNULL {
		qtype = dns.TypeNULL
	}
	fqdn = generateCMC() + "." + fqdn

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), qtype)
	msg.RecursionDesired = true
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, opt)

	r, _, err := c.dnsClient.Exchange(msg, c.dnsServer)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS error %d", r.Rcode)
	}
	return c.extractAnswer(r)
}

// extractAnswer —— 从 dns.Msg 抽出 RDATA。
//
// 支持的记录类型：NULL（rdata 是原始字节）和 TXT（rdata 是若干字符串拼起来）。
// 其它类型返回 (nil, nil)（不报错,继续等下一个响应）。
func (c *DNSClient) extractAnswer(r *dns.Msg) ([]byte, error) {
	if len(r.Answer) == 0 {
		return nil, nil
	}
	if null, ok := r.Answer[0].(*dns.NULL); ok {
		return []byte(null.Data), nil
	}
	if txt, ok := r.Answer[0].(*dns.TXT); ok {
		return []byte(strings.Join(txt.Txt, "")), nil
	}
	return nil, nil
}

// decodeResponse —— 把服务端发来的 RDATA 解成 DownPkt。
//
// 处理几种特殊响应：
//   - "x"、"EMPTY"、"OK"、"ERR"：控制类应答,不是 DownPkt,返回 nil 让 dataLoop 当 idle 处理。
//     "x" 是历史遗留的 dummy 响应（详见 DESIGN.md §7.2 / §14.0）,现在服务端已经不再发,
//     但保留客户端解码兼容,避免和旧服务端通信时崩。
//   - "CLOSED"：服务端通知会话关闭,返回构造的 Closed DownPkt。
//
// 正常路径：
//  1. NULL 模式直接用 raw；TXT 模式先 DNS-safe decode。
//  2. Vigenère 解密。
//  3. DecodeDownPkt 解头。如果 Compressed flag 置位,ZlibDecompress payload。
func (c *DNSClient) decodeResponse(raw []byte) *DownPkt {
	if raw == nil || len(raw) == 0 {
		return nil
	}
	text := string(raw)
	if text == "x" || text == "EMPTY" || text == "OK" || text == "ERR" {
		return nil
	}
	if text == "CLOSED" {
		return &DownPkt{Closed: true}
	}

	var data []byte
	var err error
	if c.useNULL {
		data = raw
	} else {
		data, err = decodeDNSSafe(text, c.encoding)
		if err != nil {
			if c.debug {
				log.Printf("Decode error: %v", err)
			}
			return nil
		}
	}

	data = vigenereDecrypt(data, c.key)

	pkt, err := DecodeDownPkt(data)
	if err != nil {
		if c.debug {
			log.Printf("Pkt decode error: %v", err)
		}
		return nil
	}

	if pkt.Compressed && len(pkt.Payload) > 0 {
		dec, err := ZlibDecompress(pkt.Payload)
		if err != nil {
			if c.debug {
				log.Printf("Decompress error: %v", err)
			}
			return nil
		}
		pkt.Payload = dec
	}

	return pkt
}
