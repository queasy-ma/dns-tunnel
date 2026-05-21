// 本文件实现 dns-tunnel 的客户端侧。
//
// 角色：监听本地 TCP,把每个连接映射成一条 stream,数据编进 DNS 查询 QNAME 发给服务端；
// DNS 应答解码后写回本地 TCP socket。
//
// 关键组件：
//   - DNSClient        ：客户端运行态,管理监听 socket + sessionID + stream 表。
//   - dataLoop         ：唯一负责"发上行 + 收下行"的 goroutine,严格 1-in-flight。
//   - dnsRecvLoop      ：唯一负责底层 socket 读的 goroutine,解出 DNS 响应送入 recvCh。
//   - streamReader     ：每个 stream 一个,本地 TCP read → 入 upBuf,唤醒 dataLoop。
//   - streamWriter     ：每个 stream 一个,从 downBuf 异步写本地 TCP,不阻塞 dataLoop。
//   - 握手 sendDNS*    ：用独立的 c.dnsClient（同步 Exchange）完成版本协商、编码探测等。
//
// 设计取舍 / 关键不变量（详见 DESIGN.md §6.1）：
//   - **严格 1-in-flight**：在 dataLoop 里用 `inFlight` 标记保证最多 1 个查询在途。
//     违反它会让 server 端 lazyHeld 兜底节流路径反复触发,QPS 飙到 ~10/s。
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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
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
		streams:     make(map[uint8]*clientStream),
		nextSID:     1,
		upNotify:    make(chan struct{}, 1),
		quit:        make(chan struct{}),
	}
	return c, nil
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

	c.mu.Lock()
	c.streams = make(map[uint8]*clientStream)
	c.nextSID = 1
	c.mu.Unlock()

	if err := c.handshake(); err != nil {
		return err
	}

	c.tunnelUp.Store(true)

	if c.debug {
		log.Printf("Tunnel ready: lazy=%v compress=%v null=%v maxfrag=%d enc=%d",
			c.lazyMode, c.compression, c.useNULL, c.maxFrag, c.encoding)
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
//   - 严格 1-in-flight：每次发包后 inFlight=true,收到响应才 inFlight=false 并发下一个。
//   - 收到响应就立刻发下一个（不加 idle gap,见 §14 修复演进 #5）。
//   - tunnelUp=false 就退出；外层 Accept 循环会触发重连。
//
// 三路 select：
//   - recvCh：收到 DNS 响应,处理 ack + payload；**只在 inFlight==0 时才发下一个**。
//   - upNotify：streamReader 通知有新上行字节,**只在 inFlight==0 && upAcked 时才 send**。
//   - timeout：lazy 模式 2s、非 lazy 5s。
//   - inFlight==0：异常路径（正常应被 server lazy hold 兜住）,补一发。
//   - inFlight>0：怀疑丢响应,补发一个 retransmit；**不重置 inFlight**,
//     让 recv 把多发的那个自然消化（详见 timeout 分支注释）。
func (c *DNSClient) dataLoop() {
	conn, err := net.Dial("udp", c.dnsServer)
	if err != nil {
		if c.debug {
			log.Printf("DNS dial failed: %v", err)
		}
		c.tunnelUp.Store(false)
		return
	}
	defer conn.Close()

	recvCh := make(chan []byte, 64)
	go c.dnsRecvLoop(conn, recvCh)

	var upSeq uint8       // 下一次上行帧的 seq
	var downAck uint8     // 要捎带给服务端的"最近收到的下行 seq"
	var lastUpData []byte // 重传缓冲：未 ack 的上行 payload
	var lastUpSID uint8   // 上一次发的 streamID（重传用）
	upAcked := true       // 上一帧已被服务端 ack
	downInited := false   // 是否已经收到过下行,用于 lastDownSeq 初始化
	var lastDownSeq uint8 // 上次收到的下行 seq,用于去重（同 seq 重传）
	// inFlight：严格 1-in-flight 不变量。**计数器**,不是布尔。
	//
	// 语义：
	//   - 0：网络上没有未回应的查询,可以自由 send()。
	//   - 1：稳态（每次 send 后到对应 recv 前）。
	//   - >1：timeout 重传造成的瞬态;recv 会把它消化掉、**不**触发新 send,
	//     直到回到 0 才发下一个。
	//
	// 历史 bug（DESIGN.md §14 / CLAUDE.md "高频地雷 #2"）：早期是 bool,
	// timeout 分支直接 c.asyncSend... 重传但 inFlight 不动,等于"幻在途"——
	// 延迟的原响应回来后客户端立刻 send,网络上稳态 2-in-flight。两个 query
	// 撞进服务端时,一个占住 lazyHeld 1s,另一个走 concurrentPoll 空响应秒回——
	// 形成 30/秒 自维持空 poll 风暴。改成计数器 + "inFlight==0 才发"的 gate
	// 后,timeout 重传只会瞬态 2-in-flight,recv 拿到第一个响应不触发新 send,
	// 等第二个响应回来 inFlight 回 0,才发下一个。
	inFlight := 0

	// lazy 降级跟踪（参考 iodine client.c send_query）：
	// windowSent/windowRecv 统计 dataLoop 启动后的发送/接收量。
	// 如果 windowSent > 6 且 windowRecv == 0，说明解析器吃掉了所有 lazy 响应，
	// 主动关闭 lazy 模式并通知服务端。
	windowSent := 0
	windowRecv := 0

	// send —— 发一个查询。优先重传未 ack 的旧帧,否则从 selectUpstream 取新数据,
	// 都没有的话发 poll。**调用方负责确认 inFlight==0 (或在 timeout 重传场景下接受瞬态 >1)**。
	send := func() {
		if !upAcked && lastUpData != nil {
			if c.debug {
				log.Printf("send: retransmit unacked sid=%d seq=%d len=%d ack=%d",
					lastUpSID, upSeq, len(lastUpData), downAck)
			}
			c.asyncSendStreamData(conn, lastUpSID, lastUpData, upSeq, downAck)
		} else {
			sid, data := c.selectUpstream()
			if data != nil {
				lastUpSID = sid
				lastUpData = data
				upAcked = false
				if c.debug {
					log.Printf("send: new data sid=%d seq=%d len=%d ack=%d", sid, upSeq, len(data), downAck)
				}
				c.asyncSendStreamData(conn, sid, data, upSeq, downAck)
			} else {
				if c.debug {
					log.Printf("send: poll (no upstream data) ack=%d", downAck)
				}
				c.asyncSendPoll(conn, downAck)
			}
		}
		windowSent++
		inFlight++
	}

	send()

	for c.tunnelUp.Load() {
		timeout := 5 * time.Second
		if c.lazyMode {
			// lazy 模式下,服务端会 hold 最多 lazyTimeout(1s),所以客户端 2s 仍未
			// 收到响应基本就是丢包/远端死了。
			timeout = 2 * time.Second
		}

		select {
		case raw := <-recvCh:
			windowRecv++
			if inFlight > 0 {
				inFlight--
			}
			pkt := c.decodeResponse(raw)
			if pkt == nil {
				if c.debug {
					log.Printf("recv: decode failed (len=%d), skip", len(raw))
				}
			} else {
				if c.debug {
					log.Printf("recv: pkt seq=%d ack=%d sid=%d payload=%d flags=%s inFlight=%d",
						pkt.Seq, pkt.Ack, pkt.StreamID, len(pkt.Payload), pktFlags(pkt), inFlight)
				}
				c.processDown(pkt, &downAck, &downInited, &lastDownSeq)
				if !upAcked && pkt.Ack == upSeq {
					if c.debug {
						log.Printf("  ack accepted: upSeq %d → %d", upSeq, nextSeq(upSeq))
					}
					upAcked = true
					upSeq = nextSeq(upSeq)
					lastUpData = nil
				} else if !upAcked && c.debug {
					log.Printf("  ack mismatch: got=%d want=%d (still waiting, will retransmit)",
						pkt.Ack, upSeq)
				}
			}

			// processDown 里如果收到 Closed 标志会把 tunnelUp 置 false。
			if !c.tunnelUp.Load() {
				if c.debug {
					log.Printf("recv: tunnelUp=false after processDown, dataLoop exiting")
				}
				return
			}

			// 严格 1-in-flight 关键 gate：只在 inFlight==0 时发下一个。
			// inFlight>0 说明此前 timeout 多发过 retransmit、网络上还有别的
			// 响应没回来,**不**触发新 send,等剩下的响应自然消化。
			// 这是消除自维持空 poll 风暴的核心机制（见上方 inFlight 注释）。
			if inFlight == 0 {
				send()
			} else if c.debug {
				log.Printf("recv: drain mode, inFlight=%d still pending, no send", inFlight)
			}

		case <-c.upNotify:
			// streamReader 通知有新上行字节。只在 inFlight==0 && upAcked 时发,
			// 否则违反 1-in-flight；下一次 recvCh 触发 send() 时 selectUpstream
			// 也会取到这些字节,数据不会丢。
			if inFlight == 0 && upAcked {
				if c.debug {
					log.Printf("upNotify: triggering send (inFlight=0 upAcked=true)")
				}
				send()
			} else if c.debug {
				log.Printf("upNotify: gated (inFlight=%d upAcked=%v) — will be picked up on next recv",
					inFlight, upAcked)
			}

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

			if inFlight > 0 && c.debug {
				log.Printf("timeout(%v): suspect response lost, retransmit (inFlight %d → %d)",
					timeout, inFlight, inFlight+1)
			} else if c.debug {
				log.Printf("timeout(%v): no inflight, idle send", timeout)
			}
			send()
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
//  3. payload + 新 seq → 入 downBuf + downSig 唤醒 writer + 更新 downAck/lastDownSeq。
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
// **背压**：recvCh 容量 64,写入时给 100ms 超时；超时丢包并打日志。
// 历史 bug（DESIGN.md §14 #8）：早期 `default` 直接丢,dataLoop 偶尔卡一下就静默丢响应,
// 看似稳定但偶现死锁。
func (c *DNSClient) dnsRecvLoop(conn net.Conn, ch chan<- []byte) {
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
			if c.debug {
				qname := ""
				if len(msg.Question) > 0 {
					qname = msg.Question[0].Name
				}
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
			select {
			case ch <- data:
			case <-time.After(100 * time.Millisecond):
				if c.debug {
					log.Printf("recv channel backpressure, dropping packet")
				}
			}
		}
	}
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
	// 服务端返回 "V,<ver>,<maxfraghex>"；解第 3 段作为初始 maxFrag。
	if resp != nil && len(resp) > 0 && resp[0] == 'V' {
		parts := strings.Split(string(resp), ",")
		if len(parts) >= 3 {
			if size, e := parseSize(parts[2]); e == nil && size > 0 {
				c.maxFrag = size
			}
		}
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

	return nil
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
