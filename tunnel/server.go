// 本文件实现 dns-tunnel 的服务端侧。
//
// 角色：监听 UDP/53(或委派 NS)、解析每条上行 DNS 查询、按命令字派发,
// 同时维护多个客户端 session,把上行字节写进真实 TCP 目标,把下行字节
// 通过 DNS 应答 RDATA 送回去。
//
// 核心结构（按粒度从大到小）：
//   - DNSServer        ：进程级,维护所有 session、监听 socket。
//   - Session          ：会话级,sessionID 索引；含 inflight 合流、L1 dnsCache、
//     L2 qmem、下行 lazy hold 状态、stream 表。
//   - Stream           ：单个 TCP 流,有独立的 reader / writer goroutine。
//   - inflightEntry    ：并发同名查询的合流槽位（详见下方 §7）。
//
// 关键路径（详见 DESIGN.md §6 / §7）：
//  1. handleDNSRequest     —— 拆 QNAME、找 session、做四层去重。
//  2. handleControl/Data   —— 按 meta 分派到具体命令处理或数据落盘。
//  3. handlePollWithAck    —— 把下行 chunk 编进 DNS 应答；lazy 模式下 hold 最多 1s。
//  4. sendAndCacheTXT/NULL —— 唯一的"写 DNS 应答 + 缓存 L1 + 填 inflight"汇聚点。
//
// 并发模型：miekg/dns 按每条查询起一个 goroutine 调 handleDNSRequest。
// 同 session 多个并发 handler 之间靠 session.mu 串行化共享状态；
// 不同 session 之间几乎完全独立（仅 DNSServer.mu 在 getOrCreateSession 短暂持有）。
package tunnel

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// dnsCacheEntry —— L1 缓存条目（per-session 的 dnsCache ring）。
//
// 缓存键：(name, qtype) 精确匹配；命中即重放 data。
// 大小写不敏感的命中用 lookupDNSCacheCI（path 上 0x20 改写过来的查询）。
type dnsCacheEntry struct {
	name   string
	qtype  uint16
	data   []byte
	isNULL bool // true 表示用 NULL 记录回；false 用 TXT。
}

// inflightEntry —— "并发同名查询合流" 的同步槽位。
//
// 触发场景：上游递归解析器 / 企业内 DC（DNS 转发器）会把同一条客户端查询
// 从多个出口 IP 几乎同时转发到本服务端。两份查询的 QNAME / qtype 完全相同，
// 但都在 L1 dnsCache 还没填好之前就到达——任何只看「过往响应」的去重层
// 都救不了它们。
//
// 设计：让第一份查询正常处理；第二份及后续在 session.inflight 里查到该
// 条目后，阻塞等待 done 被关闭，再把 first handler 写下的字节
// （entry.data / entry.isNULL）原样回放。这样两个出口 IP 收到字节完全
// 一致的 DNS 应答，DC 不管挑哪一份转给真实客户端都不会破协议。
//
// 字段语义：
//   - done：first handler 在 defer 里 close 它，唤醒所有 waiter。channel
//     的 happens-before 保证 waiter 在唤醒后读取 data / isNULL 是安全的。
//   - data：first handler 在 sendAndCacheTXT/NULL 里持锁写入；写入后只读。
//   - isNULL：原始响应是 NULL 记录（true）还是 TXT 记录（false）。
type inflightEntry struct {
	done   chan struct{}
	data   []byte
	isNULL bool
}

const (
	// dnsCacheSize —— L1 精确 / CI 缓存 ring 的容量。
	// 容量小是因为 stop-and-wait 协议下,任一时刻只有少量"刚发出去、可能被重传"
	// 的查询。8 已经够覆盖几个 RTT 的窗口。
	dnsCacheSize = 8
	// qmemSize —— L2 qmem CMC ring 的容量。
	// 留得比 L1 大一截,用于挡"超过 L1 窗口的晚到重放"（避免重新执行带副作用的控制命令）。
	qmemSize = 30
)

// inflightKey —— inflight map 的键。QNAME 必须小写以兼容路径上"0x20-bit
// 随机化"的递归解析器；qtype 直接编进尾部 2 字节，避免与 name 里可能
// 出现的分隔字符歧义。
func inflightKey(name string, qtype uint16) string {
	return strings.ToLower(name) + string([]byte{byte(qtype >> 8), byte(qtype)})
}

// Stream —— 服务端侧一条 TCP 流的运行态。
//
// 与 client 端 clientStream 对应,id 一一对齐。
//
// 字段语义：
//   - downBuf       ：从真实 TCP 目标 read 来的字节,等下行 poll 取去送回 client。
//   - upBuf         ：从 client 上行 DNS 收来的字节,等 startTCPWriter 写进真实 TCP。
//   - upSig         ：startTCPWriter 阻塞唤醒用,非阻塞写,容量 1。
//   - closed        ：硬关闭。reader / writer 退出。
//   - notifiedClose ：服务端已通过 StreamClosed 通知 client；防止重复通知。
type Stream struct {
	id            uint8
	conn          net.Conn
	downBuf       []byte // 真实 TCP read → 隧道下行
	upBuf         []byte // 隧道上行 → 真实 TCP write
	upSig         chan struct{}
	closed        bool
	notifiedClose bool
}

// Session —— 单个客户端的会话级状态。
//
// 锁规约：所有字段写都要持有 mu。读路径有两类例外：
//   - 在 handler 入口短暂持锁 snapshot 出来再处理（典型见 handleData 取 enc）。
//   - close(entry.done) 之后,first handler 对 inflightEntry 的写已经
//     happens-before 给 waiter,waiter 仍然走 mu 读以保 race-free（见 waitAndServeInflight 注释）。
type Session struct {
	mu         sync.Mutex
	closed     bool      // session 已被关闭；后续 poll 走 Closed flag 路径
	lastActive time.Time // 任一上行 / 真实 TCP 读写都会刷新；超过 5 分钟由 cleanupSessions 回收

	streams       map[uint8]*Stream
	dataReady     chan struct{} // 任一 stream 有新下行数据 / closed,唤醒 waitForDown
	lastDownSched uint8         // getAnyDownChunk 的 round-robin 游标

	// 上行 seq 跟踪：检测同一 seq 的重传（不会重复 write 到真实 TCP）。
	upRecvSeq uint8 // 当前已确认收到的最新上行 seq
	upInited  bool  // 收到过第一帧之前的初始化标志

	// 下行单 slot stop-and-wait 状态：
	//   - 同一时刻最多 1 个未 ack 的 downChunk 在途。
	//   - downAcked == false 表示这个 chunk 还在等 client ack；poll 到来时按 ack 推进。
	downSeq      uint8
	downChunk    []byte
	downChunkSID uint8
	downAcked    bool

	// 握手协商出的会话级配置。握手完成后写入,后续只读。
	lazyMode    bool
	compression bool
	useNULL     bool
	maxFrag     int
	encoding    int

	// L1 dnsCache ring：精确 / CI 命中 → 直接回放上次的 RDATA。
	dnsCache     [dnsCacheSize]dnsCacheEntry
	dnsCacheIdx  int
	dnsCacheFill int

	// L2 qmem CMC ring：仅 CMC 维度,挡晚到重放。命中后回合法空 DownPkt（不再执行命令）。
	qmemCMC  [qmemSize]string
	qmemIdx  int
	qmemFill int

	// inflight：键由 inflightKey(name, qtype) 构造。规约——只有"插入
	// 这条 entry 的那个 goroutine"负责后续把它从 map 里删掉、并 close
	// entry.done；其它撞上同 key 的 goroutine 一律是 waiter，不许动写
	// 路径（不能写 downChunk、不能抢 lazyHeld）。这条不变量是整个合流
	// 机制的正确性基础。
	inflight map[string]*inflightEntry

	// lazyHeld —— 同一 session 同一时刻最多有 1 个 goroutine 进入 lazy hold
	// （waitForDown 等下行数据,最长 lazyTimeout）。其它并发 poll 撞到这个标志
	// 时直接落到 concurrentPoll 兜底分支（不抢 downChunk slot,见 §14.1）。
	// 用 defer 重置,确保 panic 也能释放。
	lazyHeld bool
}

// Close —— 关 session。
// 关 streams 的真实 TCP socket,唤醒 writer goroutine 让它们退出。
// 多次调用安全（看 s.closed 守卫）。
//
// 注意：**不**显式 close session.dataReady / Stream.upSig channel,因为它们
// 都是非阻塞写,close 后再有 send 会 panic。让 goroutine 看到 st.closed=true
// 自然退出即可。
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		for _, st := range s.streams {
			if !st.closed && st.conn != nil {
				st.conn.Close()
				st.closed = true
			}
			if st.upSig != nil {
				select {
				case st.upSig <- struct{}{}:
				default:
				}
			}
		}
	}
}

// IsClosed —— 线程安全地读 closed 标志。getOrCreateSession 用它判断
// 老 session 是否还能复用。
func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// startTCPReader —— 真实 TCP 目标的 reader goroutine。
//
// 流程：阻塞 Read（30s deadline 防止 conn 永久挂着）→ 把字节 append 到 stream.downBuf
// → 通知 dataReady。Read 出错（包括 EOF）→ 标记 closed + 唤醒可能在等的 writer + 退出。
//
// 注意 deadline 失败（Timeout）不算错误,只是 continue 重新 Read。这让我们能
// 检测 session 关闭：session.Close() 把 st.closed=true 后,本 goroutine 下一轮
// timeout 醒来检查 closed 就退出。
func (st *Stream) startTCPReader(session *Session) {
	buf := make([]byte, 4096)
	for {
		session.mu.Lock()
		if st.closed {
			session.mu.Unlock()
			return
		}
		conn := st.conn
		session.mu.Unlock()
		if conn == nil {
			return
		}

		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			session.mu.Lock()
			st.downBuf = append(st.downBuf, buf[:n]...)
			session.lastActive = time.Now()
			session.mu.Unlock()

			select {
			case session.dataReady <- struct{}{}:
			default:
			}
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			session.mu.Lock()
			st.closed = true
			session.mu.Unlock()

			select {
			case session.dataReady <- struct{}{}:
			default:
			}
			select {
			case st.upSig <- struct{}{}:
			default:
			}
			return
		}
	}
}

// getAnyDownChunk —— round-robin 从某个 stream 取出最多 maxSize 字节下行。
//
// **必须**持有 session.mu。
//
// 公平性细节（DESIGN.md §8.3）：
//   - 从 lastDownSched+1 开始扫,确保上次服务过的 stream 不会立刻又被选中。
//   - 循环 maxStreams+1 次让 `start` 自己也被遍历到（少一次就漏掉它）。
//   - sid==0 是哨兵,continue 跳过；多一次迭代不会冲掉真 stream。
func (s *Session) getAnyDownChunk(maxSize int) (uint8, []byte) {
	start := s.lastDownSched
	for i := 1; i <= maxStreams+1; i++ {
		sid := uint8((int(start) + i) % (maxStreams + 1))
		if sid == 0 {
			continue
		}
		st, ok := s.streams[sid]
		if !ok || len(st.downBuf) == 0 {
			continue
		}
		n := maxSize
		if n > len(st.downBuf) {
			n = len(st.downBuf)
		}
		chunk := make([]byte, n)
		copy(chunk, st.downBuf[:n])
		st.downBuf = st.downBuf[n:]
		s.lastDownSched = sid
		return sid, chunk
	}
	return 0, nil
}

// getClosedStreamToNotify —— 选一个"已关闭但还没通知 client + downBuf 已空"的 stream 来发 StreamClosed。
//
// **必须**持有 session.mu。
//
// `downBuf 已空` 这个守卫确保数据先全部送达,关闭通知最后到——避免 SCP 等
// 应用丢尾字节（client 侧 closing-then-close 也对应同一保证）。
func (s *Session) getClosedStreamToNotify() uint8 {
	for _, st := range s.streams {
		if st.closed && !st.notifiedClose && len(st.downBuf) == 0 {
			st.notifiedClose = true
			return st.id
		}
	}
	return 0
}

// waitForDown —— lazy hold 等待"任意 stream 有下行数据"。
//
// 自身**不**持锁；按需 lock-then-check 短临界区,避免阻塞其它 handler。
//
// 流程：
//   - 先 try getAnyDownChunk,有就立即返回。
//   - 否则阻塞等 dataReady 或 deadline,然后再 try。
//
// timeout 通常是 lazyTimeout(1s)；非 lazy 模式下传 minLazyHold(100ms) 兜底。
func (s *Session) waitForDown(maxSize int, timeout time.Duration) (uint8, []byte) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		sid, chunk := s.getAnyDownChunk(maxSize)
		s.mu.Unlock()
		if chunk != nil {
			return sid, chunk
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		select {
		case <-s.dataReady:
		case <-time.After(remaining):
			return 0, nil
		}
	}
	return 0, nil
}

// saveToDNSCache —— L1：把响应字节存进 dnsCache ring。
// **必须**持有 s.mu。所有响应都通过 sendAndCacheTXT/NULL 走这里,无需特殊路径。
func (s *Session) saveToDNSCache(name string, qtype uint16, data []byte, isNULL bool) {
	entry := &s.dnsCache[s.dnsCacheIdx]
	entry.name = name
	entry.qtype = qtype
	entry.data = make([]byte, len(data))
	copy(entry.data, data)
	entry.isNULL = isNULL
	s.dnsCacheIdx = (s.dnsCacheIdx + 1) % dnsCacheSize
	if s.dnsCacheFill < dnsCacheSize {
		s.dnsCacheFill++
	}
}

// lookupDNSCache —— L1：精确匹配查找。**必须**持有 s.mu。
// 命中即回放,完全 bit-identical 的查询用同一份 RDATA 应答。
func (s *Session) lookupDNSCache(name string, qtype uint16) *dnsCacheEntry {
	for i := 0; i < s.dnsCacheFill; i++ {
		e := &s.dnsCache[i]
		if e.qtype == qtype && e.name == name {
			return e
		}
	}
	return nil
}

// lookupDNSCacheCI —— L1：大小写不敏感查找。**必须**持有 s.mu。
// 用于"路径上 0x20-bit 随机化"过的重传——QNAME 大小写翻乱但其它都一样。
func (s *Session) lookupDNSCacheCI(name string, qtype uint16) *dnsCacheEntry {
	lower := strings.ToLower(name)
	for i := 0; i < s.dnsCacheFill; i++ {
		e := &s.dnsCache[i]
		if e.qtype == qtype && strings.ToLower(e.name) == lower {
			return e
		}
	}
	return nil
}

// cmcInQmem —— L2：CMC 是否在 qmem 里见过。**必须**持有 s.mu。
// 大小写不敏感。命中表示这条查询是"已超出 L1 ring 但 qmem 还记得"的晚到重放,
// 调用方应当回合法空 DownPkt（不要重新执行命令）。
func (s *Session) cmcInQmem(cmc string) bool {
	lower := strings.ToLower(cmc)
	for i := 0; i < s.qmemFill; i++ {
		if s.qmemCMC[i] == lower {
			return true
		}
	}
	return false
}

// saveToQmem —— L2：把 CMC 存进 qmem ring。**必须**持有 s.mu。
// 在 handleDNSRequest 注册 inflight 那一步顺手调用,只对"首发"查询记录。
func (s *Session) saveToQmem(cmc string) {
	s.qmemCMC[s.qmemIdx] = strings.ToLower(cmc)
	s.qmemIdx = (s.qmemIdx + 1) % qmemSize
	if s.qmemFill < qmemSize {
		s.qmemFill++
	}
}

// DNSServer —— 进程级状态。
//
// 字段：
//   - dnsListener      ：监听地址（"0.0.0.0:53" 之类）。
//   - tcpDest          ：真实 TCP 目标地址（host:port）；每个 stream open 时 dial 它。
//   - sessions         ：sessionID → Session,所有客户端会话；mu 保护。
//   - domain           ：NS 委派模式下的服务端域（"t.example.com"）；空表示直连模式。
//   - parentDomain     ：domain 的父域,用于 SOA/NS 回包。
//   - domainPartsCount ：domain 用 "." 切的段数,handleDNSRequest 从尾部切掉这么多段还原 tunnelParts。
//   - dnsServerInst / quit / running / closed ：作为库使用时的生命周期状态,
//     全部由 runMu 保护（早期分两把锁导致 Close/Start 间留竞态窗口,见下方字段注释）。
//
// 作为库使用时（同进程多实例 / 反复启停）：
//   - 用独立的 dns.ServeMux 而不是包全局 mux,避免多实例互相覆盖 handler。
//   - cleanupSessions goroutine 监听 quit 退出,不会随 Close 泄漏。
type DNSServer struct {
	dnsListener      string
	tcpDest          string
	sessions         map[string]*Session
	mu               sync.Mutex
	debug            bool
	key              string
	domain           string
	parentDomain     string
	domainPartsCount int

	// 生命周期字段。**runMu 同时保护 running / closed / quit / dnsServerInst**。
	// 以前 dnsServerInst 单独放在 instMu 下,但与 runMu(closed/quit) 是两把锁,
	// 给 Close 与 Start 之间留出竞态窗口（Close 看到 dnsServerInst=nil 跳过
	// Shutdown,Start 接着 publish 了 dnsServerInst 然后阻塞 ListenAndServe,
	// 永远没人 Shutdown）。合到一把锁后,"check closed + publish dnsServerInst"
	// 可以在同一临界区原子完成。
	runMu         sync.RWMutex
	running       bool
	closed        bool
	quit          chan struct{}
	dnsServerInst *dns.Server
}

// NewDNSServer —— 构造服务端。
// 解析 domain 的段数 + 父域,后续 handleDNSRequest 用 domainPartsCount 切 FQDN。
//
// logToFile=true 时调用 EnableFileLog() 把日志重定向到
// <可执行文件目录>/<YYYY-MM-DD>.log。失败只在 stderr 打一行警告,不影响构造
// (服务端启动本身不依赖文件日志,失败时降级回 stderr 仍可用)。
func NewDNSServer(dnsListener, tcpDest string, debug bool, key string, domain string, logToFile bool) *DNSServer {
	if logToFile {
		if _, err := EnableFileLog(); err != nil {
			log.Printf("NewDNSServer: EnableFileLog failed: %v (falling back to stderr)", err)
		}
	}
	domainParts := 1
	parentDomain := domain
	if domain != "" {
		domainParts = len(strings.Split(domain, "."))
		idx := strings.Index(domain, ".")
		if idx >= 0 {
			parentDomain = domain[idx+1:]
		}
	}
	return &DNSServer{
		dnsListener:      dnsListener,
		tcpDest:          tcpDest,
		sessions:         make(map[string]*Session),
		debug:            debug,
		key:              key,
		domain:           domain,
		parentDomain:     parentDomain,
		domainPartsCount: domainParts,
	}
}

// Close —— 优雅停止 DNS 监听 + 通知 cleanupSessions 退出。多次调用安全。
// 已经建立的 session 不会被立即销毁（仍在 sessions map 里）；要彻底清理需调用方
// 在 Close 后丢弃整个 DNSServer 实例。
//
// 在 runMu 内**同时**置 closed=true + 快照 quit / dnsServerInst,之后释放锁
// 再做 IO。这保证了即使 Close 与一个还在 scheduled 状态的 Start goroutine 撞车,
// Start 也会在 runMu.Lock 内看到 closed=true,不再 publish dnsServerInst,
// 也不会阻塞 ListenAndServe。
func (s *DNSServer) Close() {
	s.runMu.Lock()
	s.closed = true
	s.running = false
	quit := s.quit
	inst := s.dnsServerInst
	s.dnsServerInst = nil
	s.runMu.Unlock()

	if quit != nil {
		select {
		case <-quit:
		default:
			close(quit)
		}
	}
	if inst != nil {
		inst.Shutdown()
	}
}

// IsRunning —— 用 RLock 允许并发查询,与 DNSClient.IsRunning 语义对齐。
func (s *DNSServer) IsRunning() bool {
	s.runMu.RLock()
	defer s.runMu.RUnlock()
	return s.running
}

// MarkRunning —— 给外部库使用者用的"我打算 Start 了"标记。
// 普通命令行模式下 Start 内部会自己置位,无需手动调用；库场景下
// `go server.Start()` 与 `IsRunning()` 查询之间会有竞态窗口,这个方法
// 在 goroutine 里调 Start 前主线程先调一下,即可消除窗口。
func (s *DNSServer) MarkRunning() {
	s.runMu.Lock()
	s.running = true
	s.runMu.Unlock()
}

// Start —— 启动后台清理 + DNS UDP 监听。阻塞调用,返回即代表致命错误。
//
// 使用自有 dns.ServeMux 而不是包全局 mux,允许同进程多 DNSServer 实例
// 各自路由互不干扰（包全局 mux 会让后注册的 handler 覆盖先注册的）。
//
// 生命周期：
//   - 同一 *DNSServer 实例**最多 Start 一次**。Close 后再 Start 直接返回 error,
//     需要重启请用 NewDNSServer 建新实例。
//   - Start 内对 dnsServerInst 的发布与 closed 检查在同一个 runMu 临界区内完成,
//     避免 Close 抢先 / 错过 inst 而后 ListenAndServe 永远没人 Shutdown。
func (s *DNSServer) Start() error {
	// 第 1 道闸：注册 quit + running。如果已被 Close 过,直接拒绝。
	s.runMu.Lock()
	if s.closed {
		s.runMu.Unlock()
		return fmt.Errorf("server has been closed; create a new DNSServer to restart")
	}
	s.running = true
	if s.quit == nil {
		s.quit = make(chan struct{})
	}
	quit := s.quit
	s.runMu.Unlock()
	defer func() {
		s.runMu.Lock()
		s.running = false
		s.runMu.Unlock()
	}()

	go s.cleanupSessions(quit)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNSRequest)
	server := &dns.Server{Addr: s.dnsListener, Net: "udp", Handler: mux}

	// 第 2 道闸：publish dnsServerInst 与 closed 检查在同一把锁下原子完成。
	// 如果 Close 在 quit 释放后 / 这里之前打进来,它看到 dnsServerInst=nil 跳过
	// Shutdown,但接下来 closed=true,我们这里直接返回,不会阻塞 ListenAndServe。
	s.runMu.Lock()
	if s.closed {
		s.runMu.Unlock()
		return nil
	}
	s.dnsServerInst = server
	s.runMu.Unlock()

	if s.debug {
		log.Printf("DNS server on %s (UDP)", s.dnsListener)
	}
	return server.ListenAndServe()
}

// getOrCreateSession —— 按 sessionID 查找或新建 Session。
//
// **注意**：任何看起来格式合法的 sessionID 都会创建 session。这是已知的 DoS
// 暴露面（攻击者可生成大量假 sessionID 占空闲条目）；目前靠 cleanupSessions
// 的 5 分钟回收兜底,生产部署应当在前面加 token / 双向预共享。
func (s *DNSServer) getOrCreateSession(sessionID string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if exists && !session.IsClosed() {
		return session, nil
	}

	session = &Session{
		lastActive:  time.Now(),
		maxFrag:     maxDownPayloadTXT,
		encoding:    EncBase32,
		compression: false,
		// lazyMode 默认 true。
		// 握手的 cmdLazy 步骤正常会显式翻转,但慢速网络下 cmdLazy 应答可能与
		// dataLoop 的首个 poll 出现竞态：若此时 lazyMode 还是 false,poll 会
		// 立即回包,client（按"收响应立刻发下一个"工作）会在 LAN RTT<1ms 的
		// 环境下立刻打到 ~1000 poll/s。默认 true 彻底消除这条竞态。
		lazyMode:  true,
		useNULL:   false,
		downSeq:   1,    // 从 1 开始,避免与客户端初始 ack=0 产生歧义（丢包时 0==0 误判为已确认）
		downAcked: true, // 初始无未 ack 的下行,允许立即取新 chunk
		streams:   make(map[uint8]*Stream),
		dataReady: make(chan struct{}, 1),
		inflight:  make(map[string]*inflightEntry),
	}

	s.sessions[sessionID] = session
	if s.debug {
		log.Printf("New session %s", sessionID)
	}
	return session, nil
}

// openStream —— 给指定 streamID 建立到真实 TCP 目标的连接。
//
// 流程：
//  1. 持锁检查 stream 是否已存在 → 是则幂等返回 nil（处理 cmdOpenStream 重发）。
//  2. 不持锁做 DNS 解析 + dial（最长 10s,**不能持锁,否则阻塞整个 session**）。
//  3. 持锁再次检查 + 注册 stream + 启动 reader / writer goroutine。
//
// 二次检查的必要性：dial 期间另一个并发 openStream 可能已经把 stream 建好,
// 此时 close 掉本次 dial 的 conn 即可。
//
// **影响 inflight 等待**：dial 最长 10s,首发 handler 在 inflight 槽位里也停留 10s,
// 重复查询的 waiter 在 lazyTimeout+1s=2s 后会 timeout 回空 DownPkt。客户端会
// 通过同步 sendDNS 的重试 + 服务端"流已存在"幂等返回最终收敛到 "OK"。
func (s *DNSServer) openStream(session *Session, streamID uint8) error {
	session.mu.Lock()
	if _, exists := session.streams[streamID]; exists {
		session.mu.Unlock()
		return nil
	}
	session.mu.Unlock()

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	host, port, err := net.SplitHostPort(s.tcpDest)
	if err != nil {
		return fmt.Errorf("bad address %s: %v", s.tcpDest, err)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolve %s: %v", host, err)
	}
	var ipv4 net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4 = ip
			break
		}
	}
	if ipv4 == nil {
		return fmt.Errorf("no IPv4 for %s", host)
	}
	conn, err := dialer.Dial("tcp4", net.JoinHostPort(ipv4.String(), port))
	if err != nil {
		return fmt.Errorf("connect failed: %v", err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	st := &Stream{id: streamID, conn: conn, upSig: make(chan struct{}, 1)}

	session.mu.Lock()
	if _, exists := session.streams[streamID]; exists {
		session.mu.Unlock()
		conn.Close()
		return nil
	}
	session.streams[streamID] = st
	session.lastActive = time.Now()
	session.mu.Unlock()

	go st.startTCPReader(session)
	go st.startTCPWriter(session)
	if s.debug {
		log.Printf("Stream %d: TCP → %s", streamID, s.tcpDest)
	}
	return nil
}

// startTCPWriter —— 把 upBuf 的字节异步写进真实 TCP 目标。
//
// 为什么独立 goroutine？handleData 只把字节 append 到 stream.upBuf 就立刻返回,
// 真正的 syscall.Write 由这里做。任何一条 stream 的真实 TCP 写慢都不会拖死
// DNS handler / dataLoop 循环,其它 stream 的 ack 照常推进。
//
// 这是 DESIGN.md §14 #2 修复（旧版本同步 Write 导致所有 stream 一起卡）。
func (st *Stream) startTCPWriter(session *Session) {
	for {
		session.mu.Lock()
		closed := st.closed
		buf := st.upBuf
		st.upBuf = nil
		session.mu.Unlock()
		if len(buf) > 0 {
			st.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			_, err := st.conn.Write(buf)
			st.conn.SetWriteDeadline(time.Time{})
			if err != nil {
				session.mu.Lock()
				st.closed = true
				session.mu.Unlock()
				st.conn.Close()
				select {
				case session.dataReady <- struct{}{}:
				default:
				}
				return
			}
			continue
		}
		if closed {
			return
		}
		select {
		case <-st.upSig:
		case <-time.After(2 * time.Second):
		}
	}
}

// handleDNSRequest —— 服务端 DNS 入口。每条查询由 miekg/dns 的内部 goroutine 调用。
//
// 流程：
//  1. 拆 FQDN：尾部去掉 domainPartsCount 段（占位 TLD 或委派域）剩 tunnelParts。
//  2. 段数不够 + 委派模式 → handleStandardQuery（让委派的 SOA/NS/A 探测通过）；
//     段数不够 + 直连模式 → FormatError。
//  3. 提取 cmc / sessionID / meta / data 四段。
//  4. ParseMeta、getOrCreateSession。
//  5. **四层去重**（L1 精确 → inflight → L1 CI → L2 qmem）,详见 §7 注释。
//  6. 注册 inflight 槽位 + defer 摘槽 close(done)。
//  7. 控制帧 → handleControl；数据帧 → handleData。
//
// 稳定性要点（针对三类异常包）：
//   - 无关包（部分字段缺失 / 非 hex meta）：在步骤 2-4 直接 FormatError 返回,**不会**走到 inflight。
//   - 单 IP 重传：L1 精确缓存命中,回放原应答；不重新处理。
//   - 多 IP 重复：第二份在步骤 5 命中 inflight,走 waitAndServeInflight 拿同样字节。
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	question := r.Question[0]
	if s.debug {
		log.Printf("DNS: %s type=%d from=%s", question.Name, question.Qtype, w.RemoteAddr())
	}

	// 构造响应骨架。带 EDNS OPT 让 UDP 应答大小提到 4096(对端如果声明了 OPT 就用对端的值)。
	msg := new(dns.Msg)
	msg.SetReply(r)
	if opt := r.IsEdns0(); opt != nil {
		msg.SetEdns0(opt.UDPSize(), opt.Do())
	} else {
		msg.SetEdns0(4096, false)
	}

	// 段数检查 —— 不到最低段数说明肯定不是隧道查询。
	// 委派模式下放行到 handleStandardQuery（NS/SOA/A 探测）；直连模式直接拒绝。
	parts := strings.Split(strings.TrimSuffix(question.Name, "."), ".")
	minParts := 4 + s.domainPartsCount
	if len(parts) < minParts {
		if s.domain != "" {
			s.handleStandardQuery(w, r, msg, question)
			return
		}
		msg.Rcode = dns.RcodeFormatError
		w.WriteMsg(msg)
		return
	}

	// 去掉 TLD / 委派域之后,tunnelParts 至少 4 段：cmc + 至少一段 data + meta + session。
	tunnelParts := parts[:len(parts)-s.domainPartsCount]
	if len(tunnelParts) < 4 {
		msg.Rcode = dns.RcodeFormatError
		w.WriteMsg(msg)
		return
	}

	cmc := strings.ToLower(tunnelParts[0])
	sessionID := strings.ToUpper(tunnelParts[len(tunnelParts)-1])
	metaStr := strings.ToLower(tunnelParts[len(tunnelParts)-2])
	dataStr := strings.Join(tunnelParts[1:len(tunnelParts)-2], ".")

	if s.debug {
		log.Printf("  session=%s meta=%s data=%s", sessionID, metaStr, dataStr)
	}

	meta, err := ParseMeta(metaStr)
	if err != nil {
		if s.debug {
			log.Printf("  bad meta: %v", err)
		}
		msg.Rcode = dns.RcodeFormatError
		w.WriteMsg(msg)
		return
	}

	session, err := s.getOrCreateSession(sessionID)
	if err != nil {
		if s.debug {
			log.Printf("  session error: %v", err)
		}
		msg.Rcode = dns.RcodeServerFailure
		w.WriteMsg(msg)
		return
	}

	// 四层去重——顺序非常重要，调换会破协议：
	//
	//   1. L1 精确缓存：bit-identical 的重传（同 QNAME 同 qtype），直接
	//      回放上次的应答字节。命中后整段函数返回，不动 inflight / qmem。
	//
	//   2. inflight 合流：当前 key 已有 in-flight handler 在跑，第二个
	//      goroutine 走 waitAndServeInflight 等 done。这一层专门挡
	//      "DC 双发 / 递归解析器并发转发"——两条查询都在 L1 写入之前
	//      到达，单靠 L1 救不了；inflight 让两边拿到一模一样的字节，
	//      DC 选谁转发都安全。
	//
	//   3. L1 大小写不敏感缓存：路径上有"0x20-bit"随机化大小写的递归
	//      解析器时，重传的 QNAME 字面会变化但语义相同。已完成的查询
	//      还在 L1 里就能命中。注意：必须放在 inflight 之后——0x20 重传
	//      和 inflight 并发场景虽然罕见，但 inflight 用小写键已经统一
	//      合流了，不会漏。
	//
	//   4. L2 qmem 晚到重放：CMC 已存过、但 L1 已经轮转出去（≥8 条新
	//      查询过去了）。此时我们不能再走原始处理路径——会重复执行
	//      cmdFragSize commit / cmdOpenStream 等带副作用的命令。回一个
	//      合法的空 DownPkt（只捎带当前 ack）让客户端把这次重传作为
	//      普通空 poll 处理掉。注意这里跟历史版本的"dummy 'x'"分支
	//      行为完全不同：'x' 长度只有 1 字节，client 端 DecodeDownPkt
	//      要求 ≥5 字节，会被静默丢——而 DC 双发场景下 dummy 包先到，
	//      就触发了 3 分钟死锁（见 §14 修复演进）。
	inflightK := inflightKey(question.Name, question.Qtype)

	session.mu.Lock()

	if cached := session.lookupDNSCache(question.Name, question.Qtype); cached != nil {
		session.mu.Unlock()
		if s.debug {
			log.Printf("  dedup: L1 dnscache hit (exact)")
		}
		if cached.isNULL {
			s.sendNULL(w, msg, question, cached.data)
		} else {
			s.sendTXT(w, msg, question, string(cached.data))
		}
		return
	}

	if entry, busy := session.inflight[inflightK]; busy {
		session.mu.Unlock()
		if s.debug {
			log.Printf("  dedup: inflight coalesce")
		}
		s.waitAndServeInflight(w, msg, question, session, entry)
		return
	}

	if cached := session.lookupDNSCacheCI(question.Name, question.Qtype); cached != nil {
		session.mu.Unlock()
		if s.debug {
			log.Printf("  dedup: L1 dnscache hit (CI)")
		}
		if cached.isNULL {
			s.sendNULL(w, msg, question, cached.data)
		} else {
			s.sendTXT(w, msg, question, string(cached.data))
		}
		return
	}

	if session.cmcInQmem(cmc) {
		ack := session.upRecvSeq
		session.mu.Unlock()
		if s.debug {
			log.Printf("  dedup: L2 qmem late-replay, empty DownPkt")
		}
		s.sendDownPkt(w, msg, question, session, &DownPkt{Ack: ack, LastFrag: true})
		return
	}

	// 走到这里：本 goroutine 是该 key 的"首发"。占位 inflight 槽位，
	// 之后并发到达的同 key 查询都会走 inflight 合流分支。
	entry := &inflightEntry{done: make(chan struct{})}
	session.inflight[inflightK] = entry
	session.saveToQmem(cmc)
	session.mu.Unlock()

	// defer 保证 panic / early-return / 任何错误路径都会：
	//   1) 把 inflight 槽位摘掉（不让"幽灵 entry"卡住后续同 key 的查询）；
	//   2) close(done) 唤醒所有正在 waitAndServeInflight 里阻塞的 waiter。
	//
	// 如果 handler 走的是 FormatError 等 w.WriteMsg 直发分支、根本没经过
	// sendAndCacheTXT/NULL，entry.data 会保持 nil；waiter 唤醒后看到 nil
	// 会走"benign 空 DownPkt"兜底，不会卡死。
	defer func() {
		session.mu.Lock()
		delete(session.inflight, inflightK)
		session.mu.Unlock()
		close(entry.done)
	}()

	if meta.IsControl {
		s.handleControl(w, msg, question, session, meta, dataStr)
	} else {
		s.handleData(w, msg, question, session, meta, dataStr)
	}
}

// waitAndServeInflight —— 重复查询的 waiter 路径。
//
// 调用前提：调用者已经在 handleDNSRequest 里持锁查到了 entry，并已经
// 释放 session.mu；entry 在 inflight map 里至少还会停留到 first
// handler 的 defer 触发。
//
// 等待上限：lazyTimeout (1s, 服务端 lazy hold 上限) + 1s buffer。
// 正常路径下 first handler 一定在 lazyTimeout 内调过 sendAndCacheXxx，
// done 早就 close 了；多出来的 1s 只是兜底，防 first handler panic 后
// 死锁（虽然 defer 兜了，但 panic→recover 路径可能有意外延迟）。
//
// 唤醒后两条分支：
//   - entry.data != nil：first handler 已经写好响应字节。直接调
//     sendTXT / sendNULL（注意：不走 sendAndCacheXxx——L1 缓存已经
//     由 first handler 写过了，重写会污染 ring 的新鲜度）。
//   - entry.data == nil：first handler 走了 FormatError 等不经过
//     sendAndCacheXxx 的分支，或者真的超时了。回一个合法空 DownPkt：
//     这是 stop-and-wait 协议里完全 benign 的状态——客户端解码得到
//     ack=upRecvSeq、payload=空，等同于一次"服务端没数据"的 lazy poll。
func (s *DNSServer) waitAndServeInflight(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, session *Session, entry *inflightEntry) {
	timeout := lazyTimeout + time.Second
	select {
	case <-entry.done:
	case <-time.After(timeout):
		if s.debug {
			log.Printf("  inflight wait timed out after %v", timeout)
		}
	}
	// 必须持锁读 entry.data / entry.isNULL：
	//   - 走 `<-entry.done` 分支时,channel close 自带 happens-before,
	//     技术上不持锁也能见到正确值；
	//   - 走 timeout 分支时,first handler 可能仍在跑、刚好与 timer 同
	//     一时刻完成。此时不加锁直接读会构成数据竞争（slice 的三字段
	//     赋值在 Go 内存模型下不是原子的,可能看到撕裂值,后续 sendTXT
	//     用错误的 len/cap 会越界 panic）。
	// 加把锁统一两条路径,代价是无竞争路径多一次 mutex acquire,可以忽略。
	session.mu.Lock()
	data := entry.data
	isNULL := entry.isNULL
	ack := session.upRecvSeq
	session.mu.Unlock()

	if data != nil {
		if isNULL {
			s.sendNULL(w, msg, q, data)
		} else {
			s.sendTXT(w, msg, q, string(data))
		}
		return
	}
	s.sendDownPkt(w, msg, q, session, &DownPkt{Ack: ack, LastFrag: true})
}

// sendResponse —— 按 qtype 路由：NULL 走 sendAndCacheNULL,TXT 走 sendAndCacheTXT。
// 给 handleControl 用的小封装,避免每个 case 自己判断 qtype。
func (s *DNSServer) sendResponse(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, session *Session, text string) {
	if q.Qtype == dns.TypeNULL {
		s.sendAndCacheNULL(w, msg, q, session, []byte(text))
	} else {
		s.sendAndCacheTXT(w, msg, q, session, text)
	}
}

func (s *DNSServer) sendAndCacheNULL(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, session *Session, data []byte) {
	session.mu.Lock()
	session.saveToDNSCache(q.Name, q.Qtype, data, true)
	// 在写 L1 缓存的同一把锁里顺手填 inflight 槽位：
	//   - 这样无论 L1 ring 之后怎么轮转，waiter 都能从 entry 自带的
	//     bytes 里读到完整响应（不依赖之后的 lookupDNSCache）。
	//   - `entry.data == nil` 检查保护"first 写者优先"语义：理论上 first
	//     handler 在一次请求里只会调一次 sendAndCacheXxx，但即便意外多
	//     调一次，waiter 看到的也是最早那份字节，与第一个 DNS 响应一致。
	//   - 这里要 copy（append nil + data）：data 上层可能复用底层数组。
	if entry, ok := session.inflight[inflightKey(q.Name, q.Qtype)]; ok && entry.data == nil {
		entry.data = append([]byte(nil), data...)
		entry.isNULL = true
	}
	session.mu.Unlock()
	s.sendNULL(w, msg, q, data)
}

func (s *DNSServer) sendAndCacheTXT(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, session *Session, text string) {
	session.mu.Lock()
	session.saveToDNSCache(q.Name, q.Qtype, []byte(text), false)
	// 见 sendAndCacheNULL 注释。text 是 string，转 []byte 已经是新分配
	// 的字节序列，不需要再 copy。
	if entry, ok := session.inflight[inflightKey(q.Name, q.Qtype)]; ok && entry.data == nil {
		entry.data = []byte(text)
		entry.isNULL = false
	}
	session.mu.Unlock()
	s.sendTXT(w, msg, q, text)
}

// handleControl —— 处理控制帧（meta.Seq == 0xFF 的查询）。
//
// 每个 case 都是**幂等**的：重复执行（晚到重传、内部状态已经是目标值）不会破坏协议。
// 这是 L2 qmem 在 inflight 兜不住时仍然安全的关键。
func (s *DNSServer) handleControl(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, session *Session, meta UpMeta, dataStr string) {
	switch meta.Command {
	case cmdVersion:
		// 握手第 1 步：告诉 client 协议版本 + 默认 maxFrag。
		resp := fmt.Sprintf("V,%d,%s", protoVersion, formatSize(maxDownPayloadTXT))
		s.sendResponse(w, msg, q, session, resp)

	case cmdFragSize:
		// param=0 时是 probe：服务端造 size 字节的固定模式数据回去。
		// param=1 时是 commit：把探到的 size 写入 session.maxFrag,之后切片用它。
		size, err := parseSize(dataStr)
		if err != nil || size <= 0 || size > 2000 {
			s.sendResponse(w, msg, q, session, "ERR")
			return
		}
		if meta.Param == 1 {
			// commit 分支：把 payload 上限设为 size - DownPkt 头部。
			// 历史 bug（§14 #9）：早期没有这条分支,客户端二分白做,服务端
			// 一直按默认 maxDownPayloadTXT 切片。
			payload := size - downPktHeaderSize
			if payload < 100 {
				payload = size
			}
			session.mu.Lock()
			session.maxFrag = payload
			session.mu.Unlock()
			s.sendResponse(w, msg, q, session, "OK")
			if s.debug {
				log.Printf("  commit maxFrag = %d (probe size %d)", payload, size)
			}
			return
		}
		// probe 分支：造 size 字节可预测内容返回。NULL 直接放进 RDATA,
		// TXT 要先 Base32 编码（TXT 不能塞二进制）。
		probe := generateFragSizeProbe(size)
		if q.Qtype == dns.TypeNULL {
			s.sendAndCacheNULL(w, msg, q, session, probe)
		} else {
			s.sendAndCacheTXT(w, msg, q, session, encodeDNSSafe(probe, EncBase32))
		}

	case cmdLazy:
		// 启 / 关 lazy hold。注意：服务端 session 默认就是 lazyMode=true,
		// 这里只在 client 明确发 cmdLazy 时才覆盖。
		session.mu.Lock()
		session.lazyMode = meta.Param == 1
		session.mu.Unlock()
		s.sendResponse(w, msg, q, session, "OK")
		if s.debug {
			log.Printf("  lazy mode = %v", meta.Param == 1)
		}

	case cmdCompress:
		// 启 / 关 zlib 压缩,影响 buildDownPkt 是否压缩 payload。
		session.mu.Lock()
		session.compression = meta.Param == 1
		session.mu.Unlock()
		s.sendResponse(w, msg, q, session, "OK")
		if s.debug {
			log.Printf("  compression = %v", meta.Param == 1)
		}

	case cmdRecType:
		// 两种用途：
		//   param=1：NULL 记录支持探测,直接回 "NULLOK"（NULL 记录形式）。
		//   param=0：Base64 编码忠实度探测,解码 dataStr 比对固定测试字节。
		if meta.Param == 1 {
			session.mu.Lock()
			session.useNULL = true
			session.maxFrag = maxDownPayloadNULL
			session.mu.Unlock()
			s.sendAndCacheNULL(w, msg, q, session, []byte("NULLOK"))
		} else {
			encTestData := []byte{0x00, 0x55, 0xAA, 0xFF, 0x01, 0x7F, 0x80, 0xFE}
			decoded, err := decodeDNSSafe(dataStr, EncBase64)
			if err == nil && len(decoded) == len(encTestData) {
				match := true
				for i := range encTestData {
					if decoded[i] != encTestData[i] {
						match = false
						break
					}
				}
				if match {
					session.mu.Lock()
					session.encoding = EncBase64
					session.mu.Unlock()
					s.sendResponse(w, msg, q, session, "ENCOK")
					return
				}
			}
			if s.debug {
				log.Printf("  encoding test failed (0x20 corruption?)")
			}
			s.sendResponse(w, msg, q, session, "ERR")
		}

	case cmdClose:
		// 关整个 session。client 主动请求或异常下线时用。
		// session.Close() 幂等,重复 cmdClose 不会出问题。
		session.Close()
		s.sendResponse(w, msg, q, session, "OK")

	case cmdPoll:
		// 纯 poll：仅捎带 downAck,等服务端返回下行数据。
		// 转给 handlePollWithAck 走 lazy hold 路径。
		s.handlePollWithAck(w, msg, q, session, meta.Param)

	case cmdOpenStream:
		// param 是 streamID;0 是非法值（哨兵）。
		// openStream 内部对"流已存在"幂等返回 nil,所以重传安全。
		streamID := meta.Param
		if streamID == 0 {
			s.sendResponse(w, msg, q, session, "ERR")
			return
		}
		if err := s.openStream(session, streamID); err != nil {
			if s.debug {
				log.Printf("  stream %d open error: %v", streamID, err)
			}
			s.sendResponse(w, msg, q, session, "ERR")
			return
		}
		s.sendResponse(w, msg, q, session, "OK")
		if s.debug {
			log.Printf("  opened stream %d", streamID)
		}

	case cmdCloseStream:
		// 关单个 stream。conn.Close + 标记 st.closed,通知 writer 退出。
		// 重传时 ok=true 但 st.closed 已经 true,仍然安全（重复关 conn 也 ok）。
		streamID := meta.Param
		session.mu.Lock()
		st, ok := session.streams[streamID]
		if ok {
			if st.conn != nil {
				st.conn.Close()
			}
			st.closed = true
		}
		session.mu.Unlock()
		if ok && st.upSig != nil {
			select {
			case st.upSig <- struct{}{}:
			default:
			}
		}
		s.sendResponse(w, msg, q, session, "OK")
		if s.debug {
			log.Printf("  closed stream %d", streamID)
		}

	default:
		// 未知 cmd——可能是协议升级 / 攻击者乱发。回 "ERR",不崩。
		s.sendResponse(w, msg, q, session, "ERR")
	}
}

// handleData —— 处理数据帧（非控制帧）。
//
// 流程：
//  1. DNS-safe decode → Vigenère decrypt → 拆出 streamID + raw payload。
//  2. 按 seq 判断 isNew：
//     - upInited=false：第一帧,接受。
//     - meta.Seq == nextSeq(upRecvSeq)：正常推进,接受。
//     - meta.Seq == upRecvSeq：客户端重传,**不重复 write**（去重）。
//     - 其它：seq 不连续（晚到帧 / 乱序）,丢弃。
//  3. 把字节 append 到 stream.upBuf,唤醒 writer goroutine。
//  4. 调 handlePollWithAck 把下行 chunk 捎回去。
//
// **不阻塞**：upBuf 是普通 slice,append 立刻返回；真正的 conn.Write 在
// startTCPWriter 里。这是 §14 #2 修复的核心。
func (s *DNSServer) handleData(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, session *Session, meta UpMeta, dataStr string) {
	session.mu.Lock()
	enc := session.encoding
	session.lastActive = time.Now()
	session.mu.Unlock()

	decoded, err := decodeDNSSafe(dataStr, enc)
	if err != nil {
		if s.debug {
			log.Printf("  decode error: %v", err)
		}
		msg.Rcode = dns.RcodeFormatError
		w.WriteMsg(msg)
		return
	}
	decoded = vigenereDecrypt(decoded, s.key)

	// payload 至少 1 字节（streamID）。
	if len(decoded) < 1 {
		msg.Rcode = dns.RcodeFormatError
		w.WriteMsg(msg)
		return
	}

	streamID := decoded[0]
	tcpData := decoded[1:]

	session.mu.Lock()
	isNew := false
	if !session.upInited {
		// 第一帧：接受任意 seq 作为起点。
		session.upRecvSeq = meta.Seq
		session.upInited = true
		isNew = true
	} else if meta.Seq == nextSeq(session.upRecvSeq) {
		// 正常推进：seq 比上次大 1。
		session.upRecvSeq = meta.Seq
		isNew = true
	} else if meta.Seq == session.upRecvSeq {
		// 重传同一帧：去重,不重复 write。
		isNew = false
	}
	// 其它 seq（既不是 +1 也不是 ==）：晚到 / 乱序,直接丢（isNew 保持 false）。

	var notifyStream *Stream
	if isNew && len(tcpData) > 0 {
		// 把字节交给 per-stream writer。stream 不存在或已关闭就丢——这种情况
		// 通常是 client 已经发了 cmdCloseStream 但还有 in-flight 数据帧。
		if st, ok := session.streams[streamID]; ok && !st.closed && st.conn != nil {
			st.upBuf = append(st.upBuf, tcpData...)
			notifyStream = st
		}
	}
	session.mu.Unlock()
	if notifyStream != nil {
		select {
		case notifyStream.upSig <- struct{}{}:
		default:
		}
	}

	// 紧跟着把下行 chunk 捎回去（捎带 meta.Ack 作为对下行 seq 的确认）。
	s.handlePollWithAck(w, msg, q, session, meta.Ack)
}

// handlePollWithAck —— 下行 chunk 调度 + DNS 应答生成的核心。
//
// 入参 downAck 是 client 捎带的"我已经收到下行 seq=N"。
//
// 流程（也是 DESIGN.md §6.3 的伪代码实现）：
//  1. 推进下行 seq：如果 downAck 等于当前未 ack 的 downSeq,清空 downChunk + seq+1。
//  2. session 已关闭 → 回 Closed DownPkt,后续 poll 重复看到 Closed,client 析构隧道。
//  3. 还有未 ack 的 downChunk → 重发（同 seq、同 payload）,等 client ack。
//  4. 取新 chunk：getAnyDownChunk round-robin 拿一个有数据的 stream。
//  5. 没有数据 → 抢 lazyHeld 进入 lazy hold,最多等 lazyTimeout 等 dataReady 唤醒。
//     并发 poll 撞到 lazyHeld 已被占 → 跳过 wait,直接发空响应（concurrentPoll 路径）。
//  6. 拿到 chunk → 缓存到 downChunk + 发出 DownPkt,等 client ack 后步骤 1 推进。
//  7. 没拿到 + 没并发占位 + 有 closed stream 待通知 → 发 StreamClosed。
//  8. 否则发只带 ack 的空 DownPkt。
//
// 多层防御（DESIGN.md §6.3 / §14.1）的实现细节看代码里的内联注释。
func (s *DNSServer) handlePollWithAck(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, session *Session, downAck uint8) {
	session.mu.Lock()
	session.lastActive = time.Now()

	// 推进下行 seq：client 捎带的 downAck 等于服务端当前下行 seq 表示这个 chunk 已收到。
	if session.downChunk != nil && downAck == session.downSeq {
		session.downChunk = nil
		session.downAcked = true
		session.downSeq = nextSeq(session.downSeq)
	}

	// session 已关闭：所有后续 poll 都回 Closed DownPkt。
	if session.closed {
		ack := session.upRecvSeq
		session.mu.Unlock()
		s.sendDownPkt(w, msg, q, session, &DownPkt{
			Ack: ack, Closed: true, LastFrag: true,
		})
		return
	}

	// 还有未 ack 的 chunk：原样重发（同 seq、同 payload）。
	// 不重新切片,因为 client 必须按 seq 顺序消费。
	if session.downChunk != nil && !session.downAcked {
		chunk := session.downChunk
		seq := session.downSeq
		ack := session.upRecvSeq
		sid := session.downChunkSID
		compression := session.compression
		session.mu.Unlock()

		pkt := s.buildDownPkt(chunk, seq, ack, sid, compression)
		s.sendDownPkt(w, msg, q, session, pkt)
		return
	}

	maxFrag := session.maxFrag
	sid, chunk := session.getAnyDownChunk(maxFrag)
	// 只在真的要做长 wait 时才抢 lazy slot。defer 重置保证 panic 也能释放
	// （早期版本是手动重置,waitForDown panic 后 lazyHeld 永久卡死）。
	willHold := chunk == nil && !session.lazyHeld
	if willHold {
		session.lazyHeld = true
		defer func() {
			session.mu.Lock()
			session.lazyHeld = false
			session.mu.Unlock()
		}()
	}
	lazy := session.lazyMode
	session.mu.Unlock()

	if willHold {
		// 主 lazy 路径：最长 lazyTimeout 等下行数据。
		// 如果 lazyMode 被意外关掉,仍然 hold minLazyHold(100ms),
		// 避免服务端 tight-loop / 客户端 RTT⁻¹ 死循环。
		hold := lazyTimeout
		if !lazy {
			hold = minLazyHold
		}
		sid, chunk = session.waitForDown(maxFrag, hold)
	}
	// 如果 chunk == nil 且 lazyHeld 已被别人占（concurrentPoll 路径）,
	// 直接落到下面的"空响应"分支。不要 time.Sleep(minLazyHold)——sleep 在
	// "客户端违反 1-in-flight" 时会引发自维持 ~10/s 风暴（详见 §14.1）。
	// 配合 inflight 合流（§7）,同 QNAME 的并发 poll 根本进不到这里。

	if chunk == nil {
		// 没有下行数据：看看有没有"已关闭等通知"的 stream。
		session.mu.Lock()
		closedSID := session.getClosedStreamToNotify()
		ack := session.upRecvSeq
		session.mu.Unlock()

		if closedSID > 0 {
			s.sendDownPkt(w, msg, q, session, &DownPkt{
				Ack: ack, LastFrag: true, StreamID: closedSID, StreamClosed: true,
			})
			return
		}

		// 真的没事干：合法空 DownPkt（只捎带 ack）。client 收到当 idle poll 处理。
		s.sendDownPkt(w, msg, q, session, &DownPkt{Ack: ack, LastFrag: true})
		return
	}

	// 拿到了 chunk：写入单 slot,等 client ack 后才能取下一个。
	session.mu.Lock()
	session.downChunk = chunk
	session.downChunkSID = sid
	session.downAcked = false
	seq := session.downSeq
	ack := session.upRecvSeq
	compression := session.compression
	session.mu.Unlock()

	pkt := s.buildDownPkt(chunk, seq, ack, sid, compression)
	s.sendDownPkt(w, msg, q, session, pkt)
}

// buildDownPkt —— 组装 DownPkt（带可选压缩）。
//
// 压缩门槛：payload > 16 字节才尝试,避免对短串做无效膨胀。
// ZlibCompress 自己有"压完没变小就不压"逻辑,这里再加 ok 判断。
func (s *DNSServer) buildDownPkt(payload []byte, seq, ack, streamID uint8, compress bool) *DownPkt {
	pkt := &DownPkt{
		Seq:      seq,
		Frag:     0,
		LastFrag: true,
		Ack:      ack,
		StreamID: streamID,
		Payload:  payload,
	}
	if compress && len(payload) > 16 {
		if compressed, ok := ZlibCompress(payload); ok {
			pkt.Payload = compressed
			pkt.Compressed = true
		}
	}
	return pkt
}

// sendDownPkt —— 把 DownPkt 编码 + Vigenère + 按 qtype 包成 DNS 应答发出。
//
// 唯一的"出口",所有数据下行都从这里走（控制类响应也最终落到 sendAndCacheXxx）,
// 保证 L1 缓存 + inflight 填充都正确发生。
func (s *DNSServer) sendDownPkt(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, session *Session, pkt *DownPkt) {
	raw := pkt.Encode()
	raw = vigenereEncrypt(raw, s.key)

	if q.Qtype == dns.TypeNULL {
		s.sendAndCacheNULL(w, msg, q, session, raw)
	} else {
		// TXT 模式：还要按 session 协商的 encoding（Base32 / Base64）再编一道。
		session.mu.Lock()
		enc := session.encoding
		session.mu.Unlock()
		encoded := encodeDNSSafe(raw, enc)
		s.sendAndCacheTXT(w, msg, q, session, encoded)
	}
}

// sendTXT —— 真正写 TXT 应答。TXT 记录单字符串上限是 255 字节,长内容必须切段。
// 这里按 254 字符切（留 1 byte 安全裕度）；空内容塞一个空 string,避免 RR 没数据。
func (s *DNSServer) sendTXT(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, text string) {
	var chunks []string
	for i := 0; i < len(text); i += 254 {
		end := i + 254
		if end > len(text) {
			end = len(text)
		}
		chunks = append(chunks, text[i:end])
	}
	if len(chunks) == 0 {
		chunks = []string{""}
	}
	msg.Answer = append(msg.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: chunks,
	})
	msg.Authoritative = true
	w.WriteMsg(msg)
}

// sendNULL —— 写 NULL 应答。NULL 记录可以塞任意二进制（不像 TXT 必须 string-like）,
// payload 上限取决于 UDP / EDNS,握手期 fragsize 探测能给出准确值。
func (s *DNSServer) sendNULL(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, data []byte) {
	msg.Answer = append(msg.Answer, &dns.NULL{
		Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNULL, Class: dns.ClassINET, Ttl: 0},
		Data: string(data),
	})
	msg.Authoritative = true
	w.WriteMsg(msg)
}

// handleStandardQuery —— NS 委派模式下,父域递归过来探测我们权威性时用。
//
// 仅处理三种类型：
//   - SOA：返回最小可信的 SOA 记录,让递归方相信我们是权威。
//   - NS ：返回 ns1.<parentDomain>,自指。
//   - A  ：返回本机监听 IP,让 NS 名字解析到自己。
//
// 不实现完整权威 NS 行为；只够通过递归方的"委派活性"检测。
func (s *DNSServer) handleStandardQuery(w dns.ResponseWriter, r *dns.Msg, msg *dns.Msg, question dns.Question) {
	qname := question.Name
	if s.debug {
		log.Printf("Standard query: %s type %d", qname, question.Qtype)
	}

	switch question.Qtype {
	case dns.TypeSOA:
		msg.Answer = append(msg.Answer, &dns.SOA{
			Hdr:     dns.RR_Header{Name: qname, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
			Ns:      "ns1." + s.parentDomain + ".",
			Mbox:    "admin." + s.parentDomain + ".",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   900,
			Expire:  86400,
			Minttl:  300,
		})
	case dns.TypeNS:
		msg.Answer = append(msg.Answer, &dns.NS{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
			Ns:  "ns1." + s.parentDomain + ".",
		})
	case dns.TypeA:
		addr := w.LocalAddr().String()
		host, _, _ := net.SplitHostPort(addr)
		ip := net.ParseIP(host)
		if ip != nil && ip.To4() != nil {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   ip.To4(),
			})
		}
	default:
		msg.Rcode = dns.RcodeSuccess
	}
	msg.Authoritative = true
	w.WriteMsg(msg)
}

// cleanupSessions —— 后台定期回收 idle / 已关闭 session。
//
// 周期 30s；超过 5 分钟没活动的 session 被关掉并从 map 中摘除。
//
// **注意**：iteration 期间持有 s.mu,session.Close() 会再去拿 session.mu。
// 这是双层锁,但顺序固定（先 server.mu 再 session.mu）,不会与 handler 路径
// （先 server.mu 短暂获取后释放,再 session.mu）发生死锁。
//
// 如果某个 session 还有 handler 在运行（典型：lazyhold 等下行）,Close 会先
// 把 closed=true 设上,handler 后续的检查会让它走 Closed 路径退出,inflight
// defer 仍然摘槽 + close(done),没有泄漏。
func (s *DNSServer) cleanupSessions(quit <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-quit:
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for id, session := range s.sessions {
				if session.IsClosed() || now.Sub(session.lastActive) > 5*time.Minute {
					if s.debug {
						log.Printf("Cleanup session %s", id)
					}
					session.Close()
					delete(s.sessions, id)
				}
			}
			s.mu.Unlock()
		}
	}
}
