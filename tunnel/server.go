// 本文件实现 dns-tunnel 的服务端侧。
//
// 角色：监听 UDP/53(或委派 NS)、解析每条上行 DNS 查询、按命令字派发,
// 同时维护多个客户端 session,把上行字节写进真实 TCP 目标,把下行字节
// 通过 DNS 应答 RDATA 送回去。
//
// 核心结构（按粒度从大到小）：
//   - DNSServer        ：进程级,维护所有 session、监听 socket。
//   - Session          ：会话级,sessionID 索引；含 pending query（iodine 风格
//     非阻塞 lazy hold）、L1 dnsCache、L2 qmem、下行 stop-and-wait、stream 表。
//   - Stream           ：单个 TCP 流,有独立的 reader / writer goroutine。
//   - pendingQuery     ：非阻塞 lazy hold 的存储槽位；含 id2/from2 双发支持。
//
// 关键路径：
//  1. handleDNSRequest     —— 拆 QNAME、找 session、做三层去重 + pending 合并。
//  2. handleControl/Data   —— 按 meta 分派到具体命令处理或数据落盘。
//  3. handlePollWithAck    —— 非阻塞：有数据立即回；无数据存 pending 等 TCP reader 唤醒。
//  4. fulfillPending       —— TCP 数据到达时取出 pending 立即应答（含 id2/from2 双发）。
//  5. sendAndCacheTXT/NULL —— 唯一的"写 DNS 应答 + 缓存 L1"汇聚点。
//
// 并发模型：miekg/dns 按每条查询起一个 goroutine 调 handleDNSRequest。
// 同 session 多个并发 handler 之间靠 session.mu 串行化共享状态；
// 不同 session 之间几乎完全独立（仅 DNSServer.mu 在 getOrCreateSession 短暂持有）。
//
// 设计参考 iodine：
//   - 非阻塞 lazy：handler 不阻塞等数据，而是把查询存到 session.pending，
//     TCP reader 有新数据时通过 fulfillPending 立即应答。
//   - id2/from2 双发：解析器重试时合并为 pending.w2，应答时双发给两个出口。
//   - pending 超时：time.AfterFunc(lazyTimeout) 到期后回空 DownPkt。
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

// pendingQuery —— 非阻塞 lazy hold 的存储槽位（参考 iodine 的 users[userid].q）。
//
// 当 handlePollWithAck 发现无下行数据且 lazyMode=true 时，不阻塞 handler，
// 而是把当前查询的 ResponseWriter / Msg 存到 session.pending。TCP reader
// 有新数据时调 fulfillPending 取出并立即应答；超时（lazyTimeout）则回空 DownPkt。
//
// id2/from2 双发（参考 iodine 的 q.id2/q.from2）：解析器重试（同 QNAME
// 不同 DNS ID / 出口 IP）到达时，存入 w2/msg2。应答时同时写两个
// ResponseWriter，保证无论解析器选哪条转发给真实客户端都能收到一致的响应。
type pendingQuery struct {
	w   dns.ResponseWriter
	msg *dns.Msg
	q   dns.Question

	qnameLower string // strings.ToLower(q.Name)，用于合并匹配

	// 解析器重试的第二路出口（id2/from2）
	w2    dns.ResponseWriter
	msg2  *dns.Msg
	hasW2 bool
}

const (
	// dnsCacheSize —— L1 精确 / CI 缓存 ring 的容量。
	dnsCacheSize = 8
	// qmemSize —— L2 qmem CMC ring 的容量。
	qmemSize = 30
)

// Stream —— 服务端侧一条 TCP 流的运行态。
//
// 与 client 端 clientStream 对应,id 一一对齐。
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
// 锁规约：所有字段写都要持有 mu。
type Session struct {
	mu         sync.Mutex
	closed     bool      // session 已被关闭；后续 poll 走 Closed flag 路径
	lastActive time.Time // 任一上行 / 真实 TCP 读写都会刷新；超过 5 分钟由 cleanupSessions 回收

	streams       map[uint8]*Stream
	lastDownSched uint8 // getAnyDownChunk 的 round-robin 游标

	server *DNSServer // 反向引用，供 startTCPReader/Writer 调 fulfillPending

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
	// respTotalBudget 是 cmdRespSize commit 来的"DNS 总响应字节预算"。0 = 未探测,
	// 走静态 maxFrag。>0 时按当前 q.Name 长度动态收紧 chunk 上限,避免"长 QNAME
	// + 大 rdata"组合超过递归路径的 UDP / EDNS 阈值被静默丢包。
	respTotalBudget int

	// L1 dnsCache ring：精确 / CI 命中 → 直接回放上次的 RDATA。
	dnsCache     [dnsCacheSize]dnsCacheEntry
	dnsCacheIdx  int
	dnsCacheFill int

	// L2 qmem CMC ring：仅 CMC 维度,挡晚到重放。命中后回合法空 DownPkt（不再执行命令）。
	qmemCMC  [qmemSize]string
	qmemIdx  int
	qmemFill int

	// 非阻塞 lazy hold（参考 iodine 的 users[userid].q）：
	//   - pending：当前存储的查询，等待 TCP 数据到达后应答。
	//   - pendingTimer：lazyTimeout 后自动回空 DownPkt 的定时器。
	// 同一时刻最多 1 个 pending；新 poll 到达时旧 pending 被回空替换。
	pending      *pendingQuery
	pendingTimer *time.Timer
}

// Close —— 关 session。
// 关 streams 的真实 TCP socket,唤醒 writer goroutine 让它们退出。
// 多次调用安全（看 s.closed 守卫）。
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true

	// 清理 pending query。
	// Stop() 返回 true 表示定时器被成功拦截、回调不会再执行，须手动处理 pending；
	// Stop() 返回 false 表示回调已开始执行（可能正在等 mu），由回调自行处理。
	if s.pendingTimer != nil {
		if s.pendingTimer.Stop() && s.pending != nil {
			p := s.pending
			s.pending = nil
			ack := s.upRecvSeq
			// 异步发送：Close 持有 mu，sendPendingResponse 内部也会短暂 lock mu。
			go func() {
				if s.server != nil {
					s.server.sendPendingResponse(s, p, &DownPkt{Ack: ack, Closed: true, LastFrag: true})
				}
			}()
		}
		s.pendingTimer = nil
	}

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
// → 调 fulfillPending 尝试立即应答存储的 pending 查询。Read 出错（包括 EOF）→
// 标记 closed + fulfillPending（可能触发 StreamClosed 通知）+ 唤醒 writer + 退出。
//
// 注意 deadline 失败（Timeout）不算错误,只是 continue 重新 Read。
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

			if session.server != nil {
				session.server.fulfillPending(session)
			}
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			session.mu.Lock()
			st.closed = true
			session.mu.Unlock()

			if session.server != nil {
				session.server.fulfillPending(session)
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

// chunkLimitForQName —— 在 session.maxFrag 基础上,按 session.respTotalBudget
// 和当前查询的 QNAME 长度收紧每次 chunk 的上限。
//
// respTotalBudget==0（客户端未探测或未提交）时直接返回 maxFrag,行为退化为旧版。
// 否则按 "总响应预算 - QNAME字符数 - DNS固定开销 - DownPkt 头" 算出 rdata 能腾出
// 给 payload 的字节数,与 maxFrag 取 min。
//
// **必须**持有 session.mu（读 respTotalBudget / maxFrag）。
func (s *Session) chunkLimitForQName(qname string) int {
	base := s.maxFrag
	if s.respTotalBudget <= 0 {
		return base
	}
	qnameLen := len(qname)
	if qnameLen > 0 && qname[qnameLen-1] == '.' {
		qnameLen-- // miekg/dns 的 q.Name 带 trailing dot,字符预算按"不含点"算
	}
	perRdata := s.respTotalBudget - qnameLen - dnsRespOverhead
	perChunk := perRdata - downPktHeaderSize
	if perChunk <= 0 {
		return base
	}
	if perChunk < base {
		return perChunk
	}
	return base
}

// getClosedStreamToNotify —— 选一个"已关闭但还没通知 client + downBuf 已空"的 stream 来发 StreamClosed。
//
// **必须**持有 session.mu。
func (s *Session) getClosedStreamToNotify() uint8 {
	for _, st := range s.streams {
		if st.closed && !st.notifiedClose && len(st.downBuf) == 0 {
			st.notifiedClose = true
			return st.id
		}
	}
	return 0
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
// 在 handleDNSRequest 注册"首发"查询时调用。
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
	runMu         sync.RWMutex
	running       bool
	closed        bool
	quit          chan struct{}
	dnsServerInst *dns.Server
}

// NewDNSServer —— 构造服务端。
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
func (s *DNSServer) MarkRunning() {
	s.runMu.Lock()
	s.running = true
	s.runMu.Unlock()
}

// Start —— 启动后台清理 + DNS UDP 监听。阻塞调用,返回即代表致命错误。
func (s *DNSServer) Start() error {
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
		lazyMode:    true,
		useNULL:     false,
		downSeq:     1,    // 从 1 开始,避免与客户端初始 ack=0 产生歧义
		downAcked:   true, // 初始无未 ack 的下行,允许立即取新 chunk
		streams:     make(map[uint8]*Stream),
		server:      s,
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
//  1. 持锁检查 stream 是否已存在 → 是则幂等返回 nil。
//  2. 不持锁做 DNS 解析 + dial（最长 10s,不能持锁否则阻塞整个 session）。
//  3. 持锁再次检查 + 注册 stream + 启动 reader / writer goroutine。
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
				if session.server != nil {
					session.server.fulfillPending(session)
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
// 去重层（L1 精确 → pending 合并 → L1 CI → L2 qmem）：
//
//  1. L1 精确缓存：bit-identical 的重传（同 QNAME 同 qtype），直接
//     回放上次的应答字节。
//
//  2. pending 合并（iodine id2/from2）：同 session 已有 pending 查询且
//     QNAME 大小写不敏感匹配——这是解析器从第二个出口 IP 重试的查询。
//     存为 w2/msg2，应答时双发。
//
//  3. L1 大小写不敏感缓存：路径上有"0x20-bit"随机化的解析器时，
//     重传的 QNAME 字面变化但语义相同。
//
//  4. L2 qmem 晚到重放：CMC 已存过但 L1 已经轮转出去。回空 DownPkt。
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	question := r.Question[0]
	if s.debug {
		log.Printf("DNS: %s type=%d from=%s", question.Name, question.Qtype, w.RemoteAddr())
	}

	msg := new(dns.Msg)
	msg.SetReply(r)
	if opt := r.IsEdns0(); opt != nil {
		msg.SetEdns0(opt.UDPSize(), opt.Do())
	} else {
		msg.SetEdns0(4096, false)
	}

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

	// ── 四层去重 ──

	session.mu.Lock()

	// L1 精确缓存
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

	// pending 合并（iodine id2/from2）：同 QNAME 的解析器重试存为双发目标。
	// miekg/dns 的 UDP ResponseWriter 在 handler 返回后仍可写（不会自动 Close），
	// 因此存下来延迟使用是安全的。
	if session.pending != nil && strings.ToLower(question.Name) == session.pending.qnameLower {
		if !session.pending.hasW2 {
			session.pending.w2 = w
			session.pending.msg2 = msg
			session.pending.hasW2 = true
		} else {
			// 已有 w2，替换为最新的重试（第三次重试覆盖第二次）
			session.pending.w2 = w
			session.pending.msg2 = msg
		}
		session.mu.Unlock()
		if s.debug {
			log.Printf("  dedup: pending merge (id2/from2)")
		}
		return
	}

	// L1 大小写不敏感缓存
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

	// L2 qmem 晚到重放
	if session.cmcInQmem(cmc) {
		ack := session.upRecvSeq
		session.mu.Unlock()
		if s.debug {
			log.Printf("  dedup: L2 qmem late-replay, empty DownPkt")
		}
		s.sendDownPkt(w, msg, question, session, &DownPkt{Ack: ack, LastFrag: true})
		return
	}

	// 本 goroutine 是该查询的"首发"。记录 qmem。
	session.saveToQmem(cmc)
	session.mu.Unlock()

	if meta.IsControl {
		s.handleControl(w, msg, question, session, meta, dataStr)
	} else {
		s.handleData(w, msg, question, session, meta, dataStr)
	}
}

// sendResponse —— 按 qtype 路由：NULL 走 sendAndCacheNULL,TXT 走 sendAndCacheTXT。
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
	session.mu.Unlock()
	s.sendNULL(w, msg, q, data)
}

func (s *DNSServer) sendAndCacheTXT(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, session *Session, text string) {
	session.mu.Lock()
	session.saveToDNSCache(q.Name, q.Qtype, []byte(text), false)
	session.mu.Unlock()
	s.sendTXT(w, msg, q, text)
}

// handleControl —— 处理控制帧（meta.Seq == 0xFF 的查询）。
//
// 每个 case 都是**幂等**的：重复执行不会破坏协议。
func (s *DNSServer) handleControl(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, session *Session, meta UpMeta, dataStr string) {
	switch meta.Command {
	case cmdVersion:
		if meta.Param != protoVersion {
			if s.debug {
				log.Printf("  version mismatch: client=%d server=%d, rejecting", meta.Param, protoVersion)
			}
			session.mu.Lock()
			session.closed = true
			session.mu.Unlock()
			s.sendResponse(w, msg, q, session, fmt.Sprintf("VERR,%d", protoVersion))
			return
		}
		resp := fmt.Sprintf("V,%d,%s", protoVersion, formatSize(maxDownPayloadTXT))
		s.sendResponse(w, msg, q, session, resp)

	case cmdFragSize:
		size, err := parseSize(dataStr)
		if err != nil || size <= 0 || size > 2000 {
			s.sendResponse(w, msg, q, session, "ERR")
			return
		}
		if meta.Param == 1 {
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
		if q.Qtype == dns.TypeNULL {
			s.sendAndCacheNULL(w, msg, q, session, generateNULLFragSizeProbe(size, s.key))
		} else {
			s.sendAndCacheTXT(w, msg, q, session, encodeDNSSafe(generateFragSizeProbe(size), EncBase32))
		}

	case cmdLazy:
		session.mu.Lock()
		session.lazyMode = meta.Param == 1
		session.mu.Unlock()
		s.sendResponse(w, msg, q, session, "OK")
		if s.debug {
			log.Printf("  lazy mode = %v", meta.Param == 1)
		}

	case cmdCompress:
		session.mu.Lock()
		session.compression = meta.Param == 1
		session.mu.Unlock()
		s.sendResponse(w, msg, q, session, "OK")
		if s.debug {
			log.Printf("  compression = %v", meta.Param == 1)
		}

	case cmdRecType:
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
		session.Close()
		s.sendResponse(w, msg, q, session, "OK")

	case cmdPoll:
		s.handlePollWithAck(w, msg, q, session, meta.Param)

	case cmdOpenStream:
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

	case cmdQNameProbe:
		s.sendResponse(w, msg, q, session, "OK")
		if s.debug {
			log.Printf("  qname probe ack (qname char len=%d)", len(q.Name)-1)
		}

	case cmdContentProbe:
		// 原样 echo dataStr 回客户端,客户端逐字节比对发现"哪个字符在路上被改了"。
		// 注意：dataStr 是从 QNAME 解出来的,递归如果做了 0x20 case 随机化、字符替换、
		// 或者把整段截短,这里 echo 出去的就是被改过的版本。客户端用这个做诊断。
		s.sendResponse(w, msg, q, session, dataStr)
		if s.debug {
			log.Printf("  content probe ack (data char len=%d)", len(dataStr))
		}

	case cmdRespSize:
		// dataStr 形如 "<sizeHex>[.<padding>...]"——padding 只是为了把 QNAME 撑到
		// 实测长度,服务端只取首段 4 个 hex。
		head := dataStr
		if dot := strings.Index(head, "."); dot >= 0 {
			head = head[:dot]
		}
		size, err := parseSize(head)
		if err != nil || size <= 0 || size > 2000 {
			s.sendResponse(w, msg, q, session, "ERR")
			return
		}
		if meta.Param == 1 {
			session.mu.Lock()
			session.respTotalBudget = size
			session.mu.Unlock()
			s.sendResponse(w, msg, q, session, "OK")
			if s.debug {
				log.Printf("  commit respTotalBudget = %d", size)
			}
			return
		}
		if q.Qtype == dns.TypeNULL {
			s.sendAndCacheNULL(w, msg, q, session, generateNULLFragSizeProbe(size, s.key))
		} else {
			s.sendAndCacheTXT(w, msg, q, session, encodeDNSSafe(generateFragSizeProbe(size), EncBase32))
		}

	default:
		s.sendResponse(w, msg, q, session, "ERR")
	}
}

// handleData —— 处理数据帧（非控制帧）。
//
// 流程：
//  1. DNS-safe decode → Vigenère decrypt → 拆出 streamID + raw payload。
//  2. 按 seq 判断 isNew：重传去重,不重复 write。
//  3. 把字节 append 到 stream.upBuf,唤醒 writer goroutine。
//  4. 调 handlePollWithAck 把下行 chunk 捎回去。
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
		session.upRecvSeq = meta.Seq
		session.upInited = true
		isNew = true
	} else if meta.Seq == nextSeq(session.upRecvSeq) {
		session.upRecvSeq = meta.Seq
		isNew = true
	} else if meta.Seq == session.upRecvSeq {
		isNew = false
	}

	var notifyStream *Stream
	if isNew && len(tcpData) > 0 {
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

	s.handlePollWithAck(w, msg, q, session, meta.Ack)
}

// handlePollWithAck —— 非阻塞下行 chunk 调度（参考 iodine 的 send_chunk_or_dataless）。
//
// 有数据 → 立即回复。无数据 + lazy → 存 pending，等 TCP 数据到达或超时。
// 无数据 + 非 lazy → 立即回空。Handler 从不阻塞。
//
// 解析器重试由 pending 合并（handleDNSRequest 的 id2/from2 路径）和 L1 缓存处理，
// 不再需要 inflight 合流或 lazyHeld 互斥。
func (s *DNSServer) handlePollWithAck(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, session *Session, downAck uint8) {
	session.mu.Lock()
	session.lastActive = time.Now()

	// 推进下行 seq：client 捎带的 downAck 等于服务端当前下行 seq 表示这个 chunk 已收到。
	if session.downChunk != nil && downAck == session.downSeq {
		session.downChunk = nil
		session.downAcked = true
		session.downSeq = nextSeq(session.downSeq)
	}

	// session 已关闭
	if session.closed {
		ack := session.upRecvSeq
		session.mu.Unlock()
		s.sendDownPkt(w, msg, q, session, &DownPkt{
			Ack: ack, Closed: true, LastFrag: true,
		})
		return
	}

	// 还有未 ack 的 chunk：原样重发
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

	// 尝试取新数据
	maxFrag := session.chunkLimitForQName(q.Name)
	sid, chunk := session.getAnyDownChunk(maxFrag)

	if chunk != nil {
		// 有数据：立即发送
		session.downChunk = chunk
		session.downChunkSID = sid
		session.downAcked = false
		seq := session.downSeq
		ack := session.upRecvSeq
		compression := session.compression
		session.mu.Unlock()
		pkt := s.buildDownPkt(chunk, seq, ack, sid, compression)
		s.sendDownPkt(w, msg, q, session, pkt)
		return
	}

	// 无数据
	if !session.lazyMode {
		// 非 lazy：检查 closed stream 通知，否则回空
		closedSID := session.getClosedStreamToNotify()
		ack := session.upRecvSeq
		session.mu.Unlock()
		if closedSID > 0 {
			s.sendDownPkt(w, msg, q, session, &DownPkt{
				Ack: ack, LastFrag: true, StreamID: closedSID, StreamClosed: true,
			})
			return
		}
		s.sendDownPkt(w, msg, q, session, &DownPkt{Ack: ack, LastFrag: true})
		return
	}

	// lazy 模式：存 pending，等 TCP 数据到达或超时
	oldPending := session.pending
	if oldPending != nil {
		if session.pendingTimer != nil {
			session.pendingTimer.Stop()
		}
	}

	p := &pendingQuery{
		w:          w,
		msg:        msg,
		q:          q,
		qnameLower: strings.ToLower(q.Name),
	}
	session.pending = p
	session.pendingTimer = time.AfterFunc(lazyTimeout, func() {
		s.expirePending(session, p)
	})
	ack := session.upRecvSeq
	session.mu.Unlock()

	// 旧 pending 回空（在锁外发送）
	if oldPending != nil {
		s.sendPendingResponse(session, oldPending, &DownPkt{Ack: ack, LastFrag: true})
	}
}

// fulfillPending —— TCP 数据到达时尝试用 pending 查询立即应答。
//
// 由 startTCPReader（数据到达 / 流关闭）和 startTCPWriter（写出错流关闭）调用。
// 无 pending 或无数据则什么都不做，保留 pending 等下次数据或超时。
func (s *DNSServer) fulfillPending(session *Session) {
	session.mu.Lock()
	p := session.pending
	if p == nil {
		session.mu.Unlock()
		return
	}

	if session.closed {
		session.pending = nil
		if session.pendingTimer != nil {
			session.pendingTimer.Stop()
			session.pendingTimer = nil
		}
		ack := session.upRecvSeq
		session.mu.Unlock()
		s.sendPendingResponse(session, p, &DownPkt{Ack: ack, Closed: true, LastFrag: true})
		return
	}

	// 尝试取数据。chunk 上限按当前 pending 查询的 QNAME 长度动态收紧
	// （long-QNAME + 大 rdata 组合是 v4 探测发现的盲区,见 protocol.go 注释）。
	sid, chunk := session.getAnyDownChunk(session.chunkLimitForQName(p.q.Name))
	if chunk == nil {
		// 没有数据块，检查是否有关闭的 stream 需要通知
		closedSID := session.getClosedStreamToNotify()
		if closedSID > 0 {
			session.pending = nil
			if session.pendingTimer != nil {
				session.pendingTimer.Stop()
				session.pendingTimer = nil
			}
			ack := session.upRecvSeq
			session.mu.Unlock()
			s.sendPendingResponse(session, p, &DownPkt{
				Ack: ack, LastFrag: true, StreamID: closedSID, StreamClosed: true,
			})
			return
		}
		// 无数据，保留 pending 继续等
		session.mu.Unlock()
		return
	}

	// 有数据：清 pending + 存 downChunk + 发送
	session.pending = nil
	if session.pendingTimer != nil {
		session.pendingTimer.Stop()
		session.pendingTimer = nil
	}
	session.downChunk = chunk
	session.downChunkSID = sid
	session.downAcked = false
	seq := session.downSeq
	ack := session.upRecvSeq
	compression := session.compression
	session.mu.Unlock()

	pkt := s.buildDownPkt(chunk, seq, ack, sid, compression)
	s.sendPendingResponse(session, p, pkt)
}

// expirePending —— pending 超时回调（time.AfterFunc）。
// 回空 DownPkt 或 StreamClosed 通知。如果 pending 已被 fulfillPending 或
// 新 poll 替换，则什么都不做。
func (s *DNSServer) expirePending(session *Session, expected *pendingQuery) {
	session.mu.Lock()
	if session.pending != expected {
		// pending 已被替换或已 fulfilled
		session.mu.Unlock()
		return
	}
	session.pending = nil
	session.pendingTimer = nil

	if session.closed {
		ack := session.upRecvSeq
		session.mu.Unlock()
		s.sendPendingResponse(session, expected, &DownPkt{Ack: ack, Closed: true, LastFrag: true})
		return
	}

	closedSID := session.getClosedStreamToNotify()
	ack := session.upRecvSeq
	session.mu.Unlock()

	if closedSID > 0 {
		s.sendPendingResponse(session, expected, &DownPkt{
			Ack: ack, LastFrag: true, StreamID: closedSID, StreamClosed: true,
		})
		return
	}
	s.sendPendingResponse(session, expected, &DownPkt{Ack: ack, LastFrag: true})
}

// sendPendingResponse —— 通过 pending 查询发送 DownPkt，含 id2/from2 双发。
//
// w1 走 sendAndCacheXxx（写 L1 缓存），w2 走 sendXxx（只发不缓存）。
// w2 使用自己的 msg 和 question（QNAME 可能有 0x20 差异），保证
// 解析器收到的应答 QNAME 与其查询一致。
func (s *DNSServer) sendPendingResponse(session *Session, p *pendingQuery, pkt *DownPkt) {
	raw := pkt.Encode()
	raw = vigenereEncrypt(raw, s.key)

	if p.q.Qtype == dns.TypeNULL {
		s.sendAndCacheNULL(p.w, p.msg, p.q, session, raw)
		if p.hasW2 && len(p.msg2.Question) > 0 {
			q2 := p.msg2.Question[0]
			s.sendNULL(p.w2, p.msg2, q2, raw)
		}
	} else {
		session.mu.Lock()
		enc := session.encoding
		session.mu.Unlock()
		encoded := encodeDNSSafe(raw, enc)
		s.sendAndCacheTXT(p.w, p.msg, p.q, session, encoded)
		if p.hasW2 && len(p.msg2.Question) > 0 {
			q2 := p.msg2.Question[0]
			s.sendTXT(p.w2, p.msg2, q2, encoded)
		}
	}
}

// buildDownPkt —— 组装 DownPkt（带可选压缩）。
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
// 直接路径（非 pending），用于 handlePollWithAck 有数据立即回的场景。
func (s *DNSServer) sendDownPkt(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, session *Session, pkt *DownPkt) {
	raw := pkt.Encode()
	raw = vigenereEncrypt(raw, s.key)

	if q.Qtype == dns.TypeNULL {
		s.sendAndCacheNULL(w, msg, q, session, raw)
	} else {
		session.mu.Lock()
		enc := session.encoding
		session.mu.Unlock()
		encoded := encodeDNSSafe(raw, enc)
		s.sendAndCacheTXT(w, msg, q, session, encoded)
	}
}

// sendTXT —— 真正写 TXT 应答。TXT 记录单字符串上限是 255 字节,长内容必须切段。
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

// sendNULL —— 写 NULL 应答。
func (s *DNSServer) sendNULL(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, data []byte) {
	msg.Answer = append(msg.Answer, &dns.NULL{
		Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNULL, Class: dns.ClassINET, Ttl: 0},
		Data: string(data),
	})
	msg.Authoritative = true
	w.WriteMsg(msg)
}

// handleStandardQuery —— NS 委派模式下,父域递归过来探测我们权威性时用。
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
