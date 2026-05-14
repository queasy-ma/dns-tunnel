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

type dnsCacheEntry struct {
	name   string
	qtype  uint16
	data   []byte
	isNULL bool
}

const (
	dnsCacheSize = 8
	qmemSize     = 30
)

type Stream struct {
	id            uint8
	conn          net.Conn
	downBuf       []byte // local TCP read → tunnel out
	upBuf         []byte // tunnel in → local TCP write
	upSig         chan struct{}
	closed        bool
	notifiedClose bool
}

type Session struct {
	mu         sync.Mutex
	closed     bool
	lastActive time.Time

	streams       map[uint8]*Stream
	dataReady     chan struct{}
	lastDownSched uint8 // round-robin cursor for getAnyDownChunk

	upRecvSeq uint8
	upInited  bool

	downSeq      uint8
	downChunk    []byte
	downChunkSID uint8
	downAcked    bool

	lazyMode    bool
	compression bool
	useNULL     bool
	maxFrag     int
	encoding    int

	dnsCache     [dnsCacheSize]dnsCacheEntry
	dnsCacheIdx  int
	dnsCacheFill int

	qmemCMC  [qmemSize]string
	qmemIdx  int
	qmemFill int

	lazyHeld bool
}

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

func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

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

// Must hold session.mu. Round-robins across streams so a heavy stream
// (e.g. ongoing file download) doesn't starve interactive peers. The loop
// runs maxStreams+1 times so the last position wraps back to `start` —
// otherwise a single-stream session serves once and then never revisits it.
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

// Must hold session.mu
func (s *Session) getClosedStreamToNotify() uint8 {
	for _, st := range s.streams {
		if st.closed && !st.notifiedClose && len(st.downBuf) == 0 {
			st.notifiedClose = true
			return st.id
		}
	}
	return 0
}

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

// Layer 1: save response to DNS cache (must hold s.mu)
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

// Layer 1: lookup exact match in DNS cache (must hold s.mu)
func (s *Session) lookupDNSCache(name string, qtype uint16) *dnsCacheEntry {
	for i := 0; i < s.dnsCacheFill; i++ {
		e := &s.dnsCache[i]
		if e.qtype == qtype && e.name == name {
			return e
		}
	}
	return nil
}

// Layer 1: case-insensitive lookup for 0x20 fallback (must hold s.mu)
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

// Layer 2: check if CMC was already seen (case-insensitive), must hold s.mu
func (s *Session) cmcInQmem(cmc string) bool {
	lower := strings.ToLower(cmc)
	for i := 0; i < s.qmemFill; i++ {
		if s.qmemCMC[i] == lower {
			return true
		}
	}
	return false
}

// Layer 2: save CMC to qmem (case-insensitive), must hold s.mu
func (s *Session) saveToQmem(cmc string) {
	s.qmemCMC[s.qmemIdx] = strings.ToLower(cmc)
	s.qmemIdx = (s.qmemIdx + 1) % qmemSize
	if s.qmemFill < qmemSize {
		s.qmemFill++
	}
}

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
}

func NewDNSServer(dnsListener, tcpDest string, debug bool, key string, domain string) *DNSServer {
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

func (s *DNSServer) Start() error {
	go s.cleanupSessions()
	dns.HandleFunc(".", s.handleDNSRequest)
	server := &dns.Server{Addr: s.dnsListener, Net: "udp"}
	if s.debug {
		log.Printf("DNS server on %s (UDP)", s.dnsListener)
	}
	return server.ListenAndServe()
}

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
		// Default to lazy-hold ON. The handshake's cmdLazy step normally
		// flips it explicitly, but on slow networks the cmdLazy reply can
		// race with the first poll from dataLoop; if lazyMode were still
		// false at that point, the poll returns instantly and the client
		// (which is "send next on response") spins at RTT⁻¹.
		lazyMode:  true,
		useNULL:   false,
		downAcked: true,
		streams:   make(map[uint8]*Stream),
		dataReady: make(chan struct{}, 1),
	}

	s.sessions[sessionID] = session
	if s.debug {
		log.Printf("New session %s", sessionID)
	}
	return session, nil
}

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

// startTCPWriter drains upBuf into the local TCP socket. By doing the write
// off the DNS handler goroutine, we never delay the DNS response (and thus
// the poll round-trip) on a slow local consumer.
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

	// Three-layer dedup
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

	if session.cmcInQmem(cmc) {
		if cached := session.lookupDNSCacheCI(question.Name, question.Qtype); cached != nil {
			session.mu.Unlock()
			if s.debug {
				log.Printf("  dedup: L2 qmem hit + CI cache fallback")
			}
			if cached.isNULL {
				s.sendNULL(w, msg, question, cached.data)
			} else {
				s.sendTXT(w, msg, question, string(cached.data))
			}
			return
		}
		session.mu.Unlock()
		if s.debug {
			log.Printf("  dedup: L2 qmem hit, sending dummy")
		}
		if question.Qtype == dns.TypeNULL {
			s.sendNULL(w, msg, question, []byte("x"))
		} else {
			s.sendTXT(w, msg, question, "x")
		}
		return
	}

	session.saveToQmem(cmc)
	session.mu.Unlock()

	if meta.IsControl {
		s.handleControl(w, msg, question, session, meta, dataStr)
	} else {
		s.handleData(w, msg, question, session, meta, dataStr)
	}
}

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

func (s *DNSServer) handleControl(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, session *Session, meta UpMeta, dataStr string) {
	switch meta.Command {
	case cmdVersion:
		resp := fmt.Sprintf("V,%d,%s", protoVersion, formatSize(maxDownPayloadTXT))
		s.sendResponse(w, msg, q, session, resp)

	case cmdFragSize:
		size, err := parseSize(dataStr)
		if err != nil || size <= 0 || size > 2000 {
			s.sendResponse(w, msg, q, session, "ERR")
			return
		}
		if meta.Param == 1 {
			// Commit: use this size as the downstream max payload for the session.
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
		probe := generateFragSizeProbe(size)
		if q.Qtype == dns.TypeNULL {
			s.sendAndCacheNULL(w, msg, q, session, probe)
		} else {
			s.sendAndCacheTXT(w, msg, q, session, encodeDNSSafe(probe, EncBase32))
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

	default:
		s.sendResponse(w, msg, q, session, "ERR")
	}
}

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

func (s *DNSServer) handlePollWithAck(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, session *Session, downAck uint8) {
	session.mu.Lock()
	session.lastActive = time.Now()

	if session.downChunk != nil && downAck == session.downSeq {
		session.downChunk = nil
		session.downAcked = true
		session.downSeq = nextSeq(session.downSeq)
	}

	if session.closed {
		ack := session.upRecvSeq
		session.mu.Unlock()
		s.sendDownPkt(w, msg, q, session, &DownPkt{
			Ack: ack, Closed: true, LastFrag: true,
		})
		return
	}

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
	// Claim the lazy slot only if we're actually going to do the long
	// wait. Releasing is via defer so a panic in waitForDown can't
	// permanently pin lazyHeld=true.
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
		// Primary lazy wait: up to lazyTimeout for downstream data.
		// If lazyMode somehow disabled, still enforce minLazyHold so
		// tight loops on the server side are impossible.
		hold := lazyTimeout
		if !lazy {
			hold = minLazyHold
		}
		sid, chunk = session.waitForDown(maxFrag, hold)
	}
	// If chunk == nil && lazyHeld was already true (concurrent poll),
	// we fall straight through to the empty response. We used to
	// time.Sleep(minLazyHold) here to throttle a misbehaving client,
	// but with the client now enforcing strict 1-in-flight, concurrent
	// polls only happen on rare retransmits — sleeping there created
	// a self-sustaining ~10/s poll storm whenever any race produced
	// even a brief overlap.

	if chunk == nil {
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

		s.sendDownPkt(w, msg, q, session, &DownPkt{Ack: ack, LastFrag: true})
		return
	}

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

func (s *DNSServer) sendNULL(w dns.ResponseWriter, msg *dns.Msg, q dns.Question, data []byte) {
	msg.Answer = append(msg.Answer, &dns.NULL{
		Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNULL, Class: dns.ClassINET, Ttl: 0},
		Data: string(data),
	})
	msg.Authoritative = true
	w.WriteMsg(msg)
}

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

func (s *DNSServer) cleanupSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
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
