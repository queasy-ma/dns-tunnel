package tunnel

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type clientStream struct {
	id      uint8
	conn    net.Conn
	upBuf   *DataBuf // local TCP → tunnel
	downBuf *DataBuf // tunnel → local TCP
	downSig chan struct{}
	closed  bool // hard closed; reader/writer exit immediately
	closing bool // soft close requested (server-side EOF); writer drains then closes
}

type DNSClient struct {
	listenAddr string
	dnsServer  string
	sessionID  string
	tld        string
	dnsClient  *dns.Client
	debug      bool
	key        string

	lazyMode    bool
	compression bool
	useNULL     bool
	maxFrag     int
	encoding    int
	upPayload   int

	mu          sync.Mutex
	streams     map[uint8]*clientStream
	nextSID     uint8
	lastUpSched uint8 // round-robin cursor for selectUpstream
	tunnelUp    bool
	upNotify    chan struct{}

	quit     chan struct{}
	listener net.Listener
	running  bool
	runMu    sync.RWMutex
}

func NewDNSClient(listenAddr, dnsServer string, debug bool, key string, domain string) (*DNSClient, error) {
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

func (c *DNSClient) MarkRunning() {
	c.runMu.Lock()
	c.running = true
	c.runMu.Unlock()
}

func (c *DNSClient) Close() {
	c.runMu.Lock()
	c.running = false
	c.runMu.Unlock()
	c.tunnelUp = false
	select {
	case <-c.quit:
	default:
		close(c.quit)
	}
	if c.listener != nil {
		c.listener.Close()
	}
}

func (c *DNSClient) IsRunning() bool {
	c.runMu.RLock()
	defer c.runMu.RUnlock()
	return c.running
}

func (c *DNSClient) Start() error {
	c.quit = make(chan struct{})
	c.runMu.Lock()
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
	c.listener = listener
	defer listener.Close()

	if c.debug {
		log.Printf("Listening on %s, DNS server %s, max upstream %d bytes", c.listenAddr, c.dnsServer, c.upPayload)
	}

	if err := c.setupTunnel(); err != nil {
		return fmt.Errorf("tunnel setup failed: %v", err)
	}

	go c.dataLoop()

	for {
		select {
		case <-c.quit:
			return nil
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-c.quit:
				return nil
			default:
			}
			if c.debug {
				log.Printf("Accept error: %v", err)
			}
			continue
		}

		if !c.tunnelUp {
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

// streamWriter drains downBuf into the local TCP socket asynchronously,
// so the dataLoop never blocks on a slow consumer.
func (c *DNSClient) streamWriter(stream *clientStream) {
	for {
		data := stream.downBuf.Take(64 * 1024)
		if len(data) > 0 {
			stream.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			_, err := stream.conn.Write(data)
			stream.conn.SetWriteDeadline(time.Time{})
			if err != nil {
				if c.debug {
					log.Printf("TCP write error (stream %d): %v", stream.id, err)
				}
				c.mu.Lock()
				stream.closed = true
				delete(c.streams, stream.id)
				c.mu.Unlock()
				stream.conn.Close()
				go c.cmdCloseStream(stream.id)
				return
			}
			continue
		}
		c.mu.Lock()
		closed := stream.closed
		closing := stream.closing
		c.mu.Unlock()
		if closed {
			return
		}
		if closing {
			// Buffer drained and server signaled EOF — finalize.
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

// allocStreamIDLocked scans for a free stream ID, starting at c.nextSID.
// Caller must hold c.mu. Returns (0, false) if all 254 slots are in use.
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

	c.tunnelUp = true

	if c.debug {
		log.Printf("Tunnel ready: lazy=%v compress=%v null=%v maxfrag=%d enc=%d",
			c.lazyMode, c.compression, c.useNULL, c.maxFrag, c.encoding)
	}
	return nil
}

func (c *DNSClient) streamReader(stream *clientStream) {
	buf := make([]byte, 4096)
	for {
		n, err := stream.conn.Read(buf)
		if n > 0 {
			stream.upBuf.Write(buf[:n])
			select {
			case c.upNotify <- struct{}{}:
			default:
			}
		}
		if err != nil {
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

func (c *DNSClient) selectUpstream() (uint8, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	maxData := c.upPayload - 1
	if maxData < 1 {
		return 0, nil
	}

	// Round-robin: start from the slot AFTER the last one we served so a
	// heavy stream cannot monopolize the single upstream window and starve
	// keepalives/control on its peers. The loop runs maxStreams+1 times so
	// that the last position visited wraps back to `start` itself — without
	// this, a single-stream tunnel serves the stream exactly once and then
	// starves it forever, because the loop ranges over the other 254 mod
	// classes (and sid=0, which is skipped).
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
			return sid, data
		}
	}
	return 0, nil
}

func (c *DNSClient) dataLoop() {
	conn, err := net.Dial("udp", c.dnsServer)
	if err != nil {
		if c.debug {
			log.Printf("DNS dial failed: %v", err)
		}
		c.tunnelUp = false
		return
	}
	defer conn.Close()

	recvCh := make(chan []byte, 64)
	go c.dnsRecvLoop(conn, recvCh)

	var upSeq uint8
	var downAck uint8
	var lastUpData []byte
	var lastUpSID uint8
	upAcked := true
	downInited := false
	var lastDownSeq uint8
	// inFlight enforces the stop-and-wait invariant: at most one query is
	// outstanding to the server at any moment. Without this, upNotify or a
	// stray timeout can fire a second query before the previous response
	// arrives, which the server's lazyHeld mutex turns into a ~10/s storm
	// (minLazyHold throttle on the concurrentPoll path).
	inFlight := false

	send := func() {
		if !upAcked && lastUpData != nil {
			c.asyncSendStreamData(conn, lastUpSID, lastUpData, upSeq, downAck)
		} else {
			sid, data := c.selectUpstream()
			if data != nil {
				lastUpSID = sid
				lastUpData = data
				upAcked = false
				c.asyncSendStreamData(conn, sid, data, upSeq, downAck)
			} else {
				c.asyncSendPoll(conn, downAck)
			}
		}
		inFlight = true
	}

	send()

	for c.tunnelUp {
		timeout := 5 * time.Second
		if c.lazyMode {
			timeout = 2 * time.Second
		}

		select {
		case raw := <-recvCh:
			inFlight = false
			pkt := c.decodeResponse(raw)
			if pkt != nil {
				c.processDown(pkt, &downAck, &downInited, &lastDownSeq)
				if !upAcked && pkt.Ack == upSeq {
					upAcked = true
					upSeq = nextSeq(upSeq)
					lastUpData = nil
				}
			}

			if !c.tunnelUp {
				return
			}

			// Keep exactly one query in flight: every received response
			// triggers the next send. The server's lazy-hold (up to
			// lazyTimeout) is what rate-limits us in idle — deferring on
			// the client side adds visible latency to async server pushes
			// (e.g. command output streaming back), so we don't.
			send()

		case <-c.upNotify:
			// New upstream bytes arrived. We can only act on them if no
			// query is in flight (1-in-flight invariant); otherwise the
			// next recvCh tick will pick them up via selectUpstream.
			if !inFlight && upAcked {
				send()
			}

		case <-time.After(timeout):
			// Either a lost response (retransmit) or a genuinely idle
			// gap. Either way only one query at a time.
			if !inFlight {
				send()
			} else {
				// Suspected lost response: retransmit the same packet
				// rather than firing a fresh second query.
				if !upAcked && lastUpData != nil {
					c.asyncSendStreamData(conn, lastUpSID, lastUpData, upSeq, downAck)
				} else {
					c.asyncSendPoll(conn, downAck)
				}
			}
		}
	}
}

func (c *DNSClient) processDown(pkt *DownPkt, downAck *uint8, downInited *bool, lastDownSeq *uint8) {
	if pkt.Closed {
		c.tunnelUp = false
		return
	}

	if pkt.StreamClosed && pkt.StreamID > 0 {
		c.mu.Lock()
		stream, ok := c.streams[pkt.StreamID]
		if ok {
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
			log.Printf("Server closed stream %d", pkt.StreamID)
		}
	}

	if len(pkt.Payload) > 0 && pkt.StreamID > 0 {
		if !*downInited || pkt.Seq != *lastDownSeq {
			if !*downInited {
				*downInited = true
			}
			c.mu.Lock()
			stream, ok := c.streams[pkt.StreamID]
			c.mu.Unlock()
			if ok && !stream.closed {
				// Hand the payload to the per-stream writer goroutine;
				// never block dataLoop on the local TCP write.
				stream.downBuf.Write(pkt.Payload)
				select {
				case stream.downSig <- struct{}{}:
				default:
				}
			}
			*downAck = pkt.Seq
			*lastDownSeq = pkt.Seq
		}
	}
}

func (c *DNSClient) dnsRecvLoop(conn net.Conn, ch chan<- []byte) {
	buf := make([]byte, 65536)
	for c.tunnelUp {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// Tolerate transient ICMP-derived errors: connection refused,
			// host/net unreachable. These can fire on Linux when the
			// server's reply socket is briefly missing or kernel emits a
			// stale unreachable, and we don't want a single ICMP bounce
			// to tear the whole tunnel down — dataLoop's timeout will
			// retransmit on its own.
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
			c.tunnelUp = false
			return
		}
		if n > 0 {
			msg := new(dns.Msg)
			if err := msg.Unpack(buf[:n]); err != nil {
				continue
			}
			if msg.Rcode != dns.RcodeSuccess {
				// FormErr / ServFail / Refused mean the server no longer
				// recognises this session (restarted, or encoding mismatch
				// after re-handshake). Tear the tunnel down so dataLoop
				// exits and the caller can reconnect with a fresh session.
				if msg.Rcode == dns.RcodeFormatError ||
					msg.Rcode == dns.RcodeServerFailure ||
					msg.Rcode == dns.RcodeRefused {
					if c.debug {
						log.Printf("DNS recv loop: fatal rcode %d, tearing down", msg.Rcode)
					}
					c.tunnelUp = false
					return
				}
				continue
			}
			raw, err := c.extractAnswer(msg)
			if err == nil && raw != nil {
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
}

func (c *DNSClient) asyncSendPoll(conn net.Conn, downAck uint8) {
	meta := CtrlMeta(cmdPoll, downAck)
	fqdn := buildFQDN("P", meta, c.sessionID, c.tld)
	c.asyncSendDNS(conn, fqdn)
}

func (c *DNSClient) asyncSendStreamData(conn net.Conn, sid uint8, data []byte, seq, downAck uint8) {
	payload := make([]byte, 1+len(data))
	payload[0] = sid
	copy(payload[1:], data)

	encrypted := vigenereEncrypt(payload, c.key)
	encoded := encodeDNSSafe(encrypted, c.encoding)
	meta := DataMeta(seq, 0, downAck, true)
	fqdn := buildFQDN(encoded, meta, c.sessionID, c.tld)
	c.asyncSendDNS(conn, fqdn)
}

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
		return
	}
	conn.Write(data)
}

func (c *DNSClient) cmdOpenStream(sid uint8) error {
	meta := CtrlMeta(cmdOpenStream, sid)
	fqdn := buildFQDN("O", meta, c.sessionID, c.tld)
	resp, err := c.sendDNS(fqdn)
	if err != nil {
		return fmt.Errorf("stream open: %v", err)
	}
	if resp == nil || string(resp) != "OK" {
		return fmt.Errorf("stream open rejected: %s", string(resp))
	}
	return nil
}

func (c *DNSClient) cmdCloseStream(sid uint8) {
	meta := CtrlMeta(cmdCloseStream, sid)
	fqdn := buildFQDN("X", meta, c.sessionID, c.tld)
	c.sendDNSOnce(fqdn)
}

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
		c.maxFrag = probed - downPktHeaderSize
		if c.maxFrag < 100 {
			c.maxFrag = probed
		}
		if c.debug {
			log.Printf("Probed fragsize: %d (payload max %d)", probed, c.maxFrag)
		}
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
	if _, ok := r.Answer[0].(*dns.NULL); ok {
		return true
	}
	return false
}

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

// commitFragSize tells the server to use `size` as its downstream max payload.
// param=1 distinguishes commit from probe (param=0).
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

func (c *DNSClient) sendDNSFew(fqdn string) ([]byte, error) {
	return c.sendDNSRetries(fqdn, 3)
}

func (c *DNSClient) sendDNS(fqdn string) ([]byte, error) {
	return c.sendDNSRetries(fqdn, maxRetries)
}

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

		r, _, err := c.dnsClient.Exchange(msg, c.dnsServer)
		if err != nil {
			if strings.Contains(err.Error(), "i/o timeout") && attempt < retries {
				time.Sleep(retryDelay)
				continue
			}
			return nil, err
		}
		if r.Rcode != dns.RcodeSuccess {
			if attempt < retries {
				time.Sleep(retryDelay)
				continue
			}
			return nil, fmt.Errorf("DNS error %d", r.Rcode)
		}
		return c.extractAnswer(r)
	}
	return nil, fmt.Errorf("max retries")
}

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
