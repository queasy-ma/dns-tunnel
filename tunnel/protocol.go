// 本文件定义本隧道的"线协议"——上行查询元数据、下行包格式、分片重组、压缩。
//
// 协议总览（详见 DESIGN.md §2、§3）：
//
//	上行查询 QNAME：
//	  <CMC>.<DATA|cmd>.<META=seq/frag/ack>.<SESSION>.<TLD>
//	  - CMC：每查询随机,反递归缓存。
//	  - META：3 字节 hex（6 字符）,seq==0xFF 表示控制帧。
//
//	下行 DNS 应答 RDATA（TXT 字符串或 NULL data）：
//	  vigenere(DownPkt.Encode())  // 一帧一段,无 fragment
//	  DownPkt: [Flags|Seq|Frag/L|Ack|SID|Payload...]
//
// 关键不变量：
//   - 上下行 seq 各 1 字节,0..254 滚动,255 保留给控制帧标识。
//   - 上下行使用 session 级小窗口；单条 frame 仍由累计 ack 释放。
//   - Frag 字段保留,本实现一帧一段、LastFrag 恒为 true。
package tunnel

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"sync"
)

const (
	// protoVersion 是 cmdVersion 握手时双方互验的协议版本号。
	// 任何线格式变更（meta 长度、DownPkt 头、新命令）都应递增这个值。
	// v2: 新增 cmdQNameProbe (0x09) 用于上行 QNAME 长度自动探测。
	// v3: 新增 cmdContentProbe (0x0A) 用于上行字符集逐字节诊断（仿 iodine pat64u 套路）。
	// v4: 新增 cmdRespSize (0x0B) 用于"长 QNAME + 大 rdata"二维总响应预算探测，
	//     解决"单维度都过 / 二维组合时静默丢包"的盲区。
	// v5: NULL 记录探测数据改为随机字节 + Vigenère 加密，消除固定递增字节模式。
	// v6: 新增 cmdWindow (0x0C),提交 session 级小窗口。
	// v7: cmdWindow Param=0 变为窗口探测；运行期允许客户端降窗重提交。
	protoVersion = 7

	// seqControl 是上行 meta 第 1 字节 == 0xFF 的"控制帧"标记。
	// 客户端发任何控制命令时 seq 都填这个,数据帧 seq 走 0..254。
	seqControl = uint8(0xFF)

	// 控制命令字（meta 第 2 字节）。新增命令必须同步加 client 发送函数 +
	// server handleControl 的 case。
	cmdPoll         = uint8(0x00) // 空查询,捎带 ack,等下行
	cmdVersion      = uint8(0x01) // 版本协商（握手第 1 步）
	cmdFragSize     = uint8(0x02) // 下行 fragsize 探测 / commit（参数区分）
	cmdLazy         = uint8(0x03) // 启 / 关 lazy hold
	cmdCompress     = uint8(0x04) // 启 / 关 zlib 压缩
	cmdRecType      = uint8(0x05) // NULL 记录探测 / Base64 编码探测
	cmdClose        = uint8(0x06) // 关整个 session
	cmdOpenStream   = uint8(0x07) // 新建 stream（参数 = streamID）
	cmdCloseStream  = uint8(0x08) // 关 stream
	cmdQNameProbe   = uint8(0x09) // 上行 QNAME 长度自动探测：服务端回 "OK",不解 dataStr
	cmdContentProbe = uint8(0x0A) // 上行内容字符集探测：服务端把 dataStr 原样 echo 回去（仿 iodine 'Z' 命令）
	cmdRespSize     = uint8(0x0B) // "长 QNAME + 大 rdata"组合下的总响应预算探测/提交（参数区分 0=probe / 1=commit）
	cmdWindow       = uint8(0x0C) // session 窗口；Param=0 探测,Param>0 提交/降窗,响应 OK,<actual>

	// DownPkt Flags 字段的位定义。
	flagLastFrag     = uint8(0x80) // 本片是最后一片（本实现恒为 1）
	flagCompressed   = uint8(0x40) // payload 走 zlib 压缩,接收端要 ZlibDecompress
	flagClosed       = uint8(0x20) // 整个 session 关闭,client 应析构隧道
	flagStreamClosed = uint8(0x10) // 某个 stream 关闭（SID 字段指明）

	maxSeqNo          = 254 // 序号最大值；255 留给 seqControl
	seqSpace          = int(maxSeqNo) + 1
	maxWindow         = 127 // Largest safe window with 1-byte seq/ack; must stay below half the seq space.
	defaultWindow     = 64  // Library default probe ceiling; CLI opts into maxWindow explicitly.
	maxActivePolls    = 16  // Active-down poll cap; data can use the full negotiated window.
	downPktHeaderSize = 5   // DownPkt 头部固定 5 字节
)

// DefaultWindow is the client-side automatic window probe ceiling.
const DefaultWindow = defaultWindow

// MaxWindow is the largest session window this implementation will negotiate.
const MaxWindow = maxWindow

// UpMeta 是上行 QNAME 的 META 段（6 hex = 3 字节）解出来的结构。
//
// 字段语义按 IsControl 分两种：
//   - 数据帧（Seq != 0xFF）：Seq / Frag / LastFrag / Ack 字段有效。
//   - 控制帧（Seq == 0xFF）：Command / Param / Ack 字段有效；其它无视。
type UpMeta struct {
	Seq       uint8 // 上行序号；==0xFF 表示控制帧
	Frag      uint8 // 上行分片号（保留,目前总 0）
	LastFrag  bool  // 是最后一片（保留,目前总 true）
	Ack       uint8 // 对最近一个**下行** seq 的确认（捎带）
	IsControl bool  // Seq == seqControl 时为 true
	Command   uint8 // 控制帧的命令字（cmd* 常量）
	Param     uint8 // 控制帧的参数；poll 用作 downAck,openStream 用作 streamID
}

// ParseMeta 把 6 字符 hex META 解成 UpMeta。
// 调用方必须保证 s 是已经从 QNAME 中切出来的 6 字符段。
func ParseMeta(s string) (UpMeta, error) {
	if len(s) != 6 {
		return UpMeta{}, fmt.Errorf("bad meta len %d", len(s))
	}
	ss, err := hexByte(s[0:2])
	if err != nil {
		return UpMeta{}, err
	}
	ff, err := hexByte(s[2:4])
	if err != nil {
		return UpMeta{}, err
	}
	aa, err := hexByte(s[4:6])
	if err != nil {
		return UpMeta{}, err
	}
	m := UpMeta{Seq: ss, Ack: aa}
	if ss == seqControl {
		// 控制帧布局：[0xFF][Command][Param]
		m.IsControl = true
		m.Command = ff
		m.Param = aa
	} else {
		// 数据帧布局：[Seq][LastFrag(1)|Frag(7)][Ack]
		m.LastFrag = (ff & 0x80) != 0
		m.Frag = ff & 0x7F
	}
	return m, nil
}

// DataMeta 给数据帧拼 6 字符 hex META。frag 截到 7 bit；LastFrag 占最高位。
func DataMeta(seq, frag, ack uint8, last bool) string {
	ff := frag & 0x7F
	if last {
		ff |= 0x80
	}
	return fmt.Sprintf("%02x%02x%02x", seq, ff, ack)
}

// CtrlMeta 给控制帧拼 6 字符 hex META。固定首字节 0xff。
func CtrlMeta(cmd, param uint8) string {
	return fmt.Sprintf("ff%02x%02x", cmd, param)
}

// DownPkt 是下行包的逻辑视图。线上格式见 Encode / DecodeDownPkt。
//
// 一次完整的下行 DNS 应答 = vigenere(DownPkt.Encode())；TXT 还要再过一道 DNS-safe 编码。
type DownPkt struct {
	Seq          uint8  // 下行序号
	Frag         uint8  // 分片号（保留,目前总 0）
	LastFrag     bool   // 是最后一片（目前总 true）
	Ack          uint8  // 对上行最近 Seq 的确认
	StreamID     uint8  // payload 所属 stream；0 表示非 stream 数据（控制响应）
	Compressed   bool   // payload 被 zlib 压缩
	Closed       bool   // 整 session 关闭
	StreamClosed bool   // 该 stream 关闭（其它 stream 不受影响）
	Payload      []byte // 真正的字节内容（可能空）
}

// Encode 把 DownPkt 序列化为 5+N 字节：
//
//	[Flags|Seq|Frag/Last|Ack|SID|Payload...]
//
// Frag 与 LastFrag 既出现在 Flags 的最高位,又重复出现在 Frag/Last 字节最高位——
// 这是历史遗留（向后兼容客户端的两种解析方式）。Decode 端两处会都看,任一为 1 即视为最后片。
func (p *DownPkt) Encode() []byte {
	flags := uint8(0)
	if p.LastFrag {
		flags |= flagLastFrag
	}
	if p.Compressed {
		flags |= flagCompressed
	}
	if p.Closed {
		flags |= flagClosed
	}
	if p.StreamClosed {
		flags |= flagStreamClosed
	}
	fb := p.Frag & 0x7F
	if p.LastFrag {
		fb |= 0x80
	}
	out := make([]byte, 5+len(p.Payload))
	out[0] = flags
	out[1] = p.Seq
	out[2] = fb
	out[3] = p.Ack
	out[4] = p.StreamID
	copy(out[5:], p.Payload)
	return out
}

// DecodeDownPkt 是 Encode 的逆操作。
//
// **稳定性要点**：至少要 5 字节才能解出头部；少于 5 字节直接报错。这是历史上
// "dummy 'x'" 死锁能复现的关键——单字节 payload 不会被当作合法 DownPkt 接受,
// 而是 silently 丢掉。现在服务端已经不再回 dummy "x",但保留这个长度检查作为防线。
func DecodeDownPkt(data []byte) (*DownPkt, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("pkt too short: %d", len(data))
	}
	p := &DownPkt{
		Seq:          data[1],
		Ack:          data[3],
		StreamID:     data[4],
		Compressed:   (data[0] & flagCompressed) != 0,
		Closed:       (data[0] & flagClosed) != 0,
		StreamClosed: (data[0] & flagStreamClosed) != 0,
	}
	p.Frag = data[2] & 0x7F
	p.LastFrag = (data[2] & 0x80) != 0
	if len(data) > 5 {
		p.Payload = data[5:]
	}
	return p, nil
}

// FragBuf 是上行重组缓冲（按分片号收齐后拼成完整帧）。
//
// **目前未使用**——本实现一帧一段,Frag 字段恒为 0、LastFrag 恒为 true。
// 保留这个结构是为了将来支持"多片上行 / 下行"协议扩展时无需重建。
type FragBuf struct {
	mu    sync.Mutex
	frags map[uint8][]byte
	last  int // 已知的最后一片下标；-1 表示尚未收到 LastFrag
}

func NewFragBuf() *FragBuf {
	return &FragBuf{frags: make(map[uint8][]byte), last: -1}
}

// Add 把一片塞进去。重复 idx 会覆盖（容忍重传）。
func (fb *FragBuf) Add(idx uint8, isLast bool, data []byte) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	d := make([]byte, len(data))
	copy(d, data)
	fb.frags[idx] = d
	if isLast {
		fb.last = int(idx)
	}
}

// Complete 检查 [0..last] 区间是否每个 idx 都收到了。
func (fb *FragBuf) Complete() bool {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if fb.last < 0 {
		return false
	}
	for i := 0; i <= fb.last; i++ {
		if _, ok := fb.frags[uint8(i)]; !ok {
			return false
		}
	}
	return true
}

// Assemble 把所有片按 idx 顺序拼起来。调用前应先 Complete()==true。
func (fb *FragBuf) Assemble() []byte {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	var out []byte
	for i := 0; i <= fb.last; i++ {
		out = append(out, fb.frags[uint8(i)]...)
	}
	return out
}

// Reset 清空缓冲,准备下一帧。
func (fb *FragBuf) Reset() {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.frags = make(map[uint8][]byte)
	fb.last = -1
}

// ZlibCompress 用最高压缩等级压缩 data。
// 仅当压缩后比原始小才返回 (compressed, true)；否则返回原 data + false。
// 这避免了对短串 / 已压缩内容做"反向膨胀"。调用方按 ok 决定是否设置 flagCompressed。
func ZlibCompress(data []byte) ([]byte, bool) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return data, false
	}
	w.Write(data)
	w.Close()
	if buf.Len() < len(data) {
		return buf.Bytes(), true
	}
	return data, false
}

// ZlibDecompress 是 ZlibCompress 的逆操作。Decode 端只在 flagCompressed=1 时调用。
func ZlibDecompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// hexByte 把 2 字符 hex 字符串解成 1 字节,接受大小写混合。
// 自己实现而不用 strconv 是因为 strconv 对前导 '0' / 大小写更挑。
func hexByte(s string) (uint8, error) {
	if len(s) != 2 {
		return 0, fmt.Errorf("need 2 hex chars")
	}
	var v uint8
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint8(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint8(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v |= uint8(c - 'A' + 10)
		default:
			return 0, fmt.Errorf("bad hex: %c", c)
		}
	}
	return v, nil
}

// nextSeq 在 [0..254] 上滚动 +1。
// 注意：返回 255 是非法的（255 == seqControl）——所以滚动到 maxSeqNo+1 时回 0,
// 而不是从 0 重新开始数。
func nextSeq(s uint8) uint8 {
	s++
	if s > maxSeqNo {
		s = 0
	}
	return s
}

// seqDistance 返回 a 相对 b 在数据 seq 环上的前向距离。
// seq 空间只有 0..254；255 是控制帧标识,不能按 256 取模。
func seqDistance(a, b uint8) int {
	return (int(a) - int(b) + seqSpace) % seqSpace
}

// seqInWindow 判断 seq 是否落在从 start 开始、长度为 window 的前向窗口内。
// start 本身算命中；window<=0 时恒 false。
func seqInWindow(seq, start uint8, window int) bool {
	if window <= 0 || window > seqSpace {
		return false
	}
	return seqDistance(seq, start) < window
}

func ackCovers(ack, seq uint8) bool {
	return seqDistance(ack, seq) < maxWindow
}

func windowProbeCandidates(requested int) []int {
	if requested < 1 {
		requested = 1
	}
	if requested > maxWindow {
		requested = maxWindow
	}
	candidates := make([]int, 0, 8)
	for n := requested; n >= 1; n = (n + 1) / 2 {
		candidates = append(candidates, n)
		if n == 1 {
			break
		}
	}
	return candidates
}

func windowProbeFallback(requested int) int {
	if requested < 1 {
		return 1
	}
	if requested > 4 {
		return 4
	}
	return requested
}

func windowIncreaseAckTarget(window int) int {
	if window < 1 {
		window = 1
	}
	target := window * 4
	if target < 16 {
		return 16
	}
	return target
}

func dataQueryCredit(window int) int {
	if window < 1 {
		return 1
	}
	if window > maxWindow {
		return maxWindow
	}
	return window
}

func canSendUpData(activeUpFrames, queryInFlight, window int) bool {
	credit := dataQueryCredit(window)
	return activeUpFrames < credit && queryInFlight < credit
}

func pollCredit(downActive, upstreamBacklog bool, window int) int {
	if upstreamBacklog {
		return 0
	}
	if !downActive {
		return 1
	}
	if window < 1 {
		return 1
	}
	if window > maxActivePolls {
		return maxActivePolls
	}
	if window > maxWindow {
		return maxWindow
	}
	return window
}

func canSendPoll(pollInFlight, queryInFlight int, downActive, upstreamBacklog bool, window int) bool {
	credit := pollCredit(downActive, upstreamBacklog, window)
	return pollInFlight < credit && queryInFlight < credit
}

func clampPollInFlight(inFlight int, downActive, upstreamBacklog bool, window int) int {
	if inFlight < 0 {
		return 0
	}
	credit := pollCredit(downActive, upstreamBacklog, window)
	if inFlight > credit {
		return credit
	}
	return inFlight
}
