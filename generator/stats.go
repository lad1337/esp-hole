package main

// In-RAM node statistics. ESP nodes report interval deltas over UDP using a
// strict subset of the InfluxDB line protocol (see main/stats.c); this side
// parses, aggregates into per-minute ring buffers, and serves the result to
// the web UI. Everything lives in RAM by design — stats are best-effort and
// loss on restart is accepted.

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const statsHistBuckets = 16

// statsNodeCap bounds memory against sprayed valid-looking packets: beyond
// this many distinct node IDs, samples from unknown nodes are dropped.
const statsNodeCap = 32

// latBucketUpper[i] is the exclusive upper edge (µs) of firmware latency
// bucket i. MUST mirror lat_bucket() in main/stats.c — change both together.
var latBucketUpper = [statsHistBuckets]float64{
	128, 256, 512, 1024, 2048, 4096, 8192, 16384,
	32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304,
}

// statsSample is one decoded node report (interval deltas + uptime gauge).
type statsSample struct {
	node     string // 12 lowercase hex chars (ethernet MAC)
	blocked  uint64
	forward  uint64
	timeouts uint64
	latSumUS uint64
	uptimeS  int64
	hist     [statsHistBuckets]uint64
}

// parseStatsLine decodes the exact subset the nodes emit:
//
//	esphole,node=<12hex> blocked=<n>i,forwarded=<n>i,...,h0=<n>i,...,h15=<n>i
//
// Unknown fields are ignored (forward compatibility). Anything malformed
// returns ok=false — this function must never panic, whatever arrives on
// the socket.
func parseStatsLine(line string) (statsSample, bool) {
	var s statsSample
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 || len(line) > 1500 {
		return s, false
	}
	header, fields, found := strings.Cut(line, " ")
	if !found {
		return s, false
	}
	const prefix = "esphole,node="
	if !strings.HasPrefix(header, prefix) {
		return s, false
	}
	node := header[len(prefix):]
	if len(node) != 12 {
		return s, false
	}
	for i := 0; i < len(node); i++ {
		c := node[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return s, false
		}
	}
	s.node = node

	for _, f := range strings.Split(fields, ",") {
		name, val, found := strings.Cut(f, "=")
		if !found || len(val) < 2 || val[len(val)-1] != 'i' {
			return s, false
		}
		num := val[:len(val)-1]
		switch name {
		case "uptime_s":
			v, err := strconv.ParseInt(num, 10, 64)
			if err != nil || v < 0 {
				return s, false
			}
			s.uptimeS = v
		case "blocked", "forwarded", "timeouts", "lat_sum_us":
			v, err := strconv.ParseUint(num, 10, 64)
			if err != nil {
				return s, false
			}
			switch name {
			case "blocked":
				s.blocked = v
			case "forwarded":
				s.forward = v
			case "timeouts":
				s.timeouts = v
			case "lat_sum_us":
				s.latSumUS = v
			}
		default:
			b, isHist := strings.CutPrefix(name, "h")
			idx, err := strconv.Atoi(b)
			if !isHist || err != nil || idx < 0 || idx >= statsHistBuckets {
				continue // unknown field: ignored for forward compat
			}
			v, err := strconv.ParseUint(num, 10, 64)
			if err != nil {
				return s, false
			}
			s.hist[idx] = v
		}
	}
	return s, true
}

// statsPoint is one minute of aggregated deltas for one node. Samples counts
// ingested reports — it distinguishes "node silent" (0, rendered as a gap)
// from "node up, zero queries" (>0, rendered as zero).
type statsPoint struct {
	Blocked  uint64
	Forward  uint64
	Timeouts uint64
	LatSumUS uint64
	Samples  uint64
	Hist     [statsHistBuckets]uint64
}

// nodeStats is a fixed-length ring of per-minute points. head is the ring
// index of headMin (the newest minute); older minutes sit behind it.
type nodeStats struct {
	points   []statsPoint
	head     int
	headMin  int64 // unix time / 60 of the head slot
	lastSeen time.Time
	uptimeS  int64
}

type statsStore struct {
	mu        sync.Mutex
	nodes     map[string]*nodeStats
	retention time.Duration
	// now is injectable for tests; time.Now in production.
	now func() time.Time
}

func newStatsStore(retention time.Duration) *statsStore {
	return &statsStore{
		nodes:     make(map[string]*nodeStats),
		retention: retention,
		now:       time.Now,
	}
}

func (st *statsStore) ringLen() int {
	n := int(st.retention / time.Minute)
	if n < 1 {
		n = 1
	}
	return n
}

// advanceTo moves the node's head to minute m, zero-filling skipped slots.
// A node silent for longer than the whole retention just gets a cleared ring.
func (ns *nodeStats) advanceTo(m int64) {
	gap := m - ns.headMin
	if gap <= 0 {
		return
	}
	if gap >= int64(len(ns.points)) {
		for i := range ns.points {
			ns.points[i] = statsPoint{}
		}
	} else {
		for i := int64(0); i < gap; i++ {
			ns.head = (ns.head + 1) % len(ns.points)
			ns.points[ns.head] = statsPoint{}
		}
	}
	ns.headMin = m
}

// ingest folds one sample's deltas into the node's current minute.
func (st *statsStore) ingest(s statsSample) {
	now := st.now()
	min := now.Unix() / 60

	st.mu.Lock()
	defer st.mu.Unlock()

	ns := st.nodes[s.node]
	if ns == nil {
		if len(st.nodes) >= statsNodeCap {
			return
		}
		// Memory: 7 d retention = 10080 points × ~160 B ≈ 1.6 MB per node,
		// bounded by statsNodeCap.
		ns = &nodeStats{points: make([]statsPoint, st.ringLen()), headMin: min}
		st.nodes[s.node] = ns
	}
	ns.advanceTo(min)
	p := &ns.points[ns.head]
	p.Blocked += s.blocked
	p.Forward += s.forward
	p.Timeouts += s.timeouts
	p.LatSumUS += s.latSumUS
	p.Samples++
	for i := range p.Hist {
		p.Hist[i] += s.hist[i]
	}
	ns.lastSeen = now
	ns.uptimeS = s.uptimeS
}

// evictStale drops nodes not heard from within the retention window.
// Caller must hold st.mu.
func (st *statsStore) evictStale(now time.Time) {
	for id, ns := range st.nodes {
		if now.Sub(ns.lastSeen) > st.retention {
			delete(st.nodes, id)
		}
	}
}

// percentileFromHist linearly interpolates the q-quantile (0 < q < 1) within
// the winning histogram bucket. ok=false when the histogram is empty.
func percentileFromHist(h [statsHistBuckets]uint64, q float64) (float64, bool) {
	var total uint64
	for _, c := range h {
		total += c
	}
	if total == 0 {
		return 0, false
	}
	rank := q * float64(total)
	var cum float64
	for i, c := range h {
		if c == 0 {
			continue
		}
		if cum+float64(c) >= rank {
			lo := 0.0
			if i > 0 {
				lo = latBucketUpper[i-1]
			}
			up := latBucketUpper[i]
			return lo + (up-lo)*(rank-cum)/float64(c), true
		}
		cum += float64(c)
	}
	// Rounding put the rank past the last non-empty bucket; return its edge.
	for i := statsHistBuckets - 1; i >= 0; i-- {
		if h[i] > 0 {
			return latBucketUpper[i], true
		}
	}
	return 0, false
}

// nodeInfo is one row of the UI's node table (totals over the range).
type nodeInfo struct {
	ID       string `json:"id"`
	LastSeen int64  `json:"lastSeen"` // unix seconds
	UptimeS  int64  `json:"uptimeS"`
	Blocked  uint64 `json:"blocked"`
	Forward  uint64 `json:"forwarded"`
	Timeouts uint64 `json:"timeouts"`
}

// nodeSeries holds per-minute series aligned to statsResponse.Times.
// nil entries mean "no data" (node silent that minute) and render as gaps.
type nodeSeries struct {
	QPS          []*float64 `json:"qps"`
	BlockedRatio []*float64 `json:"blockedRatio"`
	Timeouts     []*float64 `json:"timeouts"`
	AvgUS        []*float64 `json:"avgUs"`
	P50US        []*float64 `json:"p50Us"`
	P95US        []*float64 `json:"p95Us"`
	P99US        []*float64 `json:"p99Us"`
}

type statsResponse struct {
	Step   int64                 `json:"step"` // seconds per point (60)
	Times  []int64               `json:"times"`
	Nodes  []nodeInfo            `json:"nodes"`
	Series map[string]nodeSeries `json:"series"`
}

func fptr(v float64) *float64 { return &v }

// snapshot renders the last rng of data as UI-ready aligned series.
func (st *statsStore) snapshot(rng time.Duration) statsResponse {
	st.mu.Lock()
	defer st.mu.Unlock()

	now := st.now()
	st.evictStale(now)

	n := int(rng / time.Minute)
	if n < 1 {
		n = 1
	}
	if maxN := st.ringLen(); n > maxN {
		n = maxN
	}
	nowMin := now.Unix() / 60

	resp := statsResponse{
		Step:   60,
		Times:  make([]int64, n),
		Series: make(map[string]nodeSeries, len(st.nodes)),
	}
	for i := range resp.Times {
		resp.Times[i] = (nowMin - int64(n-1) + int64(i)) * 60
	}

	ids := make([]string, 0, len(st.nodes))
	for id := range st.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		ns := st.nodes[id]
		// Align the ring head with the current minute so index math below is
		// uniform; this only zero-fills minutes that have already passed.
		ns.advanceTo(nowMin)

		info := nodeInfo{ID: id, LastSeen: ns.lastSeen.Unix(), UptimeS: ns.uptimeS}
		ser := nodeSeries{
			QPS:          make([]*float64, n),
			BlockedRatio: make([]*float64, n),
			Timeouts:     make([]*float64, n),
			AvgUS:        make([]*float64, n),
			P50US:        make([]*float64, n),
			P95US:        make([]*float64, n),
			P99US:        make([]*float64, n),
		}
		ring := len(ns.points)
		for i := 0; i < n; i++ {
			offset := int64(n - 1 - i) // minutes back from now
			if offset >= int64(ring) {
				continue // beyond ring coverage: gap
			}
			p := &ns.points[(ns.head-int(offset)+ring)%ring]
			if p.Samples == 0 {
				continue // node silent that minute: gap
			}
			total := p.Blocked + p.Forward
			ser.QPS[i] = fptr(float64(total) / 60)
			ser.Timeouts[i] = fptr(float64(p.Timeouts))
			if total > 0 {
				ser.BlockedRatio[i] = fptr(float64(p.Blocked) / float64(total))
			}
			if p.Forward > 0 {
				ser.AvgUS[i] = fptr(float64(p.LatSumUS) / float64(p.Forward))
			}
			if v, ok := percentileFromHist(p.Hist, 0.50); ok {
				ser.P50US[i] = fptr(v)
			}
			if v, ok := percentileFromHist(p.Hist, 0.95); ok {
				ser.P95US[i] = fptr(v)
			}
			if v, ok := percentileFromHist(p.Hist, 0.99); ok {
				ser.P99US[i] = fptr(v)
			}
			info.Blocked += p.Blocked
			info.Forward += p.Forward
			info.Timeouts += p.Timeouts
		}
		resp.Nodes = append(resp.Nodes, info)
		resp.Series[id] = ser
	}
	return resp
}

// startStatsListener consumes datagrams until pc is closed. Oversized
// datagrams truncate at the read buffer, fail parsing, and are dropped —
// garbage never reaches the store.
func startStatsListener(pc net.PacketConn, store *statsStore) {
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return // listener closed
			}
			for _, line := range strings.Split(string(buf[:n]), "\n") {
				if s, ok := parseStatsLine(strings.TrimSpace(line)); ok {
					store.ingest(s)
				}
			}
		}
	}()
}
