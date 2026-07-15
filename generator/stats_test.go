package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// firmwareLine mirrors the exact snprintf output of main/stats.c.
const firmwareLine = "esphole,node=a4cf12aabbcc blocked=12i,forwarded=340i," +
	"timeouts=1i,lat_sum_us=6816400i,uptime_s=86710i," +
	"h0=0i,h1=0i,h2=3i,h3=10i,h4=100i,h5=150i,h6=50i,h7=20i," +
	"h8=5i,h9=2i,h10=0i,h11=0i,h12=0i,h13=0i,h14=0i,h15=0i"

func TestParseStatsLine(t *testing.T) {
	t.Run("firmware line round-trips", func(t *testing.T) {
		s, ok := parseStatsLine(firmwareLine)
		if !ok {
			t.Fatal("parse failed")
		}
		if s.node != "a4cf12aabbcc" {
			t.Errorf("node = %q", s.node)
		}
		if s.blocked != 12 || s.forward != 340 || s.timeouts != 1 {
			t.Errorf("counts = %d/%d/%d", s.blocked, s.forward, s.timeouts)
		}
		if s.latSumUS != 6816400 || s.uptimeS != 86710 {
			t.Errorf("latSumUS=%d uptimeS=%d", s.latSumUS, s.uptimeS)
		}
		want := [statsHistBuckets]uint64{0, 0, 3, 10, 100, 150, 50, 20, 5, 2}
		if s.hist != want {
			t.Errorf("hist = %v", s.hist)
		}
	})

	t.Run("accepts", func(t *testing.T) {
		cases := []struct {
			name string
			in   string
		}{
			{"trailing newline", firmwareLine + "\n"},
			{"trailing crlf", firmwareLine + "\r\n"},
			{"unknown field ignored", "esphole,node=aaaaaaaaaaaa blocked=1i,heap_free=1234i"},
			{"future bucket ignored", "esphole,node=aaaaaaaaaaaa blocked=1i,h16=5i"},
		}
		for _, c := range cases {
			if _, ok := parseStatsLine(c.in); !ok {
				t.Errorf("%s: rejected %q", c.name, c.in)
			}
		}
	})

	t.Run("rejects", func(t *testing.T) {
		cases := []struct {
			name string
			in   string
		}{
			{"empty", ""},
			{"garbage", "hello world"},
			{"binary junk", "\x00\x01\x02 \xff\xfe"},
			{"wrong measurement", "pihole,node=a4cf12aabbcc blocked=1i"},
			{"no node tag", "esphole blocked=1i"},
			{"short mac", "esphole,node=a4cf12 blocked=1i"},
			{"long mac", "esphole,node=a4cf12aabbccdd blocked=1i"},
			{"uppercase mac", "esphole,node=A4CF12AABBCC blocked=1i"},
			{"non-hex mac", "esphole,node=zzzzzzzzzzzz blocked=1i"},
			{"missing i suffix", "esphole,node=a4cf12aabbcc blocked=1"},
			{"negative count", "esphole,node=a4cf12aabbcc blocked=-1i"},
			{"negative uptime", "esphole,node=a4cf12aabbcc uptime_s=-5i"},
			{"count overflow", "esphole,node=a4cf12aabbcc blocked=99999999999999999999i"},
			{"field without =", "esphole,node=a4cf12aabbcc blocked"},
			{"no fields", "esphole,node=a4cf12aabbcc"},
			{"bad hist value", "esphole,node=a4cf12aabbcc h3=xxi"},
			{"oversized", "esphole,node=a4cf12aabbcc blocked=1i," + strings.Repeat("x", 1500)},
		}
		for _, c := range cases {
			if _, ok := parseStatsLine(c.in); ok {
				t.Errorf("%s: accepted %q", c.name, c.in)
			}
		}
	})
}

// testStore returns a store with a controllable clock starting at t0.
func testStore(retention time.Duration) (*statsStore, *time.Time) {
	st := newStatsStore(retention)
	t0 := time.Date(2026, 7, 7, 12, 0, 30, 0, time.UTC)
	now := &t0
	st.now = func() time.Time { return *now }
	return st, now
}

func sampleWith(node string, blocked, forward uint64) statsSample {
	return statsSample{node: node, blocked: blocked, forward: forward}
}

func TestStatsStoreIngest(t *testing.T) {
	t.Run("same minute accumulates", func(t *testing.T) {
		st, now := testStore(time.Hour)
		st.ingest(sampleWith("aaaaaaaaaaaa", 1, 10))
		*now = now.Add(10 * time.Second)
		st.ingest(sampleWith("aaaaaaaaaaaa", 2, 20))
		ns := st.nodes["aaaaaaaaaaaa"]
		p := ns.points[ns.head]
		if p.Blocked != 3 || p.Forward != 30 {
			t.Errorf("head point = %+v", p)
		}
	})

	t.Run("minute advance zero-fills gap", func(t *testing.T) {
		st, now := testStore(time.Hour)
		st.ingest(sampleWith("aaaaaaaaaaaa", 1, 0))
		*now = now.Add(3 * time.Minute)
		st.ingest(sampleWith("aaaaaaaaaaaa", 5, 0))
		ns := st.nodes["aaaaaaaaaaaa"]
		if got := ns.points[ns.head].Blocked; got != 5 {
			t.Errorf("head = %d", got)
		}
		// The two skipped minutes must be zero, the first minute intact.
		n := len(ns.points)
		if ns.points[(ns.head-1+n)%n].Blocked != 0 ||
			ns.points[(ns.head-2+n)%n].Blocked != 0 {
			t.Error("gap minutes not zeroed")
		}
		if ns.points[(ns.head-3+n)%n].Blocked != 1 {
			t.Error("oldest minute lost")
		}
	})

	t.Run("ring wraps at tiny retention", func(t *testing.T) {
		st, now := testStore(5 * time.Minute)
		for i := 0; i < 8; i++ {
			st.ingest(sampleWith("aaaaaaaaaaaa", uint64(i+1), 0))
			*now = now.Add(time.Minute)
		}
		ns := st.nodes["aaaaaaaaaaaa"]
		if len(ns.points) != 5 {
			t.Fatalf("ring len = %d", len(ns.points))
		}
		var total uint64
		for _, p := range ns.points {
			total += p.Blocked
		}
		// Last 5 ingests were 4+5+6+7+8; note head advanced once past the
		// final ingest is NOT the case here (clock advanced after), so the
		// ring holds ingests 4..8.
		if total != 4+5+6+7+8 {
			t.Errorf("ring total = %d", total)
		}
	})

	t.Run("silence beyond retention clears ring", func(t *testing.T) {
		st, now := testStore(5 * time.Minute)
		st.ingest(sampleWith("aaaaaaaaaaaa", 100, 0))
		*now = now.Add(30 * time.Minute)
		st.ingest(sampleWith("aaaaaaaaaaaa", 1, 0))
		ns := st.nodes["aaaaaaaaaaaa"]
		var total uint64
		for _, p := range ns.points {
			total += p.Blocked
		}
		if total != 1 {
			t.Errorf("ring total = %d, want only the fresh sample", total)
		}
	})

	t.Run("stale node evicted", func(t *testing.T) {
		st, now := testStore(5 * time.Minute)
		st.ingest(sampleWith("aaaaaaaaaaaa", 1, 0))
		*now = now.Add(10 * time.Minute)
		st.ingest(sampleWith("bbbbbbbbbbbb", 1, 0))
		st.mu.Lock()
		st.evictStale(*now)
		st.mu.Unlock()
		if _, ok := st.nodes["aaaaaaaaaaaa"]; ok {
			t.Error("stale node not evicted")
		}
		if _, ok := st.nodes["bbbbbbbbbbbb"]; !ok {
			t.Error("fresh node evicted")
		}
	})

	t.Run("node cap drops extras", func(t *testing.T) {
		st, _ := testStore(time.Hour)
		hex := "0123456789ab"
		for i := 0; i < statsNodeCap+1; i++ {
			node := hex[:10] + string([]byte{hex[i%12], hex[(i/12)%12]})
			// Build distinct 12-char hex ids deterministically.
			st.ingest(sampleWith(node, 1, 0))
		}
		if len(st.nodes) > statsNodeCap {
			t.Errorf("node count = %d, cap %d", len(st.nodes), statsNodeCap)
		}
	})
}

func TestPercentileFromHist(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var h [statsHistBuckets]uint64
		if _, ok := percentileFromHist(h, 0.5); ok {
			t.Error("empty histogram must not produce a percentile")
		}
	})

	t.Run("single bucket interpolates within edges", func(t *testing.T) {
		var h [statsHistBuckets]uint64
		h[4] = 100 // bucket 4 = [1024, 2048)
		v, ok := percentileFromHist(h, 0.5)
		if !ok {
			t.Fatal("no result")
		}
		if want := 1024 + (2048-1024)*0.5; v != want {
			t.Errorf("p50 = %v, want %v", v, want)
		}
		if v, _ := percentileFromHist(h, 0.99); v <= 1024 || v > 2048 {
			t.Errorf("p99 = %v outside bucket 4", v)
		}
	})

	t.Run("spread across buckets", func(t *testing.T) {
		var h [statsHistBuckets]uint64
		h[2] = 50 // [256, 512)
		h[8] = 50 // [16384, 32768)
		// p50: rank 50 lands exactly at the end of bucket 2.
		v, ok := percentileFromHist(h, 0.5)
		if !ok {
			t.Fatal("no result")
		}
		if v != 512 {
			t.Errorf("p50 = %v, want 512", v)
		}
		// p95: rank 95 → 45 into bucket 8's 50 samples.
		v, _ = percentileFromHist(h, 0.95)
		if want := 16384 + (32768-16384)*(45.0/50.0); v != want {
			t.Errorf("p95 = %v, want %v", v, want)
		}
	})

	t.Run("single sample", func(t *testing.T) {
		var h [statsHistBuckets]uint64
		h[0] = 1
		v, ok := percentileFromHist(h, 0.99)
		if !ok || v <= 0 || v > 128 {
			t.Errorf("p99 = %v ok=%v, want inside (0,128]", v, ok)
		}
	})
}

func TestStatsHTTPAPI(t *testing.T) {
	cfg := &Config{StatsRetention: jsonDuration(time.Hour)}
	s := newServer(cfg)
	ts := httptest.NewServer(s.handler())
	defer ts.Close()

	t.Run("api 503 when stats disabled", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/stats/api")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status %d, want 503", resp.StatusCode)
		}
	})

	// Populate a store with two minutes of data for one node.
	store, now := testStore(time.Hour)
	sm := statsSample{node: "a4cf12aabbcc", blocked: 6, forward: 54,
		latSumUS: 54 * 5000, uptimeS: 1000}
	sm.hist[5] = 54 // all samples in [2048, 4096) µs
	store.ingest(sm)
	*now = now.Add(time.Minute)
	store.ingest(sm)
	s.stats = store

	t.Run("page and assets served", func(t *testing.T) {
		for path, wantType := range map[string]string{
			"/stats":                  "text/html",
			"/stats/ui/uplot.min.js":  "javascript",
			"/stats/ui/uplot.min.css": "css",
		} {
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s: status %d, want 200", path, resp.StatusCode)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, wantType) {
				t.Errorf("%s: content-type %q, want %q", path, ct, wantType)
			}
		}
	})

	t.Run("api shape", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/stats/api?range=30m")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
		var r statsResponse
		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
			t.Fatal(err)
		}
		if len(r.Times) != 30 || r.Step != 60 {
			t.Fatalf("times len %d step %d, want 30/60", len(r.Times), r.Step)
		}
		if len(r.Nodes) != 1 || r.Nodes[0].ID != "a4cf12aabbcc" {
			t.Fatalf("nodes = %+v", r.Nodes)
		}
		ser, ok := r.Series["a4cf12aabbcc"]
		if !ok {
			t.Fatal("series missing")
		}
		for name, arr := range map[string][]*float64{
			"qps": ser.QPS, "blockedRatio": ser.BlockedRatio,
			"p50Us": ser.P50US, "avgUs": ser.AvgUS,
		} {
			if len(arr) != len(r.Times) {
				t.Errorf("%s: len %d != times %d", name, len(arr), len(r.Times))
			}
		}
		// The two reported minutes carry values; the rest are null gaps.
		var nonNull int
		for _, v := range ser.QPS {
			if v != nil {
				nonNull++
				if *v != 1.0 { // (6+54)/60
					t.Errorf("qps = %v, want 1.0", *v)
				}
			}
		}
		if nonNull != 2 {
			t.Errorf("non-null qps points = %d, want 2", nonNull)
		}
		// p50 must interpolate inside bucket 5 = [2048, 4096).
		for _, v := range ser.P50US {
			if v != nil && (*v < 2048 || *v >= 4096) {
				t.Errorf("p50 = %v outside bucket 5", *v)
			}
		}
	})

	t.Run("range clamped to retention", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/stats/api?range=9000h")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var r statsResponse
		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
			t.Fatal(err)
		}
		if len(r.Times) != 60 { // retention 1h → 60 points max
			t.Errorf("times len = %d, want 60", len(r.Times))
		}
	})
}

func TestStatsUDPEndToEnd(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	store := newStatsStore(time.Hour)
	startStatsListener(pc, store)

	conn, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// One valid line, one garbage datagram, one multi-line datagram.
	conn.Write([]byte(firmwareLine))
	conn.Write([]byte("total garbage \x00\xff"))
	conn.Write([]byte("esphole,node=bbbbbbbbbbbb blocked=7i\n" +
		"esphole,node=cccccccccccc forwarded=9i\n"))

	deadline := time.Now().Add(2 * time.Second)
	for {
		store.mu.Lock()
		n := len(store.nodes)
		store.mu.Unlock()
		if n == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d nodes ingested before deadline", n)
		}
		time.Sleep(10 * time.Millisecond)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if ns := store.nodes["a4cf12aabbcc"]; ns == nil ||
		ns.points[ns.head].Forward != 340 {
		t.Error("valid line not ingested correctly")
	}
	if ns := store.nodes["bbbbbbbbbbbb"]; ns == nil ||
		ns.points[ns.head].Blocked != 7 {
		t.Error("multi-line datagram line 1 lost")
	}
	if len(store.nodes) != 3 {
		t.Errorf("node count = %d, want 3 (garbage must not create nodes)",
			len(store.nodes))
	}
}
