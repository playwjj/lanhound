package core

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

// BenchmarkDevices measures building every device view (what each web
// client snapshot and many publishes cost) as the network grows.
func BenchmarkDevices(b *testing.B) {
	for _, n := range []int{50, 500, 2000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			h := newHarness(&testing.T{}, b.TempDir()+"/b.db")
			for i := 0; i < n; i++ {
				mac := fmt.Sprintf("da:00:00:00:%02x:%02x", i/256, i%256)
				h.r.Observe(sight(mac, fmt.Sprintf("10.%d.%d.1", i/256, i%256), fp(fmt.Sprintf("host-%d", i%40), "", iosFP)))
				h.clk.Add(time.Second)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = h.r.Devices()
			}
		})
	}
}

// The feature index must not change any suggestion: compare it with the
// exhaustive scan on a random population.
func TestIndexedMatchEqualsFullScan(t *testing.T) {
	h := newHarness(t, "")
	rnd := rand.New(rand.NewPCG(1, 2))
	names := []string{"iPhone", "Moms-iPhone", "Galaxy-S24", "Kitchen-Plug", ""}
	models := []string{"", "iPhone15,2", "J305AP"}
	fps := []string{"", iosFP, "1,3,6|android-dhcp-14"}
	for i := 0; i < 300; i++ {
		mac := fmt.Sprintf("da:00:00:00:%02x:%02x", i/256, i%256)
		h.r.Observe(sight(mac, fmt.Sprintf("10.1.%d.%d", i/256, i%256+1),
			fp(names[rnd.IntN(len(names))], models[rnd.IntN(len(models))], fps[rnd.IntN(len(fps))])))
		h.clk.Add(time.Duration(rnd.IntN(3600)) * time.Second)
	}
	h.r.mu.Lock()
	defer h.r.mu.Unlock()
	idx := h.r.index()
	matched := 0
	for _, d := range h.r.devices {
		a, okA := h.r.bestMatch(d, nil)
		b, okB := h.r.bestMatch(d, idx)
		if okA != okB || (okA && (a.ID != b.ID || a.Score != b.Score)) {
			t.Fatalf("device %d: full %+v %v, indexed %+v %v", d.ID, a, okA, b, okB)
		}
		if okA {
			matched++
		}
	}
	if matched == 0 {
		t.Fatal("population produced no matches; the test would prove nothing")
	}
}

func TestIndexInvariant(t *testing.T) {
	if scoreModel+scoreDHCP >= SuggestScore {
		t.Fatal("featureIndex assumes a hostname match is needed to reach SuggestScore")
	}
}
