package core

import (
	"fmt"
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
