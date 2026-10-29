package router

import (
	"strings"
	"testing"
)

// Router tables are fetched from devices on the network; parsing must
// survive anything.
func FuzzParseText(f *testing.F) {
	f.Add("1730190000 00:1e:a0:11:22:33 192.168.1.50 IPTV-Box *\n")
	f.Add("IP address HW type Flags HW address Mask Device\n192.168.1.50 0x1 0x2 00:1e:a0:11:22:33 * br-lan\n")
	f.Add("name,ip,mac\nbox,192.168.1.50,00-1E-A0-11-22-33\n\"a,b\",1.2.3.4,zz\n")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseText(strings.NewReader(s))
	})
}
