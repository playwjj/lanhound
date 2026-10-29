package passive

import (
	"bufio"
	"bytes"
	"strings"
)

// ssdpServer returns the SERVER header of an SSDP NOTIFY or M-SEARCH
// response ("Linux/3.14 UPnP/1.0 Roku/9.4"), a decent hint at what the
// device is.
func ssdpServer(payload []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(payload))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "server") {
			return cleanName(strings.TrimSpace(v))
		}
	}
	return ""
}
