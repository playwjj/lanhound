package scanner

import (
	"golang.org/x/net/bpf"

	"github.com/playwjj/lanhound/internal/passive"
)

// filter is the kernel-side packet filter attached to each raw socket:
// keep ARP, and IPv4 UDP to/from the ports the passive decoder reads.
// Everything else (the host's own TCP traffic, video streams…) is
// dropped in the kernel and never copied to LanHound — that is what
// keeps the listener cheap on a busy NAS.
func filter() []bpf.Instruction {
	ports := []uint32{passive.PortDHCPServer, passive.PortDHCPClient, passive.PortNBNS, passive.PortSSDP, passive.PortMDNS}
	var prog []bpf.Instruction
	add := func(i ...bpf.Instruction) { prog = append(prog, i...) }

	// Jump targets are patched below once the layout is known.
	add(
		bpf.LoadAbsolute{Off: 12, Size: 2},                           // 0: EtherType
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0806, SkipTrue: 0},    // 1: ARP → accept
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipTrue: 0},    // 2: IPv6 → icmp6 check (patched below)
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x0800, SkipTrue: 0}, // 3: not IPv4 → drop
		bpf.LoadAbsolute{Off: 23, Size: 1},                           // 3: IP protocol
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 17, SkipTrue: 0},     // 4: not UDP → drop
		bpf.LoadAbsolute{Off: 20, Size: 2},                           // 5: flags + fragment offset
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 0},  // 6: fragment → drop
		bpf.LoadMemShift{Off: 14},                                    // 7: X = IP header length
		bpf.LoadIndirect{Off: 14, Size: 2},                           // 8: UDP source port
	)
	for _, p := range ports {
		add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: p})
	}
	add(bpf.LoadIndirect{Off: 16, Size: 2}) // UDP destination port
	for _, p := range ports {
		add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: p})
	}
	drop := len(prog)
	add(bpf.RetConstant{Val: 0})
	accept := len(prog)
	add(bpf.RetConstant{Val: 0x40000})
	// IPv6: keep ICMPv6 (neighbour discovery, echo replies) only.
	icmp6 := len(prog)
	add(
		bpf.LoadAbsolute{Off: 20, Size: 1}, // next header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 0x40000},
	)

	for i, ins := range prog {
		j, ok := ins.(bpf.JumpIf)
		if !ok {
			continue
		}
		// Every "equal" test means a match (accept), every "not equal"
		// or "bits set" test a reject (drop).
		to := drop
		switch {
		case i == 2:
			to = icmp6
		case i == icmp6+1:
			to = icmp6 + 3 // ICMPv6 → accept
		case j.Cond == bpf.JumpEqual:
			to = accept
		}
		j.SkipTrue = uint8(to - i - 1)
		prog[i] = j
	}
	return prog
}
