package server

import "net"

// assignResourceVIP returns a stable CGNAT VIP for the resource key.
// Algorithm must stay in sync with client.hashVIP / AssignVIP.
func assignResourceVIP(resourceID string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(resourceID); i++ {
		h ^= uint32(resourceID[i])
		h *= 16777619
	}
	v := h & 0x3fffff
	base := uint32(100)<<24 | uint32(64)<<16
	addr := base + v
	if addr&0xff < 2 {
		addr += 2
	}
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)).String()
}
