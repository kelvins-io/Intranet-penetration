package client

import "net"

const (
	defaultVIPNet = "100.64.0.0/10"
	clientTUNIP   = "100.64.0.1"
)

// AssignVIP returns a stable IPv4 in 100.64.0.0/10 for a resource id.
// Must match server.assignResourceVIP.
func AssignVIP(resourceID string) string {
	return hashVIP(resourceID)
}

func hashVIP(resourceID string) string {
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

func parseVIPNet(cidr string) *net.IPNet {
	if cidr == "" {
		cidr = defaultVIPNet
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		_, n, _ = net.ParseCIDR(defaultVIPNet)
	}
	return n
}
