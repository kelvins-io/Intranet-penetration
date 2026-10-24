//go:build darwin

package client

import (
	"fmt"
	"os/exec"
	"strings"
)

// SystemProxy manages macOS HTTP/HTTPS/SOCKS proxy via networksetup.
type SystemProxy struct {
	service string
	socks   string
	enabled bool
}

func DetectNetworkService() string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return "Wi-Fi"
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		if line == "Wi-Fi" || line == "Ethernet" || strings.Contains(line, "USB") {
			return line
		}
	}
	return "Wi-Fi"
}

func NewSystemProxy(socksAddr string) *SystemProxy {
	return &SystemProxy{service: DetectNetworkService(), socks: socksAddr}
}

func (p *SystemProxy) Enable() error {
	host, port, ok := splitHostPort(p.socks)
	if !ok {
		return fmt.Errorf("bad socks addr %q", p.socks)
	}
	cmds := [][]string{
		{"-setsocksfirewallproxy", p.service, host, port},
		{"-setsocksfirewallproxystate", p.service, "on"},
	}
	for _, args := range cmds {
		cmd := exec.Command("networksetup", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("networksetup %v: %w (%s)", args, err, strings.TrimSpace(string(out)))
		}
	}
	p.enabled = true
	return nil
}

func (p *SystemProxy) Disable() error {
	if !p.enabled {
		return nil
	}
	cmd := exec.Command("networksetup", "-setsocksfirewallproxystate", p.service, "off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("disable socks proxy: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	p.enabled = false
	return nil
}

func splitHostPort(addr string) (host, port string, ok bool) {
	i := strings.LastIndexByte(addr, ':')
	if i <= 0 {
		return "", "", false
	}
	return addr[:i], addr[i+1:], true
}
