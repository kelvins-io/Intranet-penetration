//go:build linux

package client

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// SystemProxy sets common Linux desktop env / gsettings when available.
type SystemProxy struct {
	socks   string
	enabled bool
	prevHTTP, prevHTTPS, prevALL string
}

func NewSystemProxy(socksAddr string) *SystemProxy {
	return &SystemProxy{socks: socksAddr}
}

func (p *SystemProxy) Enable() error {
	proxyURL := "socks5://" + p.socks
	p.prevHTTP = os.Getenv("http_proxy")
	p.prevHTTPS = os.Getenv("https_proxy")
	p.prevALL = os.Getenv("ALL_PROXY")
	_ = os.Setenv("http_proxy", proxyURL)
	_ = os.Setenv("https_proxy", proxyURL)
	_ = os.Setenv("ALL_PROXY", proxyURL)
	// Best-effort GNOME
	_ = exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "manual").Run()
	host, port, ok := splitHostPort(p.socks)
	if ok {
		_ = exec.Command("gsettings", "set", "org.gnome.system.proxy.socks", "host", host).Run()
		_ = exec.Command("gsettings", "set", "org.gnome.system.proxy.socks", "port", port).Run()
	}
	p.enabled = true
	fmt.Fprintf(os.Stderr, "linux system proxy: export ALL_PROXY=%s (also attempted gsettings)\n", proxyURL)
	return nil
}

func (p *SystemProxy) Disable() error {
	if !p.enabled {
		return nil
	}
	_ = os.Setenv("http_proxy", p.prevHTTP)
	_ = os.Setenv("https_proxy", p.prevHTTPS)
	_ = os.Setenv("ALL_PROXY", p.prevALL)
	_ = exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
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
