package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

// Panel is a local HTTP control surface (P2 stand-in for tray GUI).
type Panel struct {
	c      *Client
	addr   string
	proxy  *SystemProxy
	mu     sync.Mutex
	proxyOn atomic.Bool
}

func NewPanel(c *Client, addr string, proxy *SystemProxy) *Panel {
	p := &Panel{c: c, addr: addr, proxy: proxy}
	if proxy != nil {
		p.proxyOn.Store(true)
	}
	return p
}

func (p *Panel) Start(ctx context.Context) error {
	if p.addr == "" || p.addr == "-" {
		<-ctx.Done()
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handleIndex)
	mux.HandleFunc("/api/status", p.handleStatus)
	mux.HandleFunc("/api/proxy", p.handleProxy)
	srv := &http.Server{Addr: p.addr, Handler: mux}
	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		return fmt.Errorf("panel listen: %w", err)
	}
	p.c.log.Info("control panel", "url", "http://"+ln.Addr().String()+"/")
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	err = srv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (p *Panel) handleStatus(w http.ResponseWriter, r *http.Request) {
	ack := p.c.Ack()
	posture := p.c.buildPosture()
	out := map[string]any{
		"connected":   p.c.SessionReady(),
		"mode":        p.c.cfg.Mode,
		"socks":       p.c.cfg.SOCKSListen,
		"system_proxy": p.proxyOn.Load(),
		"device_id":   p.c.cfg.DeviceID,
		"posture":     posture,
		"resources":   p.c.Resources(),
	}
	if ack != nil {
		out["user"] = ack.UserEmail
		out["tenant"] = ack.TenantSlug
		out["session_id"] = ack.SessionID
		out["edge"] = ack.EdgeID
		out["region"] = ack.Region
		out["vip_cidr"] = ack.VIPCIDR
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (p *Panel) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Enable *bool `json:"enable"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.proxy == nil {
		p.proxy = NewSystemProxy(p.c.cfg.SOCKSListen)
	}
	enable := !p.proxyOn.Load()
	if body.Enable != nil {
		enable = *body.Enable
	}
	var err error
	if enable {
		err = p.proxy.Enable()
		if err == nil {
			p.proxyOn.Store(true)
		}
	} else {
		err = p.proxy.Disable()
		if err == nil {
			p.proxyOn.Store(false)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error(), "enabled": p.proxyOn.Load()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "enabled": p.proxyOn.Load()})
}

func (p *Panel) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(panelHTML))
}

const panelHTML = `<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Access Client</title>
<style>
:root{--bg:#0f1419;--card:#1a2332;--fg:#e7ecf3;--muted:#8b9bb4;--accent:#3d8bfd;--ok:#3dd68c;--bad:#f07178}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
main{max-width:720px;margin:0 auto;padding:28px 20px}h1{font-size:1.4rem;margin:0 0 4px}
.sub{color:var(--muted);margin-bottom:20px}.row{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
.pill{background:var(--card);padding:6px 12px;border-radius:999px;font-size:13px}
.pill.ok{outline:1px solid var(--ok)}.pill.bad{outline:1px solid var(--bad)}
button{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:8px 14px;cursor:pointer}
table{width:100%;border-collapse:collapse;margin-top:8px}td,th{text-align:left;padding:8px;border-bottom:1px solid #243044;font-size:13px}
code{font-size:12px;color:#9ecbff}
</style></head><body><main>
<h1>Access Client</h1>
<p class="sub">本机控制面板 · 资源 / 姿态 / 系统代理</p>
<div class="row" id="status"></div>
<div class="row"><button id="proxyBtn">切换系统代理</button><button onclick="load()">刷新</button></div>
<h2>资源</h2><table><thead><tr><th>名称</th><th>VIP</th><th>主机</th><th>类型</th></tr></thead><tbody id="res"></tbody></table>
<h2>姿态</h2><pre id="posture" style="background:var(--card);padding:12px;border-radius:8px;overflow:auto"></pre>
<script>
async function load(){
  const s=await (await fetch('/api/status')).json();
  const st=document.getElementById('status');
  const conn=s.connected?'ok':'bad';
  const connTxt=s.connected?'已连接':'未连接';
  st.innerHTML=
    '<span class="pill '+conn+'">'+connTxt+'</span>'+
    '<span class="pill">'+(s.user||'-')+' @ '+(s.tenant||'-')+'</span>'+
    '<span class="pill">mode '+s.mode+'</span>'+
    '<span class="pill">proxy '+(s.system_proxy?'ON':'OFF')+'</span>'+
    '<span class="pill">device <code>'+(s.device_id||'')+'</code></span>'+
    '<span class="pill">session <code>'+(s.session_id||'-')+'</code></span>';
  document.getElementById('posture').textContent=JSON.stringify(s.posture,null,2);
  const rows=(s.resources||[]).map(function(r){
    return '<tr><td>'+r.name+'</td><td><code>'+(r.vip||'')+'</code></td><td>'+(r.hostname||r.browser_url||'')+'</td><td>'+r.type+'</td></tr>';
  }).join('');
  document.getElementById('res').innerHTML=rows||'<tr><td colspan=4>无资源</td></tr>';
}
document.getElementById('proxyBtn').onclick=async function(){
  await fetch('/api/proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
  load();
};
load();setInterval(load,5000);
</script></main></body></html>`
