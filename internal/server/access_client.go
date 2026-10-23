package server

import (
	"net/http"
	"strings"
)

const accessClientHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Access Client</title>
<style>
:root{--bg:#0f1419;--panel:#1a2332;--text:#e7ecf3;--muted:#8b9bb4;--accent:#3d9cf0;--ok:#3ecf8e;--border:#2a3548}
*{box-sizing:border-box}body{margin:0;font-family:ui-sans-serif,system-ui,sans-serif;background:radial-gradient(1200px 600px at 10% -10%,#1b3a5a 0%,var(--bg) 55%);color:var(--text);min-height:100vh}
header{padding:1.5rem 1.25rem .5rem;max-width:880px;margin:0 auto}
header h1{margin:0;font-size:1.5rem;letter-spacing:.02em}
header p{margin:.4rem 0 0;color:var(--muted);font-size:.95rem}
main{max-width:880px;margin:0 auto;padding:1rem 1.25rem 3rem;display:grid;gap:1rem}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:1rem 1.1rem}
label{display:block;font-size:.8rem;color:var(--muted);margin-bottom:.35rem}
input{width:100%;padding:.65rem .75rem;border-radius:8px;border:1px solid var(--border);background:#0d121a;color:var(--text)}
.row{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:.75rem}
button,.btn{appearance:none;border:0;border-radius:8px;padding:.65rem 1rem;background:var(--accent);color:#fff;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block}
button.secondary{background:#2a3548}
.muted{color:var(--muted);font-size:.85rem}
.tun{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:.7rem 0;border-bottom:1px solid var(--border)}
.tun:last-child{border-bottom:0}
.badge{font-size:.75rem;padding:.15rem .45rem;border-radius:999px;background:#243044;color:var(--ok)}
.err{color:#ff7b7b;font-size:.9rem;margin-top:.5rem}
</style>
</head>
<body>
<header>
  <h1>Access Client</h1>
  <p>登录后查看可用隧道，并按区域推荐接入点。</p>
</header>
<main>
  <section class="card" id="loginCard">
    <label>API Key 或邮箱密码</label>
    <input id="apiKey" placeholder="Bearer API Key / X-API-Key" autocomplete="off"/>
    <div class="row">
      <input id="email" placeholder="email（可选）" style="flex:1"/>
      <input id="password" type="password" placeholder="password（可选）" style="flex:1"/>
    </div>
    <div class="row">
      <button id="btnLogin">进入</button>
      <button class="secondary" id="btnClear">清除</button>
    </div>
    <div class="err" id="err"></div>
  </section>
  <section class="card" id="meCard" hidden>
    <div class="muted" id="meLine"></div>
    <div class="row" style="margin-top:.75rem">
      <button class="secondary" id="btnRefresh">刷新</button>
      <button class="secondary" id="btnLogout">退出</button>
    </div>
  </section>
  <section class="card" id="regionCard" hidden>
    <strong>区域推荐</strong>
    <pre class="muted" id="regionOut" style="white-space:pre-wrap;margin:.6rem 0 0"></pre>
  </section>
  <section class="card" id="tunCard" hidden>
    <strong>可用隧道</strong>
    <div id="tunList"></div>
  </section>
</main>
<script>
const $ = (id)=>document.getElementById(id);
const keyStore = 'ip_access_key';
function authHeaders(){
  const k = localStorage.getItem(keyStore)||'';
  const h = {'Content-Type':'application/json'};
  if(k) h['Authorization']='Bearer '+k;
  return h;
}
async function login(){
  $('err').textContent='';
  const key = $('apiKey').value.trim();
  if(key){
    localStorage.setItem(keyStore,key);
    document.cookie='ip_access_key='+encodeURIComponent(key)+'; Path=/; SameSite=Lax';
    return load();
  }
  const email=$('email').value.trim(), password=$('password').value;
  const res = await fetch('/api/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});
  const data = await res.json().catch(()=>({}));
  if(!res.ok){ $('err').textContent=data.error||('login failed '+res.status); return; }
  const apiKey = data.api_key || data.user?.api_key || '';
  if(!apiKey){ $('err').textContent='login ok but no api_key in response'; return; }
  localStorage.setItem(keyStore,apiKey);
  document.cookie='ip_access_key='+encodeURIComponent(apiKey)+'; Path=/; SameSite=Lax';
  $('apiKey').value=apiKey;
  return load();
}
async function load(){
  $('err').textContent='';
  const meRes = await fetch('/api/v1/me',{headers:authHeaders()});
  if(!meRes.ok){ $('err').textContent='未登录或密钥无效'; $('meCard').hidden=$('regionCard').hidden=$('tunCard').hidden=true; return; }
  const me = await meRes.json();
  $('loginCard').hidden=true;
  $('meCard').hidden=false;
  $('meLine').textContent = (me.user?.email||'')+' · tenant '+(me.tenant?.slug||me.tenant?.id||'');
  const pref = me.tenant?.slug || 'local';
  const reg = await fetch('/api/v1/regions/recommend?prefer='+encodeURIComponent(pref),{headers:authHeaders()}).then(r=>r.json());
  $('regionCard').hidden=false;
  $('regionOut').textContent = JSON.stringify(reg,null,2);
  const tuns = await fetch('/api/v1/tunnels',{headers:authHeaders()}).then(r=>r.json());
  const list = Array.isArray(tuns)?tuns:(tuns.tunnels||[]);
  $('tunCard').hidden=false;
  const box=$('tunList'); box.innerHTML='';
  if(!list.length){ box.innerHTML='<p class="muted">暂无隧道在线</p>'; return; }
  for(const t of list){
    const name=t.name||t.tunnel_name;
    const slug=me.tenant?.slug||'default';
    const type=t.type||'http';
    const pub=t.public_addr||t.PublicAddr||'';
    const href = type==='http' ? ('/'+slug+'/'+name+'/') : (pub?('http://'+pub):'#');
    const el=document.createElement('div'); el.className='tun';
    el.innerHTML='<div><div><strong>'+name+'</strong> <span class="badge">'+type+'</span></div><div class="muted">'+(pub||'path /'+slug+'/'+name+'/')+'</div></div>';
    if(type==='http'){
      const a=document.createElement('a'); a.className='btn'; a.href=href; a.target='_blank'; a.textContent='打开';
      el.appendChild(a);
    }
    box.appendChild(el);
  }
}
function logout(){
  localStorage.removeItem(keyStore);
  document.cookie='ip_access_key=; Path=/; Max-Age=0';
  $('loginCard').hidden=false; $('meCard').hidden=$('regionCard').hidden=$('tunCard').hidden=true;
  $('apiKey').value='';
}
$('btnLogin').onclick=login;
$('btnClear').onclick=()=>{$('apiKey').value='';$('email').value='';$('password').value='';};
$('btnRefresh').onclick=load;
$('btnLogout').onclick=logout;
if(localStorage.getItem(keyStore)){ $('apiKey').value=localStorage.getItem(keyStore); load(); }
</script>
</body>
</html>
`

func (s *Server) mountAccessClient(mux *http.ServeMux) {
	mux.HandleFunc("/access", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/access/", http.StatusFound)
	})
	mux.HandleFunc("/access/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/access/" && r.URL.Path != "/access" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(accessClientHTML))
	})
}

// pathReserved returns true for gateway-owned first path segments.
func pathReserved(slug string) bool {
	switch strings.ToLower(slug) {
	case "healthz", "api", "dashboard", "internal", "access", "metrics", "agent":
		return true
	default:
		return false
	}
}
