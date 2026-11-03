'use strict';
/* ============ ZeusVPN App ============ */
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const LS_KEY = 'zeusvpn_v1';
const state = { servers: [], subs: [] };

function load(){ try{ const d = JSON.parse(localStorage.getItem(LS_KEY) || '{}'); state.servers = d.servers || []; state.subs = d.subs || []; }catch(e){} }
function save(){ localStorage.setItem(LS_KEY, JSON.stringify({ servers: state.servers, subs: state.subs })); }
const uid = () => Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

/* ---------- base64 helpers ---------- */
function b64ToUtf8(b64){
  let b = String(b64).trim().replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
  while (b.length % 4) b += '=';
  const bin = atob(b);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}
function utf8ToB64Url(str){
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (const x of bytes) bin += String.fromCharCode(x);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function looksB64(t){ t = t.trim(); return t.length > 8 && !t.includes('://') && /^[A-Za-z0-9+/\-_=\s]+$/.test(t); }

/* ---------- parsers ---------- */
function parseVmess(raw){
  try{
    const j = JSON.parse(b64ToUtf8(raw.slice(8)));
    if (!j.add) return null;
    return { proto:'vmess', name: j.ps || j.remarks || j.add, host: String(j.add), port: +j.port || 443,
      net: j.net || 'tcp', tls: j.tls === 'tls' ? 'tls' : 'none', sni: j.sni || j.host || '', fp: j.fp || '',
      path: j.path || '', hostHeader: j.host || '', uuid: j.id || '', aid: j.aid ?? 0, scy: j.scy || 'auto', raw };
  }catch(e){ return null; }
}
function urlParts(raw){
  try{
    const u = new URL(raw);
    const name = decodeURIComponent(u.hash.slice(1)) || u.hostname;
    return { u, q: u.searchParams, user: decodeURIComponent(u.username || ''), pass: decodeURIComponent(u.password || ''),
      name, host: u.hostname, port: +u.port };
  }catch(e){ return null; }
}
function parseVless(raw){
  const p = urlParts(raw); if (!p || !p.host) return null; const q = p.q;
  return { proto:'vless', name:p.name, host:p.host, port:p.port || 443, net:q.get('type') || 'tcp',
    tls:q.get('security') || 'none', sni:q.get('sni') || '', fp:q.get('fp') || '', path:q.get('path') || '',
    hostHeader:q.get('host') || '', uuid:p.user, flow:q.get('flow') || '', pbk:q.get('pbk') || '', raw };
}
function parseTrojan(raw){
  const p = urlParts(raw); if (!p || !p.host) return null; const q = p.q;
  return { proto:'trojan', name:p.name, host:p.host, port:p.port || 443, net:q.get('type') || 'tcp', tls:'tls',
    sni:q.get('sni') || '', fp:q.get('fp') || '', path:q.get('path') || '', hostHeader:q.get('host') || '',
    password:p.user, raw };
}
function parseHy2(raw){
  const p = urlParts(raw); if (!p || !p.host) return null; const q = p.q;
  return { proto:'hy2', name:p.name, host:p.host, port:p.port || 443, net:'udp', tls:'tls',
    sni:q.get('sni') || '', auth:p.user || p.pass || '', raw };
}
function parseTuic(raw){
  const p = urlParts(raw); if (!p || !p.host) return null; const q = p.q;
  return { proto:'tuic', name:p.name, host:p.host, port:p.port || 443, net:'udp', tls:'tls',
    sni:q.get('sni') || '', uuid:p.user, password:p.pass, raw };
}
function splitHostPort(hp){
  hp = hp.trim();
  if (hp.startsWith('[')){ const e = hp.indexOf(']'); return [hp.slice(1, e), hp.slice(e + 2)]; }
  const k = hp.lastIndexOf(':'); return k > -1 ? [hp.slice(0, k), hp.slice(k + 1)] : [hp, ''];
}
function parseSS(raw){
  try{
    let rest = raw.slice(5), name = '', query = '';
    const hi = rest.indexOf('#'); if (hi > -1){ name = decodeURIComponent(rest.slice(hi + 1)); rest = rest.slice(0, hi); }
    const qi = rest.indexOf('?'); if (qi > -1){ query = rest.slice(qi + 1); rest = rest.slice(0, qi); }
    let method, pass, host, port;
    if (rest.includes('@')){
      const ai = rest.lastIndexOf('@'), info = rest.slice(0, ai), hp = rest.slice(ai + 1);
      if (info.includes(':')){ const k = info.indexOf(':'); method = decodeURIComponent(info.slice(0, k)); pass = decodeURIComponent(info.slice(k + 1)); }
      else { const dec = b64ToUtf8(info); const k = dec.indexOf(':'); method = dec.slice(0, k); pass = dec.slice(k + 1); }
      [host, port] = splitHostPort(hp);
    } else {
      const dec = b64ToUtf8(rest);
      const m = dec.match(/^([^:]+):([^@]*)@(.+)$/); if (!m) return null;
      method = m[1]; pass = m[2]; [host, port] = splitHostPort(m[3]);
    }
    if (!host || !method) return null;
    return { proto:'ss', name: name || host, host, port: +port || 443, method, pass, net:'tcp', tls:'none', plugin: query, raw };
  }catch(e){ return null; }
}
function parseLink(raw){
  raw = raw.trim();
  if (raw.startsWith('vmess://')) return parseVmess(raw);
  if (raw.startsWith('vless://')) return parseVless(raw);
  if (raw.startsWith('trojan://')) return parseTrojan(raw);
  if (raw.startsWith('ss://')) return parseSS(raw);
  if (raw.startsWith('hysteria2://') || raw.startsWith('hy2://')) return parseHy2(raw);
  if (raw.startsWith('tuic://')) return parseTuic(raw);
  return null;
}

/* ---------- import ---------- */
function importText(text, silent){
  const lines = String(text).split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  let added = 0, dup = 0, bad = 0;
  for (const l of lines){
    if (state.servers.some(s => s.raw === l)){ dup++; continue; }
    const s = parseLink(l);
    if (s){ s.id = uid(); s.status = ''; s.ms = null; state.servers.push(s); added++; } else bad++;
  }
  save(); render(); updateStats();
  if (!silent) toast(`⚡ ${added} کانفیگ اضافه شد` + (dup ? ` · ${dup} تکراری` : '') + (bad ? ` · ${bad} نامعتبر` : ''));
  return added;
}
async function importSub(url){
  toast('در حال دریافت اشتراک...', 99999);
  const txt = await fetchSub(url);
  if (!txt){ toast('❌ دریافت اشتراک ناموفق بود — CORS یا لینک اشتباه'); return; }
  let body = txt.trim();
  if (looksB64(body)){ try{ body = b64ToUtf8(body); }catch(e){} }
  if (!state.subs.includes(url)){ state.subs.push(url); save(); }
  const n = importText(body, true);
  toast(n ? `📡 اشتراک دریافت شد — ${n} کانفیگ اضافه شد` : '⚠️ اشتراک خالی بود یا قابل خواندن نبود');
}
async function fetchSub(url){
  const tries = [
    url,
    'https://api.allorigins.win/raw?url=' + encodeURIComponent(url),
    'https://corsproxy.io/?url=' + encodeURIComponent(url)
  ];
  for (const t of tries){
    try{
      const r = await fetch(t, { cache:'no-store' });
      if (!r.ok) continue;
      const txt = await r.text();
      if (txt && txt.trim()) return txt;
    }catch(e){}
  }
  return null;
}

/* ---------- render ---------- */
function render(){
  const list = $('#srvList'), filter = ($('#inFilter').value || '').toLowerCase();
  const items = state.servers.filter(s =>
    !filter || (s.name + ' ' + s.host + ' ' + s.proto).toLowerCase().includes(filter));
  $('#emptyState').style.display = state.servers.length ? 'none' : '';
  list.innerHTML = items.map(srvHTML).join('');
  $$('.srv [data-act]').forEach(btn => btn.addEventListener('click', onSrvAction));
}
function statusHTML(s){
  if (s.status === 'testing') return `<span class="status testing"><span class="sdot"></span>در حال تست…</span>`;
  if (s.status === 'ok') return `<span class="status ok"><span class="sdot"></span>آنلاین ${s.ms != null ? s.ms + 'ms' : ''}</span>`;
  if (s.status === 'bad') return `<span class="status bad"><span class="sdot"></span>پاسخی نبود</span>`;
  return `<span class="status"><span class="sdot"></span>تست نشده</span>`;
}
function srvHTML(s){
  const net = s.net ? ` · ${esc(s.net)}` : '';
  const tls = s.tls === 'tls' ? ' · TLS' : '';
  return `<div class="srv" data-id="${s.id}">
    <div class="head">
      <span class="proto ${esc(s.proto)}">${esc(s.proto.toUpperCase())}</span>
      <span class="name" title="${esc(s.name)}">${esc(s.name)}</span>
    </div>
    <div class="meta">
      <span class="m">📍 <b>${esc(s.host)}:${s.port}</b></span>
      <span class="m">🌐 <b>${esc((s.net || 'tcp') + (s.tls === 'tls' ? ' + tls' : ''))}</b>${s.sni ? ` · SNI: <b>${esc(s.sni)}</b>` : ''}</span>
      <span class="m">${statusHTML(s)}</span>
    </div>
    <div class="foot">
      <button class="btn small primary" data-act="open">🚀 اتصال</button>
      <button class="btn small ghost" data-act="test">📶 تست</button>
      <button class="btn small ghost" data-act="qr">🔳 QR</button>
      <button class="btn small ghost" data-act="copy">📋 کپی</button>
      <button class="btn small ghost" data-act="json">🧾 JSON</button>
      <button class="btn small danger" data-act="del">🗑</button>
    </div>
  </div>`;
}
function onSrvAction(e){
  const id = e.currentTarget.closest('.srv').dataset.id;
  const s = state.servers.find(x => x.id === id); if (!s) return;
  switch (e.currentTarget.dataset.act){
    case 'open': openModal(s); break;
    case 'test': testOne(s); break;
    case 'qr': openModal(s); break;
    case 'copy': copy(s.raw, 'لینک کپی شد ✅'); break;
    case 'json': copyJSON(s); break;
    case 'del': state.servers = state.servers.filter(x => x.id !== id); save(); render(); updateStats(); toast('حذف شد 🗑'); break;
  }
}
function updateStats(){
  $('#stTotal').textContent = state.servers.length;
  $('#stOnline').textContent = state.servers.filter(s => s.status === 'ok').length;
  $('#stProtos').textContent = new Set(state.servers.map(s => s.proto)).size;
  $('#hdStat').textContent = state.servers.length ? `${state.servers.length} کانفیگ فعال` : 'آماده⚡';
}

/* ---------- connectivity tests (real) ---------- */
function wsTest(s){
  return new Promise(res => {
    if (!('WebSocket' in window)) return res(null);
    let done = false; const t0 = performance.now();
    let ws;
    try{ ws = new WebSocket(`wss://${s.host}:${s.port}${s.path || '/'}`); }catch(e){ return res(null); }
    const to = setTimeout(() => { if (!done){ done = true; try{ ws.close(); }catch(e){} res({ ok:false, ms: Math.round(performance.now() - t0) }); } }, 6000);
    ws.onopen = () => { if (!done){ done = true; clearTimeout(to); try{ ws.close(); }catch(e){} res({ ok:true, ms: Math.round(performance.now() - t0) }); } };
    ws.onerror = () => { if (!done){ done = true; clearTimeout(to); res({ ok:false, ms: Math.round(performance.now() - t0) }); } };
  });
}
async function testOne(s){
  s.status = 'testing'; render();
  const t0 = performance.now();
  let httpOk = false;
  try{
    await fetch(`https://${s.host}:${s.port}/`, { mode:'no-cors', cache:'no-store', signal: AbortSignal.timeout(6000) });
    httpOk = true;
  }catch(e){}
  const wsRes = (s.net === 'ws' && s.tls === 'tls') ? await wsTest(s) : null;
  if (httpOk || (wsRes && wsRes.ok)){ s.status = 'ok'; s.ms = wsRes && wsRes.ok ? wsRes.ms : Math.round(performance.now() - t0); }
  else { s.status = 'bad'; s.ms = null; }
  save(); render(); updateStats();
}
async function testAll(){
  if (!state.servers.length) return toast('اول کانفیگ اضافه کن 🙂');
  toast('در حال تست همه سرورها…', 99999);
  for (const s of [...state.servers]){ await testOne(s); await new Promise(r => setTimeout(r, 250)); }
  const ok = state.servers.filter(s => s.status === 'ok').length;
  toast(`✅ تست تمام شد — ${ok} از ${state.servers.length} سرور پاسخ داد`);
}

/* ---------- exports / deep links ---------- */
function deepLinks(s){
  const enc = encodeURIComponent, b = utf8ToB64Url(s.raw);
  return [
    { app:'⚡ Happ', url:`happ://import/${b}` },
    { app:'📦 V2Box', url:`v2box://install-sub?url=${enc(s.raw)}` },
    { app:'🟢 v2rayNG', url:s.raw },
    { app:'🟣 Hiddify', url:`hiddify://import/${enc(s.raw)}` },
    { app:'🍏 Streisand (iOS)', url:`streisand://import/${enc(s.raw)}` },
    { app:'🌐 باز کردن در مرورگر', url:s.raw }
  ];
}
function subDeepLinks(url){
  const enc = encodeURIComponent, b = utf8ToB64Url(url);
  return [
    { app:'⚡ Happ', url:`happ://add/${url}` },
    { app:'📦 V2Box', url:`v2box://install-sub?url=${enc(url)}` },
    { app:'🟢 v2rayNG', url:`v2rayng://install-config/?url=${enc(url)}` },
    { app:'🟣 Hiddify', url:`hiddify://import/${enc(url)}` }
  ];
}
function toOutbound(s){
  const stream = { network: s.net === 'udp' ? 'tcp' : (s.net || 'tcp'), security: s.tls === 'tls' ? 'tls' : 'none' };
  if (s.tls === 'tls') stream.tlsSettings = { allowInsecure:true, serverName: s.sni || s.host, ...(s.fp ? { fingerprint: s.fp } : {}) };
  if (stream.network === 'ws') stream.wsSettings = { path: s.path || '/', ...(s.hostHeader ? { headers:{ Host: s.hostHeader } } : {}) };
  if (stream.network === 'grpc') stream.grpcSettings = { serviceName: s.path || '' };
  const base = { tag: s.name || s.proto, streamSettings: stream };
  switch (s.proto){
    case 'vmess': return { ...base, protocol:'vmess', settings:{ vnext:[{ address:s.host, port:s.port,
      users:[{ id:s.uuid, alterId:+s.aid || 0, security:s.scy || 'auto' }] }] } };
    case 'vless': return { ...base, protocol:'vless', settings:{ vnext:[{ address:s.host, port:s.port,
      users:[{ id:s.uuid, encryption:'none', flow:s.flow || '' }] }] } };
    case 'trojan': return { ...base, protocol:'trojan', settings:{ servers:[{ address:s.host, port:s.port, password:s.password }] } };
    case 'ss': return { ...base, protocol:'shadowsocks', settings:{ servers:[{ address:s.host, port:s.port, method:s.method, password:s.pass }] } };
    default: return null;
  }
}
function copyJSON(s){
  const o = toOutbound(s);
  if (!o) return toast('⚠️ برای این پروتکل JSON نداریم — لینک خام را کپی کن');
  copy(JSON.stringify(o, null, 2), 'JSON کپی شد 🧾');
}
function exportSub(){
  if (!state.servers.length) return toast('چیزی برای خروجی گرفتن نیست');
  const b64 = btoa(String.fromCharCode(...new TextEncoder().encode(state.servers.map(s => s.raw).join('\n'))));
  download('zeusvpn-subscription.txt', b64);
  toast('فایل اشتراک (Base64) دانلود شد 📤');
}
function exportJSON(){
  const out = state.servers.map(toOutbound).filter(Boolean);
  if (!out.length) return toast('پروتکل قابل خروجی JSON پیدا نشد');
  download('zeusvpn-config.json', JSON.stringify({ outbounds: out, remarks: 'ZeusVPN' }, null, 2));
  toast('فایل JSON دانلود شد 🧾');
}
function download(name, text){
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type:'text/plain' }));
  a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

/* ---------- modal / QR ---------- */
let modalRaw = '';
function openModal(s){
  modalRaw = s.raw;
  $('#qrTitle').textContent = s.name || 'کانفیگ';
  const box = $('#qrbox'); box.innerHTML = '';
  try{ new QRCode(box, { text: s.raw, width: 224, height: 224, colorDark: '#1e0b38', colorLight: '#ffffff', correctLevel: QRCode.CorrectLevel.M }); }
  catch(e){ box.innerHTML = '<small style="color:#333">QR در دسترس نیست</small>'; }
  $('#appLinks').innerHTML = deepLinks(s).map(l =>
    `<a class="btn ghost" href="${esc(l.url)}">${esc(l.app)}</a>`).join('');
  $('#qrModal').classList.add('open');
}
function openSubModal(url){
  modalRaw = url;
  $('#qrTitle').textContent = 'اشتراک: ' + url.slice(0, 40) + '…';
  const box = $('#qrbox'); box.innerHTML = '';
  try{ new QRCode(box, { text: url, width: 224, height: 224, colorDark: '#1e0b38', colorLight: '#ffffff', correctLevel: QRCode.CorrectLevel.M }); }
  catch(e){ box.innerHTML = '<small style="color:#333">QR در دسترس نیست</small>'; }
  $('#appLinks').innerHTML = subDeepLinks(url).map(l =>
    `<a class="btn ghost" href="${esc(l.url)}">${esc(l.app)}</a>`).join('');
  $('#qrModal').classList.add('open');
}
$('#btnCloseModal').addEventListener('click', () => $('#qrModal').classList.remove('open'));
$('#qrModal').addEventListener('click', e => { if (e.target === $('#qrModal')) $('#qrModal').classList.remove('open'); });
$('#btnCopyRaw').addEventListener('click', () => copy(modalRaw, 'لینک کپی شد ✅'));

/* ---------- clipboard ---------- */
async function copy(text, msg){
  try{ await navigator.clipboard.writeText(text); toast(msg); }
  catch(e){
    const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta);
    ta.select(); try{ document.execCommand('copy'); toast(msg); }catch(_){ toast('کپی نشد — دستی کپی کن'); }
    ta.remove();
  }
}

/* ---------- toast ---------- */
let toastTimer;
function toast(msg, ms){
  const t = $('#toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), ms && ms !== 99999 ? ms : 2600);
}

/* ---------- UI wiring ---------- */
$$('.tab').forEach(t => t.addEventListener('click', () => {
  $$('.tab').forEach(x => x.classList.remove('active')); t.classList.add('active');
  $$('.pane').forEach(p => p.hidden = true);
  $('#pane-' + t.dataset.tab).hidden = false;
}));
$('#btnAdd').addEventListener('click', () => {
  const v = $('#taLinks').value.trim();
  if (!v) return toast('اول لینک کانفیگ بچسبان 🙂');
  const n = importText(v); if (n) $('#taLinks').value = '';
});
$('#btnFile').addEventListener('click', () => $('#fileImport').click());
$('#fileImport').addEventListener('change', e => {
  const f = e.target.files[0]; if (!f) return;
  const r = new FileReader();
  r.onload = () => importText(r.result);
  r.readAsText(f); e.target.value = '';
});
$('#btnSub').addEventListener('click', () => {
  const u = $('#inSub').value.trim();
  if (!/^https?:\/\//.test(u)) return toast('لینک اشتراک معتبر نیست');
  importSub(u);
});
$('#btnB64').addEventListener('click', () => {
  const v = $('#taB64').value.trim(); if (!v) return toast('متن Base64 خالیه');
  try{ importText(b64ToUtf8(v)); $('#taB64').value = ''; }
  catch(e){ toast('❌ Base64 معتبر نبود'); }
});
$('#inFilter').addEventListener('input', render);
$('#btnTestAll').addEventListener('click', testAll);
$('#btnExpSub').addEventListener('click', exportSub);
$('#btnExpJson').addEventListener('click', exportJSON);

let clearArm = false, clearTimer;
$('#btnClear').addEventListener('click', () => {
  if (!state.servers.length) return toast('لیست خالیه');
  if (!clearArm){
    clearArm = true; $('#btnClear').textContent = '⚠️ مطمئنی؟ دوباره بزن';
    clearTimer = setTimeout(() => { clearArm = false; $('#btnClear').textContent = '🗑 پاک‌سازی همه'; }, 3000);
    return;
  }
  clearTimeout(clearTimer); clearArm = false;
  $('#btnClear').textContent = '🗑 پاک‌سازی همه';
  state.servers = []; state.subs = []; save(); render(); updateStats(); toast('همه پاک شد 🗑');
});

/* drag & drop */
document.addEventListener('dragover', e => e.preventDefault());
document.addEventListener('drop', e => {
  e.preventDefault();
  const f = e.dataTransfer.files[0];
  if (f){ const r = new FileReader(); r.onload = () => importText(r.result); r.readAsText(f); }
  else { const t = e.dataTransfer.getData('text'); if (t) importText(t); }
});

/* ---------- boot ---------- */
load(); render(); updateStats();
if ('serviceWorker' in navigator && location.protocol === 'https:'){
  navigator.serviceWorker.register('./sw.js').catch(() => {});
}
