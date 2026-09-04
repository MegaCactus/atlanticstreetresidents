import { EmailMessage } from "cloudflare:email";

// Bindings expected: DB (KV), EMAIL (send_email), OWNER_EMAIL, FROM_EMAIL, SITE_ORIGIN, API_ORIGIN

const CATS = ["water","hvac","elev","win","fire","amen","garage","pm","clean","you","other"];
const ORIGINS = ["https://atlanticstreetresidents.com","http://atlanticstreetresidents.com","https://www.atlanticstreetresidents.com","http://www.atlanticstreetresidents.com","http://localhost:8125"];

export default {
  async fetch(request, env, ctx) {
    try { return await route(request, env, ctx); }
    catch (e) { return json({ ok: false, error: String(e && e.message || e) }, 500, request); }
  },
  async email(message, env, ctx) {
    try { await ingestEmail(message, env); }
    catch (e) { console.log("ingest failed: " + (e && e.message) + " " + (e && e.stack)); }
    try { await message.forward(env.OWNER_EMAIL); } catch (e) { console.log("forward failed: " + (e && e.message)); }
  }
};

// ---------- helpers ----------
function cors(request) {
  const o = request.headers.get("Origin") || "";
  const allow = ORIGINS.includes(o) ? o : ORIGINS[0];
  return { "Access-Control-Allow-Origin": allow, "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type", "Vary": "Origin" };
}
function json(obj, status, request, extra) {
  return new Response(JSON.stringify(obj), { status: status || 200, headers: Object.assign({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }, request ? cors(request) : {}, extra || {}) });
}
function html(body, status, extra) {
  return new Response(body, { status: status || 200, headers: Object.assign({ "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }, extra || {}) });
}
function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
function id() { return Date.now().toString(36) + "-" + crypto.randomUUID().slice(0, 8); }
function todayNY(date) {
  const d = date || new Date();
  const p = new Intl.DateTimeFormat("en-CA", { timeZone: "America/New_York", year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(d);
  const g = k => p.find(x => x.type === k).value;
  return g("year") + "-" + g("month") + "-" + g("day");
}
function b64url(buf) { return btoa(String.fromCharCode.apply(null, new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function unb64url(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }

async function getKey(env) {
  let hex = await env.DB.get("sys:key");
  if (!hex) {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    hex = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
    await env.DB.put("sys:key", hex);
  }
  return crypto.subtle.importKey("raw", unhex(hex), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
function unhex(h) { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
async function sign(env, payload) {
  const key = await getKey(env);
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = b64url(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body)));
  return body + "." + sig;
}
async function verify(env, token) {
  if (!token || token.indexOf(".") < 0) return null;
  const [body, sig] = token.split(".");
  const key = await getKey(env);
  const ok = await crypto.subtle.verify("HMAC", key, unb64url(sig), new TextEncoder().encode(body));
  if (!ok) return null;
  const payload = JSON.parse(new TextDecoder().decode(unb64url(body)));
  if (payload.exp && Date.now() > payload.exp) return null;
  return payload;
}
async function readList(env, k) { const v = await env.DB.get(k, "json"); return Array.isArray(v) ? v : []; }
async function writeList(env, k, list) { await env.DB.put(k, JSON.stringify(list)); }

async function sendMail(env, subject, text) {
  if (!env.EMAIL || !env.OWNER_EMAIL) return;
  subject = subject.replace(/[\r\n]/g, " ");
  try { await env.EMAIL.send({ from: env.FROM_EMAIL, to: env.OWNER_EMAIL, subject: subject, text: text }); return; }
  catch (e) { console.log("email service send failed, trying legacy: " + (e && e.message)); }
  const raw = "From: 355 Atlantic tracker <" + env.FROM_EMAIL + ">\r\nTo: " + env.OWNER_EMAIL + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + text;
  await env.EMAIL.send(new EmailMessage(env.FROM_EMAIL, env.OWNER_EMAIL, raw));
}

// ---------- routing ----------
async function route(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(request) });

if (path === "/") return json({ ok: true, service: "355 Atlantic residents API" }, 200, request);
  if (path === "/incidents" && request.method === "GET") {
    const pub = await env.DB.get("pub", "json");
    return json(pub || { incidents: [], reports: [] }, 200, request, { "Cache-Control": "public, max-age=60" });
  }
  if (path.startsWith("/img/") && request.method === "GET") {
    const key = "img:" + path.slice(5).replace(/[^a-z0-9-]/gi, "");
    const { value, metadata } = await env.DB.getWithMetadata(key, "arrayBuffer");
    if (!value) return new Response("Not found", { status: 404 });
    return new Response(value, { headers: { "Content-Type": (metadata && metadata.ct) || "image/jpeg", "Cache-Control": "public, max-age=31536000, immutable", "Access-Control-Allow-Origin": "*" } });
  }
  if (path === "/submit" && request.method === "POST") return submit(request, env);
  if (path === "/a" && request.method === "GET") return actFromLink(url, env);
  if (path === "/admin") return admin(request, env);
  if (path === "/admin/login" && request.method === "POST") return adminLogin(request, env);
  if (path === "/admin/auth") return adminAuth(url, env);
  if (path === "/admin/list") return adminList(request, env);
  if (path === "/admin/act" && request.method === "POST") return adminAct(request, env);
  return json({ ok: false, error: "Not found" }, 404, request);
}

// ---------- submissions ----------
async function submit(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "0";
  const hour = new Date().toISOString().slice(0, 13);
  const rlKey = "rl:" + ip + ":" + hour;
  const count = parseInt((await env.DB.get(rlKey)) || "0", 10);
  if (count >= 8) return json({ ok: false, error: "Too many submissions from this connection. Try again in an hour." }, 429, request);
  await env.DB.put(rlKey, String(count + 1), { expirationTtl: 3600 });

let body;
  try { body = await request.json(); } catch (e) { return json({ ok: false, error: "The submission could not be read." }, 400, request); }
  if (body.website) return json({ ok: true, id: "ok" }, 200, request); // honeypot

const kind = body.kind === "report" ? "report" : "ticket";
  const text = String(body.text || "").trim().slice(0, 2000);
  if (text.length < 10) return json({ ok: false, error: "Add a short description (at least 10 characters)." }, 400, request);

const imgs = [];
  const list = Array.isArray(body.images) ? body.images.slice(0, 3) : [];
  for (const dataUrl of list) {
    const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(dataUrl || ""));
    if (!m) continue;
    const bytes = Uint8Array.from(atob(m[2]), c => c.charCodeAt(0));
    if (bytes.length > 1500000) return json({ ok: false, error: "A photo is too large after compression. Try a smaller one." }, 400, request);
    const iid = id();
    await env.DB.put("img:" + iid, bytes, { metadata: { ct: m[1] } });
    imgs.push(iid);
  }

const item = { id: id(), kind: kind, at: new Date().toISOString(), status: "pending", img: imgs, ip: ip.slice(0, 64) };
  if (kind === "ticket") {
    item.c = "you"; item.t = "R";
    item.cat = CATS.includes(body.cat) ? body.cat : "other";
    item.s = String(body.title || "").trim().slice(0, 140) || text.slice(0, 80);
    item.x = text;
    item.w = cleanFloors(body.where);
    item.d = cleanDate(body.date) || todayNY();
    item.m = false;
  } else {
    item.title = String(body.title || "").trim().slice(0, 140) || text.slice(0, 80);
    item.text = text;
    item.where = cleanFloors(body.where);
    item.cat = CATS.includes(body.cat) ? body.cat : "other";
    item.d = cleanDate(body.date) || todayNY();
    item.anon = body.anon !== false;
    item.name = item.anon ? "" : String(body.name || "").trim().slice(0, 60);
  }
  item.contact = String(body.contact || "").trim().slice(0, 120);
  item.stack = cleanStack(body.stack);

const pend = await readList(env, "pend");
  pend.unshift(item);
  await writeList(env, "pend", pend);

try {
  const approve = env.API_ORIGIN + "/a?id=" + item.id + "&act=approve&t=" + encodeURIComponent(await sign(env, { p: "act", id: item.id, act: "approve", exp: Date.now() + 30 * 86400000 }));
  const reject = env.API_ORIGIN + "/a?id=" + item.id + "&act=reject&t=" + encodeURIComponent(await sign(env, { p: "act", id: item.id, act: "reject", exp: Date.now() + 30 * 86400000 }));
  const photos = imgs.map(i => env.API_ORIGIN + "/img/" + i).join("\n");
  await sendMail(env, "[Review] New " + kind + ": " + (item.s || item.title),
                 "A new " + kind + " is waiting for review.\n\nWhat: " + (item.s || item.title) + "\nWhere: " + (item.w || item.where) + (item.stack ? " (" + item.stack + " line)" : "") + "\nDate: " + item.d + "\nCategory: " + item.cat + (kind === "report" ? "\nBy: " + (item.anon ? "anonymous" : item.name || "(no name)") : "") + (item.contact ? "\nContact: " + item.contact : "") + "\n\n" + text + "\n\nPhotos:\n" + (photos || "none") + "\n\nApprove: " + approve + "\nReject: " + reject + "\n\nOr open the review page: " + env.API_ORIGIN + "/admin\n");
} catch (e) { console.log("notify failed: " + (e && e.message)); }

return json({ ok: true, id: item.id }, 200, request);
}
function cleanFloors(v) {
  v = String(v || "").trim().slice(0, 40);
  const allowed = ["Floors 6–16", "Floors 17–26", "Whole building", "Garage", "Amenities", "Exterior", "Lobby", "All units", "Upper floors"];
  if (allowed.includes(v)) return v;
  if (/^Floors \d{1,2}–(\d{1,2}|P2)$/.test(v) || /^\d{1,2}(st|nd|rd|th) floor$/.test(v)) return v;
  return "Upper floors";
}
function cleanStack(v) { v = String(v || "").trim().toUpperCase().slice(0, 1); return /^[A-HJ-NPRST]$/.test(v) ? v : ""; }
function cleanDate(v) { v = String(v || ""); return /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : (/^\d{4}-\d{2}$/.test(v) ? v : ""); }

// ---------- moderation ----------
async function applyAction(env, itemId, act) {
  const pend = await readList(env, "pend");
  const idx = pend.findIndex(x => x.id === itemId);
  if (idx < 0) return { ok: false, error: "That item is no longer pending." };
  const item = pend[idx];
  pend.splice(idx, 1);
  await writeList(env, "pend", pend);
  if (act === "approve") {
    const pub = (await env.DB.get("pub", "json")) || { incidents: [], reports: [] };
    delete item.ip; delete item.contact;
    item.status = "approved";
    if (item.kind === "ticket") {
      pub.incidents.unshift({ id: item.id, d: item.d, e: "", m: false, c: "you", t: "R", s: item.s, x: item.x, w: item.w, g: item.cat === "water" ? "hotwater" : "", dur: "", src: "ticket", img: item.img, cat: item.cat, stack: item.stack || "" });
    } else if (item.kind === "incident") {
      pub.incidents.unshift({ id: item.id, d: item.d, e: "", c: item.c, t: item.t, s: item.s, x: item.x, w: item.w, g: item.g || "", dur: "", src: "email", via: "resident", copies: item.copies || 1, img: [] });
    } else {
      pub.reports.unshift({ id: item.id, d: item.d, title: item.title, text: item.text, where: item.where, cat: item.cat, img: item.img, anon: item.anon, name: item.name, at: item.at, stack: item.stack || "" });
    }
    await env.DB.put("pub", JSON.stringify(pub));
    return { ok: true, status: "approved" };
  }
  for (const i of item.img || []) await env.DB.delete("img:" + i);
  if (item.kind === "incident" || item.kind === "report") {
    const rej = await readList(env, "rej");
    rej.unshift({ s: item.s || item.title || "", d: item.d, c: item.c || item.cat || "", at: Date.now() });
    await writeList(env, "rej", rej.slice(0, 500));
  }
  return { ok: true, status: "rejected" };
}
async function actFromLink(url, env) {
  const p = await verify(env, url.searchParams.get("t"));
  if (!p || p.p !== "act" || p.id !== url.searchParams.get("id") || p.act !== url.searchParams.get("act")) return html(page("That link is invalid or has expired.", "Open the review page instead: <a href='/admin'>/admin</a>"), 400);
  const r = await applyAction(env, p.id, p.act);
  return html(page(r.ok ? (r.status === "approved" ? "Approved and published." : "Rejected and removed.") : r.error, "<a href='/admin'>Open the review page</a>"));
}
function page(title, bodyHtml) {
  return "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>" + esc(title) + "</title><style>body{font-family:system-ui,sans-serif;max-width:560px;margin:60px auto;padding:0 20px;color:#1B2430}h1{font-size:22px}</style><h1>" + esc(title) + "</h1><p>" + bodyHtml + "</p>";
}
function getCookie(request, name) {
  const c = request.headers.get("Cookie") || "";
  const m = new RegExp("(?:^|; )" + name + "=([^;]*)").exec(c);
  return m ? decodeURIComponent(m[1]) : "";
}
async function isAdmin(request, env) {
  const p = await verify(env, getCookie(request, "asr_admin"));
  return !!(p && p.p === "auth");
}
async function adminLogin(request, env) {
  const t = await sign(env, { p: "auth", exp: Date.now() + 7 * 86400000 });
  await sendMail(env, "[Review] Your login link", "Open this link to review submissions (valid 7 days):\n\n" + env.API_ORIGIN + "/admin/auth?t=" + encodeURIComponent(t) + "\n");
  return html(page("Check your email.", "A login link was sent to the site owner's address. It stays valid for 7 days."));
}
async function adminAuth(url, env) {
  const t = url.searchParams.get("t") || "";
  const p = await verify(env, t);
  if (!p || p.p !== "auth") return html(page("That link is invalid or has expired.", "<a href='/admin'>Request a new one</a>"), 400);
  return new Response(null, { status: 302, headers: { "Location": "/admin", "Set-Cookie": "asr_admin=" + encodeURIComponent(t) + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800" } });
}
async function adminList(request, env) {
  if (!(await isAdmin(request, env))) return json({ ok: false, error: "Not signed in" }, 401);
  const pend = await readList(env, "pend");
  const pub = (await env.DB.get("pub", "json")) || { incidents: [], reports: [] };
  return json({ ok: true, pending: pend, incidents: pub.incidents, reports: pub.reports });
}
async function adminAct(request, env) {
  if (!(await isAdmin(request, env))) return json({ ok: false, error: "Not signed in" }, 401);
  const b = await request.json();
  if (b.action === "approve" || b.action === "reject") {
    if (b.edit) {
      const pend = await readList(env, "pend");
      const it = pend.find(x => x.id === b.id);
      if (it) {
        if (b.edit.s != null) { it.s = String(b.edit.s).slice(0, 140); it.title = it.s; }
        if (b.edit.x != null) { it.x = String(b.edit.x).slice(0, 2000); it.text = it.x; }
        if (b.edit.w != null) { it.w = cleanFloors(b.edit.w); it.where = it.w; }
        if (b.edit.cat != null && CATS.includes(b.edit.cat)) it.cat = b.edit.cat;
        if (b.edit.d != null && cleanDate(b.edit.d)) it.d = cleanDate(b.edit.d);
        await writeList(env, "pend", pend);
      }
    }
    return json(await applyAction(env, b.id, b.action));
  }
  if (b.action === "unpublish") {
    const pub = (await env.DB.get("pub", "json")) || { incidents: [], reports: [] };
    pub.incidents = pub.incidents.filter(x => x.id !== b.id);
    pub.reports = pub.reports.filter(x => x.id !== b.id);
    await env.DB.put("pub", JSON.stringify(pub));
    return json({ ok: true });
  }
  if (b.action === "setEnd") {
    const pub = (await env.DB.get("pub", "json")) || { incidents: [], reports: [] };
    const it = pub.incidents.find(x => x.id === b.id);
    if (it) { it.e = cleanDate(b.e) || ""; if (b.dur != null) it.dur = String(b.dur).slice(0, 60); }
    await env.DB.put("pub", JSON.stringify(pub));
    return json({ ok: true });
  }
  return json({ ok: false, error: "Unknown action" }, 400);
}
async function admin(request, env) {
  if (!(await isAdmin(request, env))) {
    return html("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Review sign-in</title><style>body{font-family:system-ui,sans-serif;max-width:480px;margin:80px auto;padding:0 20px;color:#1B2430}button{font:inherit;padding:10px 16px;border-radius:8px;border:1px solid #1B2430;background:#1B2430;color:#fff;cursor:pointer}</style><h1>Review submissions</h1><p>A login link will be emailed to the site owner's address.</p><form method=post action='/admin/login'><button>Email me a login link</button></form>");
  }
  return html(ADMIN_HTML);
}

const ADMIN_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Review submissions</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#F4F6F8;color:#1B2430}
header{background:#16202B;color:#fff;padding:14px 20px;font-weight:600;display:flex;justify-content:space-between;align-items:center}
header a{color:#cbd5e1;text-decoration:none;font-weight:400;font-size:14px}
main{max-width:920px;margin:0 auto;padding:20px}
h2{font-size:18px;margin:26px 0 10px}
.item{background:#fff;border:1px solid #D8DDE3;border-radius:10px;padding:16px;margin:0 0 14px;display:grid;grid-template-columns:1fr 200px;gap:16px}
.item.pub{grid-template-columns:1fr}
.meta{color:#5D6877;font-size:13px;margin:0 0 8px}
label{display:block;font-size:12px;color:#5D6877;margin:8px 0 3px}
input,select,textarea{font:inherit;font-size:14px;width:100%;box-sizing:border-box;border:1px solid #AEB7C2;border-radius:6px;padding:6px 8px;background:#fff}
textarea{min-height:80px}
.row{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap}
button{font:inherit;font-size:14px;padding:8px 14px;border-radius:8px;border:1px solid #1B2430;background:#1B2430;color:#fff;cursor:pointer}
button.secondary{background:#fff;color:#1B2430}
button.danger{background:#fff;color:#B91C1C;border-color:#B91C1C}
.thumbs img{width:100%;border-radius:8px;margin-bottom:8px;display:block}
.empty{color:#5D6877;padding:20px 0}
.ok{color:#15803D}
</style></head><body>
<header><span>Review submissions</span><a href="/">API</a></header>
<main>
<h2>Waiting for review <span id="pc"></span></h2>
<div id="pending"></div>
<h2>Published from residents</h2>
<div id="published"></div>
</main>
<script>
var CATS={water:"Hot water & plumbing",hvac:"Heating & cooling",elev:"Elevators",win:"Windows & exterior",fire:"Fire & life safety",amen:"Amenities & systems",garage:"Garage & common areas",pm:"Preventive maintenance",clean:"Cleaning",you:"Resident tickets",other:"Other"};
var WHERE=["Upper floors","Floors 6–16","Floors 17–26","Whole building","Garage","Amenities","Exterior","Lobby"];
function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
function opt(list,sel){return Object.keys(list).map(function(k){return '<option value="'+k+'"'+(k===sel?' selected':'')+'>'+esc(list[k])+'</option>';}).join("");}
function wopt(sel){return WHERE.map(function(w){return '<option'+(w===sel?' selected':'')+'>'+esc(w)+'</option>';}).join("");}
function load(){
fetch("/admin/list").then(function(r){return r.json();}).then(function(d){
if(!d.ok){location.href="/admin";return;}
document.getElementById("pc").textContent="("+d.pending.length+")";
var p=document.getElementById("pending");
p.innerHTML=d.pending.length?d.pending.map(card).join(""):'<p class="empty">Nothing waiting. New submissions also arrive by email with one-click links.</p>';
var pub=document.getElementById("published");
var items=d.incidents.filter(function(x){return x.src==="ticket"||x.via==="resident";}).concat(d.reports);
pub.innerHTML=items.length?items.map(pubCard).join(""):'<p class="empty">Nothing published from residents yet.</p>';
});
}
function card(it){
var kind=it.kind==="report"?"Report":(it.kind==="incident"?"Forwarded notice":"Ticket");
var who=it.kind==="report"?(it.anon?"anonymous":(it.name||"no name")):"";
return '<div class="item" data-id="'+it.id+'"><div>'+
'<p class="meta">'+kind+(who?" from "+esc(who):"")+' filed '+esc(it.at.slice(0,16).replace("T"," "))+(it.stack?' from the '+esc(it.stack)+' line':'')+(it.contact?' (from: '+esc(it.contact)+')':'')+(it.copies>1?' \u00b7 forwarded by '+it.copies+' people':'')+(it.note?'<br>Note from sender: '+esc(it.note):'')+'</p>'+
'<label>Title</label><input name="s" value="'+esc(it.s||it.title)+'">'+
'<label>Description</label><textarea name="x">'+esc(it.x||it.text)+'</textarea>'+
'<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px"><div><label>Category</label><select name="cat">'+opt(CATS,it.cat)+'</select></div><div><label>Where</label><select name="w">'+wopt(it.w||it.where)+'</select></div><div><label>Date</label><input name="d" value="'+esc(it.d)+'"></div></div>'+
'<div class="row"><button onclick="act(this,\\'approve\\')">Approve and publish</button><button class="danger" onclick="act(this,\\'reject\\')">Reject</button></div>'+
'</div><div class="thumbs">'+(it.img||[]).map(function(i){return '<a href="/img/'+i+'" target="_blank"><img src="/img/'+i+'" alt=""></a>';}).join("")+'</div></div>';
}
function pubCard(it){
return '<div class="item pub" data-id="'+it.id+'"><div><p class="meta">'+esc(it.d)+(it.kind==="report"||it.title?" report":(it.via==="resident"?" forwarded notice":" ticket"))+(it.name?" from "+esc(it.name):"")+(it.copies>1?" (forwarded by "+it.copies+" people)":"")+'</p><strong>'+esc(it.s||it.title)+'</strong><div style="font-size:14px;color:#5D6877;margin-top:4px">'+esc(it.x||it.text)+'</div>'+
(it.title?'':'<div class="row"><label style="margin:0">Ended on</label><input name="e" style="max-width:150px" value="'+esc(it.e||"")+'" placeholder="YYYY-MM-DD"><button class="secondary" onclick="setEnd(this)">Save end date</button></div>')+
'<div class="row"><button class="danger" onclick="unpub(this)">Unpublish</button></div></div></div>';
}
function post(body){return fetch("/admin/act",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}).then(function(r){return r.json();});}
function act(btn,action){
var el=btn.closest(".item"),id=el.dataset.id;
var edit={s:el.querySelector('[name=s]').value,x:el.querySelector('[name=x]').value,cat:el.querySelector('[name=cat]').value,w:el.querySelector('[name=w]').value,d:el.querySelector('[name=d]').value};
btn.disabled=true;
post({action:action,id:id,edit:edit}).then(function(r){ if(!r.ok) alert(r.error||"Failed"); load(); });
}
function unpub(btn){ if(!confirm("Remove this from the public site?")) return; post({action:"unpublish",id:btn.closest(".item").dataset.id}).then(load); }
function setEnd(btn){ var el=btn.closest(".item"); post({action:"setEnd",id:el.dataset.id,e:el.querySelector('[name=e]').value}).then(function(){ btn.textContent="Saved"; }); }
load();
</script></body></html>`;

// ---------- email ingestion ----------
const IGNORE_SENDERS = /noreply@google\.com|forwarding-noreply|mailer-daemon|postmaster@|no-reply@cloudflare|noreply@github|@squarespace\.com|@proton\.me.*notify|noreply@atlanticstreetresidents/i;
const BUILDING = /rentcafe\.com|greystar\.com|bozzuto\.com|atlantic ?station/i;

function trustedList(env) {
  return String(env.TRUSTED_SENDERS || env.OWNER_EMAIL || "").toLowerCase().split(/[,\s]+/).filter(Boolean);
}
function isTrusted(env, parsed, message) {
  const t = trustedList(env);
  if (!t.length) return false;
  const hay = [message.from || "", parsed.from || "", parsed.headers["return-path"] || "", parsed.headers["x-forwarded-for"] || "", parsed.headers["x-original-sender"] || ""].join(" ").toLowerCase();
  return t.some(a => hay.indexOf(a) >= 0);
}
function senderAddress(parsed, message) {
  const m = /<([^>]+)>/.exec(parsed.from || "") || /([^\s<>]+@[^\s<>]+)/.exec(parsed.from || "");
  return (m ? m[1] : (message.from || "")).toLowerCase();
}
// Unwrap a forwarded message (Gmail, Apple Mail, Outlook) into {subject, date, from, body, note}
function extractForwarded(subject, text) {
  const m = /(-{2,}\s*Forwarded message\s*-{2,}|Begin forwarded message:|-{2,}\s*Original Message\s*-{2,}|-{2,}\s*Forwarded by[^\n]*-{2,})/i.exec(text);
  const fwdSubject = /^\s*(fwd?|fw)\s*:/i.test(subject);
  if (!m && !fwdSubject) return null;
  let note = m ? text.slice(0, m.index).trim() : "";
  let rest = m ? text.slice(m.index + m[0].length) : text;
  const out = { subject: cleanSubject(subject), date: null, from: "", body: rest, note: note.slice(0, 300) };
  const lines = rest.split("\n");
  let i = 0, seen = 0;
  while (i < lines.length && i < 14) {
    const l = lines[i].trim();
    if (!l) { if (seen) break; i++; continue; }
    const h = /^(From|Date|Sent|Subject|To|Cc|Reply-To)\s*:\s*(.*)$/i.exec(l);
    if (!h) { if (seen) break; i++; continue; }
    seen++;
    const k = h[1].toLowerCase(), v = h[2].trim();
    if (k === "from") out.from = v;
    else if (k === "subject") out.subject = cleanSubject(v);
    else if (k === "date" || k === "sent") { const d = new Date(v.replace(/ at /i, " ").replace(/\s+\(.*\)$/, "")); if (!isNaN(d.getTime())) out.date = d; }
    i++;
  }
  if (seen) out.body = lines.slice(i).join("\n").trim();
  return out;
}
function norm(s) { return String(s || "").toLowerCase().replace(/^\s*((fwd?|re|fw)\s*:\s*)+/i, "").replace(/[^a-z0-9 ]/g, " ").replace(/\s+/g, " ").trim(); }
function sameEvent(a, b) {
  if (!a || !b) return false;
  if (a.c && b.c && a.c !== b.c) return false;
  if (a.d && b.d && Math.abs(daysBetween(a.d, b.d)) > 1) return false;
  return norm(a.s) === norm(b.s) || similar(a.s || "", b.s || "");
}

async function ingestEmail(message, env) {
  const raw = await new Response(message.raw).text();
  const parsed = parseMime(raw);
  const sender = senderAddress(parsed, message);
  if (IGNORE_SENDERS.test(sender) || IGNORE_SENDERS.test(parsed.from || "")) return;
  const trusted = isTrusted(env, parsed, message);
  const fwd = extractForwarded(parsed.subject, parsed.text);
  const origin = fwd ? fwd : { subject: cleanSubject(parsed.subject), date: parsed.date, from: parsed.from || "", body: parsed.text, note: "" };
  if (!origin.date) origin.date = parsed.date;
  const text = String(origin.body || "").slice(0, 6000);
  const subject = origin.subject || "Building notice";
  const isBuilding = BUILDING.test(origin.from + " " + (parsed.headers["x-forwarded-for"] || "") + " " + text.slice(0, 500)) || BUILDING.test(parsed.from || "");
  const date = origin.date ? todayNY(origin.date) : todayNY();

if (isBuilding) {
  const hay = (subject + " " + text.slice(0, 1200)).toLowerCase();
  const cand = { c: classify(hay), t: typeOf(hay), w: floorsOf(hay, classify(hay)), d: date, s: subject.slice(0, 140), x: firstSentences(text, 300), hay: hay };
  if (trusted) return publishIncident(env, cand);
  return reviewCandidate(env, { kind: "incident", c: cand.c, t: cand.t, w: cand.w, d: cand.d, s: cand.s, x: cand.x, g: (cand.c === "hvac" && /boiler/.test(hay)) ? "hotwater" : "" }, sender, origin.note);
}
  // Not a building notice: a resident (or you) writing directly
const hay2 = (subject + " " + text.slice(0, 1200)).toLowerCase();
  const rep = { kind: "report", title: subject.slice(0, 140), text: firstSentences(text, 1200), where: reportWhere(floorsOf(hay2, classify(hay2))), cat: classify(hay2), d: date, anon: true, name: "", img: [] };
  if (trusted) {
    const pub = (await env.DB.get("pub", "json")) || { incidents: [], reports: [] };
    if (pub.reports.some(r => sameEvent({ s: r.title, d: r.d }, { s: rep.title, d: rep.d }))) return;
    pub.reports.unshift({ id: id(), d: rep.d, title: rep.title, text: rep.text, where: rep.where, cat: rep.cat, img: [], anon: true, name: "", at: new Date().toISOString(), via: "email" });
    await env.DB.put("pub", JSON.stringify(pub));
    return;
  }
  return reviewCandidate(env, rep, sender, "");
}
function reportWhere(w) { return ["Floors 6–16", "Floors 17–26", "Whole building", "Garage", "Amenities", "Exterior", "Lobby"].includes(w) ? w : "Whole building"; }

// Auto-publish a building notice (trusted path): merge restorations and updates, otherwise add a row
async function publishIncident(env, cand) {
  const { c, t, w, d: date, s: subject, x: detail, hay } = cand;
  const pub = (await env.DB.get("pub", "json")) || { incidents: [], reports: [] };
  if (/restored|resolved|back on|is back|has been completed|repairs? (are|is) complete|reopened/i.test(subject) || /has been restored|is now restored|fully restored/i.test(detail)) {
    const open = pub.incidents.find(x => x.c === c && x.t === "U" && !x.e && daysBetween(x.d, date) <= 6);
    if (open) {
      if (open.d !== date) open.e = date;
      open.x = (open.x ? open.x + " " : "") + "Restored: " + subject + " (" + date + ").";
      open.dur = open.dur || (open.d === date ? "same day" : "≈" + daysBetween(open.d, date) + " day" + (daysBetween(open.d, date) === 1 ? "" : "s"));
      await env.DB.put("pub", JSON.stringify(pub));
      return;
    }
  }
  const dup = pub.incidents.find(x => x.c === c && x.src === "email" && Math.abs(daysBetween(x.d, date)) <= 1 && similar(x.s, subject));
  if (dup) {
    if (norm(dup.s) !== norm(subject)) dup.x = (dup.x ? dup.x + " " : "") + "Update " + date + ": " + detail;
    await env.DB.put("pub", JSON.stringify(pub));
    return;
  }
  pub.incidents.unshift({ id: id(), d: date, e: "", c: c, t: t, s: subject.slice(0, 140), x: detail, w: w, g: (c === "hvac" && /boiler/.test(hay)) ? "hotwater" : "", dur: "", src: "email", img: [] });
  await env.DB.put("pub", JSON.stringify(pub));
}

// Untrusted path: create one reviewable event per distinct notice; duplicates only bump a counter
async function reviewCandidate(env, item, sender, note) {
  const key = { s: item.s || item.title, d: item.d, c: item.c || "" };
  const pub = (await env.DB.get("pub", "json")) || { incidents: [], reports: [] };
  const pubMatch = item.kind === "incident"
  ? pub.incidents.find(x => sameEvent({ s: x.s, d: x.d, c: x.c }, key))
    : pub.reports.find(x => sameEvent({ s: x.title, d: x.d }, { s: key.s, d: key.d }));
  if (pubMatch) { pubMatch.copies = (pubMatch.copies || 1) + 1; await env.DB.put("pub", JSON.stringify(pub)); return; }
  const rej = await readList(env, "rej");
  if (rej.some(r => sameEvent({ s: r.s, d: r.d, c: r.c }, key))) return;
  const pend = await readList(env, "pend");
  const pendMatch = pend.find(x => x.kind === item.kind && sameEvent({ s: x.s || x.title, d: x.d, c: x.c || "" }, key));
  if (pendMatch) {
    pendMatch.copies = (pendMatch.copies || 1) + 1;
    if (sender && pendMatch.contact && pendMatch.contact.indexOf(sender) < 0) pendMatch.contact = (pendMatch.contact + ", " + sender).slice(0, 300);
    await writeList(env, "pend", pend);
    return;
  }
  item.id = id(); item.at = new Date().toISOString(); item.status = "pending"; item.img = item.img || []; item.copies = 1;
  item.contact = sender.slice(0, 120); item.note = String(note || "").slice(0, 300); item.stack = ""; item.cat = item.cat || item.c || "other";
  pend.unshift(item);
  await writeList(env, "pend", pend);
  try {
    const approve = env.API_ORIGIN + "/a?id=" + item.id + "&act=approve&t=" + encodeURIComponent(await sign(env, { p: "act", id: item.id, act: "approve", exp: Date.now() + 30 * 86400000 }));
    const reject = env.API_ORIGIN + "/a?id=" + item.id + "&act=reject&t=" + encodeURIComponent(await sign(env, { p: "act", id: item.id, act: "reject", exp: Date.now() + 30 * 86400000 }));
    const what = item.kind === "incident" ? "forwarded notice" : "emailed report";
    await sendMail(env, "[Review] New " + what + ": " + key.s,
                   "A resident emailed a " + what + " that is waiting for review.\n\nFrom: " + sender + (item.note ? "\nTheir note: " + item.note : "") + "\n\nWhat: " + key.s + "\nDate: " + item.d + "\nCategory: " + (item.c || item.cat) + (item.t ? "\nType: " + item.t : "") + "\nWhere: " + (item.w || item.where) + "\n\n" + (item.x || item.text) + "\n\nApprove: " + approve + "\nReject: " + reject + "\n\nIf more residents forward the same notice, it will not create another review; the count is shown on the review page: " + env.API_ORIGIN + "/admin\n");
  } catch (e) { console.log("notify failed: " + (e && e.message)); }
}
function daysBetween(a, b) { return Math.round((Date.parse(b) - Date.parse(a)) / 86400000); }
function similar(a, b) { a = a.toLowerCase().replace(/[^a-z0-9 ]/g, ""); b = b.toLowerCase().replace(/[^a-z0-9 ]/g, ""); if (!a || !b) return false; const wa = new Set(a.split(/\s+/)); const wb = b.split(/\s+/); let hit = 0; wb.forEach(x => { if (wa.has(x)) hit++; }); return hit / Math.max(wa.size, wb.length) >= 0.5; }
function cleanSubject(s) { return String(s || "Building notice").replace(/^\s*((fwd?|re|fw)\s*:\s*)+/i, "").replace(/\s+/g, " ").trim(); }
function classify(h) {
  if (/cleaning|cleaners|janitorial|housekeeping|cleaning service/.test(h) && !/water/.test(h)) return "clean";
  if (/hot water|water (service|shut|outage|interruption|main|pressure|discolor|line|supply)|plumbing|riser|no water|water (is|will be) (off|shut)/.test(h)) return "water";
  if (/elevator/.test(h)) return "elev";
  if (/fire alarm|sprinkler|life safety|smoke detector|alarm test|fire marshal|fire inspection/.test(h)) return "fire";
  if (/boiler|heat(ing)?\b|cooling|hvac|air condition|thermostat|winter weather|cooling tower/.test(h)) return "hvac";
  if (/window|scaffold|rigging|exterior|bucket truck|caulk|facade|crane/.test(h)) return "win";
  if (/preventive maintenance|apartment inspection|unit inspection/.test(h)) return "pm";
  if (/pool|sky terrace|amenit|package|ev charg|trash chute|gym|fitness|yoga|concierge/.test(h)) return "amen";
  if (/garage|driveway|cobblestone|parking|gate|street|corridor|entrance|lobby|construction/.test(h)) return "garage";
  return "other";
}
function typeOf(h) {
  if (/emergency|unexpected|no hot water|without (hot )?water|out of service|outage|failure|failed|leak|discolor|malfunction|apolog|currently (experiencing|unavailable)|not working/.test(h)) return "U";
  if (/schedul|planned|will be (shut|closed|off|unavailable|interrupted)|inspection|testing|preventive|maintenance|temporary/.test(h)) return "S";
  return "N";
}
function floorsOf(h, c) {
  const m = /floors?\s*(\d{1,2})\s*(?:through|thru|to|-|–|—)\s*(\d{1,2}|p2|ph|penthouse)/i.exec(h);
  if (m) { const b = /^\d+$/.test(m[2]) ? m[2] : "P2"; return "Floors " + m[1] + "–" + b; }
  const single = /(\d{1,2})(st|nd|rd|th) floor/i.exec(h);
  if (/entire building|whole building|all floors|building-wide|all residents/.test(h)) return "Whole building";
  if (single && c !== "water") return single[1] + single[2] + " floor";
  if (c === "amen") { const k = /pool|sky terrace|package|garage|gym|yoga|lobby|trash chute/.exec(h); return k ? k[0].replace(/\b\w/g, x => x.toUpperCase()) : "Amenities"; }
  if (c === "garage") { const k = /garage|driveway|lobby|entrance|street|corridor/.exec(h); return k ? k[0].replace(/\b\w/g, x => x.toUpperCase()) : "Garage"; }
  if (c === "win") return "Exterior";
  if (c === "pm") return "All units";
  return "Whole building";
}
function firstSentences(text, max) {
  let t = text.replace(/^(dear|hello|hi)[^\n,.:]*[,.:]?\s*/i, "").replace(/\s+/g, " ").trim();
  t = t.replace(/(thank you|sincerely|best regards|warm regards|kind regards|the atlantic station team|atlantic station management)[\s\S]*$/i, "").trim();
  if (t.length <= max) return t;
  const cut = t.slice(0, max);
  const end = Math.max(cut.lastIndexOf(". "), cut.lastIndexOf("! "));
  return (end > 80 ? cut.slice(0, end + 1) : cut.replace(/\s+\S*$/, "") + "…");
}

// Minimal MIME reader: headers, date, subject, and a text body (text/plain preferred, else HTML stripped)
function parseMime(raw) {
  const sep = raw.indexOf("\r\n\r\n") >= 0 ? "\r\n\r\n" : "\n\n";
  const hEnd = raw.indexOf(sep);
  const headRaw = hEnd >= 0 ? raw.slice(0, hEnd) : raw;
  const bodyRaw = hEnd >= 0 ? raw.slice(hEnd + sep.length) : "";
  const headers = parseHeaders(headRaw);
  const out = { headers: headers, subject: decodeWords(headers["subject"] || ""), from: headers["from"] || "", date: headers["date"] ? new Date(headers["date"]) : null, text: "" };
  if (out.date && isNaN(out.date.getTime())) out.date = null;
  const parts = collectParts(headers, bodyRaw);
  const plain = parts.find(p => /^text\/plain/i.test(p.ct));
  const htmlPart = parts.find(p => /^text\/html/i.test(p.ct));
  if (plain && plain.body.replace(/\s+/g, "").length > 40) out.text = plain.body;
  else if (htmlPart) out.text = stripHtml(htmlPart.body);
  else if (plain) out.text = plain.body;
  out.text = out.text.replace(/\r/g, "").replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
  return out;
}
function parseHeaders(h) {
  const o = {};
  h.replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/).forEach(l => { const i = l.indexOf(":"); if (i > 0) o[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim(); });
  return o;
}
function collectParts(headers, body) {
  const ct = headers["content-type"] || "text/plain";
  const bm = /boundary="?([^";]+)"?/i.exec(ct);
  if (bm) {
    const parts = [];
    const chunks = body.split("--" + bm[1]);
    for (let i = 1; i < chunks.length; i++) {
      let ch = chunks[i];
      if (ch.startsWith("--")) break;
      ch = ch.replace(/^\r?\n/, "");
      const sep = ch.indexOf("\r\n\r\n") >= 0 ? "\r\n\r\n" : "\n\n";
      const k = ch.indexOf(sep);
      const ph = parseHeaders(k >= 0 ? ch.slice(0, k) : "");
      const pb = k >= 0 ? ch.slice(k + sep.length) : ch;
      parts.push.apply(parts, collectParts(ph, pb));
    }
    return parts;
  }
  return [{ ct: ct, body: decodeBody(body, headers["content-transfer-encoding"] || "") }];
}
function decodeBody(b, enc) {
  enc = enc.toLowerCase();
  if (enc.indexOf("quoted-printable") >= 0) return qp(b);
  if (enc.indexOf("base64") >= 0) { try { return new TextDecoder().decode(Uint8Array.from(atob(b.replace(/\s+/g, "")), c => c.charCodeAt(0))); } catch (e) { return b; } }
  return b;
}
function qp(s) {
  s = s.replace(/=\r?\n/g, "");
  const bytes = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "=" && /^[0-9A-Fa-f]{2}$/.test(s.substr(i + 1, 2))) { bytes.push(parseInt(s.substr(i + 1, 2), 16)); i += 2; }
    else bytes.push(s.charCodeAt(i) & 255);
  }
  try { return new TextDecoder().decode(new Uint8Array(bytes)); } catch (e) { return s; }
}
function decodeWords(s) {
  return s.replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g, (m, cs, enc, txt) => {
    try {
      if (enc.toUpperCase() === "B") return new TextDecoder().decode(Uint8Array.from(atob(txt), c => c.charCodeAt(0)));
      return qp(txt.replace(/_/g, " "));
    } catch (e) { return txt; }
  });
}
function stripHtml(h) {
  return h.replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<br\s*\/?>/gi, "\n").replace(/<\/(p|div|tr|li|h\d)>/gi, "\n").replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&#39;|&rsquo;/g, "’").replace(/&quot;|&ldquo;|&rdquo;/g, "\"").replace(/&[a-z]+;/g, " ").replace(/[ \t]+/g, " ").replace(/\n\s*\n/g, "\n\n").trim();
}
