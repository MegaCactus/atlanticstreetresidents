import { EmailMessage } from "cloudflare:email";

// 355 Atlantic Street residents API (asr-api)
// Bindings: DB (KV: photos, rate limits, the signing key, and a mirror of the records), SQL (D1, optional: the
// records, written with compare-and-swap so two emails that arrive together can't erase each other), EMAIL (send_email).
// Vars: OWNER_EMAIL, FROM_EMAIL, SITE_ORIGIN, API_ORIGIN, TRUSTED_SENDERS, ADMIN_USER, ADMIN_HASH, IMPORT_KEY.
// Cron trigger (hourly): ends water/heat outages that never got a restoration email, and sends "still out?" check-ins.

const CATS = ["water","hvac","elev","win","fire","amen","garage","pm","clean","you","other"];
const ORIGINS = ["https://atlanticstreetresidents.com","http://atlanticstreetresidents.com","https://www.atlanticstreetresidents.com","http://www.atlanticstreetresidents.com","http://localhost:8125"];

export default {
  async fetch(request, env, ctx) {
    try { await migrate(env, ctx); } catch (e) { console.log("migration failed: " + (e && e.message)); }
    try { return await route(request, env, ctx); }
    catch (e) { return json({ ok: false, error: String(e && e.message || e) }, 500, request); }
  },
  async email(message, env, ctx) {
    try { await migrate(env, ctx); } catch (e) { console.log("migration failed: " + (e && e.message)); }
    try { await ingestEmail(message, env, ctx); }
    catch (e) { console.log("ingest failed: " + (e && e.message) + " " + (e && e.stack)); }
    try { await message.forward(env.OWNER_EMAIL); } catch (e) { console.log("forward failed: " + (e && e.message)); }
  },
  async scheduled(event, env, ctx) {
    try { await migrate(env, ctx); } catch (e) { console.log("migration failed: " + (e && e.message)); }
    await runSchedule(env, ctx, true);
  }
};

// ---------- helpers ----------
function cors(request) {
  const o = request.headers.get("Origin") || "";
  const allow = ORIGINS.includes(o) ? o : ORIGINS[0];
  return { "Access-Control-Allow-Origin": allow, "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type,X-Import-Key", "Vary": "Origin" };
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
function hourNY(date) {
  return parseInt(new Intl.DateTimeFormat("en-US", { timeZone: "America/New_York", hour: "numeric", hourCycle: "h23" }).format(date || new Date()), 10);
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
  try {
    const key = await getKey(env);
    const ok = await crypto.subtle.verify("HMAC", key, unb64url(sig), new TextEncoder().encode(body));
    if (!ok) return null;
    const payload = JSON.parse(new TextDecoder().decode(unb64url(body)));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) { return null; }
}

async function sendMail(env, subject, text) {
  if (!env.EMAIL || !env.OWNER_EMAIL) return;
  subject = subject.replace(/[\r\n]/g, " ");
  try { await env.EMAIL.send({ from: env.FROM_EMAIL, to: env.OWNER_EMAIL, subject: subject, text: text }); return; }
  catch (e) { console.log("email service send failed, trying legacy: " + (e && e.message)); }
  const raw = "From: 355 Atlantic tracker <" + env.FROM_EMAIL + ">\r\nTo: " + env.OWNER_EMAIL + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + text;
  await env.EMAIL.send(new EmailMessage(env.FROM_EMAIL, env.OWNER_EMAIL, raw));
}
// A signed link for the owner's emails (check-ins, publish-anyway)
async function link(env, path, payload, days) {
  return env.API_ORIGIN + path + "?t=" + encodeURIComponent(await sign(env, Object.assign({ exp: Date.now() + (days || 30) * 86400000 }, payload)));
}

// ---------- dates ----------
function daysBetween(a, b) { return Math.round((Date.parse(String(b).slice(0, 10) + "T12:00:00Z") - Date.parse(String(a).slice(0, 10) + "T12:00:00Z")) / 86400000); }
function addDays(d, n) { const t = Date.parse(String(d).slice(0, 10) + "T12:00:00Z"); return isNaN(t) ? "" : new Date(t + n * 86400000).toISOString().slice(0, 10); }
function validDate(v) { return /^\d{4}-\d{2}-\d{2}$/.test(String(v || "")) && !isNaN(Date.parse(v + "T12:00:00Z")) && new Date(v + "T12:00:00Z").toISOString().slice(0, 10) === v; }
// End-date guard: an end before the start is never stored (it would hide the entry from the calendar)
function guardEnd(item) {
  if (!item) return item;
  const e = String(item.e || "").replace(/^~/, "");
  if (e && item.d && /^\d{4}-\d{2}-\d{2}$/.test(String(item.d)) && e < item.d) item.e = "";
  return item;
}
function hoursLabel(ms) {
  if (!(ms > 0)) return "";
  const h = ms / 3600000;
  if (h < 0.75) return "≈" + Math.max(5, Math.round(h * 60 / 5) * 5) + " min";
  if (h < 20) return "≈" + (h < 3 ? Math.round(h * 2) / 2 : Math.round(h)) + " h";
  const d = Math.round(h / 24);
  return "≈" + d + " day" + (d === 1 ? "" : "s");
}

// ---------- storage: D1 documents with compare-and-swap; KV keeps a mirror (and is the store when D1 isn't bound) ----------
// Every change to pub / pend / rej / held / sys goes through mutateDoc: read the row and its version, apply the change,
// and write only if the version hasn't moved; otherwise read again and re-apply.
let STORE_READY = false;
function docDefault(name) { return name === "pub" ? { incidents: [], reports: [] } : name === "sys" ? {} : []; }
async function ensureStore(env) {
  if (!env.SQL || STORE_READY) return;
  await env.SQL.prepare("CREATE TABLE IF NOT EXISTS docs (id TEXT PRIMARY KEY, body TEXT NOT NULL, ver INTEGER NOT NULL DEFAULT 0, at TEXT)").run();
  const row = await env.SQL.prepare("SELECT COUNT(*) AS n FROM docs").first();
  if (!row || !row.n) {
    const now = new Date().toISOString();
    for (const name of ["pub", "pend", "rej", "held", "sys"]) {
      const v = await env.DB.get(name);
      await env.SQL.prepare("INSERT OR IGNORE INTO docs (id, body, ver, at) VALUES (?, ?, 0, ?)").bind(name, v || JSON.stringify(docDefault(name)), now).run();
    }
  }
  STORE_READY = true;
}
async function getDoc(env, name) {
  if (env.SQL) {
    await ensureStore(env);
    const r = await env.SQL.prepare("SELECT body, ver FROM docs WHERE id = ?").bind(name).first();
    if (r) { try { return { body: fixShape(name, JSON.parse(r.body)), ver: r.ver }; } catch (e) { return { body: docDefault(name), ver: r.ver }; } }
    return { body: docDefault(name), ver: -1 };
  }
  const v = await env.DB.get(name, "json");
  return { body: fixShape(name, v), ver: 0 };
}
function fixShape(name, v) {
  if (name === "pub") { v = v && typeof v === "object" && !Array.isArray(v) ? v : {}; if (!Array.isArray(v.incidents)) v.incidents = []; if (!Array.isArray(v.reports)) v.reports = []; return v; }
  if (name === "sys") return v && typeof v === "object" && !Array.isArray(v) ? v : {};
  return Array.isArray(v) ? v : [];
}
async function readDoc(env, name) { return (await getDoc(env, name)).body; }
// fn(body) may run more than once, so it must only change body (or return a replacement) and never send mail.
// Return false from fn to skip the write.
async function mutateDoc(env, name, fn, ctx) {
  for (let i = 0; i < 12; i++) {
    const { body, ver } = await getDoc(env, name);
    const out = await fn(body);
    if (out === false) return body;
    const next = out === undefined || out === true ? body : out;
    const text = JSON.stringify(next);
    if (!env.SQL) { await env.DB.put(name, text); return next; }
    const now = new Date().toISOString();
    const res = ver < 0
      ? await env.SQL.prepare("INSERT OR IGNORE INTO docs (id, body, ver, at) VALUES (?, ?, 1, ?)").bind(name, text, now).run()
      : await env.SQL.prepare("UPDATE docs SET body = ?, ver = ver + 1, at = ? WHERE id = ? AND ver = ?").bind(text, now, name, ver).run();
    if (res && res.meta && res.meta.changes === 1) {
      const mirror = env.DB.put(name, text).catch(e => console.log("mirror failed: " + (e && e.message)));
      if (ctx && ctx.waitUntil) ctx.waitUntil(mirror); else await mirror;
      return next;
    }
    await new Promise(r => setTimeout(r, 25 + Math.random() * 90 * (i + 1)));
  }
  throw new Error("The record is busy; try again.");
}
async function readListDoc(env, name) { const v = await readDoc(env, name); return Array.isArray(v) ? v : []; }
function findAnywhere(pub, itemId) {
  return (pub.incidents || []).find(x => x.id === itemId) || (pub.reports || []).find(x => x.id === itemId) || null;
}

// ---------- routing ----------
async function route(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(request) });

  if (path === "/") return json({ ok: true, service: "355 Atlantic residents API" }, 200, request);
  if (path === "/incidents" && request.method === "GET") return publicRecord(request, env, ctx);
  if (path.startsWith("/img/") && request.method === "GET") return serveImage(url, path, env);
  if (path === "/calendar.ics" && request.method === "GET") return feedIcs(env);
  if (path === "/feed.xml" && request.method === "GET") return feedRss(env);
  if (path === "/submit" && request.method === "POST") return submit(request, env, ctx);
  if (path === "/a" && (request.method === "GET" || request.method === "POST")) return actFromLink(url, env, request, ctx);
  if (path === "/s" && (request.method === "GET" || request.method === "POST")) return statusLink(url, env, request, ctx);
  if (path === "/g" && (request.method === "GET" || request.method === "POST")) return publishHeldLink(url, env, request, ctx);
  if (path === "/admin") return admin(request, env);
  if (path === "/admin/login" && request.method === "POST") return adminLogin(request, env);
  if (path === "/admin/logout") return new Response(null, { status: 302, headers: { "Location": "/admin", "Set-Cookie": "asr_admin=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0" } });
  if (path === "/admin/list") return adminList(request, env, ctx);
  if (path === "/admin/act" && request.method === "POST") return adminAct(request, env, ctx);
  if (path === "/admin/thumbs" && request.method === "GET") return adminThumbList(request, env);
  if (path === "/admin/thumb" && request.method === "POST") return adminThumb(request, env);
  if (path === "/admin/import") return adminImport(request, env, ctx);
  return json({ ok: false, error: "Not found" }, 404, request);
}

async function publicRecord(request, env, ctx) {
  let pub;
  try { pub = await readDoc(env, "pub"); }
  catch (e) { console.log("record read failed, using the mirror: " + (e && e.message)); pub = fixShape("pub", await env.DB.get("pub", "json")); }
  sweepSoon(env, ctx);
  const out = { incidents: pub.incidents, reports: pub.reports };
  if (pub.banner) out.banner = pub.banner;
  return json(out, 200, request, { "Cache-Control": "public, max-age=60" });
}
async function serveImage(url, path, env) {
  const key = "img:" + path.slice(5).replace(/[^a-z0-9-]/gi, "");
  const wantThumb = url.searchParams.get("s") === "t";
  let r = wantThumb ? await env.DB.getWithMetadata(key + ":t", "arrayBuffer") : null;
  const fallback = wantThumb && !(r && r.value);
  if (!r || !r.value) r = await env.DB.getWithMetadata(key, "arrayBuffer");
  if (!r || !r.value) return new Response("Not found", { status: 404 });
  // A thumbnail URL answered with the full photo (no thumbnail made yet) is cached briefly, so the real one shows up later
  return new Response(r.value, { headers: { "Content-Type": (r.metadata && r.metadata.ct) || "image/jpeg", "Cache-Control": fallback ? "public, max-age=3600" : "public, max-age=31536000, immutable", "Access-Control-Allow-Origin": "*" } });
}

// ---------- one-time corrections to the live record (2026-10-28) ----------
const MIGRATION = "fix-2026-10-28";
let MIGRATED = false;
async function migrate(env, ctx) {
  if (MIGRATED) return;
  const pub = await readDoc(env, "pub");
  if (pub.meta && Array.isArray(pub.meta.done) && pub.meta.done.indexOf(MIGRATION) >= 0) { MIGRATED = true; return; }
  await mutateDoc(env, "pub", p => {
    p.meta = p.meta && typeof p.meta === "object" && !Array.isArray(p.meta) ? p.meta : {};
    p.meta.done = Array.isArray(p.meta.done) ? p.meta.done : [];
    if (p.meta.done.indexOf(MIGRATION) >= 0) return false;
    fixRecord20261028(p);
    p.meta.done.push(MIGRATION);
  }, ctx);
  MIGRATED = true;
}
function fixRecord20261028(p) {
  const inc = k => p.incidents.find(x => x.id === k);
  const rep = k => p.reports.find(x => x.id === k);
  const set = (x, f) => { if (x) Object.assign(x, f); return x; };
  // Titles and summaries of building emails already on the record: no "Subject:", greetings or footers; old
  // "Restored: ..." and "Update ...:" notes become dated updates
  for (const x of p.incidents) {
    if (x.src !== "email") continue;
    x.s = cleanTitle(x.s);
    let t = String(x.x || "");
    t = t.replace(/\s*Restored: (.+?) \((\d{4}-\d{2}-\d{2})\)\.?/g, (m, title, d) => { addUpdate(x, d, "Restored: " + cleanTitle(title)); return ""; });
    t = t.replace(/\s*Update (\d{4}-\d{2}-\d{2}): ([\s\S]*?)(?=\s*Update \d{4}-\d{2}-\d{2}:|$)/g, (m, d, u) => { addUpdate(x, d, u); return ""; });
    x.x = firstSentences(stripBoilerplate(t), 400);
    const fw = floorRangeText(String(x.w || "")); if (fw) x.w = fw;
  }
  for (const x of p.incidents.concat(p.reports)) guardEnd(x);
  if (!inc("mvbdx67t-92649d20")) return;   // not the live record (a fresh store): nothing else to correct
  const PM_X = "Mandatory entry to every unit to check HVAC systems, smoke alarms and other equipment, starting about 9 a.m. each day.";
  p.incidents = p.incidents.filter(x => x.id !== "mvbb9y9u-0881854b" && x.id !== "mvb44rmh-0823d55c");   // rent reminder; a restoration posted as its own notice
  set(inc("mvh2c7av-9d90b704"), { e: "2026-10-20", status: "resolved", dur: "≈1.5 h" });
  set(inc("mvbdx67t-92649d20"), { d: "2026-09-21", e: "", c: "elev", t: "U", status: "open", s: "Elevator out of service", w: "Whole building", dur: "",
    x: "A resident reported on Sep 21 that the elevator was bouncing and jerking and was shut down. It has been out of service since.",
    confirmed: "2026-10-28", updates: [{ d: "2026-10-16", text: "Building email: an elevator is still out of service, waiting on a part." }, { d: "2026-10-28", text: "Residents confirm it is still out." }] });
  set(inc("mva6c76k-786e2582"), { s: "Temporary water outage – Floors 16–26", e: "2026-10-15", status: "resolved", dur: "same day (no restoration notice)", updates: [],
    x: "A leak in the building shut off water to floors 16–26; the building expected it back within the hour." });
  if (!inc("fix-20261016-hw")) p.incidents.unshift({ id: "fix-20261016-hw", d: "2026-10-16", e: "2026-10-16", c: "water", t: "U", s: "Temporary hot water interruption – Floors 17–26",
    x: "A problem in one unit paused hot water to floors 17–26; it was restored the same morning.", w: "Floors 17–26", g: "", dur: "≈20 min", src: "email", img: [],
    status: "resolved", at: "2026-10-16T14:56:47.000Z", updates: [{ d: "2026-10-16", text: "Restored: Hot water restored" }] });
  set(inc("mv5dwfo2-2187f19f"), { d: "2026-10-22", e: "2026-10-23", c: "pm", t: "S", s: "Preventive maintenance with unit entry – Floors 14–26", w: "Floors 14–26", x: PM_X, updates: [] });
  if (!inc("fix-20261029-pm")) p.incidents.unshift({ id: "fix-20261029-pm", d: "2026-10-29", e: "2026-10-30", c: "pm", t: "S", s: "Preventive maintenance with unit entry – Floors 6–12",
    x: PM_X, w: "Floors 6–12", g: "", dur: "", src: "email", img: [] });
  set(inc("mupl6qrt-3179ceda"), { e: "2026-10-01", status: "resolved", dur: "≈3.5 h" });
  set(inc("mueo2szg-c3be49ab"), { d: "2026-09-25", e: "2026-09-25", t: "S", s: "Parking garage work on G2",
    x: "Work in the parking garage on Friday, September 25, from 9 a.m. to 6 p.m.; extra caution on G2." });
  set(rep("mussmrfd-13950f78"), { cat: "elev" });
  const r = rep("mulpio20-3bc95f1e"); if (r) { delete r.banner; delete r.pinUntil; r.incident = "mvbdx67t-92649d20"; }
}

// ---------- submissions ----------
async function submit(request, env, ctx) {
  if (+(request.headers.get("Content-Length") || 0) > 8000000) return json({ ok: false, error: "That submission is too large. Try fewer or smaller photos." }, 413, request);
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
  if ((await readListDoc(env, "pend")).length >= PEND_MAX) return json({ ok: false, error: "Submissions are paused while the review queue catches up. Try again tomorrow." }, 503, request);

  const imgs = [];
  const list = Array.isArray(body.images) ? body.images.slice(0, 3) : [];
  const thumbs = Array.isArray(body.thumbs) ? body.thumbs : [];
  for (let n = 0; n < list.length; n++) {
    const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(list[n] || ""));
    if (!m) continue;
    const bytes = Uint8Array.from(atob(m[2]), c => c.charCodeAt(0));
    if (bytes.length > 1500000) return json({ ok: false, error: "A photo is too large after compression. Try a smaller one." }, 400, request);
    const iid = id();
    await env.DB.put("img:" + iid, bytes, { metadata: { ct: m[1] } });
    const t = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(thumbs[n] || ""));
    if (t) {
      const tb = Uint8Array.from(atob(t[2]), c => c.charCodeAt(0));
      if (tb.length <= 300000) await env.DB.put("img:" + iid + ":t", tb, { metadata: { ct: t[1] } });
    }
    imgs.push(iid);
  }

  const today = todayNY();
  const item = { id: id(), kind: kind, at: new Date().toISOString(), status: "pending", img: imgs, ip: ip.slice(0, 64) };
  let d = cleanDate(body.date) || today;
  if (d.length === 10 && d > addDays(today, 1)) d = today;
  if (kind === "ticket") {
    item.c = "you"; item.t = "R";
    item.cat = CATS.includes(body.cat) && body.cat !== "you" ? body.cat : "other";
    item.s = String(body.title || "").trim().slice(0, 140) || text.slice(0, 80);
    item.x = text;
    item.w = cleanFloors(body.where);
    item.d = d;
    item.m = false;
  } else {
    item.title = String(body.title || "").trim().slice(0, 140) || text.slice(0, 80);
    item.text = text;
    item.where = cleanFloors(body.where);
    item.cat = CATS.includes(body.cat) && body.cat !== "you" ? body.cat : "other";
    item.d = d;
    item.anon = body.anon !== false;
    item.name = item.anon ? "" : String(body.name || "").trim().slice(0, 60);
  }
  // Is it still happening? Kept apart from the review status; it becomes the published status on approval
  item.state = body.status === "open" ? "open" : body.status === "resolved" ? "resolved" : "";
  if (item.state === "resolved" && validDate(body.end) && body.end >= String(item.d).slice(0, 10) && body.end <= addDays(today, 1)) item.end = String(body.end);
  item.contact = String(body.contact || "").trim().slice(0, 120);
  item.stack = cleanStack(body.stack);
  if (body.lang === "es") item.lang = "es";

  await mutateDoc(env, "pend", pend => { if (!pend.some(x => x.id === item.id)) pend.unshift(item); }, ctx);

  try {
    const approve = env.API_ORIGIN + "/a?id=" + item.id + "&act=approve&t=" + encodeURIComponent(await sign(env, { p: "act", id: item.id, act: "approve", exp: Date.now() + 30 * 86400000 }));
    const reject = env.API_ORIGIN + "/a?id=" + item.id + "&act=reject&t=" + encodeURIComponent(await sign(env, { p: "act", id: item.id, act: "reject", exp: Date.now() + 30 * 86400000 }));
    const photos = imgs.map(i => env.API_ORIGIN + "/img/" + i).join("\n");
    const still = item.state === "open" ? "yes" : item.state === "resolved" ? "no, fixed" + (item.end ? " on " + item.end : "") : "not sure";
    await sendMail(env, "[Review] New " + kind + ": " + (item.s || item.title),
      "A new " + kind + " is waiting for review.\n\nWhat: " + (item.s || item.title) + "\nWhere: " + (item.w || item.where) + (item.stack ? " (" + item.stack + " line)" : "") + "\nDate: " + item.d + "\nStill happening: " + still + "\nCategory: " + item.cat + (kind === "report" ? "\nBy: " + (item.anon ? "anonymous" : item.name || "(no name)") : "") + (item.contact ? "\nContact: " + item.contact : "") + (item.lang === "es" ? "\nSent from the Spanish form" : "") + "\n\n" + text + "\n\nPhotos:\n" + (photos || "none") + "\n\nApprove: " + approve + "\nReject: " + reject + "\n\nOr open the review page: " + env.API_ORIGIN + "/admin\n");
  } catch (e) { console.log("notify failed: " + (e && e.message)); }

  return json({ ok: true, id: item.id }, 200, request);
}
const PEND_MAX = 300;
const PLACES = ["Floors 6–16", "Floors 17–26", "Whole building", "Garage", "Amenities", "Exterior", "Lobby", "All units", "Upper floors",
  "Pool", "Sky Terrace", "Package", "Gym", "Yoga", "Trash Chute", "Driveway", "Entrance", "Street", "Corridor"];
function cleanFloors(v, keep) {
  v = String(v || "").trim().slice(0, 40);
  if (keep !== undefined && keep !== null && v === String(keep)) return v;
  if (PLACES.includes(v)) return v;
  if (/^Floors \d{1,2}–(\d{1,2}|P2)$/.test(v) || /^\d{1,2}(st|nd|rd|th) floor$/.test(v)) return v;
  return "Upper floors";
}
function cleanStack(v) { v = String(v || "").trim().toUpperCase().slice(0, 1); return /^[A-HJ-NPRST]$/.test(v) ? v : ""; }
function cleanDate(v) { v = String(v || ""); return validDate(v) ? v : (/^\d{4}-(0[1-9]|1[0-2])$/.test(v) ? v : ""); }

// ---------- moderation ----------
// What a pending item becomes on the public record. "state" is the submitter's (or the email gate's) answer to
// "is it still happening?"; resident tickets are personal repairs, so they never stay open on the record.
function publishedFromPending(item) {
  const start = String(item.d || "").slice(0, 10);
  const endOk = d => (validDate(d) && d >= start) ? d : "";
  const state = item.state || "";
  if (item.kind === "ticket") {
    const v = { id: item.id, d: item.d, e: "", m: false, c: "you", t: "R", s: item.s, x: item.x, w: item.w, g: item.cat === "water" ? "hotwater" : "", dur: "", src: "ticket", img: item.img || [], cat: item.cat, stack: item.stack || "" };
    if (state === "resolved" && validDate(start)) { v.status = "resolved"; v.e = endOk(item.end) || start; }
    return { list: "incidents", v: v };
  }
  if (item.kind === "incident") {
    const v = { id: item.id, d: item.d, e: endOk(item.end || item.e), c: item.c, t: item.t || "N", s: item.s, x: item.x, w: item.w, g: item.g || "", dur: "", src: item.src || "email", via: item.via == null ? "resident" : item.via, copies: item.copies || 1, img: item.img || [] };
    if (!v.via) delete v.via;
    if (item.at) v.at = item.at;
    if (v.t === "U" && state === "open") { v.status = "open"; v.e = ""; v.confirmed = start; }
    else if (v.t === "U" && state === "resolved") { v.status = "resolved"; v.e = v.e || start; }
    return { list: "incidents", v: v };
  }
  const v = { id: item.id, d: item.d, title: item.title, text: item.text, where: item.where, cat: item.cat, img: item.img || [], anon: item.anon !== false, name: item.name || "", at: item.at, stack: item.stack || "" };
  if (state === "open") { v.status = "open"; v.confirmed = start; }
  else if (state === "resolved") { v.status = "resolved"; v.e = endOk(item.end) || start; }
  return { list: "reports", v: v };
}
// Put approved items on the public record. Safe to run twice: an item already there (by id, or by the update it
// left on an open entry) is skipped. Returns how many changed the record.
function publishPending(pub, items) {
  let n = 0;
  for (const raw of items) {
    if (findAnywhere(pub, raw.id) || seenEmail(pub, "p:" + raw.id)) continue;
    const item = Object.assign({}, raw); delete item.ip; delete item.contact;
    // A building update or restoration attaches to the open entry it belongs to, when there is one
    if (item.kind === "incident" && (item.gk === "restored" || item.gk === "update")) {
      const day = String(item.d).slice(0, 10);
      const open = findOpenEntry(pub, item.c, item.w, day);
      if (open) {
        if (item.gk === "restored") closeEntry(open, day, item.at, "Restored: " + item.s, "p:" + item.id);
        else addUpdate(open, day, "Building email: " + (item.upd || item.x || item.s), "p:" + item.id);
        n++;
        continue;
      }
    }
    const out = publishedFromPending(item);
    guardEnd(out.v);
    pub[out.list].unshift(out.v);
    n++;
  }
  return n;
}
async function applyAction(env, itemId, act, ctx) {
  const item = (await readListDoc(env, "pend")).find(x => x.id === itemId);
  if (!item) return { ok: false, error: "That item is no longer pending." };
  if (act === "approve") {
    // Publish first, then take it off the queue: a failure in between leaves it waiting, never lost
    await mutateDoc(env, "pub", pub => publishPending(pub, [item]) ? undefined : false, ctx);
    await mutateDoc(env, "pend", pend => { const i = pend.findIndex(x => x.id === itemId); if (i < 0) return false; pend.splice(i, 1); }, ctx);
    return { ok: true, status: "approved" };
  }
  let gone = false;
  await mutateDoc(env, "pend", pend => { gone = false; const i = pend.findIndex(x => x.id === itemId); if (i < 0) return false; pend.splice(i, 1); gone = true; }, ctx);
  if (!gone) return { ok: false, error: "That item is no longer pending." };
  for (const i of item.img || []) { await env.DB.delete("img:" + i); await env.DB.delete("img:" + i + ":t"); }
  if (item.kind === "incident" || item.kind === "report") {
    await mutateDoc(env, "rej", rej => { rej.unshift({ s: item.s || item.title || "", d: item.d, c: item.c || item.cat || "", gk: newsKind(item) || undefined, at: Date.now() }); if (rej.length > 500) rej.length = 500; }, ctx);
  }
  return { ok: true, status: "rejected" };
}
async function actFromLink(url, env, request, ctx) {
  const p = await verify(env, url.searchParams.get("t"));
  if (!p || p.p !== "act" || p.id !== url.searchParams.get("id") || p.act !== url.searchParams.get("act")) return html(page("That link is invalid or has expired.", "Open the review page instead: <a href='/admin'>/admin</a>"), 400);
  if (request.method === "GET") {
    const it = (await readListDoc(env, "pend")).find(x => x.id === p.id);
    if (!it) return html(page("That item is no longer pending.", "<a href='/admin'>Open the review page</a>"));
    const approve = p.act === "approve";
    return html(page(approve ? "Approve and publish this?" : "Reject and remove this?", "<p><strong>" + esc(it.s || it.title) + "</strong> (" + esc(it.d) + ")</p><form method=post><button>" + (approve ? "Approve and publish" : "Reject") + "</button></form><p><a href='/admin'>Or open the review page</a></p>"));
  }
  const r = await applyAction(env, p.id, p.act, ctx);
  return html(page(r.ok ? (r.status === "approved" ? "Approved and published." : "Rejected and removed.") : r.error, "<a href='/admin'>Open the review page</a>"));
}
function page(title, bodyHtml) {
  return "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>" + esc(title) + "</title><style>body{font-family:system-ui,sans-serif;max-width:560px;margin:60px auto;padding:0 20px;color:#1B2430;line-height:1.5}h1{font-size:22px}input,button{font:inherit;padding:10px 14px;border-radius:8px}input{border:1px solid #AEB7C2}button{border:1px solid #1B2430;background:#1B2430;color:#fff;cursor:pointer;min-height:44px}</style><h1>" + esc(title) + "</h1><div>" + bodyHtml + "</div>";
}

// ---------- links in the owner's emails: still out / fixed, and publish a held notice anyway ----------
async function statusLink(url, env, request, ctx) {
  const p = await verify(env, url.searchParams.get("t"));
  if (!p || p.p !== "status" || !p.id) return html(page("That link is invalid or has expired.", "Open the review page instead: <a href='/admin'>/admin</a>"), 400);
  const today = todayNY();
  if (p.act === "still" && request.method === "GET") {
    const it = findAnywhere(await readDoc(env, "pub"), p.id);
    if (!it) return html(page("That entry is no longer on the site.", "<a href='/admin'>Open the review page</a>"), 404);
    return html(page("Still out?", "<p>" + esc(it.s || it.title) + " (since " + esc(it.d) + ")</p><form method=post><button>Yes, it's still out</button></form>"));
  }
  if (p.act === "fixed" && request.method === "GET") {
    const it = findAnywhere(await readDoc(env, "pub"), p.id);
    if (!it) return html(page("That entry is no longer on the site.", "<a href='/admin'>Open the review page</a>"), 404);
    const min = /^\d{4}-\d{2}-\d{2}$/.test(String(it.d)) ? it.d : "";
    return html(page("When was it fixed?", "<form method=post><p>" + esc(it.s || it.title) + " (since " + esc(it.d) + ")</p><p><label>Fixed on <input type=date name=e value='" + today + "' max='" + today + "' min='" + esc(min) + "' required></label></p><p><button>Mark it resolved</button></p></form>"));
  }
  let e = today;
  if (p.act === "fixed") { try { const f = await request.formData(); if (validDate(f.get("e"))) e = String(f.get("e")); } catch (x) { /* keep today */ } }
  let found = null;
  await mutateDoc(env, "pub", pub => {
    const it = findAnywhere(pub, p.id); found = it; if (!it) return false;
    if (p.act === "still") { it.status = "open"; it.e = ""; it.confirmed = today; it.checkedAt = today; }
    else if (p.act === "fixed") { it.status = "resolved"; it.e = e < String(it.d).slice(0, 10) ? String(it.d).slice(0, 10) : e; it.checkedAt = today; }
    else return false;
  }, ctx);
  if (!found) return html(page("That entry is no longer on the site.", "<a href='/admin'>Open the review page</a>"), 404);
  const where = env.SITE_ORIGIN + "/#" + (found.title !== undefined ? "report-" : "entry-") + encodeURIComponent(found.id);
  return html(page(p.act === "still" ? "Marked as still out." : "Marked as resolved on " + (e < String(found.d).slice(0, 10) ? found.d : e) + ".", "<a href='" + esc(where) + "'>See it on the site</a> &nbsp; <a href='/admin'>Review page</a>"));
}
async function publishHeldLink(url, env, request, ctx) {
  const p = await verify(env, url.searchParams.get("t"));
  if (!p || p.p !== "held" || !p.id) return html(page("That link is invalid or has expired.", "<a href='/admin'>Open the review page</a>"), 400);
  if (request.method === "GET") {
    const h = (await readListDoc(env, "held")).find(x => x.id === p.id);
    if (!h) return html(page("That notice is no longer held.", "<a href='/admin'>Open the review page</a>"), 404);
    return html(page("Post this notice on the site?", "<p><strong>" + esc(h.s) + "</strong> (" + esc(h.d) + ")</p><p>It was held back as: " + esc(h.why) + ".</p><form method=post><button>Post it</button></form>"));
  }
  const r = await publishHeldItem(env, p.id, ctx);
  return html(page(r.ok ? "Posted." : r.error, "<a href='/admin'>Open the review page</a>"));
}
async function publishHeldItem(env, heldId, ctx) {
  const item = (await readListDoc(env, "held")).find(x => x.id === heldId);
  if (!item) return { ok: false, error: "That notice is no longer held." };
  // Publish first (under an id made from the held one, so a retry can't post it twice), then take it off the list
  const entry = Object.assign({ e: "", t: "N", g: "", dur: "", src: "email", img: [] }, item.cand || {}, { id: "h" + heldId, s: item.s, d: item.d });
  await mutateDoc(env, "pub", pub => { if (findAnywhere(pub, entry.id)) return false; pub.incidents.unshift(entry); }, ctx);
  await mutateDoc(env, "held", list => { const i = list.findIndex(x => x.id === heldId); if (i < 0) return false; list.splice(i, 1); }, ctx);
  return { ok: true };
}

// ---------- admin ----------
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
  let form = null;
  try { form = await request.formData(); } catch (e) { form = null; }
  const user = form ? String(form.get("user") || "").trim() : "";
  const pass = form ? String(form.get("pass") || "") : "";
  if (user || pass) {
    const ip = request.headers.get("CF-Connecting-IP") || "0";
    const rlKey = "login:" + ip + ":" + new Date().toISOString().slice(0, 13);
    const tries = parseInt((await env.DB.get(rlKey)) || "0", 10);
    if (tries >= 6) return html(page("Too many attempts.", "Try again in an hour."), 429);
    const ok = env.ADMIN_USER && env.ADMIN_HASH && user === env.ADMIN_USER && (await checkPassword(pass, env.ADMIN_HASH));
    if (!ok) {
      await env.DB.put(rlKey, String(tries + 1), { expirationTtl: 3600 });
      return html(page("That sign-in did not match.", "<a href='/admin'>Try again</a>"), 401);
    }
    const t = await sign(env, { p: "auth", exp: Date.now() + 7 * 86400000 });
    return new Response(null, { status: 302, headers: { "Location": "/admin", "Set-Cookie": "asr_admin=" + encodeURIComponent(t) + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800" } });
  }
  return html(page("Sign in required.", "<a href='/admin'>Back to the sign-in page</a>"), 400);
}
// ADMIN_HASH format: pbkdf2$<iterations>$<saltHex>$<hashHex>
async function checkPassword(pass, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iter = parseInt(parts[1], 10), salt = unhex(parts[2]), want = parts[3].toLowerCase();
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: iter }, key, 256);
  const got = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
  if (got.length !== want.length) return false;
  let diff = 0; for (let i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ want.charCodeAt(i);
  return diff === 0;
}
async function adminList(request, env, ctx) {
  if (!(await isAdmin(request, env))) return json({ ok: false, error: "Not signed in" }, 401);
  sweepSoon(env, ctx);
  const pend = await readListDoc(env, "pend");
  const pub = await readDoc(env, "pub");
  const held = await readListDoc(env, "held");
  return json({ ok: true, today: todayNY(), pending: pend, incidents: pub.incidents, reports: pub.reports, banner: pub.banner || null, held: held.slice(0, 60), store: env.SQL ? "d1" : "kv" });
}
function applyPendingEdit(it, e) {
  if (e.s != null) { const t = String(e.s).trim().slice(0, 140); if (t) { if (it.kind === "report") it.title = t; else it.s = t; } }
  if (e.x != null) { const t = String(e.x).slice(0, 2000); if (it.kind === "report") it.text = t; else it.x = t; }
  if (e.w != null) { const w = cleanFloors(e.w, it.kind === "report" ? it.where : it.w); if (it.kind === "report") it.where = w; else it.w = w; }
  if (e.cat != null && CATS.includes(e.cat) && e.cat !== "you") { it.cat = e.cat; if (it.kind === "incident") it.c = e.cat; }
  if (e.d != null && cleanDate(e.d)) it.d = cleanDate(e.d);
  if (e.t != null && it.kind === "incident" && ["U", "S", "N"].includes(e.t)) it.t = e.t;
  if (e.state != null) it.state = e.state === "open" ? "open" : e.state === "resolved" ? "resolved" : "";
  if (e.e != null) it.end = validDate(e.e) ? String(e.e) : "";
}
async function adminAct(request, env, ctx) {
  if (!(await isAdmin(request, env))) return json({ ok: false, error: "Not signed in" }, 401);
  let b;
  try { b = await request.json(); } catch (e) { return json({ ok: false, error: "The request could not be read." }, 400); }
  const today = todayNY();
  const NOT_PUB = { ok: false, error: "That item is not published." };
  if (b.action === "approve" || b.action === "reject") {
    if (b.edit) await mutateDoc(env, "pend", pend => { const it = pend.find(x => x.id === b.id); if (!it) return false; applyPendingEdit(it, b.edit); }, ctx);
    return json(await applyAction(env, b.id, b.action, ctx));
  }
  if (b.action === "approveAll") {
    // Two writes for the whole queue (D1 allows only so many queries per request): publish all, then clear them
    const pend = await readListDoc(env, "pend");
    if (!pend.length) return json({ ok: true, approved: 0 });
    const ids = new Set(pend.map(x => x.id));
    await mutateDoc(env, "pub", pub => publishPending(pub, pend) ? undefined : false, ctx);
    await mutateDoc(env, "pend", list => { const rest = list.filter(x => !ids.has(x.id)); return rest.length === list.length ? false : rest; }, ctx);
    return json({ ok: true, approved: pend.length });
  }
  if (b.action === "editPub") {
    let found = false;
    await mutateDoc(env, "pub", pub => {
      const it = findAnywhere(pub, b.id); found = !!it; if (!it) return false;
      const e = b.edit || {};
      const isReport = it.title !== undefined;
      if (e.s != null) { const t = String(e.s).trim().slice(0, 140); if (t) { if (isReport) it.title = t; else it.s = t; } }
      if (e.x != null) { const t = String(e.x).slice(0, 2000); if (isReport) it.text = t; else it.x = t; }
      if (e.w != null) { const w = cleanFloors(e.w, isReport ? it.where : it.w); if (isReport) it.where = w; else it.w = w; }
      if (e.cat != null && CATS.includes(e.cat)) { if (isReport || it.c === "you") { if (e.cat !== "you") it.cat = e.cat; } else if (e.cat !== "you") it.c = e.cat; }
      if (e.d != null && cleanDate(e.d)) it.d = cleanDate(e.d);
      if (e.t != null && !isReport && it.c !== "you" && ["U", "S", "N"].includes(e.t)) it.t = e.t;
      if (e.banner != null) { if (e.banner === "pin" || e.banner === "hide") it.banner = e.banner; else delete it.banner; }
      if (e.pinUntil != null) { const u = cleanDate(e.pinUntil); if (u && u.length === 10 && it.banner === "pin") it.pinUntil = u; else delete it.pinUntil; }
      guardEnd(it);
    }, ctx);
    return json(found ? { ok: true } : NOT_PUB, found ? 200 : 404);
  }
  if (b.action === "unpublish") {
    await mutateDoc(env, "pub", pub => {
      const n = pub.incidents.length + pub.reports.length;
      pub.incidents = pub.incidents.filter(x => x.id !== b.id);
      pub.reports = pub.reports.filter(x => x.id !== b.id);
      if (pub.incidents.length + pub.reports.length === n) return false;
    }, ctx);
    return json({ ok: true });
  }
  if (b.action === "setEnd") {
    let err = "";
    await mutateDoc(env, "pub", pub => {
      const it = findAnywhere(pub, b.id); if (!it) { err = NOT_PUB.error; return false; }
      const e = String(b.e || "").trim();
      if (e && !validDate(e)) { err = "Use a date like 2026-10-20."; return false; }
      if (e && /^\d{4}-\d{2}-\d{2}$/.test(String(it.d)) && e < it.d) { err = "That date is before the start date (" + it.d + ")."; return false; }
      err = "";
      it.e = e;
      if (b.dur != null && it.title === undefined) it.dur = String(b.dur).slice(0, 60);
      if (e && it.status === "open") it.status = "resolved";
    }, ctx);
    return json(err ? { ok: false, error: err } : { ok: true });
  }
  if (b.action === "setStatus") {
    let err = "";
    await mutateDoc(env, "pub", pub => {
      const it = findAnywhere(pub, b.id); if (!it) { err = NOT_PUB.error; return false; }
      err = "";
      if (b.status === "open") {
        it.status = "open"; it.e = ""; it.confirmed = today; it.checkedAt = today;
        if (it.dur && /no restoration notice/.test(it.dur)) it.dur = "";
      } else if (b.status === "resolved") {
        const e = validDate(b.e) ? String(b.e) : today;
        if (/^\d{4}-\d{2}-\d{2}$/.test(String(it.d)) && e < it.d) { err = "That date is before the start date (" + it.d + ")."; return false; }
        it.status = "resolved"; it.e = e; it.checkedAt = today;
      } else if (b.status === "none") {
        delete it.status;
      } else { err = "Unknown status."; return false; }
    }, ctx);
    return json(err ? { ok: false, error: err } : { ok: true });
  }
  if (b.action === "addUpdate") {
    const text = String(b.text || "").replace(/\s+/g, " ").trim().slice(0, 300);
    if (!text) return json({ ok: false, error: "Type the update first." });
    let found = false;
    await mutateDoc(env, "pub", pub => { const it = findAnywhere(pub, b.id); found = !!it; if (!it) return false; addUpdate(it, validDate(b.d) ? String(b.d) : today, text); }, ctx);
    return json(found ? { ok: true } : NOT_PUB);
  }
  if (b.action === "removeUpdate") {
    await mutateDoc(env, "pub", pub => {
      const it = findAnywhere(pub, b.id); if (!it || !Array.isArray(it.updates)) return false;
      const n = it.updates.length;
      it.updates = it.updates.filter(u => !(u.d === b.d && u.text === b.text));
      if (it.updates.length === n) return false;
    }, ctx);
    return json({ ok: true });
  }
  if (b.action === "addEntry") {
    const e = b.entry || {};
    const kind = e.kind === "report" ? "report" : "incident";
    const title = String(e.s || "").trim().slice(0, 140);
    const d = validDate(e.d) ? String(e.d) : "";
    if (!title || !d) return json({ ok: false, error: "A title and a start date are needed." });
    const end = validDate(e.e) ? String(e.e) : "";
    if (end && end < d) return json({ ok: false, error: "The end date is before the start date." });
    const cat = CATS.includes(e.cat) && e.cat !== "you" ? e.cat : "other";
    const state = e.status === "open" ? "open" : e.status === "resolved" ? "resolved" : "";
    let v;
    if (kind === "report") v = { id: id(), d: d, title: title, text: String(e.x || "").slice(0, 2000), where: cleanFloors(e.w), cat: cat, img: [], anon: true, name: "", at: new Date().toISOString(), stack: "", via: "admin" };
    else v = { id: id(), d: d, e: end, c: cat, t: ["U", "S", "N"].includes(e.t) ? e.t : "U", s: title, x: String(e.x || "").slice(0, 2000), w: cleanFloors(e.w), g: "", dur: String(e.dur || "").slice(0, 60), src: "admin", img: [] };
    if (state === "open" && (kind === "report" || v.t === "U")) { v.status = "open"; v.e = ""; v.confirmed = today; }
    else if (state === "resolved") { v.status = "resolved"; v.e = end || d; }
    else if (end) v.e = end;
    await mutateDoc(env, "pub", pub => { if (findAnywhere(pub, v.id)) return false; pub[kind === "report" ? "reports" : "incidents"].unshift(v); }, ctx);
    return json({ ok: true, id: v.id });
  }
  if (b.action === "publishHeld") return json(await publishHeldItem(env, String(b.id || ""), ctx));
  if (b.action === "dropHeld") {
    await mutateDoc(env, "held", list => { const i = list.findIndex(x => x.id === b.id); if (i < 0) return false; list.splice(i, 1); }, ctx);
    return json({ ok: true });
  }
  if (b.action === "setBanner") {
    const text = String(b.text || "").replace(/\s+/g, " ").trim().slice(0, 300);
    let banner = null;
    await mutateDoc(env, "pub", pub => { if (text) pub.banner = { text: text, at: new Date().toISOString() }; else delete pub.banner; banner = pub.banner || null; }, ctx);
    return json({ ok: true, banner: banner });
  }
  return json({ ok: false, error: "Unknown action" }, 400);
}
// Photos uploaded before thumbnails existed: the review page makes a small copy in the browser and sends it here
async function adminThumbList(request, env) {
  if (!(await isAdmin(request, env))) return json({ ok: false, error: "Not signed in" }, 401);
  const names = [];
  let cursor;
  for (let i = 0; i < 20; i++) {
    const r = await env.DB.list({ prefix: "img:", cursor: cursor });
    for (const k of r.keys) names.push(k.name);
    if (r.list_complete || !r.cursor) break;
    cursor = r.cursor;
  }
  const have = new Set(names.filter(n => n.endsWith(":t")).map(n => n.slice(0, -2)));
  return json({ ok: true, ids: names.filter(n => !n.endsWith(":t") && !have.has(n)).map(n => n.slice(4)) });
}
async function adminThumb(request, env) {
  if (!(await isAdmin(request, env))) return json({ ok: false, error: "Not signed in" }, 401);
  let b; try { b = await request.json(); } catch (e) { return json({ ok: false, error: "Bad JSON" }, 400); }
  const iid = String(b.id || "").replace(/[^a-z0-9-]/gi, "");
  const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(b.data || ""));
  if (!iid || !m) return json({ ok: false, error: "Bad thumbnail" }, 400);
  if (!(await env.DB.get("img:" + iid, "arrayBuffer"))) return json({ ok: false, error: "No such photo" }, 404);
  const bytes = Uint8Array.from(atob(m[2]), c => c.charCodeAt(0));
  if (bytes.length > 300000) return json({ ok: false, error: "Too large" }, 400);
  await env.DB.put("img:" + iid + ":t", bytes, { metadata: { ct: m[1] } });
  return json({ ok: true });
}
async function adminImport(request, env, ctx) {
  const h = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type,X-Import-Key" };
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: h });
  if (request.method !== "POST") return new Response(JSON.stringify({ ok: false, error: "POST only" }), { status: 405, headers: Object.assign({ "Content-Type": "application/json" }, h) });
  if (!env.IMPORT_KEY || request.headers.get("X-Import-Key") !== env.IMPORT_KEY) return new Response(JSON.stringify({ ok: false, error: "Not allowed" }), { status: 401, headers: Object.assign({ "Content-Type": "application/json" }, h) });
  let body; try { body = await request.json(); } catch (e) { return new Response(JSON.stringify({ ok: false, error: "Bad JSON" }), { status: 400, headers: Object.assign({ "Content-Type": "application/json" }, h) }); }
  const items = Array.isArray(body.items) ? body.items.slice(0, 200) : [];
  const ready = [];
  for (const it of items) {
    const kind = it.kind === "incident" ? "incident" : "report";
    const title = String(it.s || it.title || "").trim().slice(0, 140);
    const d = cleanDate(it.d);
    if (!title || !d) { ready.push(null); continue; }
    const imgs = [];
    for (const dataUrl of (Array.isArray(it.images) ? it.images.slice(0, 4) : [])) {
      const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(dataUrl || ""));
      if (!m) continue;
      const bytes = Uint8Array.from(atob(m[2]), c => c.charCodeAt(0));
      if (bytes.length > 1500000) continue;
      const iid = id(); await env.DB.put("img:" + iid, bytes, { metadata: { ct: m[1] } }); imgs.push(iid);
    }
    const base = { id: id(), kind: kind, at: new Date().toISOString(), status: "pending", img: imgs, contact: String(it.source || "import").slice(0, 60), note: String(it.note || "").slice(0, 300), stack: "", copies: Math.max(1, parseInt(it.reporters, 10) || 1), src: String(it.source || "import").slice(0, 20), d: d };
    if (kind === "incident") {
      Object.assign(base, { c: CATS.includes(it.c) ? it.c : "other", t: ["U", "S", "N"].includes(it.t) ? it.t : "U", s: title, x: String(it.x || it.text || "").slice(0, 2000), w: cleanFloors(it.w || it.where), g: "", cat: CATS.includes(it.c) ? it.c : "other" });
    } else {
      Object.assign(base, { title: title, text: String(it.text || it.x || "").slice(0, 2000), where: cleanFloors(it.where || it.w), cat: CATS.includes(it.cat) ? it.cat : "other", anon: true, name: "" });
    }
    ready.push(base);
  }
  let added = 0, skipped = 0, total = 0;
  await mutateDoc(env, "pend", pend => {
    added = 0; skipped = 0;
    for (const base of ready) {
      if (!base) { skipped++; continue; }
      const title = base.s || base.title;
      if (pend.some(p => (p.s || p.title) === title && p.d === base.d)) { skipped++; continue; }
      pend.push(base); added++;
    }
    total = pend.length;
    if (!added) return false;
  }, ctx);
  return new Response(JSON.stringify({ ok: true, added: added, skipped: skipped, pending: total }), { headers: Object.assign({ "Content-Type": "application/json" }, h) });
}
async function admin(request, env) {
  if (!(await isAdmin(request, env))) {
    return html("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Review sign-in</title><style>body{font-family:system-ui,sans-serif;max-width:420px;margin:80px auto;padding:0 20px;color:#1B2430}label{display:block;font-size:14px;margin:14px 0 4px}input{font:inherit;width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #AEB7C2;border-radius:8px}button{font:inherit;padding:10px 16px;border-radius:8px;border:1px solid #1B2430;background:#1B2430;color:#fff;cursor:pointer;margin-top:18px}p.small{font-size:13px;color:#5D6877}</style><h1>Review submissions</h1><form method=post action='/admin/login'><label for=u>Username</label><input id=u name=user autocomplete=username required><label for=p>Password</label><input id=p name=pass type=password autocomplete=current-password required><button>Sign in</button></form><p class=small>Signed-in sessions last 7 days.</p>");
  }
  return html(ADMIN_HTML);
}

const ADMIN_HTML = String.raw`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Review submissions</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#F4F6F8;color:#1B2430}
header{background:#16202B;color:#fff;padding:14px 20px;font-weight:600;display:flex;justify-content:space-between;align-items:center}
header a{color:#cbd5e1;text-decoration:none;font-weight:400;font-size:14px}
main{max-width:920px;margin:0 auto;padding:20px}
h2{font-size:18px;margin:26px 0 10px}
.item{background:#fff;border:1px solid #D8DDE3;border-radius:10px;padding:16px;margin:0 0 14px;display:grid;grid-template-columns:1fr 200px;gap:16px}
.item.pub,.item.row{grid-template-columns:1fr}
.meta{color:#5D6877;font-size:13px;margin:0 0 8px}
label{display:block;font-size:12px;color:#5D6877;margin:8px 0 3px}
input,select,textarea{font:inherit;font-size:14px;width:100%;box-sizing:border-box;border:1px solid #AEB7C2;border-radius:6px;padding:6px 8px;background:#fff}
input[type=date]{max-width:170px}
textarea{min-height:80px}
.row{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap;align-items:center}
.row label{margin:0}
button{font:inherit;font-size:14px;padding:8px 14px;border-radius:8px;border:1px solid #1B2430;background:#1B2430;color:#fff;cursor:pointer}
button.secondary{background:#fff;color:#1B2430}
button.danger{background:#fff;color:#B91C1C;border-color:#B91C1C}
button.small{font-size:13px;padding:5px 10px}
button.link{background:none;border:none;color:#1D4ED8;padding:0 4px;font-size:13px;text-decoration:underline}
button:disabled{opacity:.6;cursor:default}
.thumbs img{width:100%;border-radius:8px;margin-bottom:8px;display:block}
.empty{color:#5D6877;padding:12px 0}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:#16202B;color:#fff;padding:10px 16px;border-radius:8px;font-size:14px;box-shadow:0 6px 20px rgba(0,0,0,.25);opacity:0;transition:opacity .2s;pointer-events:none;z-index:20}
.toast.on{opacity:1}
.item.flash{box-shadow:0 0 0 3px #C98A1B;transition:box-shadow .3s}
.pinned-flash{background:#FFF1B8;border-radius:6px;padding:2px 6px;transition:background .3s}
.status{font-size:14px;margin:10px 0 0;padding:10px 12px;border-radius:8px;background:#F4F6F8}
.status.open{background:#FDECEC}
.status strong{font-weight:600}
.chip{display:inline-block;font-size:12px;font-weight:600;padding:2px 8px;border-radius:99px;background:#E7EBF0;color:#1B2430;margin-left:8px;vertical-align:2px}
.chip.open{background:#B91C1C;color:#fff}
.updates{margin:8px 0 0;padding-left:18px;font-size:13px;color:#384250}
.updates li{margin:2px 0}
details.box{background:#fff;border:1px solid #D8DDE3;border-radius:10px;padding:12px 16px;margin:0 0 14px}
details.box summary{cursor:pointer;font-weight:600}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
.gate{display:inline-block;background:#EEF2FF;color:#3730A3;border-radius:6px;padding:1px 6px}
#thumbState{font-size:13px;color:#5D6877;margin:0}
@media (max-width:700px){.item{grid-template-columns:1fr}.grid3{grid-template-columns:1fr 1fr}main{padding:14px}}
</style></head><body>
<header><span>Review submissions</span><span><a href="https://atlanticstreetresidents.com/">Site</a> &nbsp; <a href="/admin/logout">Sign out</a></span></header>
<div class="toast" id="toast" role="status" aria-live="polite"></div>
<main>
<p id="thumbState" aria-live="polite"></p>
<h2>Waiting for review <span id="pc"></span> <button class="secondary small" style="margin-left:12px" data-do="approveAll">Approve everything waiting</button></h2>
<div id="pending"></div>
<h2>Still going <span id="oc"></span></h2>
<p class="meta">Everything the site shows as still out, with a day count. Mark each one when it's fixed. Anything with no news for 3 days also gets a check-in email with the same two choices.</p>
<div id="openList"></div>
<details class="box" id="heldBox"><summary>Building emails not posted <span id="hc"></span></summary>
<p class="meta">Rent, parking, event and other announcements are kept off the site, and so is anything that names a person, unit or car. If one of these should be on the site, post it.</p>
<div id="held"></div></details>
<details class="box" id="addBox"><summary>Add an entry</summary>
<div class="grid3"><div><label for="nKind">Kind</label><select id="nKind"><option value="U">Outage</option><option value="S">Planned work</option><option value="N">Announcement</option><option value="report">Building issue (resident report)</option></select></div>
<div><label for="nCat">Category</label><select id="nCat"></select></div>
<div><label for="nW">Where</label><select id="nW"></select></div></div>
<label for="nS">Title</label><input id="nS" placeholder="e.g. Elevator out of service">
<label for="nX">Details</label><textarea id="nX" style="min-height:60px"></textarea>
<div class="grid3"><div><label for="nD">Started</label><input id="nD" type="date"></div>
<div><label for="nState">Still going?</label><select id="nState"><option value="open">Yes, still going</option><option value="resolved">No, it's fixed</option><option value="">Doesn't apply</option></select></div>
<div><label for="nE">Ended (optional)</label><input id="nE" type="date"></div></div>
<div class="row"><button data-do="addEntry">Add to the site</button></div></details>
<h2>Active now banner</h2>
<div class="item pub"><div><p class="meta">"Active now" on the site lists everything marked still going, plus outages from the last 3 days and building issues from the last 7 days that have no status. Per item, use the Banner setting below to force something in or out. To replace the whole list with your own wording, type it here; leave it empty to go back to automatic.</p>
<label for="bannerText">Custom banner text (optional)</label><textarea id="bannerText" style="min-height:52px"></textarea>
<div class="row"><button data-do="saveBanner">Save banner</button><span id="bannerState" class="meta" style="margin:0"></span></div>
<div id="bannerNow" style="margin-top:12px;font-size:14px"></div></div></div>
<h2>Published (edit and save, or unpublish) <span id="pubc"></span></h2>
<div style="margin:0 0 12px"><label for="pubq">Search published items</label><input id="pubq" placeholder="e.g. Tesla, elevator, garage" style="max-width:420px"></div>
<div id="published"></div>
</main>
<script>
var CATS={water:"Hot water & plumbing",hvac:"Heating & cooling",elev:"Elevators",win:"Windows & exterior",fire:"Fire & life safety",amen:"Amenities & systems",garage:"Garage & common areas",pm:"Preventive maintenance",clean:"Cleaning",you:"Resident tickets",other:"Other"};
var CATS_NOTICKET={};Object.keys(CATS).forEach(function(k){if(k!=="you")CATS_NOTICKET[k]=CATS[k];});
var WHERE=["Upper floors","Floors 6–16","Floors 17–26","Whole building","Garage","Amenities","Exterior","Lobby"];
var TYPES={U:"Outage",S:"Planned work",N:"Announcement"};
var MON=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
var D={pending:[],incidents:[],reports:[],held:[]},BY={},TODAY=new Date().toISOString().slice(0,10);
function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
function opt(list,sel){return Object.keys(list).map(function(k){return '<option value="'+k+'"'+(k===sel?' selected':'')+'>'+esc(list[k])+'</option>';}).join("");}
function wopt(sel){var l=WHERE.slice();if(sel&&l.indexOf(sel)<0)l.unshift(sel);return l.map(function(w){return '<option'+(w===sel?' selected':'')+'>'+esc(w)+'</option>';}).join("");}
function isDate(v){return /^\d{4}-\d{2}-\d{2}$/.test(String(v||""));}
function fmtD(d){var m=/^(\d{4})-(\d{2})-(\d{2})$/.exec(d||"");if(!m)return d||"";var s=MON[+m[2]-1]+" "+(+m[3]);return m[1]===TODAY.slice(0,4)?s:s+", "+m[1];}
function days(a,b){return Math.round((Date.parse(b+"T12:00:00Z")-Date.parse(a+"T12:00:00Z"))/86400000);}
function isRep(it){return it.title!==undefined;}
function lastConf(it){var l=it.confirmed||"";(it.updates||[]).forEach(function(u){if(u&&u.d>l)l=u.d;});return l;}
function post(body){return fetch("/admin/act",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}).then(function(r){return r.json();});}
function toast(msg){var t=document.getElementById("toast");t.textContent=msg;t.classList.add("on");clearTimeout(t._h);t._h=setTimeout(function(){t.classList.remove("on");},2800);}
function flash(iid){var c=document.querySelector('#published .item[data-id="'+iid+'"]')||document.querySelector('.item[data-id="'+iid+'"]');if(c){c.classList.add("flash");setTimeout(function(){c.classList.remove("flash");},3000);}}
function loadFailed(why){document.getElementById("pending").innerHTML='<p class="empty">The review page could not load ('+esc(why)+'). Reload in a minute.</p>';}
function load(){
  return fetch("/admin/list").then(function(r){if(r.status===401){location.href="/admin";return null;}return r.json().catch(function(){return {ok:false};});}).then(function(d){
    if(!d)return;
    if(!d.ok){loadFailed(d.error||"server error");return;}
    D=d;TODAY=d.today||TODAY;BY={};
    d.incidents.concat(d.reports).forEach(function(x){BY[x.id]=x;});
    d.pending.forEach(function(x){BY["p:"+x.id]=x;});
    document.getElementById("pc").textContent="("+d.pending.length+")";
    document.getElementById("pending").innerHTML=d.pending.length?d.pending.map(card).join(""):'<p class="empty">Nothing waiting. New submissions also arrive by email with approve and reject links.</p>';
    var open=d.incidents.concat(d.reports).filter(function(x){return x.status==="open";}).sort(function(a,b){return String(a.d).localeCompare(String(b.d));});
    document.getElementById("oc").textContent="("+open.length+")";
    document.getElementById("openList").innerHTML=open.length?open.map(openRow).join(""):'<p class="empty">Nothing is marked as still going.</p>';
    var held=d.held||[];
    document.getElementById("hc").textContent="("+held.length+")";
    document.getElementById("held").innerHTML=held.length?held.map(heldRow).join(""):'<p class="empty">None so far.</p>';
    document.getElementById("bannerText").value=(d.banner&&d.banner.text)||"";
    document.getElementById("bannerState").textContent=(d.banner&&d.banner.text)?"Custom text is showing on the site.":"Automatic.";
    renderBannerNow(d);
    window.__pubItems=d.incidents.concat(d.reports).sort(function(a,b){return String(b.d||"").localeCompare(String(a.d||""))||String(b.at||"").localeCompare(String(a.at||""));});
    renderPublished();
  }).catch(function(e){loadFailed(e&&e.message?e.message:"network error");});
}
function kindOf(it){
  if(isRep(it))return "building issue";
  if(it.c==="you")return "resident ticket";
  var t=TYPES[it.t]?TYPES[it.t].toLowerCase():"entry";
  return t+(it.src==="discord"?" (from Discord)":it.src==="admin"?" (added here)":it.via==="resident"?" (forwarded)":it.src==="email"?" (building email)":"");
}
function statusBox(it){
  var rep=isRep(it),show=rep||it.status||(it.c!=="you"&&it.t==="U");
  if(!show)return "";
  var line;
  if(it.status==="open"){var n=days(String(it.d).slice(0,10),TODAY)+1,l=lastConf(it);line="<strong>Still going</strong> since "+esc(fmtD(it.d))+" · day "+n+(l&&l!==it.d?" · last confirmed "+esc(fmtD(l)):"");}
  else if(it.status==="resolved")line="<strong>Resolved</strong> "+esc(fmtD(it.e||it.d))+(it.dur?" ("+esc(it.dur)+")":"");
  else if(it.e)line="Ended "+esc(fmtD(it.e))+" (no status set)";
  else line="No status: the site shows it on "+esc(fmtD(it.d))+" only";
  var ups=(it.updates||[]).slice().sort(function(a,b){return String(b.d).localeCompare(String(a.d));});
  return '<div class="status'+(it.status==="open"?" open":"")+'">'+line+
    '<div class="row" style="margin-top:8px"><button class="small'+(it.status==="open"?" secondary":"")+'" data-do="still">Still out</button><span class="meta" style="margin:0">or fixed on</span><input type="date" name="fixedOn" value="'+TODAY+'" max="'+TODAY+'" aria-label="Fixed on"><button class="small secondary" data-do="fixed">Mark resolved</button></div>'+
    (ups.length?'<ul class="updates">'+ups.map(function(u){return '<li>'+esc(fmtD(u.d))+': '+esc(u.text)+' <button class="link" data-do="rmUpdate" data-d="'+esc(u.d)+'" data-text="'+esc(u.text)+'">remove</button></li>';}).join("")+'</ul>':'')+
    '<div class="row" style="margin-top:8px"><input name="upd" placeholder="Add an update, e.g. Part arrived; repair set for Friday" style="flex:1;min-width:200px"><button class="small secondary" data-do="addUpdate">Add update</button></div></div>';
}
function openRow(it){
  var where=it.w||it.where||"";
  return '<div class="item row" data-id="'+esc(it.id)+'"><div><a href="#pub-'+esc(it.id)+'" style="color:inherit"><strong>'+esc(it.s||it.title)+'</strong></a>'+(where?' <span class="meta">('+esc(where)+')</span>':'')+statusBox(it)+'</div></div>';
}
function heldRow(h){
  return '<div class="item row" data-id="'+esc(h.id)+'"><div><p class="meta">'+esc(fmtD(h.d))+' · held as <span class="gate">'+esc(h.why)+'</span></p><strong>'+esc(h.s)+'</strong>'+(h.x?'<p class="meta" style="margin-top:6px">'+esc(h.x)+'</p>':'')+
    '<div class="row"><button class="small" data-do="postHeld">Post it on the site</button><button class="small danger" data-do="dropHeld">Remove from this list</button></div></div></div>';
}
function card(it){
  var kind=(it.src==="discord"?"Discord ":"")+(it.kind==="report"?"Report":(it.kind==="incident"?(it.via===""?"Building email":"Notice"):"Ticket"));
  var who=it.kind==="report"?(it.anon?"anonymous":(it.name||"no name")):"";
  var state=it.state||"";
  return '<div class="item" data-id="'+esc(it.id)+'" data-pending="1"><div>'+
   '<p class="meta">'+kind+(who?" from "+esc(who):"")+' filed '+esc(String(it.at||"").slice(0,16).replace("T"," "))+(it.stack?' from the '+esc(it.stack)+' line':'')+(it.contact?' (from: '+esc(it.contact)+')':'')+(it.copies>1?' · reported by '+it.copies+' people':'')+(it.lang==="es"?' · sent in Spanish':'')+(it.note?'<br>Note from sender: '+esc(it.note):'')+(it.gate?'<br>Why it is here: <span class="gate">'+esc(it.gate)+'</span>':'')+'</p>'+
   '<label>Title</label><input name="s" value="'+esc(it.s||it.title)+'">'+
   '<label>Description</label><textarea name="x">'+esc(it.x||it.text)+'</textarea>'+
   '<div class="grid3"><div><label>Category</label><select name="cat">'+opt(CATS_NOTICKET,it.kind==="incident"?(it.c||it.cat):it.cat)+'</select></div><div><label>Where</label><select name="w">'+wopt(it.w||it.where)+'</select></div><div><label>Date</label><input name="d" value="'+esc(it.d)+'"></div></div>'+
   '<div class="grid3">'+(it.kind==="incident"?'<div><label>Type</label><select name="t">'+opt(TYPES,it.t||"N")+'</select></div>':'')+
   ('<div><label>Still happening?</label><select name="state"><option value="open"'+(state==="open"?" selected":"")+'>Yes, still going</option><option value="resolved"'+(state==="resolved"?" selected":"")+'>No, fixed</option><option value=""'+(state===""?" selected":"")+'>Not sure / doesn\'t apply</option></select></div><div><label>Fixed on (optional)</label><input type="date" name="end" value="'+esc(it.end||"")+'"></div>')+'</div>'+
   '<div class="row"><button data-do="approve">Approve and publish</button><button class="danger" data-do="reject">Reject</button></div>'+
   '</div><div class="thumbs">'+(it.img||[]).map(function(i){return '<a href="/img/'+esc(i)+'" target="_blank"><img src="/img/'+esc(i)+'?s=t" alt="Photo"></a>';}).join("")+'</div></div>';
}
function pubCard(it){
  var rep=isRep(it);
  var cat=rep?it.cat:(it.c==="you"?it.cat:it.c);
  return '<div class="item pub" data-id="'+esc(it.id)+'" id="pub-'+esc(it.id)+'"><div><p class="meta">'+esc(it.d)+' · '+esc(kindOf(it))+(it.name?" from "+esc(it.name):"")+(it.copies>1?" (reported by "+it.copies+" people)":"")+'</p><strong>'+esc(it.s||it.title)+'</strong>'+(it.status==="open"?'<span class="chip open">Still going</span>':'')+
   statusBox(it)+
   '<label>Title</label><input name="s" value="'+esc(it.s||it.title)+'">'+
   '<label>Description</label><textarea name="x">'+esc(it.x||it.text)+'</textarea>'+
   '<div class="grid3"><div><label>Category</label><select name="cat">'+opt(CATS_NOTICKET,cat)+'</select></div><div><label>Where</label><select name="w">'+wopt(it.w||it.where)+'</select></div><div><label>Date</label><input name="d" value="'+esc(it.d)+'"></div></div>'+
   (!rep&&it.c!=="you"?'<div class="grid3"><div><label>Type</label><select name="t">'+opt(TYPES,it.t||"N")+'</select></div></div>':'')+
   '<div class="row"><label>'+(rep?"Resolved on":"Ended on")+'</label><input name="e" style="max-width:150px" value="'+esc(it.e||"")+'" placeholder="YYYY-MM-DD"><button class="secondary" data-do="setEnd">'+(rep?"Save resolved date":"Save end date")+'</button></div>'+
   '<div class="row"><span class="meta" style="margin:0">Banner: '+bannerState(it)+'</span>'+
   (it.banner==="pin"?'<button class="secondary" data-do="banner" data-mode="hide">Remove from banner</button><button class="secondary" data-do="banner" data-mode="">Set automatic</button>':
   '<label>Until (optional)</label><input name="pu" style="max-width:150px" value="" placeholder="YYYY-MM-DD"><button data-do="banner" data-mode="pin">Add to banner</button>'+(it.banner==="hide"?'<button class="secondary" data-do="banner" data-mode="">Set automatic</button>':'<button class="secondary" data-do="banner" data-mode="hide">Never show</button>'))+'</div>'+
   '<div class="row"><button data-do="save">Save changes</button><button class="danger" data-do="unpub">Unpublish</button></div></div></div>';
}
function bannerState(it){
  if(it.banner==="hide")return "never shown";
  if(it.banner==="pin")return "showing"+(it.pinUntil?" until "+esc(it.pinUntil):" (no expiration)");
  return "automatic";
}
function renderPublished(){
  var q=(document.getElementById("pubq").value||"").trim().toLowerCase();
  var items=(window.__pubItems||[]).filter(function(it){if(!q)return true;var hay=((it.s||it.title||"")+" "+(it.x||it.text||"")+" "+(it.w||it.where||"")+" "+(it.d||"")).toLowerCase().replace(/[–—]/g,"-");return hay.indexOf(q.replace(/[–—]/g,"-"))>=0;});
  document.getElementById("pubc").textContent="("+items.length+(q?" of "+(window.__pubItems||[]).length:"")+")";
  document.getElementById("published").innerHTML=items.length?items.map(pubCard).join(""):'<p class="empty">'+(q?"Nothing matches that search.":"Nothing published yet.")+'</p>';
}
document.getElementById("pubq").addEventListener("input",renderPublished);
function renderBannerNow(d){
  function daysAgo(x){return days(String(x).slice(0,10),TODAY);}
  function isPinned(x){return x.banner==="pin"&&(!x.pinUntil||x.pinUntil>=TODAY);}
  var all=d.incidents.map(function(x){return {kind:"incident",x:x};}).concat(d.reports.map(function(x){return {kind:"report",x:x};}));
  var pinned=all.filter(function(o){return isPinned(o.x);});
  var auto=all.filter(function(o){var x=o.x;if(x.banner==="hide"||isPinned(x)||!x.d||String(x.d)>TODAY)return false;if(x.status==="open")return true;if(x.status)return false;var a=daysAgo(x.d);return o.kind==="incident"?(x.t==="U"&&!x.e&&a<=3):(!x.e&&a<=7);});
  function name(o){return esc(o.x.s||o.x.title)+(o.x.pinUntil?" (until "+esc(o.x.pinUntil)+")":(o.x.banner==="pin"?" (no expiration)":""));}
  var h=(d.banner&&d.banner.text)?'<p class="meta">Custom text is showing first, followed by up to three of the items below.</p>':'';
  h+='<p style="margin:6px 0"><span id="pinnedLine"><strong>Pinned:</strong> '+(pinned.length?pinned.map(name).join("; "):"none")+'</span></p>';
  h+='<p style="margin:6px 0"><strong>Automatic right now:</strong> '+(auto.length?auto.map(name).join("; "):"none")+'</p>';
  h+='<p class="meta">The site shows up to four items, most recently confirmed first.</p>';
  document.getElementById("bannerNow").innerHTML=h;
}
function val(el,n){var f=el.querySelector('[name='+n+']');return f?f.value:null;}
function after(r,msg,iid){if(!r||!r.ok){alert((r&&r.error)||"That didn't work. Try again.");return load();}return load().then(function(){if(msg)toast(msg);if(iid)flash(iid);});}
var ACT={
  approveAll:function(){if(!confirm("Approve and publish every item waiting for review?"))return;return post({action:"approveAll"}).then(function(r){return after(r,(r.approved||0)+" published");});},
  approve:function(b,el,iid){return modPending(b,el,iid,"approve");},
  reject:function(b,el,iid){return modPending(b,el,iid,"reject");},
  still:function(b,el,iid){return post({action:"setStatus",id:iid,status:"open"}).then(function(r){return after(r,"Marked as still out",iid);});},
  fixed:function(b,el,iid){var e=val(el,"fixedOn")||TODAY;if(!isDate(e)){alert("Pick the date it was fixed.");return;}return post({action:"setStatus",id:iid,status:"resolved",e:e}).then(function(r){return after(r,"Marked as resolved on "+fmtD(e),iid);});},
  addUpdate:function(b,el,iid){var t=(val(el,"upd")||"").trim();if(!t){alert("Type the update first.");return;}return post({action:"addUpdate",id:iid,text:t}).then(function(r){return after(r,"Update added",iid);});},
  rmUpdate:function(b,el,iid){if(!confirm("Remove this update?"))return;return post({action:"removeUpdate",id:iid,d:b.getAttribute("data-d"),text:b.getAttribute("data-text")}).then(function(r){return after(r,"Update removed",iid);});},
  save:function(b,el,iid){var edit={s:val(el,"s"),x:val(el,"x"),cat:val(el,"cat"),w:val(el,"w"),d:val(el,"d")};var t=val(el,"t");if(t)edit.t=t;return post({action:"editPub",id:iid,edit:edit}).then(function(r){return after(r,"Saved",iid);});},
  unpub:function(b,el,iid){if(!confirm("Remove this from the public site?"))return;return post({action:"unpublish",id:iid}).then(function(r){return after(r,"Unpublished");});},
  setEnd:function(b,el,iid){var e=(val(el,"e")||"").trim();if(e&&!isDate(e)){alert("Use a date like 2026-10-20, or leave it empty.");return;}return post({action:"setEnd",id:iid,e:e}).then(function(r){return after(r,e?"End date saved":"End date cleared",iid);});},
  banner:function(b,el,iid){var mode=b.getAttribute("data-mode"),pu=el.querySelector("[name=pu]"),until=(mode==="pin"&&pu)?pu.value.trim():"";if(mode==="pin"&&until&&!isDate(until)){alert("Use a date like 2026-09-30, or leave it empty for no expiration.");return;}var msg=mode==="pin"?("Added to the banner"+(until?" until "+until:" (no expiration)")):(mode==="hide"?"Removed from the banner":"Set to automatic");return post({action:"editPub",id:iid,edit:{banner:mode,pinUntil:until}}).then(function(r){return after(r,msg,iid).then(function(){var pl=document.getElementById("pinnedLine");if(pl){pl.classList.add("pinned-flash");setTimeout(function(){pl.classList.remove("pinned-flash");},3000);}});});},
  saveBanner:function(){var t=document.getElementById("bannerText").value;return post({action:"setBanner",text:t}).then(function(r){return after(r,r&&r.banner?"Custom banner saved":"Banner set to automatic");});},
  postHeld:function(b,el,iid){if(!confirm("Post this building email on the site?"))return;return post({action:"publishHeld",id:iid}).then(function(r){return after(r,"Posted. Edit it below if needed.");});},
  dropHeld:function(b,el,iid){return post({action:"dropHeld",id:iid}).then(function(r){return after(r,"Removed from the list");});},
  addEntry:function(){
    var k=document.getElementById("nKind").value,s=document.getElementById("nS").value.trim(),dd=document.getElementById("nD").value,e=document.getElementById("nE").value;
    if(!s||!isDate(dd)){alert("Add a title and the start date.");return;}
    if(e&&e<dd){alert("The end date is before the start date.");return;}
    var entry={kind:k==="report"?"report":"incident",t:k==="report"?"":k,s:s,x:document.getElementById("nX").value,cat:document.getElementById("nCat").value,w:document.getElementById("nW").value,d:dd,e:e,status:document.getElementById("nState").value};
    return post({action:"addEntry",entry:entry}).then(function(r){if(r&&r.ok){document.getElementById("nS").value="";document.getElementById("nX").value="";document.getElementById("nE").value="";}return after(r,"Added to the site",r&&r.id);});
  }
};
function modPending(b,el,iid,action){
  var edit={s:val(el,"s"),x:val(el,"x"),cat:val(el,"cat"),w:val(el,"w"),d:val(el,"d")};
  var t=val(el,"t");if(t)edit.t=t;
  var st=val(el,"state");if(st!==null)edit.state=st;
  var en=val(el,"end");if(en!==null)edit.e=en;
  return post({action:action,id:iid,edit:edit}).then(function(r){return after(r,action==="approve"?"Published":"Rejected");});
}
document.addEventListener("click",function(ev){
  var b=ev.target.closest("[data-do]");if(!b)return;
  var f=ACT[b.getAttribute("data-do")];if(!f)return;
  ev.preventDefault();
  var el=b.closest("[data-id]"),iid=el?el.getAttribute("data-id"):"";
  b.disabled=true;
  Promise.resolve(f(b,el,iid)).then(function(){b.disabled=false;},function(){b.disabled=false;alert("That didn't work. Check your connection and try again.");});
});
document.getElementById("nCat").innerHTML=opt(CATS_NOTICKET,"elev");
document.getElementById("nW").innerHTML=wopt("Whole building");
// Photos sent before thumbnails existed: make a small copy here once, so the public page loads faster
function makeThumbs(){
  fetch("/admin/thumbs").then(function(r){return r.json();}).then(function(d){
    if(!d||!d.ok||!d.ids||!d.ids.length)return;
    var ids=d.ids.slice(0,80),i=0,done=0,st=document.getElementById("thumbState");
    function next(){
      if(i>=ids.length){st.textContent=done?"Made "+done+" photo previews.":"";setTimeout(function(){st.textContent="";},5000);return;}
      var iid=ids[i++];st.textContent="Making small photo previews: "+i+" of "+ids.length;
      var img=new Image();
      img.onload=function(){
        try{var s=Math.min(1,480/Math.max(img.naturalWidth,img.naturalHeight)),c=document.createElement("canvas");c.width=Math.max(1,Math.round(img.naturalWidth*s));c.height=Math.max(1,Math.round(img.naturalHeight*s));c.getContext("2d").drawImage(img,0,0,c.width,c.height);
          fetch("/admin/thumb",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:iid,data:c.toDataURL("image/jpeg",0.72)})}).then(function(r){return r.json();}).then(function(r){if(r&&r.ok)done++;next();},next);
        }catch(e){next();}
      };
      img.onerror=next;img.src="/img/"+encodeURIComponent(iid);
    }
    next();
  }).catch(function(){});
}
load().then(function(){document.getElementById("nD").value=TODAY;if(location.hash){var t=document.querySelector(location.hash);if(t)t.scrollIntoView();}setTimeout(makeThumbs,800);});
</script></body></html>`;

// ---------- email ingestion ----------
const IGNORE_SENDERS = /noreply@google\.com|forwarding-noreply|mailer-daemon|postmaster@|no-reply@cloudflare|noreply@github|@squarespace\.com|@proton\.me.*notify|noreply@atlanticstreetresidents/i;
const BUILDING = /rentcafe\.com|greystar\.com|bozzuto\.com|atlantic ?station/i;

function trustedList(env) {
  return String(env.TRUSTED_SENDERS || env.OWNER_EMAIL || "").toLowerCase().split(/[,\s]+/).filter(Boolean);
}
// Only the envelope sender counts: the From line and the forwarding headers are written by whoever sends the mail.
// Gmail's auto-forward sends as you+caf_=...@gmail.com, so a +tag is ignored.
function isTrusted(env, parsed, message) {
  const t = trustedList(env);
  const from = String(message.from || "").trim().toLowerCase().replace(/^<|>$/g, "");
  const m = /^([^@+\s]+)(?:\+[^@\s]*)?@([^@\s]+)$/.exec(from);
  return !!(t.length && m && (t.includes(m[1] + "@" + m[2]) || t.includes(from)));
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
    else if (k === "date" || k === "sent") { const d = looseDate(v); if (d) out.date = d; }
    i++;
  }
  if (seen) out.body = lines.slice(i).join("\n").trim();
  return out;
}
// A forwarded "Date:" line; Gmail and Outlook give no time zone, and the time they show is New York's
function looseDate(v) {
  const s = String(v || "").replace(/ at /i, " ").replace(/\s+\(.*\)$/, "").trim();
  const d = new Date(s);
  if (isNaN(d.getTime())) return null;
  if (/\b(GMT|UTC|UT|[ECMP][SD]T)\b|[+-]\d{2}:?\d{2}\b|\dZ\b/i.test(s)) return d;
  const t = d.getTime();
  const p = new Intl.DateTimeFormat("en-US", { timeZone: "America/New_York", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }).formatToParts(d);
  const g = k => +p.find(x => x.type === k).value;
  const offset = Date.UTC(g("year"), g("month") - 1, g("day"), g("hour"), g("minute"), g("second")) - t;
  return new Date(t - offset);
}
function norm(s) { return String(s || "").toLowerCase().replace(/^\s*((fwd?|re|fw)\s*:\s*)+/i, "").replace(/[^a-z0-9 ]/g, " ").replace(/\s+/g, " ").trim(); }
function sameEvent(a, b) {
  if (!a || !b) return false;
  if (a.c && b.c && a.c !== b.c) return false;
  if (a.d && b.d && Math.abs(daysBetween(a.d, b.d)) > 1) return false;
  return norm(a.s) === norm(b.s) || similar(a.s || "", b.s || "");
}

async function ingestEmail(message, env, ctx) {
  const raw = await new Response(message.raw).text();
  const parsed = parseMime(raw);
  const sender = senderAddress(parsed, message);
  if (IGNORE_SENDERS.test(sender) || IGNORE_SENDERS.test(parsed.from || "")) return;
  const trusted = isTrusted(env, parsed, message);
  console.log("email from " + String(message.from || "?") + " trusted=" + trusted);
  const fwd = extractForwarded(parsed.subject, parsed.text);
  const origin = fwd ? fwd : { subject: cleanSubject(parsed.subject), date: parsed.date, from: parsed.from || "", body: parsed.text, note: "" };
  if (!origin.date) origin.date = parsed.date;
  const text = String(origin.body || "").slice(0, 6000);
  const subject = origin.subject || "Building notice";
  const isBuilding = BUILDING.test(origin.from + " " + (parsed.headers["x-forwarded-for"] || "") + " " + text.slice(0, 500)) || BUILDING.test(parsed.from || "");
  const sentAt = origin.date && !isNaN(origin.date.getTime()) ? origin.date : new Date();
  const date = todayNY(sentAt);
  const envelope = String(message.from || "").trim().toLowerCase().slice(0, 120);
  if (isBuilding) return ingestNotice(env, ctx, { subject: subject, text: text, sentAt: sentAt, date: date, trusted: trusted, sender: BUILDING.test(sender) && envelope ? envelope : sender, note: origin.note || "" });

  // Not a building notice: a resident (or you) writing directly
  const hay2 = (subject + " " + text.slice(0, 1200)).toLowerCase();
  const rep = { kind: "report", title: subject.slice(0, 140), text: firstSentences(text, 1200), where: reportWhere(floorsOf(hay2, classify(hay2))), cat: classify(hay2), d: date, anon: true, name: "", img: [] };
  if (trusted) {
    await mutateDoc(env, "pub", pub => {
      if (pub.reports.some(r => sameEvent({ s: r.title, d: r.d }, { s: rep.title, d: rep.d }))) return false;
      pub.reports.unshift({ id: id(), d: rep.d, title: rep.title, text: rep.text, where: rep.where, cat: rep.cat, img: [], anon: true, name: "", at: new Date().toISOString(), via: "email" });
    }, ctx);
    return;
  }
  return reviewCandidate(env, ctx, rep, sender, "", true);
}
function reportWhere(w) { return ["Floors 6–16", "Floors 17–26", "Whole building", "Garage", "Amenities", "Exterior", "Lobby"].includes(w) ? w : "Whole building"; }

// A building email: the gate decides what it is before anything reaches the public record.
//   drop: announcements (rent, parking, events, leasing) and anything naming a person, unit or car. Never posted;
//         kept in the "not posted" list with a post-anyway link.
//   restored: closes the open entry it belongs to.   update: news about an open entry (opens one if the text says it's down).
//   outage: opens an entry that stays open until restored.   scheduled: planned work, dated on the days it happens.
//   info / review: wait in the review queue.
async function ingestNotice(env, ctx, n) {
  const title = cleanTitle(n.subject);
  const body = stripBoilerplate(n.text);
  const gate = noticeKind(n.subject, n.text, n.sentAt);
  const hay = (title + " " + body.slice(0, 1200)).toLowerCase();
  const c = classify(hay);
  const f = { title: title, body: body, summary: firstSentences(body, 300), c: c, w: floorRangeText(hay) || floorsOf(hay, c), at: new Date(n.sentAt).toISOString(), g: (c === "hvac" && /boiler/.test(hay)) ? "hotwater" : "" };
  f.ref = f.at.slice(0, 19) + "|" + norm(title).slice(0, 48);
  const label = gate.kind + ": " + gate.why;
  if (gate.kind === "drop") return holdNotice(env, ctx, n, f, gate.why);
  if (!n.trusted) {
    // A resident forwarded a building notice: it waits for review, with the gate's reading attached
    const t = gate.kind === "scheduled" ? "S" : ["outage", "update", "restored"].includes(gate.kind) ? "U" : "N";
    const ev = gate.kind === "scheduled" ? eventDates(n.subject, n.text, n.sentAt) : null;
    return reviewCandidate(env, ctx, { kind: "incident", c: c, t: t, w: f.w, d: ev ? ev.d : n.date, e: ev && ev.e ? ev.e : "", s: title, x: f.summary, g: f.g, at: f.at, gk: gate.kind, gate: label, upd: keySentence(body),
      state: gate.kind === "outage" || gate.kind === "update" ? "open" : gate.kind === "restored" ? "resolved" : "" }, n.sender, n.note, true);
  }
  if (gate.kind === "restored") return noticeRestored(env, ctx, n, f);
  if (gate.kind === "update") return noticeUpdate(env, ctx, n, f, gate);
  if (gate.kind === "outage") return noticeOutage(env, ctx, n, f);
  if (gate.kind === "scheduled") return noticeScheduled(env, ctx, n, f);
  return reviewCandidate(env, ctx, { kind: "incident", c: c, t: "N", w: f.w, d: n.date, s: title, x: f.summary, g: f.g, at: f.at, via: "", gk: gate.kind, gate: label, state: "" }, "building email", "", false);
}
async function noticeRestored(env, ctx, n, f) {
  let done = false;
  await mutateDoc(env, "pub", pub => {
    done = false;
    if (seenEmail(pub, f.ref)) { done = true; return false; }
    let x = findOpenEntry(pub, f.c, f.w, n.date);
    if (x) { closeEntry(x, n.date, f.at, "Restored: " + f.title, f.ref); done = true; return; }
    // Already ended (by an earlier email, or by the same-day rule): note the restoration on it
    x = recentlyEnded(pub, f.c, f.w, n.date);
    if (x) {
      done = true;
      if ((x.updates || []).some(u => u.d === n.date && /^Restored:/.test(u.text))) return false;
      if (/no restoration notice/.test(x.dur || "")) { x.dur = ""; closeEntry(x, n.date, f.at, ""); }
      addUpdate(x, n.date, "Restored: " + f.title, f.ref);
      return;
    }
    // The end of planned work: "service restored" after a scheduled shutoff, "project complete"
    x = activePlanned(pub, f.c, f.w, n.date);
    if (x) {
      done = true;
      if ((x.updates || []).some(u => u.d === n.date && /^(Restored|Done):/.test(u.text))) return false;
      x.e = n.date;
      addUpdate(x, n.date, "Done: " + f.title, f.ref);
      return;
    }
    return false;
  }, ctx);
  if (done) return;
  return reviewCandidate(env, ctx, { kind: "incident", c: f.c, t: "U", w: f.w, d: n.date, e: n.date, s: f.title, x: f.summary, g: f.g, at: f.at, via: "", gk: "restored", gate: "restored: nothing open to close", state: "resolved" }, "building email", "", false);
}
async function noticeUpdate(env, ctx, n, f, gate) {
  const upd = "Building email: " + keySentence(f.body);
  const fresh = x => !(x.updates || []).some(u => u.d === n.date && u.text === upd.slice(0, 300));
  let done = false;
  await mutateDoc(env, "pub", pub => {
    done = false;
    if (seenEmail(pub, f.ref)) { done = true; return false; }
    let x = findOpenEntry(pub, f.c, f.w, n.date);
    if (x) {
      done = true;
      if (!fresh(x)) return false;
      addUpdate(x, n.date, upd, f.ref);
      if (x.title === undefined && !x.status && x.t === "U") x.status = "open";
      return;
    }
    // News about planned work under way ("extended through August 14th")
    x = activePlanned(pub, f.c, f.w, n.date);
    if (x) {
      done = true;
      if (!fresh(x)) return false;
      addUpdate(x, n.date, upd, f.ref);
      if (/\bextend/i.test(f.title)) { const ev = eventDates(n.subject, "", n.sentAt); if (ev && ev.d > String(x.e || x.d)) x.e = ev.d; }
      return;
    }
    // About something that just ended; if the same-day rule ended it but the building says it's still down, reopen it
    x = recentlyEnded(pub, f.c, f.w, n.date);
    if (x) {
      done = true;
      if (!fresh(x)) return false;
      if (gate.ifNoneOpen === "outage" && /no restoration notice/.test(x.dur || "")) { x.status = "open"; x.e = ""; x.dur = ""; }
      addUpdate(x, n.date, upd, f.ref);
      return;
    }
    return false;
  }, ctx);
  if (done) return;
  if (gate.ifNoneOpen === "outage") return noticeOutage(env, ctx, n, f);
  return reviewCandidate(env, ctx, { kind: "incident", c: f.c, t: "U", w: f.w, d: n.date, s: f.title, x: f.summary, g: f.g, at: f.at, via: "", gk: "update", gate: "update: nothing open to attach it to", upd: keySentence(f.body), state: "open" }, "building email", "", false);
}
async function noticeOutage(env, ctx, n, f) {
  const upd = "Building email: " + keySentence(f.body);
  await mutateDoc(env, "pub", pub => {
    if (seenEmail(pub, f.ref)) return false;
    // The same outage sent twice, or a second email about it within a day: one entry
    const dup = pub.incidents.find(x => x.c === f.c && x.t === "U" && x.src === "email" && floorsOverlap(x.w, f.w) && (norm(x.s) === norm(f.title) || similar(x.s, f.title)) &&
      (isOpenEntry(x, n.date) ? Math.abs(daysBetween(x.d, n.date)) <= 1 : (x.d === n.date && norm(x.s) === norm(f.title))));
    if (dup) {
      if (!isOpenEntry(dup, n.date) || norm(dup.s) === norm(f.title)) return false;
      addUpdate(dup, n.date, upd, f.ref);
      return;
    }
    // Already open: a long-running problem (elevator, garage door...), or a water/heat outage the building is still
    // sending news about, or the same floors within a day. The email is news about it, not a new outage.
    const open = findOpenEntry(pub, f.c, f.w, n.date);
    if (open && (!AUTO_CLOSE[f.c] || (open.updates || []).some(u => /^Building email:/.test(u.text)) || (entryWhere(open) === f.w && Date.parse(f.at) - Date.parse(open.at || f.at) < 24 * 3600000))) {
      if ((open.updates || []).some(u => u.d === n.date && u.text === upd.slice(0, 300))) return false;
      addUpdate(open, n.date, upd, f.ref);
      return;
    }
    pub.incidents.unshift({ id: id(), d: n.date, e: "", c: f.c, t: "U", s: f.title, x: f.summary, w: f.w, g: f.g, dur: "", src: "email", img: [], status: "open", at: f.at, confirmed: n.date, ref: f.ref });
  }, ctx);
}
async function noticeScheduled(env, ctx, n, f) {
  const ev = eventDates(n.subject, n.text, n.sentAt);
  let parts = null;
  if (ev && ev.windows > 1) {
    // "October 22–23: floors 26 through 14 · October 29–30: floors 12 through 6" becomes one entry per window
    parts = ev.list.map((wi, k) => ({ d: wi.d, e: wi.e, w: floorRangeText(ev.text.slice(wi.at, k + 1 < ev.list.length ? ev.list[k + 1].at : wi.end + 120)) }));
    if (!parts.every(p => p.w) || new Set(parts.map(p => p.w)).size !== parts.length) parts = null;
  }
  if (!ev || (ev.windows > 1 && !parts)) {
    return reviewCandidate(env, ctx, { kind: "incident", c: f.c, t: "S", w: f.w, d: ev ? ev.d : n.date, e: ev && ev.e ? ev.e : "", s: f.title, x: f.summary, g: "", at: f.at, via: "", gk: "scheduled",
      gate: ev ? "planned work on more than one date: approve one window and add the others" : "planned work: the email gives no date", state: "" }, "building email", "", false);
  }
  if (!parts) parts = [{ d: ev.d, e: ev.e, w: f.w }];
  const titleHasFloors = /floors?\s*\d/i.test(f.title);
  await mutateDoc(env, "pub", pub => {
    let changed = false;
    for (const p of parts) {
      const end = p.e && p.e > p.d ? p.e : p.d;
      const dup = pub.incidents.find(x => x.t === "S" && x.c === f.c && x.d === p.d && floorsOverlap(x.w, p.w));
      if (dup) { if ((!dup.e || dup.e === dup.d) && end > dup.d) { dup.e = end; changed = true; } continue; }
      pub.incidents.unshift({ id: id(), d: p.d, e: end, c: f.c, t: "S", s: parts.length > 1 && !titleHasFloors ? f.title + " – " + p.w : f.title, x: f.summary, w: p.w, g: "", dur: "", src: "email", img: [], at: f.at, ref: f.ref });
      changed = true;
    }
    return changed ? undefined : false;
  }, ctx);
}
async function holdNotice(env, ctx, n, f, why) {
  const hid = id();
  let added = false;
  await mutateDoc(env, "held", list => {
    added = false;
    if (list.some(h => h.d === n.date && norm(h.s) === norm(f.title))) return false;
    list.unshift({ id: hid, d: n.date, at: f.at, s: f.title, why: why, x: f.summary, cand: { c: f.c, t: "N", w: f.w, x: f.summary, g: f.g, at: f.at } });
    if (list.length > 200) list.length = 200;
    added = true;
  }, ctx);
  if (!added) return;
  try {
    const post = await link(env, "/g", { p: "held", id: hid }, 45);
    await sendMail(env, "[Not posted] " + f.title, "This building email was kept off the site: " + why + ".\n\n" + f.title + "\n" + f.summary + "\n\nIf it belongs on the site, post it: " + post + "\n\nEmails kept off the site are also listed on the review page: " + env.API_ORIGIN + "/admin\n");
  } catch (e) { console.log("held notice mail failed: " + (e && e.message)); }
}

// Review queue: one item per distinct notice; residents' duplicate copies only bump a counter
// A restoration or an update is news about an entry, not a copy of it, so it is matched on its kind as well
function newsKind(x) { return x && (x.gk === "restored" || x.gk === "update") ? x.gk : ""; }
async function reviewCandidate(env, ctx, item, sender, note, fromResident) {
  const key = { s: item.s || item.title, d: item.d, c: item.c || "" };
  const news = item.kind === "incident" ? newsKind(item) : "";
  const newsText = news ? String(news === "restored" ? "Restored: " + item.s : "Building email: " + (item.upd || item.x || item.s)).replace(/\s+/g, " ").trim().slice(0, 300) : "";
  let onSite = false;
  await mutateDoc(env, "pub", pub => {
    onSite = false;
    // News is on the site once it has been applied to an entry (by the building's own copy, or an earlier approval)
    const m = news
      ? pub.incidents.concat(pub.reports).find(x => (x.updates || []).some(u => u.d === String(item.d).slice(0, 10) && u.text === newsText))
      : item.kind === "incident"
        ? pub.incidents.find(x => sameEvent({ s: x.s, d: x.d, c: x.c }, key))
        : pub.reports.find(x => sameEvent({ s: x.title, d: x.d }, { s: key.s, d: key.d }));
    if (!m) return false;
    onSite = true;
    if (!fromResident) return false;
    m.copies = (m.copies || 1) + 1;
  }, ctx);
  if (onSite) return;
  const rej = await readListDoc(env, "rej");
  if (rej.some(r => newsKind(r) === news && sameEvent({ s: r.s, d: r.d, c: r.c }, key))) return;
  if ((await readListDoc(env, "pend")).length >= PEND_MAX) { console.log("review queue full; not queued: " + key.s); return; }
  item.id = id(); item.at = item.at || new Date().toISOString(); item.status = "pending"; item.img = item.img || []; item.copies = 1;
  item.contact = String(sender || "").slice(0, 120); item.note = String(note || "").slice(0, 300); item.stack = ""; item.cat = item.cat || item.c || "other";
  let created = false;
  await mutateDoc(env, "pend", pend => {
    created = false;
    const pm = pend.find(x => x.kind === item.kind && newsKind(x) === news && sameEvent({ s: x.s || x.title, d: x.d, c: x.c || "" }, key));
    if (pm) {
      if (!fromResident) return false;
      pm.copies = (pm.copies || 1) + 1;
      if (sender && pm.contact && pm.contact.indexOf(sender) < 0) pm.contact = (pm.contact + ", " + sender).slice(0, 300);
      return;
    }
    pend.unshift(Object.assign({}, item));
    created = true;
  }, ctx);
  if (!created) return;
  try {
    const approve = env.API_ORIGIN + "/a?id=" + item.id + "&act=approve&t=" + encodeURIComponent(await sign(env, { p: "act", id: item.id, act: "approve", exp: Date.now() + 30 * 86400000 }));
    const reject = env.API_ORIGIN + "/a?id=" + item.id + "&act=reject&t=" + encodeURIComponent(await sign(env, { p: "act", id: item.id, act: "reject", exp: Date.now() + 30 * 86400000 }));
    const what = item.kind === "incident" ? "forwarded notice" : "emailed report";
    const typeWord = { U: "outage", S: "planned work", N: "announcement" }[item.t] || "";
    const head = fromResident
      ? "A resident emailed a " + what + " that is waiting for review.\n\nFrom: " + sender + (item.note ? "\nTheir note: " + item.note : "") + (item.gate ? "\nThe automatic reading: " + item.gate : "") + "\n\n"
      : "A building email is waiting for review instead of being posted automatically.\nWhy: " + (item.gate || "") + "\n\n";
    await sendMail(env, "[Review] " + (fromResident ? "New " + what : "Building email") + ": " + key.s,
      head + "What: " + key.s + "\nDate: " + item.d + (item.e && item.e !== item.d ? " to " + item.e : "") + "\nCategory: " + (item.c || item.cat) + (typeWord ? "\nType: " + typeWord : "") + "\nWhere: " + (item.w || item.where) + "\n\n" + (item.x || item.text) + "\n\nApprove: " + approve + "\nReject: " + reject + "\n\n" + (fromResident ? "If more residents forward the same notice, it will not create another review; the count is shown on the review page: " : "To edit it before approving, use the review page: ") + env.API_ORIGIN + "/admin\n");
  } catch (e) { console.log("notify failed: " + (e && e.message)); }
}

// ---------- open / resolved ----------
// Water, heat and fire-alarm outages end the same day when no restoration email arrives (the building usually sends
// one); everything else (elevators, garage doors, trash chutes, amenities...) stays open until a restoration email,
// a check-in answer or the review page closes it.
const AUTO_CLOSE = { water: 1, hvac: 1, fire: 1 };
const AUTO_CLOSE_HOURS = 36;
function entryCat(x) { return x.title !== undefined ? x.cat : x.c; }
function entryWhere(x) { return x.title !== undefined ? x.where : x.w; }
function isOpenEntry(x, date) {
  if (!x || x.c === "you") return false;
  if (x.status === "open") return true;
  if (x.status) return false;
  // Entries from before statuses existed: an unplanned building-email outage with no end, from the last 3 days
  return x.title === undefined && x.t === "U" && !x.e && x.src === "email" && (!date || (daysBetween(x.d, date) >= 0 && daysBetween(x.d, date) <= 3));
}
function newestFirst(a, b) { return String(b.d) > String(a.d) ? 1 : String(b.d) < String(a.d) ? -1 : String(b.at || "").localeCompare(String(a.at || "")); }
function findOpenEntry(pub, c, w, date) {
  const maxDays = AUTO_CLOSE[c] ? 3 : 400;
  return (pub.incidents || []).concat(pub.reports || [])
    .filter(x => x && entryCat(x) === c && isOpenEntry(x, date) && daysBetween(x.d, date) >= -1 && daysBetween(x.d, date) <= maxDays && floorsOverlap(entryWhere(x), w))
    .sort(newestFirst)[0] || null;
}
function recentlyEnded(pub, c, w, date) {
  return (pub.incidents || []).filter(x => x && x.c === c && x.t === "U" && (x.status === "resolved" || (!x.status && x.e)) && daysBetween(x.d, date) >= 0 && daysBetween(String(x.e || x.d).replace(/^~/, ""), date) >= 0 && daysBetween(String(x.e || x.d).replace(/^~/, ""), date) <= 2 && floorsOverlap(x.w, w))
    .sort(newestFirst)[0] || null;
}
// Planned work under way in the same category and floors (long jobs like the driveway: up to 30 days past the planned end)
function activePlanned(pub, c, w, date) {
  const slack = AUTO_CLOSE[c] ? 0 : 30;
  return (pub.incidents || []).filter(x => x && x.t === "S" && x.c === c && /^\d{4}-\d{2}-\d{2}$/.test(String(x.d)) && x.d <= date && date <= addDays(String(x.e || x.d).replace(/^~/, "") || x.d, slack) && floorsOverlap(x.w, w))
    .sort(newestFirst)[0] || null;
}
function seenEmail(pub, ref) {
  if (!ref) return false;
  for (const x of (pub.incidents || []).concat(pub.reports || [])) {
    if (x.ref === ref) return true;
    for (const u of x.updates || []) if (u.ref === ref) return true;
  }
  return false;
}
function closeEntry(x, date, atIso, label, ref) {
  const start = String(x.d).slice(0, 10);
  x.status = "resolved";
  x.e = date < start ? start : date;
  if (x.title === undefined && (!x.dur || /^same day/.test(x.dur))) {
    const ms = x.at && atIso ? Date.parse(atIso) - Date.parse(x.at) : 0;
    const n = daysBetween(start, x.e);
    x.dur = hoursLabel(ms) || (n <= 0 ? "same day" : "≈" + n + " day" + (n === 1 ? "" : "s"));
  }
  if (label) addUpdate(x, date, label, ref);
  return x;
}
function addUpdate(x, date, text, ref) {
  x.updates = Array.isArray(x.updates) ? x.updates : [];
  text = String(text || "").replace(/\s+/g, " ").trim().slice(0, 300);
  if (!text) return;
  const same = x.updates.find(u => u.d === date && u.text === text);
  if (!same) x.updates.push(ref ? { d: date, text: text, ref: ref } : { d: date, text: text });
  else if (ref && !same.ref) same.ref = ref;
  x.updates.sort((a, b) => String(a.d).localeCompare(String(b.d)));
  if (x.updates.length > 30) x.updates = x.updates.slice(-30);
  if (x.status !== "resolved" && (!x.confirmed || x.confirmed < date)) x.confirmed = date;
}
// The sentence of a building update that carries the news ("awaiting a part", "expected Friday"), not the greeting
function keySentence(body) {
  const t = String(body || "").replace(/\s+/g, " ").trim();
  const sents = (t.match(/[^.!?]+(?:[.!?]+|$)/g) || []).map(s => s.trim()).filter(s => s.length > 20);
  const FILLER = /\b(writing to (provide|share|inform|update)|provide (you with )?(an|a quick|this) update|we understand|inconvenience|appreciate your (continued )?(patience|understanding|cooperation)|thank you|apologi[sz]e|do not hesitate|reach out|have an? (great|wonderful|excellent|good))\b/i;
  const KEY = /\b(parts?|expect\w*|eta|estimated|anticipat\w*|schedul\w*|technician|vendor|contractor|company|complet\w*|restor\w*|await\w*|waiting|deliver\w*|inspect\w*|repair\w*|replac\w*|order\w*|tomorrow|today|tonight|next week|this week|monday|tuesday|wednesday|thursday|friday|saturday|sunday|hours?|days?)\b/i;
  const good = sents.filter(s => !FILLER.test(s));
  const pick = good.filter(s => KEY.test(s)).slice(0, 2);
  let out = (pick.length ? pick : good.slice(0, 1)).join(" ")
    .replace(/^(please (know|note|be advised) that|we (would like to|want to|wanted to) (inform you|let you know) that|we are pleased to (share|inform you) that)\s+/i, "");
  if (!out) out = firstSentences(t, 220);
  out = out.charAt(0).toUpperCase() + out.slice(1);
  return out.length > 240 ? out.slice(0, 238).replace(/\s+\S*$/, "") + "…" : out;
}

// ---------- the gate ----------
const G_SERVICE = /\b(hot water|cold water|water|heat(ing)?|hvac|boiler|thermostat|air condition\w*|a\/c|elevators?|fire alarm|sprinkler|smoke (alarm|detector)s?|life safety|trash chute|chute|(parking )?garage|gate arms?|plumbing|riser|leak|outage|interruption|shut-? ?off|out of service|maintenance|repair|inspection|testing|discolou?r\w*|power|electric\w*|generator|pool heater)\b/i;
const G_ADMIN = new RegExp([
  "\\brent\\b", "\\bpayments?\\b", "\\bleas(e|ing)\\b", "renewal", "office hours", "holiday (office )?hours", "office (will be )?clos",
  "\\bevents?\\b", "happy hour", "\\bpart(y|ies)\\b", "celebrat", "open house", "\\btoast\\b", "lounge (is )?reserved", "reserved from",
  "golf lounge", "fresh ?& ?co", "backpacks?", "donation", "fundrais", "\\bsurvey\\b", "newsletter", "introducing",
  "parking (reminder|violation|polic)", "no parking in", "\\btowed\\b", "unauthori[sz]ed vehicle", "move (your |the )?vehicle",
  "pick ?up\\/drop ?off", "drop ?off maximum", "community reminder", "friendly reminder", "gate reminder", "package (room )?(polic|reminder|hours)",
  "move-?in|move-?out", "welcome (to )?our new"
].join("|"), "i");
const G_PRIVATE = /\b(license plate|licen[cs]e|plate\b|[A-Z]{2}-\d{4,6}|vehicle owner|owner of a)\b|\bunit\s*#?\s*\d{1,2}[A-Z]\b|\bapartment\s+\d{1,2}[A-Z]\b/i;
const G_RESTORED_SUBJ = /\b(restored|resumed|resolved|back (in service|on ?line|up and running)|is back|reopened|complete[d!]?|fixed)\b/i;
const G_RESTORED_BODY = /\b(has|have) (now )?been (fully )?(restored|resolved|repaired|completed)\b|\bis now (fully )?restored\b|\bfully restored\b|\bis back in service\b|\brepairs? (are|is|have been) complete/i;
const G_NOT_YET = /\b(to be|will be|should be|expected to be|anticipate[sd]?( (it|service|water) (will )?(being|be))?|until|once|before it is)\s+(fully\s+)?(restored|resumed|completed?|back)\b|\brestored soon\b|\bwaiting for\b/i;
const G_UPDATE_SUBJ = /\b(update|eta|extended|still)\b/i;
const G_OUTAGE = /\b(interruption|outage|shut-? ?off|shut off|turned off|out of service|leak|discolou?r\w*|no (hot |cold )?water|not working|malfunction\w*|failure|failed|broken|challenges with|waiting for the hot water|pause[d]? (hot )?water|unexpected|emergency|false alarm|alarm activation)\b/i;
const G_SCHEDULED = /\b(schedul\w*|planned|test(ing)?\b|inspections?|preventa?tive maintenance|proactive|repair (work|project)|work will be taking place|will be (temporarily )?(shut|turned|closed|off|unavailable|interrupted|conduct\w*|perform\w*|tak\w*)|tomorrow|beginning (on )?(mon|tues|wednes|thurs|fri|satur|sun)day)\b/i;
const G_CURRENT = /\b(currently|right now|this morning|earlier today|due to (a|an) (leak|issue|emergency)|have had to|has been temporarily shut off|is temporarily shut off|unfortunately|unexpected|emergency)\b/i;
const G_INFO = /\b(cooling towers?|seasonal|heating season|winter weather|weather advisory|advisory|activated|activation of|garage doors|gate arms|infrastructure|improvement project)\b/i;
const G_INFO_SUBJ = /\b(weather|advisory|seasonal|cooling towers?|heating season)\b/i;
const G_RECAP = /\b(we want(ed)? to (take a moment to )?acknowledge|in each instance|over the past (few )?(days|weeks?))\b/i;

function stripBoilerplate(t) {
  return String(t || "")
    .replace(/\s*\^?\s*355 Atlantic Street\s*[|,.]?\s*Stamford[^\n|]{0,40}/gi, " ")
    .replace(/\s*THE INFORMATION CONTAINED IN THIS MESSAGE[\s\S]*$/, "")
    .replace(/\s*(©|This (e-?mail|message) was sent to|Unsubscribe from|Click here to unsubscribe)[\s\S]*$/i, "")
    .replace(/\|/g, " ")
    .replace(/^\s*(atlantic-station\s*)?(welcome to atlantic station( west)?!?\s*)?(atlantic sta(tion|ton)\s*)?(\bAS\b\s*)?\.?\s*/i, "")
    .replace(/^(dear|good (morning|afternoon|evening)|hello|hi)\b[^,.:!]{0,60}[,.:!]\s*/i, "")
    .replace(/\s+/g, " ")
    .replace(/\s*\(?\b\d{3}\)?[\s.-]*\d{3}[\s.-]\d{4}\s*$/, "")
    .trim();
}
function cleanSubject(s) { return String(s || "Building notice").replace(/^\s*((fwd?|re|fw)\s*:\s*)+/i, "").replace(/\s+/g, " ").trim(); }
function cleanTitle(s) {
  s = String(s || "Building notice").replace(/^\s*((fwd?|re|fw)\s*:\s*)+/i, "").replace(/^\s*subject\s*:\s*/i, "").replace(/^\s*atlantic\s+station\s*(?::|-|–|—)\s*/i, "").replace(/\s+/g, " ").trim();
  const letters = s.replace(/[^A-Za-z]/g, ""), upper = s.replace(/[^A-Z]/g, "");
  if (letters.length >= 6 && upper.length / letters.length > 0.7) {
    let x = s.toLowerCase();
    x = x.replace(/\b(hvac|ev|rxo|otis|pm|am|ph|g[1-5])\b/g, m => m.toUpperCase());
    x = x.replace(/\b(january|february|march|april|june|july|august|september|october|november|december|monday|tuesday|wednesday|thursday|friday|saturday|sunday|jan|feb|apr|jun|jul|aug|sept?|oct|nov|dec)\b/g, m => m.charAt(0).toUpperCase() + m.slice(1));
    x = x.replace(/\bmay(?=\s*\d)/g, "May").replace(/\batlantic station\b/g, "Atlantic Station").replace(/\bstamford\b/g, "Stamford").replace(/\bfloors?(?=\s*\d)/g, m => m.charAt(0).toUpperCase() + m.slice(1));
    s = x.charAt(0).toUpperCase() + x.slice(1);
  }
  s = s.replace(/(\d)\s*-\s*(\d)/g, "$1–$2").replace(/\s+-\s+/g, " – ").replace(/\s*!+$/, "").replace(/\s*\.\s*(to be restored soon)$/i, ": $1");
  const lead = s.replace(/^(reminder|important( notice)?|attention|notice)\s*[:\-–—]\s*/i, "");
  if (lead.length >= 8) s = lead;
  const tail = s.replace(/[\s,;:!.\-–—]*(please (review|read|note|see below)|important)[!.]*$/i, "");
  if (tail.length >= 8) s = tail;
  s = s.charAt(0).toUpperCase() + s.slice(1);
  return s.slice(0, 140) || "Building notice";
}
function noticeKind(subject, text, sentAt) {
  const s = cleanTitle(subject), body = stripBoilerplate(text), lead = body.slice(0, 260);
  const all = s + " " + body.slice(0, 1200);
  const svcSubject = G_SERVICE.test(s);
  if (G_PRIVATE.test(all)) return { kind: G_ADMIN.test(all) || /parking|vehicle/i.test(all) ? "drop" : "review", why: "names a person, unit or vehicle" };
  if (G_ADMIN.test(s) && !(svcSubject && !/\b(rent|event|lounge|parking|leasing)\b/i.test(s))) return { kind: "drop", why: "announcement (" + (G_ADMIN.exec(s) || [""])[0].toLowerCase() + ")" };
  if (!svcSubject && G_ADMIN.test(lead) && !G_OUTAGE.test(lead)) return { kind: "drop", why: "announcement (" + (G_ADMIN.exec(lead) || [""])[0].toLowerCase() + ")" };
  const restoredSubj = G_RESTORED_SUBJ.test(s) && !G_NOT_YET.test(s);
  const restoredBody = G_RESTORED_BODY.test(lead) && !G_NOT_YET.test(lead.slice(0, 160)) && !/\bupdate\b/i.test(s.replace(/service update$/i, ""));
  if (restoredSubj || restoredBody) return { kind: "restored", why: restoredSubj ? "restored, per the subject" : "restored, per the first lines" };
  if (/\breminder\b/i.test(s) && !G_OUTAGE.test(s) && !G_SCHEDULED.test(all)) return { kind: "drop", why: "reminder with no service impact" };
  if (G_INFO_SUBJ.test(s) && !G_OUTAGE.test(s)) return { kind: "info", why: "building operations, no outage" };
  const recap = G_RECAP.test(lead) && !/\b(currently|right now|this morning|earlier today|is (temporarily )?(shut|out|off|down))\b/i.test(lead);
  if (G_UPDATE_SUBJ.test(s) && G_SERVICE.test(all)) {
    if (G_INFO.test(all) && !G_OUTAGE.test(lead)) return { kind: "info", why: "operations update, no outage" };
    return { kind: "update", why: recap ? "looks back on recent outages" : "update on a service", ifNoneOpen: !recap && (G_OUTAGE.test(lead) || /currently|awaiting|remains|still/i.test(lead)) ? "outage" : "review" };
  }
  if (sentAt && G_OUTAGE.test(s)) { const ev = eventDates(subject, "", sentAt); if (ev && ev.d > todayNY(new Date(sentAt))) return { kind: "scheduled", why: "planned work (the subject names a later day)" }; }
  if (recap) return { kind: "update", why: "looks back on recent outages", ifNoneOpen: "review" };
  const sched = G_SCHEDULED.test(all), now = G_CURRENT.test(lead) || (G_OUTAGE.test(s) && !sched);
  if (G_OUTAGE.test(all) && (now || !sched)) return { kind: "outage", why: "a service is down now" };
  if (sched && G_SERVICE.test(all)) return { kind: "scheduled", why: "planned work" };
  if (G_INFO.test(all)) return { kind: "info", why: "building operations, no outage" };
  if (G_OUTAGE.test(all)) return { kind: "outage", why: "a service is down" };
  return { kind: "review", why: "no rule matched" };
}
// Floors as a numeric range; reversed ranges and stack letters normalised ("26 through 14" -> 14–26, "17M-26M" -> 17–26)
function floorRangeText(h) {
  h = String(h || "");
  const m = /floors?\s*:?\s*(\d{1,2})[a-z]?\s*(?:through|thru|to|-|–|—)\s*(\d{1,2})[a-z]?\b/i.exec(h);
  if (m) { const a = +m[1], b = +m[2]; return "Floors " + Math.min(a, b) + "–" + Math.max(a, b); }
  const l = /floors?\s*:?\s*(\d{1,2}(?:\s*(?:,|and|&)\s*\d{1,2})+)\b/i.exec(h);
  if (l) { const ns = l[1].split(/\s*(?:,|and|&)\s*/).map(Number).filter(n => n >= 1 && n <= 40); if (ns.length >= 2) return "Floors " + Math.min.apply(null, ns) + "–" + Math.max.apply(null, ns); }
  return "";
}
function floorRangeOf(w) {
  w = String(w || "");
  if (/whole building|all units|all floors/i.test(w)) return { lo: 6, hi: 26 };
  const m = /(\d{1,2})\s*[–—-]\s*(\d{1,2}|P2|PH)\b/i.exec(w);
  if (m) { const a = +m[1], b = /^\d+$/.test(m[2]) ? +m[2] : 27; return { lo: Math.min(a, b), hi: Math.max(a, b) }; }
  const s = /\b(\d{1,2})(?:st|nd|rd|th)\s+floor/i.exec(w); if (s) return { lo: +s[1], hi: +s[1] };
  if (/upper floors/i.test(w)) return { lo: 17, hi: 26 };
  return null;
}
// Same part of the building? Floor ranges must overlap; named places (Pool, Trash Chute, Driveway...) must match,
// except the catch-alls "Amenities" and "Exterior"; a floor range and a named place count as overlapping.
function floorsOverlap(a, b) {
  const fa = floorRangeOf(a), fb = floorRangeOf(b);
  if (fa && fb) return fa.lo <= fb.hi && fb.lo <= fa.hi;
  if (fa || fb) return true;
  const x = String(a || "").trim().toLowerCase(), y = String(b || "").trim().toLowerCase();
  return !x || !y || x === y || x === "amenities" || y === "amenities" || x === "exterior" || y === "exterior";
}
const G_MONTHS = ["january","february","march","april","may","june","july","august","september","october","november","december"];
// Dates the work happens on: "October 22–23", "OCTOBER 22nd-OCTOBER 23rd", "Friday, September 25", "2/5 and Friday, 2/6", "tomorrow"
function eventDates(subject, text, sentAt) {
  const base = new Date(todayNY(sentAt ? new Date(sentAt) : new Date()) + "T12:00:00Z"), year = base.getUTCFullYear();
  const iso = d => d.toISOString().slice(0, 10);
  const mk = (mo, da) => { let d = new Date(Date.UTC(year, mo, da, 12)); if (d < new Date(base.getTime() - 60 * 86400000)) d = new Date(Date.UTC(year + 1, mo, da, 12)); return d; };
  const h = cleanTitle(subject) + " " + stripBoilerplate(text).slice(0, 1500);
  const found = [], windows = [];
  const mon = "(" + G_MONTHS.join("|") + "|jan|feb|mar|apr|jun|jul|aug|sept?|oct|nov|dec)";
  const wday = "(?:(?:mon|tues|wednes|thurs|fri|satur|sun)day,?\\s+)?";
  const reRange = new RegExp("\\b" + mon + "\\.?\\s+(\\d{1,2})(?:st|nd|rd|th)?\\b(?:\\s*(?:-|–|—|to|through|and|&)\\s*" + wday + "(?:" + mon + "\\.?\\s+)?(\\d{1,2})(?:st|nd|rd|th)?\\b)?", "ig");
  let m;
  while ((m = reRange.exec(h))) {
    const mi = G_MONTHS.findIndex(x => x.startsWith(m[1].toLowerCase().slice(0, 3)));
    const m2 = m[3] ? G_MONTHS.findIndex(x => x.startsWith(m[3].toLowerCase().slice(0, 3))) : mi;
    if (+m[2] < 1 || +m[2] > 31) continue;
    const a = mk(mi, +m[2]); found.push(a);
    const b = m[4] && +m[4] >= 1 && +m[4] <= 31 ? mk(m2, +m[4]) : a; if (b !== a) found.push(b);
    windows.push({ d: iso(a), e: iso(b < a ? a : b), at: m.index, end: m.index + m[0].length });
  }
  const reNum = /\b(\d{1,2})\/(\d{1,2})(?:\/(\d{2,4}))?\b/g;
  while ((m = reNum.exec(h))) { const mo = +m[1] - 1, da = +m[2]; if (mo >= 0 && mo < 12 && da >= 1 && da <= 31) found.push(mk(mo, da)); }
  const wd = /\b(this |next )?(sunday|monday|tuesday|wednesday|thursday|friday|saturday)\b/i.exec(h);
  if (!found.length && wd) { const want = ["sunday","monday","tuesday","wednesday","thursday","friday","saturday"].indexOf(wd[2].toLowerCase()); let k = (want - base.getUTCDay() + 7) % 7; if (wd[1] && /next/i.test(wd[1])) k += 7; found.push(new Date(base.getTime() + k * 86400000)); }
  if (/\btomorrow\b/i.test(h)) found.push(new Date(base.getTime() + 86400000));
  if (/\btoday\b/i.test(h) && !found.length) found.push(base);
  const future = found.filter(d => d >= new Date(base.getTime() - 86400000)).sort((a, b) => a - b);
  if (!future.length) return null;
  let list = windows.filter(w => w.d >= iso(new Date(base.getTime() - 86400000)));
  list = list.filter((w, i) => list.findIndex(x => x.d === w.d && x.e === w.e) === i);
  list = list.filter(w => !list.some(x => x !== w && x.d <= w.d && x.e >= w.e));
  return { d: iso(future[0]), e: future.length > 1 ? iso(future[future.length - 1]) : "", windows: list.length, list: list, text: h };
}

function similar(a, b) { a = String(a || "").toLowerCase().replace(/[^a-z0-9 ]/g, ""); b = String(b || "").toLowerCase().replace(/[^a-z0-9 ]/g, ""); if (!a || !b) return false; const wa = new Set(a.split(/\s+/)); const wb = b.split(/\s+/); let hit = 0; wb.forEach(x => { if (wa.has(x)) hit++; }); return hit / Math.max(wa.size, wb.length) >= 0.5; }
function classify(h) {
  if (/preventa?tive maintenance|apartment inspection|unit inspection|unit entry|access to all units|entry (in)?to (all|every|each) (unit|apartment)/.test(h)) return "pm";
  if (/cleaning|cleaners|janitorial|housekeeping|cleaning service/.test(h) && !/water/.test(h)) return "clean";
  if (/hot water|water (service|shut|outage|interruption|main|pressure|discolor|line|supply)|plumbing|riser|no water|water (is|will be) (off|shut)/.test(h)) return "water";
  if (/elevator/.test(h)) return "elev";
  if (/fire alarm|sprinkler|life safety|smoke detector|alarm test|fire marshal|fire inspection/.test(h)) return "fire";
  if (/boiler|heat(ing)?\b|cooling|hvac|air condition|thermostat|winter weather|cooling tower/.test(h)) return "hvac";
  if (/window|scaffold|rigging|exterior|bucket truck|caulk|facade|crane/.test(h)) return "win";
  if (/pool|sky terrace|amenit|package|ev charg|trash chute|gym|fitness|yoga|concierge/.test(h)) return "amen";
  if (/garage|driveway|cobblestone|parking|gate|street|corridor|entrance|lobby|construction/.test(h)) return "garage";
  return "other";
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
  let t = String(text || "").replace(/^(dear|hello|hi)[^\n,.:]*[,.:]?\s*/i, "").replace(/\s+/g, " ").trim();
  t = t.replace(/(thank you|sincerely|best regards|warm regards|kind regards|the atlantic station team|atlantic station management)[\s\S]*$/i, "").trim();
  if (t.length <= max) return t;
  const cut = t.slice(0, max);
  const end = Math.max(cut.lastIndexOf(". "), cut.lastIndexOf("! "));
  return (end > 80 ? cut.slice(0, end + 1) : cut.replace(/\s+\S*$/, "") + "…");
}

// ---------- schedule: end water/heat outages that never got a restoration email; check in on anything still open ----------
let LAST_SWEEP = 0;
// The same sweep runs (without emails) from page loads, so it still happens if the cron trigger is ever missing
function sweepSoon(env, ctx) {
  if (Date.now() - LAST_SWEEP < 30 * 60000) return;
  LAST_SWEEP = Date.now();
  const p = runSchedule(env, ctx, false).catch(e => console.log("sweep failed: " + (e && e.message)));
  if (ctx && ctx.waitUntil) ctx.waitUntil(p);
}
async function runSchedule(env, ctx, withMail) {
  const today = todayNY(), now = Date.now();
  await mutateDoc(env, "pub", pub => {
    let changed = false;
    for (const x of pub.incidents) {
      // Only an outage nobody has said anything more about: building updates on a later day, a resident or the
      // review page confirming it keep it open (the check-ins take over from there)
      if (x.status !== "open" || !AUTO_CLOSE[x.c] || (x.confirmed && x.confirmed > String(x.d).slice(0, 10)) || x.checkedAt || x.src === "admin") continue;
      const opened = x.at ? Date.parse(x.at) : Date.parse(String(x.d).slice(0, 10) + "T12:00:00-04:00");
      if (now - opened > AUTO_CLOSE_HOURS * 3600000) {
        x.status = "resolved"; x.e = String(x.d).slice(0, 10);
        if (!x.dur) x.dur = "same day (no restoration notice)";
        changed = true;
      }
    }
    return changed ? undefined : false;
  }, ctx);
  if (!withMail || hourNY() < 9) return;
  let go = false;
  await mutateDoc(env, "sys", sys => { go = false; if (sys.lastCheckin === today) return false; sys.lastCheckin = today; go = true; }, ctx);
  if (!go) return;
  const due = [];
  await mutateDoc(env, "pub", pub => {
    due.length = 0;
    for (const x of pub.incidents.concat(pub.reports)) {
      if (x.status !== "open") continue;
      if (due.length >= 10) break;   // the rest wait for tomorrow's check-in
      let last = String(x.d).slice(0, 10);
      for (const v of [x.confirmed, x.checkedAt].concat((x.updates || []).map(u => u.d))) if (v && v > last) last = v;
      // Every 3 days for the first two weeks, then weekly
      if (daysBetween(last, today) >= (daysBetween(String(x.d).slice(0, 10), today) >= 14 ? 7 : 3)) { x.checkedAt = today; due.push({ id: x.id, title: x.s || x.title, d: String(x.d).slice(0, 10), w: x.w || x.where || "", confirmed: x.confirmed || String(x.d).slice(0, 10) }); }
    }
    return due.length ? undefined : false;
  }, ctx);
  for (const it of due) {
    try {
      const still = await link(env, "/s", { p: "status", id: it.id, act: "still" }, 21);
      const fixed = await link(env, "/s", { p: "status", id: it.id, act: "fixed" }, 21);
      const days = daysBetween(it.d, today) + 1;
      await sendMail(env, "[Check] Still out? " + it.title + " (day " + days + ")",
        "The site shows this as still going:\n\n" + it.title + (it.w ? " (" + it.w + ")" : "") + "\nSince " + it.d + ", day " + days + ". Last confirmed " + it.confirmed + ".\n\nStill out: " + still + "\nFixed (pick the date): " + fixed + "\n\nIf nobody answers, it stays on the site as still going; after two weeks without news it also reads \"last confirmed " + it.confirmed + "\".\n");
    } catch (e) { console.log("check-in mail failed: " + (e && e.message)); }
  }
}

// ---------- feeds: a calendar of outages and planned work, and a news feed of new problems and fixes ----------
function noCtl(s) { return String(s || "").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ""); }
function icsEsc(s) { return noCtl(s).replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/,/g, "\\,").replace(/\r?\n/g, "\\n"); }
function icsFold(line) { const out = []; let s = line; while (new TextEncoder().encode(s).length > 74) { let n = 74; while (new TextEncoder().encode(s.slice(0, n)).length > 74) n--; out.push(s.slice(0, n)); s = " " + s.slice(n); } out.push(s); return out.join("\r\n"); }
function typeWordEn(x) { return x.title !== undefined ? "Building issue" : x.t === "S" ? "Planned work" : x.t === "U" ? "Outage" : x.t === "R" ? "Resident ticket" : "Announcement"; }
function feedTitle(x) { return x.title !== undefined ? String(x.title || "") : cleanTitle(x.s); }
async function feedIcs(env) {
  const pub = await readDoc(env, "pub"), today = todayNY(), from = addDays(today, -60);
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  const lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//355 Atlantic Street residents//maintenance record//EN", "CALSCALE:GREGORIAN", "METHOD:PUBLISH", "X-WR-CALNAME:355 Atlantic Street: outages and planned work", "X-WR-TIMEZONE:America/New_York", "REFRESH-INTERVAL;VALUE=DURATION:PT1H", "X-PUBLISHED-TTL:PT1H"];
  const items = pub.incidents.filter(x => validDate(x.d) && (x.t === "S" || x.t === "U") && (x.status === "open" || String(x.e || x.d).replace(/^~/, "") >= from))
    .concat(pub.reports.filter(x => x.status === "open" && validDate(x.d)));
  for (const x of items) {
    const open = x.status === "open";
    let end = open ? today : (String(x.e || "").replace(/^~/, "") || x.d);
    if (!validDate(end) || end < x.d) end = x.d;
    const title = (open ? "Still out: " : typeWordEn(x) + ": ") + feedTitle(x);
    const desc = [x.w || x.where || "", String(x.x || x.text || "").slice(0, 400), open ? "Still going as of " + today + "." : (x.dur ? "Duration: " + x.dur + "." : "")].filter(Boolean).join("\n");
    lines.push("BEGIN:VEVENT", "UID:" + x.id + "@atlanticstreetresidents.com", "DTSTAMP:" + stamp, "DTSTART;VALUE=DATE:" + x.d.replace(/-/g, ""), "DTEND;VALUE=DATE:" + addDays(end, 1).replace(/-/g, ""),
      icsFold("SUMMARY:" + icsEsc(title)), icsFold("DESCRIPTION:" + icsEsc(desc)), "URL:" + env.SITE_ORIGIN + "/#" + (x.title !== undefined ? "report-" : "entry-") + encodeURIComponent(x.id), "TRANSP:TRANSPARENT", "END:VEVENT");
  }
  lines.push("END:VCALENDAR");
  return new Response(lines.join("\r\n") + "\r\n", { headers: { "Content-Type": "text/calendar; charset=utf-8", "Cache-Control": "public, max-age=900", "Access-Control-Allow-Origin": "*", "Content-Disposition": "inline; filename=\"atlantic-street.ics\"" } });
}
function xmlEsc(s) { return noCtl(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
function rssDate(d, at) { const t = at ? Date.parse(at) : Date.parse(String(d).slice(0, 10) + "T12:00:00-04:00"); return new Date(isNaN(t) ? Date.now() : t).toUTCString(); }
async function feedRss(env) {
  const pub = await readDoc(env, "pub");
  const items = [];
  for (const x of pub.incidents.filter(x => x.t !== "N" && x.c !== "you" && validDate(x.d))) {
    items.push({ key: x.at || x.d, guid: x.id, title: typeWordEn(x) + ": " + feedTitle(x), link: "#entry-" + x.id, desc: [x.w, x.x].filter(Boolean).join(". "), date: rssDate(x.d, x.at) });
    const xe = String(x.e || "").replace(/^~/, "");
    if (x.status === "resolved" && validDate(xe)) items.push({ key: xe + "T23", guid: x.id + "-resolved", title: "Resolved: " + feedTitle(x), link: "#entry-" + x.id, desc: "Resolved " + x.e + (x.dur ? " (" + x.dur + ")" : "") + ".", date: rssDate(xe) });
  }
  for (const x of pub.reports.filter(x => validDate(x.d))) {
    items.push({ key: x.at || x.d, guid: x.id, title: "Building issue: " + feedTitle(x), link: "#report-" + x.id, desc: [x.where, x.text].filter(Boolean).join(". "), date: rssDate(x.d, x.at) });
    const xe = String(x.e || "").replace(/^~/, "");
    if (x.status === "resolved" && validDate(xe)) items.push({ key: xe + "T23", guid: x.id + "-resolved", title: "Resolved: " + feedTitle(x), link: "#report-" + x.id, desc: "Resolved " + x.e + ".", date: rssDate(xe) });
  }
  items.sort((a, b) => (a.key < b.key ? 1 : a.key > b.key ? -1 : 0));
  const body = '<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>' +
    "<title>355 Atlantic Street: outages and repairs</title><link>" + xmlEsc(env.SITE_ORIGIN) + "/</link><description>New outages, planned work, restorations and resident reports at 355 Atlantic Street, Stamford.</description><language>en-us</language>" +
    '<atom:link href="' + xmlEsc(env.API_ORIGIN) + '/feed.xml" rel="self" type="application/rss+xml"/>' +
    items.slice(0, 50).map(i => "<item><title>" + xmlEsc(i.title) + "</title><link>" + xmlEsc(env.SITE_ORIGIN + "/" + i.link) + '</link><guid isPermaLink="false">' + xmlEsc(i.guid) + "</guid><pubDate>" + i.date + "</pubDate><description>" + xmlEsc(String(i.desc).slice(0, 600)) + "</description></item>").join("") +
    "</channel></rss>";
  return new Response(body, { headers: { "Content-Type": "application/rss+xml; charset=utf-8", "Cache-Control": "public, max-age=600", "Access-Control-Allow-Origin": "*" } });
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
