// LDS API on Cloudflare Workers + D1.
// Sign-in: Steam OpenID 2.0, verified server-side (check_authentication), then a signed session token.
// Data: league data ("db") and live judging ("live") are written by admins only; every pilot writes only their own profile.

const STEAM_OPENID = "https://steamcommunity.com/openid/login";
const TOKEN_DAYS = 30;
const MAX_PROFILE = 400_000; // team logos are small data URLs
const MAX_DB = 2_000_000;

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const cors = corsHeaders(req, env);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    try {
      const res = new Response(...(r => [r.body, r])(await route(req, env, url))); // redirects have immutable headers: copy first
      for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
      return res;
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      return json({ error: e instanceof HttpError ? e.message : "server error" }, status, cors);
    }
  },
};

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

async function route(req, env, url) {
  const p = url.pathname, m = req.method;
  if (m === "GET" && p === "/auth/steam") return steamStart(env, url);
  if (m === "GET" && p === "/auth/steam/callback") return steamCallback(env, url);
  if (m === "GET" && p === "/api/state") return getState(env, url);
  if (p === "/api/me") {
    const sid = await auth(req, env);
    if (m === "GET") return getMe(env, sid);
    if (m === "PUT") return putMe(req, env, sid);
  }
  if (m === "PUT" && p === "/api/db") return putDb(req, env, await requireRole(req, env, ["owner", "admin", "tech"]));
  if (m === "PUT" && p === "/api/live") return putLive(req, env, await requireRole(req, env, ["owner", "admin", "judge", "streamer"]));
  if (m === "POST" && p === "/api/protest") return postProtest(req, env, await auth(req, env));
  if (m === "POST" && p === "/api/owner/user") return ownerUser(req, env, await requireOwner(req, env));
  if (m === "GET" && p === "/") return json({ ok: true, service: "lds-api" });
  throw new HttpError(404, "not found");
}

// ---------- helpers ----------
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });

function corsHeaders(req, env) {
  const origin = req.headers.get("origin") || "";
  const allowed = siteOrigins(env);
  return allowed.includes(origin)
    ? { "access-control-allow-origin": origin, "access-control-allow-methods": "GET, PUT, POST, OPTIONS", "access-control-allow-headers": "authorization, content-type", "access-control-max-age": "86400", vary: "origin" }
    : {};
}
const siteOrigins = env => String(env.SITE_ORIGIN || "").split(",").map(s => s.trim()).filter(Boolean);
// only send people back to our own site (no open redirect)
function safeReturn(env, ret) {
  try { const u = new URL(ret); if (siteOrigins(env).includes(u.origin)) return u.origin + u.pathname; } catch {}
  throw new HttpError(400, "bad return url");
}

const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64urlText = s => b64url(new TextEncoder().encode(s));
const fromB64url = s => new TextDecoder().decode(Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0)));
async function hmac(env, data) {
  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) throw new HttpError(500, "SESSION_SECRET is not set");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data)));
}
export async function signToken(env, sid, now = Date.now()) {
  const body = b64urlText(JSON.stringify({ sid, exp: now + TOKEN_DAYS * 864e5 }));
  return body + "." + await hmac(env, body);
}
export async function verifyToken(env, token, now = Date.now()) {
  const [body, sig] = String(token || "").split(".");
  if (!body || !sig) return null;
  const good = await hmac(env, body);
  if (good.length !== sig.length) return null;
  let diff = 0; for (let i = 0; i < good.length; i++) diff |= good.charCodeAt(i) ^ sig.charCodeAt(i); // constant time
  if (diff) return null;
  try { const t = JSON.parse(fromB64url(body)); return t.exp > now && /^\d{17}$/.test(t.sid) ? t.sid : null; } catch { return null; }
}
async function auth(req, env) {
  const sid = await verifyToken(env, (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, ""));
  if (!sid) throw new HttpError(401, "sign in required");
  return sid;
}
async function readJson(req, max) {
  const text = await req.text();
  if (text.length > max) throw new HttpError(413, "too large");
  try { return JSON.parse(text); } catch { throw new HttpError(400, "bad json"); }
}

// ---------- storage (D1) ----------
async function kvGet(env, k) { const r = await env.DB.prepare("SELECT v FROM kv WHERE k = ?").bind(k).first(); return r ? JSON.parse(r.v) : null; }
async function kvSet(env, k, v) { await env.DB.prepare("INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(k, JSON.stringify(v)).run(); }
async function bump(env) { await env.DB.prepare("INSERT INTO kv (k, v) VALUES ('version', '1') ON CONFLICT(k) DO UPDATE SET v = CAST(v AS INTEGER) + 1").run(); }
async function getUser(env, sid) { const r = await env.DB.prepare("SELECT data FROM users WHERE sid = ?").bind(sid).first(); return r ? JSON.parse(r.data) : null; }
async function setUser(env, sid, data) {
  await env.DB.prepare("INSERT INTO users (sid, data, updated) VALUES (?, ?, ?) ON CONFLICT(sid) DO UPDATE SET data = excluded.data, updated = excluded.updated")
    .bind(sid, JSON.stringify(data), Date.now()).run();
}
const isOwner = (env, sid) => String(env.OWNER_STEAM_IDS || "").split(",").map(s => s.trim()).includes(sid);
async function requireOwner(req, env) {
  const sid = await auth(req, env);
  if (!isOwner(env, sid)) throw new HttpError(403, "head admin only");
  return sid;
}
// roles: owner (OWNER_STEAM_IDS), then what the head admin set in db.roleIds (older saves: db.adminIds = admins)
const ROLES = ["admin", "judge", "streamer", "tech"];
async function roleOf(env, sid, db) {
  if (isOwner(env, sid)) return "owner";
  db ??= await kvGet(env, "db");
  const r = db?.roleIds?.[sid];
  if (ROLES.includes(r)) return r;
  // the old admin list counts only until the head admin has saved roles once
  return !db?.roleIds && Array.isArray(db?.adminIds) && db.adminIds.includes(sid) ? "admin" : "";
}
async function requireRole(req, env, allowed) {
  const sid = await auth(req, env), role = await roleOf(env, sid);
  if (!allowed.includes(role)) throw new HttpError(403, "not allowed for this role");
  return { sid, role };
}

// ---------- Steam sign-in ----------
function steamStart(env, url) {
  const ret = safeReturn(env, url.searchParams.get("return") || "");
  const cb = new URL("/auth/steam/callback", url.origin);
  cb.searchParams.set("return", ret);
  const q = new URLSearchParams({
    "openid.ns": "http://specs.openid.net/auth/2.0",
    "openid.mode": "checkid_setup",
    "openid.return_to": cb.toString(),
    "openid.realm": url.origin,
    "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
    "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
  });
  return Response.redirect(`${STEAM_OPENID}?${q}`, 302);
}

async function steamCallback(env, url) {
  const ret = safeReturn(env, url.searchParams.get("return") || "");
  const params = new URLSearchParams();
  for (const [k, v] of url.searchParams) if (k.startsWith("openid.")) params.set(k, v);
  // the assertion must be for this endpoint, from Steam, and Steam itself must confirm it
  const claimed = params.get("openid.claimed_id") || "";
  const sid = (claimed.match(/^https:\/\/steamcommunity\.com\/openid\/id\/(\d{17})$/) || [])[1];
  const returnTo = params.get("openid.return_to") || "";
  if (!sid || params.get("openid.mode") !== "id_res" || params.get("openid.op_endpoint") !== STEAM_OPENID || !returnTo.startsWith(new URL("/auth/steam/callback", url.origin).toString()))
    return Response.redirect(`${ret}#auth=failed`, 302);
  params.set("openid.mode", "check_authentication");
  const check = await fetch(STEAM_OPENID, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: params.toString() });
  if (!/is_valid\s*:\s*true/.test(await check.text())) return Response.redirect(`${ret}#auth=failed`, 302);

  const steam = await steamProfile(env, sid);
  const user = { ...(await getUser(env, sid)), steamId: sid, name: steam.name, avatar: steam.avatar };
  await setUser(env, sid, user);
  await bump(env);
  return Response.redirect(`${ret}#token=${await signToken(env, sid)}`, 302);
}

async function steamProfile(env, sid) {
  const fallback = { name: `Pilot ${sid.slice(-4)}`, avatar: "" };
  if (!env.STEAM_API_KEY) return fallback;
  try {
    const r = await fetch(`https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${env.STEAM_API_KEY}&steamids=${sid}`);
    const p = (await r.json())?.response?.players?.[0];
    return p ? { name: String(p.personaname || fallback.name).slice(0, 32), avatar: String(p.avatarfull || "") } : fallback;
  } catch { return fallback; }
}

// ---------- data ----------
// what a pilot may set on their own profile; name and avatar always come from Steam
const PROFILE_KEYS = ["team", "num", "car", "about", "regs", "regAt", "created", "declined"];
const publicUser = (u, env) => ({ steamId: u.steamId, name: u.name, avatar: u.avatar, team: u.team ?? null, num: u.num ?? null, car: u.car ?? null,
  about: u.about ?? null, regs: u.regs ?? [], regAt: u.regAt ?? {}, created: u.created ?? null, owner: isOwner(env, u.steamId) });

async function getState(env, url) {
  const v = (await kvGet(env, "version")) ?? 0;
  if (url.searchParams.get("v") === String(v)) return json({ v }); // nothing changed: cheap answer
  const [db, live, rows] = await Promise.all([kvGet(env, "db"), kvGet(env, "live"), env.DB.prepare("SELECT data FROM users").all()]);
  return json({ v, db, live, users: rows.results.map(r => publicUser(JSON.parse(r.data), env)) });
}

async function getMe(env, sid) {
  const u = await getUser(env, sid);
  if (!u) throw new HttpError(401, "sign in required");
  const role = await roleOf(env, sid);
  return json({ user: u, admin: role === "owner" || role === "admin", owner: role === "owner", role });
}

async function putMe(req, env, sid) {
  const body = await readJson(req, MAX_PROFILE);
  const u = await getUser(env, sid);
  if (!u) throw new HttpError(401, "sign in required");
  for (const k of PROFILE_KEYS) if (k in body) u[k] = body[k];
  // shortcut: field shapes are trusted (number range, team id); validate per field once real abuse shows up
  if (u.num != null && !(Number.isInteger(u.num) && u.num >= 1 && u.num <= 999)) u.num = null;
  if (typeof u.about === "object" && u.about) u.about = { ru: String(u.about.ru || "").slice(0, 60) };
  await setUser(env, sid, u);
  await bump(env);
  return json({ ok: true });
}

// admins write the league data, but only the head admin changes roles; a technical assistant writes only the rules
async function putDb(req, env, { role }) {
  const body = await readJson(req, MAX_DB);
  if (!body || typeof body.db !== "object" || !body.db) throw new HttpError(400, "db required");
  const stored = (await kvGet(env, "db")) || {};
  const next = role === "tech" ? { ...stored, rules: body.db.rules ?? stored.rules } : body.db;
  if (role !== "owner") for (const k of ["roleIds", "adminIds", "roles"]) next[k] = stored[k];
  await kvSet(env, "db", next);
  if (role !== "tech" && body.live && typeof body.live === "object") await kvSet(env, "live", body.live);
  await bump(env);
  return json({ ok: true });
}

async function putLive(req, env) {
  const body = await readJson(req, MAX_DB);
  await kvSet(env, "live", body);
  await bump(env);
  return json({ ok: true });
}

const RUNNING = ["qualifying", "top32", "top16", "top8", "top4", "final"];
async function postProtest(req, env, sid) {
  const body = await readJson(req, 10_000), u = await getUser(env, sid);
  const text = String(body.text || "").trim().slice(0, 500), against = String(body.against || "").slice(0, 40), tour = Number(body.tour);
  if (!u || !text || !against || !Number.isInteger(tour)) throw new HttpError(400, "bad protest");
  const [db, live] = [(await kvGet(env, "db")) || {}, (await kvGet(env, "live")) || {}];
  // only while that stage is running, only by a pilot entered in it, one open protest per opponent
  if (!RUNNING.includes(live.statuses?.[tour])) throw new HttpError(409, "stage is not running");
  const st = (db.tours || []).find(x => x.id === tour);
  if (!(u.regs || []).includes(tour) && !st?.add?.includes(u.name)) throw new HttpError(403, "not in this stage");
  const list = Array.isArray(db.protests) ? db.protests : [];
  if (list.some(p => p.tour === tour && p.from === u.name && p.against === against && p.status === "new")) throw new HttpError(409, "already filed");
  list.push({ id: Math.max(0, ...list.map(p => p.id || 0)) + 1, tour, from: u.name, against, text, status: "new", verdict: "" });
  db.protests = list;
  await kvSet(env, "db", db);
  await bump(env);
  return json({ ok: true });
}

// head admin: set another pilot's number, or remove the pilot (their profile is deleted; signing in again starts a fresh one)
async function ownerUser(req, env, ownerSid) {
  const body = await readJson(req, 1_000), sid = String(body.sid || "");
  if (!/^\d{17}$/.test(sid) || sid === ownerSid) throw new HttpError(400, "bad pilot");
  const u = await getUser(env, sid);
  if (!u) throw new HttpError(404, "no such pilot");
  if (body.kick === true) {
    await env.DB.prepare("DELETE FROM users WHERE sid = ?").bind(sid).run();
    const db = await kvGet(env, "db");
    if (db && (db.adminIds?.includes?.(sid) || db.roleIds?.[sid])) { // a removed pilot loses any role
      if (Array.isArray(db.adminIds)) db.adminIds = db.adminIds.filter(x => x !== sid);
      if (db.roleIds) delete db.roleIds[sid];
      await kvSet(env, "db", db);
    }
  } else {
    const num = body.num;
    if (!(Number.isInteger(num) && num >= 1 && num <= 999)) throw new HttpError(400, "bad number");
    const rows = await env.DB.prepare("SELECT sid, data FROM users").all();
    if (rows.results.some(r => r.sid !== sid && JSON.parse(r.data).num === num)) throw new HttpError(409, "number taken");
    u.num = num;
    await setUser(env, sid, u);
  }
  await bump(env);
  return json({ ok: true });
}
