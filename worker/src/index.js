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
  if (m === "POST" && p === "/api/ready") return postReady(req, env, await requireRole(req, env, ["owner", "admin", "judge", "streamer"]));
  if (m === "POST" && p === "/api/protest") return postProtest(req, env, await auth(req, env));
  if (m === "POST" && p === "/api/owner/user") return ownerUser(req, env, await requireOwner(req, env));
  if (m === "POST" && p === "/api/team/create") return createTeam(req, env, await auth(req, env));
  if (m === "PUT" && p === "/api/team") return putTeam(req, env, await auth(req, env));
  if (m === "POST" && p === "/api/team/disband") return disbandTeam(req, env, await auth(req, env));
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
const PROFILE_KEYS = ["team", "num", "car", "about", "regs", "regAt", "declined"]; // a team itself lives in the teams table
const publicUser = (u, env) => ({ steamId: u.steamId, name: u.name, avatar: u.avatar, team: u.team ?? null, num: u.num ?? null, car: u.car ?? null,
  about: u.about ?? null, regs: u.regs ?? [], regAt: u.regAt ?? {},
  owner: isOwner(env, u.steamId) });

// long poll: with ?wait=N the request is held (up to 25 s) until the version changes, so open pages update within about a second
async function getState(env, url) {
  let v = (await kvGet(env, "version")) ?? 0;
  const since = url.searchParams.get("v"), end = Date.now() + Math.min(25, Number(url.searchParams.get("wait")) || 0) * 1000;
  while (since === String(v) && Date.now() < end) { await new Promise(r => setTimeout(r, 1000)); v = (await kvGet(env, "version")) ?? 0; }
  if (since === String(v)) return json({ v }); // nothing changed: cheap answer
  const [db, live, rows] = await Promise.all([kvGet(env, "db"), kvGet(env, "live"), env.DB.prepare("SELECT data FROM users").all()]);
  const users = rows.results.map(r => JSON.parse(r.data));
  return json({ v, db, live, users: users.map(u => publicUser(u, env)), teams: await allTeamsMigrated(env, users) });
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
  const prevTeam = u.team ?? null, prevNum = u.num ?? null;
  for (const k of PROFILE_KEYS) if (k in body) u[k] = body[k];
  if (prevNum != null) u.num = prevNum; // a claimed number stays for the season; only the head admin changes it (ownerUser)
  // joining a team: an open team with room, or a closed one that invited this pilot; otherwise the pilot stays where they were
  if ((u.team ?? null) !== prevTeam && u.team != null && !(await canJoin(env, u, Number(u.team)))) u.team = prevTeam;
  // shortcut: field shapes are trusted (number range, team id); validate per field once real abuse shows up
  if (u.num != null && !(Number.isInteger(u.num) && u.num >= 1 && u.num <= 999)) u.num = null;
  if (typeof u.about === "object" && u.about) u.about = { ru: String(u.about.ru || "").slice(0, 60) };
  if (prevTeam != null && (u.team ?? null) !== prevTeam) await dropRep(env, prevTeam, u.name);
  await setUser(env, sid, u);
  await bump(env);
  return json({ ok: true, team: u.team ?? null }); // the team actually kept, so the page can show a refused join
}
async function canJoin(env, u, id) {
  const db = await kvGet(env, "db"), tm = (await getTeam(env, id)) || (db?.teams || []).find(x => x.id === id);
  if (!tm) return false;
  if (tm.founder === u.steamId) return true;
  if (tm.closed && !(tm.invites || []).includes(u.name)) return false;
  const max = db?.settings?.maxTeam ?? 4;
  const members = (await env.DB.prepare("SELECT data FROM users").all()).results.map(r => JSON.parse(r.data)).filter(x => x.team === id && x.steamId !== u.steamId);
  return members.length < max;
}

// a pilot who leaves (or is removed) loses the representative mark; coming back starts as a plain member
async function dropRep(env, teamId, name) {
  const tm = await getTeam(env, Number(teamId));
  if (tm && tm.rep && tm.rep === name) { delete tm.rep; await setTeam(env, tm); }
}
// ---------- teams: stored on their own, so the founder role can pass to another member with everything the team has ----------
const teamIdOf = sid => 1e6 + Number(String(sid).slice(-6));
async function getTeam(env, id) { const r = await env.DB.prepare("SELECT data FROM teams WHERE id = ?").bind(id).first(); return r ? JSON.parse(r.data) : null; }
async function setTeam(env, tm) {
  await env.DB.prepare("INSERT INTO teams (id, data, updated) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated = excluded.updated")
    .bind(tm.id, JSON.stringify(tm), Date.now()).run();
}
// teams created before this table lived in their creator's profile: move each one over the first time it is missing
async function allTeamsMigrated(env, users) {
  const teams = (await env.DB.prepare("SELECT data FROM teams").all()).results.map(r => JSON.parse(r.data)), have = new Set(teams.map(z => z.id));
  for (const u of users) if (u.created && typeof u.created === "object" && !have.has(teamIdOf(u.steamId))) {
    const tm = { invites: [], closed: false, desc: "", ...u.created, id: teamIdOf(u.steamId), founder: u.steamId, creator: u.steamId, regs: u.teamRegs || {}, reqs: u.teamReqs || [] };
    await setTeam(env, tm); teams.push(tm); have.add(tm.id);
  }
  return teams;
}
// a team's stage entry may be filed or changed only while that stage takes registrations; the filing time is the server's
async function keepRegs(env, prev, given) {
  const [live, db] = await Promise.all([kvGet(env, "live"), kvGet(env, "db")]), next = {};
  given = given && typeof given === "object" && !Array.isArray(given) ? given : {};
  for (const k of new Set([...Object.keys(prev), ...Object.keys(given)])) {
    // the live status wins; a stage never moved on the judging side still has its status in the league data
    const status = live?.statuses?.[k] ?? (db?.tours || []).find(x => String(x.id) === k)?.status;
    const e = status === "reg" ? given[k] : prev[k];
    if (e && typeof e === "object" && Array.isArray(e.pilots)) next[k] = { founderNick: String(e.founderNick || "").slice(0, 32), at: prev[k]?.at ?? Date.now(),
      pilots: e.pilots.slice(0, 15).map(p => ({ name: String(p?.name || "").slice(0, 40), nick: String(p?.nick || "").slice(0, 32) })) };
  }
  return next;
}
async function createTeam(req, env, sid) {
  const body = await readJson(req, 2_000), u = await getUser(env, sid);
  const name = String(body.name || "").trim().slice(0, 32), tag = String(body.tag || "").trim().toUpperCase().slice(0, 4);
  if (!u || !name || !tag) throw new HttpError(400, "name and tag required");
  const id = teamIdOf(sid);
  if (await getTeam(env, id)) throw new HttpError(409, "team already created"); // one created team per pilot
  const tm = { id, name, tag, desc: "", invites: [], closed: false, founder: sid, creator: sid, regs: {}, reqs: [] };
  await setTeam(env, tm);
  u.team = id; delete u.created;
  await setUser(env, sid, u);
  await bump(env);
  return json({ ok: true, team: tm });
}
// the founder (or an admin) edits the team; the founder role goes only to a pilot who is in the team
async function putTeam(req, env, sid) {
  const body = await readJson(req, 400_000), tm = await getTeam(env, Number(body.id));
  if (!tm) throw new HttpError(404, "no such team");
  const role = await roleOf(env, sid), me = await getUser(env, sid);
  // the representative (R) may change only the description and the logo; everything else stays with the founder (or an admin)
  const rep = !!me && !!tm.rep && me.name === tm.rep && me.team === tm.id;
  if (tm.founder !== sid && role !== "owner" && role !== "admin" && !rep) throw new HttpError(403, "founder only");
  if ("desc" in body) tm.desc = String(body.desc || "").slice(0, 300);
  if ("img" in body) tm.img = /^data:image\/(webp|jpeg|png);base64,/.test(body.img || "") && body.img.length < 300_000 ? body.img : undefined;
  if (rep && tm.founder !== sid && role !== "owner" && role !== "admin") { await setTeam(env, tm); await bump(env); return json({ ok: true, regs: tm.regs }); }
  if ("closed" in body) tm.closed = !!body.closed;
  if ("invites" in body) tm.invites = (Array.isArray(body.invites) ? body.invites : []).slice(0, 50).map(n => String(n).slice(0, 40));
  if ("rep" in body) tm.rep = body.rep ? String(body.rep).slice(0, 40) : undefined;
  if ("reqs" in body) tm.reqs = (Array.isArray(body.reqs) ? body.reqs : []).slice(-50);
  if ("regs" in body) tm.regs = await keepRegs(env, tm.regs || {}, body.regs);
  if ("founder" in body && body.founder !== tm.founder) {
    const to = await getUser(env, String(body.founder || ""));
    if (!to || to.team !== tm.id) throw new HttpError(400, "the new founder must be in the team");
    tm.founder = to.steamId;
    if (tm.rep === to.name) tm.rep = undefined;
  }
  await setTeam(env, tm);
  await bump(env);
  return json({ ok: true, regs: tm.regs }); // what was kept, so the page can show a refused stage entry
}
async function disbandTeam(req, env, sid) {
  const body = await readJson(req, 1_000), tm = await getTeam(env, Number(body.id));
  if (!tm) throw new HttpError(404, "no such team");
  const role = await roleOf(env, sid);
  if (tm.founder !== sid && role !== "owner" && role !== "admin") throw new HttpError(403, "founder only");
  await env.DB.prepare("DELETE FROM teams WHERE id = ?").bind(tm.id).run();
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
  if (role !== "tech" && body.live && typeof body.live === "object") await kvSet(env, "live", keepCrew(await kvGet(env, "live"), body.live));
  await bump(env);
  return json({ ok: true });
}

async function putLive(req, env) {
  const body = await readJson(req, MAX_DB);
  await kvSet(env, "live", keepCrew(await kvGet(env, "live"), body));
  await bump(env);
  return json({ ok: true });
}

// crew readiness (marshal, judge, streamer) is changed only through /api/ready, one field at a time,
// so presses from different machines never overwrite each other through a whole-state write
const CREW = ["marshal", "judge", "streamer"], CREW_KEYS = ["ready", "readyAt", "gridMini"];
function keepCrew(stored, next) {
  if (!next || typeof next !== "object") return next;
  const bc = next.bc && typeof next.bc === "object" ? { ...next.bc } : null;
  if (!bc) return next;
  for (const k of CREW_KEYS) { if (stored?.bc && k in stored.bc) bc[k] = stored.bc[k]; else delete bc[k]; }
  return { ...next, bc };
}
async function postReady(req, env) {
  const body = await readJson(req, 1_000), v = String(body.v || "");
  if (!CREW.includes(v) && v !== "reset") throw new HttpError(400, "bad crew role");
  const live = (await kvGet(env, "live")) || {}, bc = { ...(live.bc || {}) };
  if (v === "reset") {
    if (body.at != null && bc.readyAt !== body.at) return json({ ok: true, bc }); // someone already reset or a new round started
    bc.ready = {}; bc.readyAt = null;
  } else {
    bc.ready = { ...(bc.ready || {}), [v]: !bc.ready?.[v] };
    const all = CREW.every(k => bc.ready[k]);
    bc.readyAt = all ? Date.now() : null;
    // the page sends the grid's score key; the grid folds to the top 3 until that key changes (the next run score)
    if (all && typeof body.key === "string" && body.key.length <= 32) bc.gridMini = body.key;
  }
  await kvSet(env, "live", { ...live, bc });
  await bump(env);
  return json({ ok: true, bc });
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
    if (u.team != null) await dropRep(env, u.team, u.name);
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
