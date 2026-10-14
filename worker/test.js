// Checks the API against a running `wrangler dev` (local D1 with the two test users from test-users.sql).
// usage: node test.js [http://localhost:8787]
import assert from "node:assert/strict";
import { signToken, verifyToken } from "./src/index.js";

const API = process.argv[2] || "http://localhost:8787";
const env = { SESSION_SECRET: "local-test-secret-0123456789abcdef0123456789" };
const SITE = "http://localhost:8766", OWNER = "76561198000000001", PILOT = "76561198000000002";
const owner = await signToken(env, OWNER), pilot = await signToken(env, PILOT);
const call = (path, { token, ...opt } = {}) => fetch(API + path, { redirect: "manual", ...opt, headers: { origin: SITE, "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) } });
let n = 0; const ok = (cond, msg) => { assert.ok(cond, msg); n++; };

// tokens
ok(await verifyToken(env, owner) === OWNER, "token round trip");
ok(await verifyToken(env, owner.slice(0, -2) + "xx") === null, "tampered token rejected");
ok(await verifyToken(env, await signToken(env, OWNER, Date.now() - 31 * 864e5)) === null, "expired token rejected");

// Steam redirect: only back to our own site
let r = await call("/auth/steam?return=" + encodeURIComponent(SITE + "/"));
ok(r.status === 302 && r.headers.get("location").startsWith("https://steamcommunity.com/openid/login?"), "redirects to Steam");
ok(new URL(r.headers.get("location")).searchParams.get("openid.return_to").includes("/auth/steam/callback"), "return_to is our callback");
ok((await call("/auth/steam?return=" + encodeURIComponent("https://evil.example/"))).status === 400, "foreign return url refused");
// a forged callback (no real Steam assertion) does not sign anyone in
r = await call("/auth/steam/callback?return=" + encodeURIComponent(SITE + "/") + "&openid.mode=id_res&openid.claimed_id=" + encodeURIComponent("https://steamcommunity.com/openid/id/" + OWNER) + "&openid.op_endpoint=" + encodeURIComponent("https://steamcommunity.com/openid/login") + "&openid.return_to=" + encodeURIComponent(API + "/auth/steam/callback"));
ok(r.status === 302 && r.headers.get("location").endsWith("#auth=failed"), "forged Steam answer rejected");

// who am I
ok((await call("/api/me")).status === 401, "no token: 401");
ok((await call("/api/me", { token: "junk.junk" })).status === 401, "bad token: 401");
ok((await (await call("/api/me", { token: owner })).json()).admin === true, "owner is admin");
ok((await (await call("/api/me", { token: pilot })).json()).admin === false, "pilot is not admin");
ok((await (await call("/api/me", { token: owner })).json()).owner === true, "owner is head admin");

// a pilot edits only their own profile; name stays the Steam name
r = await call("/api/me", { method: "PUT", token: pilot, body: JSON.stringify({ num: 55, regs: [203], name: "Hacker", about: { ru: "x".repeat(200) } }) });
ok(r.ok, "pilot saves profile");
let st = await (await call("/api/state")).json();
const p = st.users.find(u => u.steamId === PILOT);
ok(p.num === 55 && p.regs[0] === 203 && p.name === "Test Pilot" && p.about.ru.length === 60, "profile saved, name untouched, about capped");

// league data: admins only
ok((await call("/api/db", { method: "PUT", token: pilot, body: JSON.stringify({ db: { teams: [] } }) })).status === 403, "pilot cannot write league data");
ok((await call("/api/live", { method: "PUT", token: pilot, body: "{}" })).status === 403, "pilot cannot write live data");
ok((await call("/api/db", { method: "PUT", token: owner, body: JSON.stringify({ db: { settings: { maxStage: 40 }, protests: [] } }) })).ok, "owner writes league data");
ok((await call("/api/live", { method: "PUT", token: owner, body: JSON.stringify({ bc: { onTrack: "Test Pilot" }, scores: {} }) })).ok, "owner writes live data");

// roles by SteamID: tech writes only the rules, judges write live data, admins can't touch roles
const putDbAs = (token, db) => call("/api/db", { method: "PUT", token, body: JSON.stringify({ db }) });
const base = { settings: { maxStage: 40 }, protests: [] };
const setRole = r => putDbAs(owner, { ...base, roleIds: r ? { [PILOT]: r } : {} });
await setRole("tech");
ok((await (await call("/api/me", { token: pilot })).json()).role === "tech", "role comes from roleIds");
ok((await putDbAs(pilot, { rules: { version: "9" }, settings: { maxStage: 1 } })).ok, "tech saves");
st = await (await call("/api/state")).json();
ok(st.db.rules.version === "9" && st.db.settings.maxStage === 40, "tech changed only the rules");
ok((await call("/api/live", { method: "PUT", token: pilot, body: "{}" })).status === 403, "tech cannot write live data");
await setRole("judge");
ok((await call("/api/live", { method: "PUT", token: pilot, body: JSON.stringify({ bc: { onTrack: "Test Pilot" }, scores: {}, brackets: { 203: { w: {} } } }) })).ok, "judge writes live data");
ok((await putDbAs(pilot, base)).status === 403, "judge cannot write league data");
await setRole("admin");
ok((await putDbAs(pilot, { ...base, roleIds: {} })).ok, "admin writes league data");
st = await (await call("/api/state")).json();
ok(st.db.roleIds[PILOT] === "admin", "admin cannot change roles");
await setRole("");
ok((await (await call("/api/me", { token: pilot })).json()).role === "", "role removed");

// protests: only while the stage runs, only by its pilots, once per opponent; it lands under the pilot's Steam name
const protest = (tour, token = pilot) => call("/api/protest", { method: "POST", token, body: JSON.stringify({ tour, against: "Someone", text: "contact" }) });
ok((await protest(203)).status === 409, "no protest before the stage runs");
await call("/api/live", { method: "PUT", token: owner, body: JSON.stringify({ bc: { onTrack: "Test Pilot" }, scores: {}, statuses: { 203: "qualifying", 204: "qualifying" } }) });
ok((await protest(204)).status === 403, "no protest from a pilot not in the stage");
ok((await protest(203)).ok, "pilot files protest");
ok((await protest(203)).status === 409, "duplicate protest refused");
st = await (await call("/api/state")).json();
ok(st.db.settings.maxStage === 40 && st.db.protests.at(-1).from === "Test Pilot" && st.live.bc.onTrack === "Test Pilot", "state has db, protest and live");

// head admin: numbers and removals; others can't
const ownerCall = (body, token = owner) => call("/api/owner/user", { method: "POST", token, body: JSON.stringify(body) });
ok((await ownerCall({ sid: OWNER, num: 7 }, pilot)).status === 403, "pilot cannot use head admin tools");
ok((await ownerCall({ sid: PILOT, num: 0 })).status === 400, "bad number refused");
ok((await ownerCall({ sid: PILOT, num: 12 })).ok, "head admin sets a number");
st = await (await call("/api/state")).json();
ok(st.users.find(u => u.steamId === PILOT).num === 12 && st.users.find(u => u.steamId === OWNER).owner === true, "number saved, owner flagged");
ok((await ownerCall({ sid: PILOT, kick: true })).ok, "head admin removes a pilot");
ok((await call("/api/me", { token: pilot })).status === 401, "removed pilot is signed out");
st = await (await call("/api/state")).json();

// cheap poll when nothing changed
ok(Object.keys(await (await call("/api/state?v=" + st.v)).json()).join() === "v", "unchanged state answers with version only");

// long poll: held while nothing changes, answers as soon as something does
let t0 = Date.now(), held = await (await call(`/api/state?v=${st.v}&wait=2`)).json();
ok(Object.keys(held).join() === "v" && Date.now() - t0 >= 1800, "long poll waits when nothing changed");
t0 = Date.now();
const waiting = call(`/api/state?v=${st.v}&wait=20`).then(r => r.json());
setTimeout(() => call("/api/me", { method: "PUT", token: owner, body: JSON.stringify({ num: 9 }) }), 1200);
held = await waiting;
ok("users" in held && Date.now() - t0 < 6000, "long poll answers right after a change");

// CORS only for the site
ok((await call("/api/state")).headers.get("access-control-allow-origin") === SITE, "CORS for the site");
ok(!(await fetch(API + "/api/state", { headers: { origin: "https://evil.example" } })).headers.get("access-control-allow-origin"), "no CORS for other sites");

console.log(`all ${n} checks passed`);
