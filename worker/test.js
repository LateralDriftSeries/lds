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
await call("/api/me", { method: "PUT", token: pilot, body: JSON.stringify({ num: 77 }) });
ok((await (await call("/api/state")).json()).users.find(u => u.steamId === PILOT).num === 55, "a claimed number is locked for the pilot");

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

// teams: created by a pilot, edited by its founder (or an admin), the founder role goes to a team member
const THIRD = "76561198000000003", third = await signToken(env, THIRD), TID = 1e6 + Number(PILOT.slice(-6));
const team = (path, body, token = pilot, method = "POST") => call(path, { method, token, body: JSON.stringify(body) });
const teamNow = async () => (await (await call("/api/state")).json()).teams.find(z => z.id === TID);
ok((await team("/api/team/create", { name: "Test Team", tag: "tst" })).ok, "pilot creates a team");
ok((await team("/api/team/create", { name: "Again", tag: "AG" })).status === 409, "only one created team per pilot");
let tmNow = await teamNow();
ok(tmNow.tag === "TST" && tmNow.founder === PILOT, "team stored with its founder");
ok((await team("/api/team", { id: TID, desc: "hi" }, third, "PUT")).status === 403, "a non-founder cannot edit the team");
ok((await team("/api/team", { id: TID, desc: "hi" }, pilot, "PUT")).ok && (await teamNow()).desc === "hi", "founder edits the team");
ok((await team("/api/team", { id: TID, founder: THIRD }, pilot, "PUT")).status === 400, "founder role only to a team member");
// joining: a closed team only by invitation, an open one freely
const teamOf = async sid => (await (await call("/api/state")).json()).users.find(u => u.steamId === sid).team;
await team("/api/team", { id: TID, closed: true }, pilot, "PUT");
await call("/api/me", { method: "PUT", token: third, body: JSON.stringify({ team: TID }) });
ok(await teamOf(THIRD) === null, "a closed team can't be joined without an invitation");
await team("/api/team", { id: TID, closed: true, invites: ["Test Third"] }, pilot, "PUT");
await call("/api/me", { method: "PUT", token: third, body: JSON.stringify({ team: TID }) });
ok(await teamOf(THIRD) === TID, "an invited pilot joins a closed team");
await call("/api/me", { method: "PUT", token: third, body: JSON.stringify({ team: null }) });
await team("/api/team", { id: TID, closed: false, invites: [] }, pilot, "PUT");
await call("/api/me", { method: "PUT", token: third, body: JSON.stringify({ team: TID }) });
ok(await teamOf(THIRD) === TID, "anyone joins an open team");
// the representative edits the description and logo, nothing else
await team("/api/team", { id: TID, rep: "Test Third" }, pilot, "PUT");
ok((await team("/api/team", { id: TID, desc: "by rep", closed: true, invites: ["x"] }, third, "PUT")).ok, "representative may save");
tmNow = await teamNow();
ok(tmNow.desc === "by rep" && !tmNow.closed && !tmNow.invites.length, "representative changed the description only");
await call("/api/me", { method: "PUT", token: third, body: JSON.stringify({ team: null }) });
await call("/api/me", { method: "PUT", token: third, body: JSON.stringify({ team: TID }) });
ok(await teamOf(THIRD) === TID && !(await teamNow()).rep, "leaving drops the representative mark; rejoining starts plain");
ok((await team("/api/team", { id: TID, founder: THIRD }, pilot, "PUT")).ok && (await teamNow()).founder === THIRD, "founder role handed over");
ok((await team("/api/team", { id: TID, desc: "x" }, pilot, "PUT")).status === 403, "the former founder cannot edit any more");
// stage entries live with the team: only while the stage takes registrations, with the server's filing time
const entry = { founderNick: "T", pilots: [{ name: "Test Third", nick: "T3" }], at: 1 };
await team("/api/team", { id: TID, regs: { 203: entry } }, third, "PUT");
ok(!(await teamNow()).regs[203], "no team entry while the stage is not in registration");
await call("/api/live", { method: "PUT", token: owner, body: JSON.stringify({ bc: null, scores: {}, statuses: { 203: "reg" } }) });
await team("/api/team", { id: TID, regs: { 203: entry } }, third, "PUT");
tmNow = await teamNow();
ok(tmNow.regs[203]?.pilots[0].nick === "T3" && tmNow.regs[203].at > 1e12, "team entry saved with the server time");
await call("/api/live", { method: "PUT", token: owner, body: JSON.stringify({ bc: null, scores: {}, statuses: {} }) });
await team("/api/team", { id: TID, regs: {} }, third, "PUT");
ok((await teamNow()).regs[203]?.pilots[0].nick === "T3", "after registration the entry cannot be changed or withdrawn");
ok((await team("/api/team/disband", { id: TID }, pilot)).status === 403, "only the founder disbands");
ok((await team("/api/team/disband", { id: TID }, third)).ok && !(await teamNow()), "founder disbands the team");

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
ok((await ownerCall({ sid: PILOT, num: -1 })).status === 400 && (await ownerCall({ sid: PILOT, num: 1000 })).status === 400, "bad number refused");
ok((await ownerCall({ sid: PILOT, num: 0 })).ok, "head admin can give number 0");
await call("/api/me", { method: "PUT", token: pilot, body: JSON.stringify({ num: 5, regs: [203] }) });
ok((await (await call("/api/me", { token: pilot })).json()).user.num === 0, "number 0 survives the pilot's own saves");
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

// crew readiness: one press at a time on the server, never undone by a whole live-state write
const ready = (v, token, extra = {}) => call("/api/ready", { method: "POST", token, body: JSON.stringify({ v, ...extra }) });
ok((await ready("judge", pilot)).status === 403, "a pilot cannot press readiness");
await ready("marshal", owner); await ready("judge", owner);
await call("/api/live", { method: "PUT", token: owner, body: JSON.stringify({ bc: { onTrack: "Test Pilot", ready: {}, gridMini: "x" }, scores: {} }) });
let rd = await (await ready("streamer", owner, { key: "k1" })).json();
ok(rd.bc.ready.marshal && rd.bc.ready.judge && rd.bc.ready.streamer && rd.bc.readyAt > 0 && rd.bc.gridMini === "k1", "presses add up; a whole-state write doesn't undo them");
ok((await (await call("/api/state")).json()).live.bc.onTrack === "Test Pilot", "the rest of the live state still saves");
rd = await (await ready("reset", owner, { at: 1 })).json();
ok(rd.bc.readyAt > 0, "a stale reset is ignored");
rd = await (await ready("reset", owner, { at: rd.bc.readyAt })).json();
ok(!rd.bc.readyAt && !Object.keys(rd.bc.ready).length && rd.bc.gridMini === "k1", "reset clears the buttons, the grid stays folded");
// Discord: run with --var DISCORD_WEBHOOK:http://127.0.0.1:8769/hook; this script stands in for Discord and counts the posts
const { createServer } = await import("node:http");
const hooks = [], hookSrv = createServer((q, s) => { let b = ""; q.on("data", c => b += c); q.on("end", () => { hooks.push(JSON.parse(b)); s.writeHead(204); s.end(); }); }).listen(8769, "127.0.0.1");
await call("/api/db", { method: "PUT", token: owner, body: JSON.stringify({ db: { tours: [{ id: 901, season: 9, stage: 2, track: "Hook Track @everyone", dates: "1–2 Jan", status: "soon" }], seasons: [{ id: 9, name: "S9" }] } }) });
const setStatus = s => call("/api/live", { method: "PUT", token: owner, body: JSON.stringify({ bc: null, scores: {}, statuses: { 901: s } }) });
await setStatus("soon"); await setStatus("reg"); await setStatus("reg");
await new Promise(z => setTimeout(z, 300));
ok(hooks.length === 1 && hooks[0].embeds[0].title.includes("Регистрация открыта") && hooks[0].embeds[0].url.endsWith("#t-901"), "registration opening is posted once");
ok(hooks[0].allowed_mentions?.parse?.length === 0, "the post can't ping anyone");
await setStatus("qualifying"); await setStatus("reg"); await setStatus("qualifying");
await new Promise(z => setTimeout(z, 300));
ok(hooks.length === 2 && hooks[1].embeds[0].title.includes("Регистрация закрыта"), "qualifying start is posted once, flipping back doesn't repeat");
// Discord settings from the admin panel: own text and picture; the webhook address is checked and never read back
const PX = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
const dput = (body, token = owner) => call("/api/discord", { method: "PUT", token, body: JSON.stringify(body) });
ok((await dput({ reg: { text: "x" } }, pilot)).status === 403 && (await call("/api/discord", { token: pilot })).status === 403, "a pilot can't read or change Discord settings");
ok((await dput({ hook: "https://evil.example/api/webhooks/1/abc" })).status === 400, "only a discord.com webhook address is taken");
const dc = await (await dput({ hook: "https://discord.com/api/webhooks/123/abc-DEF_9", reg: { text: "Своё объявление", img: PX }, qualifying: { text: "" } })).json();
ok(dc.hook === true && !JSON.stringify(dc).includes("abc-DEF_9") && dc.reg.text === "Своё объявление", "the webhook is saved but never sent back");
ok((await dput({ hook: "" })).ok, "the webhook can be cleared");
const imgRes = await call("/api/discord/img/reg");
ok(imgRes.ok && imgRes.headers.get("content-type") === "image/png" && (await imgRes.arrayBuffer()).byteLength === 70, "the picture is served for Discord");
await call("/api/db", { method: "PUT", token: owner, body: JSON.stringify({ db: { tours: [{ id: 901, season: 9, stage: 2, track: "Hook Track", status: "soon" }, { id: 902, season: 9, stage: 3, track: "Own Text", status: "soon" }], seasons: [{ id: 9, name: "S9" }] } }) });
await call("/api/live", { method: "PUT", token: owner, body: JSON.stringify({ bc: null, scores: {}, statuses: { 901: "reg", 902: "reg" } }) });
await new Promise(z => setTimeout(z, 300));
ok(hooks.length === 3 && hooks[2].embeds[0].description.startsWith("Своё объявление") && /\/api\/discord\/img\/reg\?v=\d+$/.test(hooks[2].embeds[0].image?.url || ""), "the post carries the admin's text and picture");
hookSrv.close();
// CORS only for the site
ok((await call("/api/state")).headers.get("access-control-allow-origin") === SITE, "CORS for the site");
ok(!(await fetch(API + "/api/state", { headers: { origin: "https://evil.example" } })).headers.get("access-control-allow-origin"), "no CORS for other sites");

console.log(`all ${n} checks passed`);
