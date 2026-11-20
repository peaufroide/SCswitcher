// Vérifications de sécurité du background, sans navigateur : node tests/security.test.js
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const assert = require("assert");

function makeArea() {
  const data = {};
  return {
    async get(keys) {
      const out = {};
      for (const k of [].concat(keys)) if (Object.hasOwn(data, k)) out[k] = structuredClone(data[k]);
      return out;
    },
    async set(obj) { Object.assign(data, structuredClone(obj)); },
    async remove(keys) { for (const k of [].concat(keys)) delete data[k]; },
    raw: data
  };
}

const listeners = {};
const ev = (name) => ({ addListener: (fn) => { listeners[name] = fn; } });
const jar = [];
const setCalls = [];
const noop = async () => {};
const chrome = {
  runtime: { id: "ext", onMessage: ev("msg"), onInstalled: ev("inst"), onStartup: ev("start") },
  cookies: { onChanged: ev("cookie"), getAll: async () => jar.slice(), set: async (d) => { setCalls.push(d); }, remove: noop },
  storage: { local: makeArea(), session: makeArea() },
  action: { setBadgeText: noop, setBadgeBackgroundColor: noop },
  tabs: { query: async () => [], create: noop, update: noop, reload: noop },
  windows: { update: noop }
};

const ctx = vm.createContext({
  chrome, crypto: globalThis.crypto, TextEncoder, TextDecoder, btoa, atob, console,
  setTimeout, clearTimeout, fetch: async () => ({ ok: false })
});
vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "background.js"), "utf8"), ctx);

function send(msg, sender = { id: "ext" }) {
  return new Promise((resolve) => {
    if (listeners.msg(msg, sender, resolve) !== true) resolve(undefined);
  });
}

const TOKEN = "2-000000-111111-SECRETTOKEN";
const goodCookie = { name: "oauth_token", value: TOKEN, domain: ".soundcloud.com", path: "/", secure: false, httpOnly: false, storeId: "1" };
const evilCookie = { name: "x", value: "1", domain: ".evilsoundcloud.com", path: "/" };

(async () => {
  // Cookies : domaine SoundCloud seulement, Secure forcé, storeId ignoré.
  assert.strictEqual(ctx.sanitizeCookie(evilCookie), null);
  assert.strictEqual(ctx.sanitizeCookie({ ...goodCookie, domain: "soundcloud.com.evil.com" }), null);
  assert.strictEqual(ctx.sanitizeCookie({ ...goodCookie, value: "a;b" }), null);
  const clean = ctx.sanitizeCookie(goodCookie);
  assert.strictEqual(clean.secure, true);
  assert.strictEqual(clean.storeId, undefined);

  // Import piégé : cookies hors SoundCloud, avatar espion, __proto__.
  const evil = JSON.parse(JSON.stringify({
    p: { name: "__proto__", cookies: [goodCookie] },
    e: { name: "Evil", avatarUrl: "https://attacker.example/pixel.gif", cookies: [goodCookie, evilCookie] }
  }));
  assert.strictEqual((await send({ action: "IMPORT_ACCOUNTS", accounts: evil })).count, 1);
  const stored = chrome.storage.local.raw.sc_accounts.Evil;
  assert.strictEqual(stored.avatarUrl, null);
  assert.deepStrictEqual(stored.cookies.map((c) => c.name), ["oauth_token"]);

  await send({ action: "SWITCH_ACCOUNT", accountName: "Evil" });
  assert.ok(setCalls.length === 1 && setCalls[0].secure && setCalls[0].url.startsWith("https://"));

  console.log("OK : toutes les vérifications de sécurité passent");
})().catch((e) => { console.error(e); process.exit(1); });
