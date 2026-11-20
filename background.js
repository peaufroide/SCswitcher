const SOUNDCLOUD_DOMAINS = [
  "soundcloud.com",
  ".soundcloud.com",
  "api.soundcloud.com",
  "api-v2.soundcloud.com",
  "m.soundcloud.com"
];

// Verrou pour éviter les boucles d'auto-sauvegarde pendant les transactions
let isSwitching = false;

// ---------------------------------------------------------------------------
// 0. COFFRE CHIFFRÉ
// Les cookies de chaque compte sont chiffrés (AES-GCM 256) avec une clé dérivée
// de la passphrase (PBKDF2-SHA256). La clé ne vit que dans chrome.storage.session
// (mémoire, effacée à la fermeture du navigateur) : sur disque, rien d'exploitable.
// ---------------------------------------------------------------------------
const LOCKED = "LOCKED";
const VAULT_CHECK = "sc-switcher-vault-v1";
const PBKDF2_ITERATIONS = 600000;
const MIN_PASSPHRASE = 8;
const utf8 = new TextEncoder();
const utf8Decoder = new TextDecoder();

function toB64(buf) {
  let s = "";
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s);
}

function fromB64(s) {
  return Uint8Array.from(atob(String(s)), (c) => c.charCodeAt(0));
}

async function deriveKey(passphrase, salt) {
  const base = await crypto.subtle.importKey("raw", utf8.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function encryptJson(key, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, utf8.encode(JSON.stringify(value)));
  return { iv: toB64(iv), ct: toB64(ct) };
}

async function decryptJson(key, box) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(box.iv) }, key, fromB64(box.ct));
  return JSON.parse(utf8Decoder.decode(pt));
}

async function getSessionKey() {
  const { sc_key } = await chrome.storage.session.get("sc_key");
  if (!sc_key) return null;
  return crypto.subtle.importKey("raw", fromB64(sc_key), "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function requireKey() {
  const key = await getSessionKey();
  if (!key) throw new Error(LOCKED);
  return key;
}

async function getVaultState() {
  const { sc_vault, sc_accounts = {} } = await chrome.storage.local.get(["sc_vault", "sc_accounts"]);
  return {
    success: true,
    hasVault: Boolean(sc_vault),
    unlocked: Boolean(await getSessionKey()),
    hasLegacy: Object.values(sc_accounts).some((a) => Array.isArray(a?.cookies))
  };
}

// Déverrouille le coffre (ou le crée au premier usage) et migre les anciens
// comptes stockés en clair (v1.1.0).
async function handleUnlock(passphrase) {
  if (typeof passphrase !== "string" || !passphrase) {
    return { success: false, error: "Passphrase requise." };
  }

  const { sc_vault, sc_accounts = {} } = await chrome.storage.local.get(["sc_vault", "sc_accounts"]);
  let key;

  if (sc_vault) {
    key = await deriveKey(passphrase, fromB64(sc_vault.salt));
    try {
      await decryptJson(key, sc_vault.check);
    } catch {
      return { success: false, error: "Passphrase incorrecte." };
    }
  } else {
    if (passphrase.length < MIN_PASSPHRASE) {
      return { success: false, error: `Passphrase trop courte (${MIN_PASSPHRASE} caractères min.).` };
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    key = await deriveKey(passphrase, salt);
    await chrome.storage.local.set({
      sc_vault: { salt: toB64(salt), check: await encryptJson(key, VAULT_CHECK) }
    });
  }

  await chrome.storage.session.set({ sc_key: toB64(await crypto.subtle.exportKey("raw", key)) });

  let migrated = false;
  for (const acc of Object.values(sc_accounts)) {
    if (Array.isArray(acc?.cookies)) {
      acc.secret = await encryptJson(key, acc.cookies.map(sanitizeCookie).filter(Boolean));
      delete acc.cookies;
      migrated = true;
    }
  }
  if (migrated) await chrome.storage.local.set({ sc_accounts });

  return { success: true };
}

// Passphrase oubliée : seule issue, tout effacer.
async function handleResetVault() {
  await chrome.storage.local.remove(["sc_vault", "sc_accounts", "sc_active_account"]);
  await chrome.storage.session.remove("sc_key");
  await updateExtensionBadge();
  return { success: true };
}

// Initialisation au démarrage
chrome.runtime.onInstalled.addListener(() => {
  updateExtensionBadge();
});

chrome.runtime.onStartup.addListener(() => {
  updateExtensionBadge();
});

// 1. ÉCOUTEUR DE MESSAGES POPUP
const handlers = {
  SWITCH_ACCOUNT: (r) => handleSwitchAccount(r.accountName).then(() => ({ success: true })),
  CLEAN_LOGOUT: () => handleCleanLogout().then(() => ({ success: true })),
  SAVE_ACTIVE_ACCOUNT: (r) => handleManualSave(r.name),
  DELETE_ACCOUNT: (r) => handleDeleteAccount(r.name),
  IMPORT_ACCOUNTS: (r) => handleImportAccounts(r.file, r.passphrase),
  GET_CURRENT_SC_PROFILE: () => detectCurrentProfile(),
  GET_VAULT_STATE: () => getVaultState(),
  UNLOCK: (r) => handleUnlock(r.passphrase),
  RESET_VAULT: () => handleResetVault()
};

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Uniquement nos propres pages (popup), jamais un onglet / content script.
  if (sender.id !== chrome.runtime.id || sender.tab) return;
  if (!request || !Object.hasOwn(handlers, request.action)) return;

  handlers[request.action](request).then(sendResponse, (err) => {
    sendResponse({ success: false, error: err?.message || String(err) });
  });
  return true;
});

// 2. AUTO-SYNC EN TEMPS RÉEL
chrome.cookies.onChanged.addListener((changeInfo) => {
  if (isSwitching) return;

  const domain = changeInfo.cookie?.domain || "";
  if (!SOUNDCLOUD_DOMAINS.some(d => domain.includes("soundcloud.com"))) return;

  debouncedSyncActiveAccount();
});

let syncTimeout = null;
function debouncedSyncActiveAccount() {
  if (isSwitching) return;
  if (syncTimeout) clearTimeout(syncTimeout);

  syncTimeout = setTimeout(async () => {
    if (isSwitching) return;
    try {
      const key = await getSessionKey();
      if (!key) return; // Coffre verrouillé : impossible de chiffrer, on attend.

      const data = await chrome.storage.local.get(["sc_active_account", "sc_accounts"]);
      const activeName = data.sc_active_account;
      const accounts = data.sc_accounts || {};

      if (activeName && Object.hasOwn(accounts, activeName)) {
        const freshCookies = await getSoundcloudCookies();
        if (hasSoundcloudAuthCookie(freshCookies)) {
          accounts[activeName].secret = await encryptJson(key, freshCookies.map(sanitizeCookie).filter(Boolean));
          delete accounts[activeName].cookies;
          accounts[activeName].lastSynced = new Date().toISOString();
          await chrome.storage.local.set({ sc_accounts: accounts });
        }
      }
    } catch (e) {
      console.warn("Auto-sync background error:", e);
    }
  }, 1200);
}

// 3. RÉCUPÉRATION DU PROFIL SOUNDCLOUD VIA API
async function fetchSoundcloudUserProfile(oauthToken) {
  if (!oauthToken) return null;
  try {
    const response = await fetch("https://api-v2.soundcloud.com/me", {
      headers: {
        "Authorization": `OAuth ${oauthToken}`,
        "Accept": "application/json"
      }
    });
    if (response.ok) {
      const user = await response.json();
      return {
        username: user.username || user.permalink || "",
        avatarUrl: user.avatar_url || "",
        permalinkUrl: user.permalink_url || `https://soundcloud.com/${user.permalink}`,
        followersCount: user.followers_count || 0
      };
    }
  } catch (e) {
    console.warn("SoundCloud Profile Fetch error:", e);
  }
  return null;
}

// Détection du profil actif actuellement dans le navigateur
async function detectCurrentProfile() {
  const cookies = await getSoundcloudCookies();
  const oauthCookie = cookies.find(c => c.name === "oauth_token" && c.value);
  if (!oauthCookie) {
    return { success: false, authenticated: false };
  }

  const profile = await fetchSoundcloudUserProfile(oauthCookie.value);
  return {
    success: true,
    authenticated: true,
    profile: profile
  };
}

// 4. GESTION DES BADGES D'ICÔNE CHROME
async function updateExtensionBadge() {
  try {
    const data = await chrome.storage.local.get(["sc_active_account"]);
    const active = data.sc_active_account;
    if (active) {
      const badgeText = active.trim().substring(0, 3).toUpperCase();
      await chrome.action.setBadgeText({ text: badgeText });
      await chrome.action.setBadgeBackgroundColor({ color: "#ff5500" });
    } else {
      await chrome.action.setBadgeText({ text: "" });
    }
  } catch (e) {
    console.warn("Badge update error:", e);
  }
}

// 5. GESTION DES COOKIES
const COOKIE_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$/;
const UNSAFE_COOKIE_CHARS = /[\u0000-\u001F\u007F;]/;
const SAME_SITE_VALUES = ["no_restriction", "lax", "strict"];
const MAX_COOKIES_PER_ACCOUNT = 100;

function isSoundcloudDomain(domain) {
  const d = String(domain).replace(/^\./, "").toLowerCase();
  return d === "soundcloud.com" || d.endsWith(".soundcloud.com");
}

// Seul format de cookie accepté avant injection dans le navigateur : domaine
// SoundCloud uniquement, Secure forcé, champs reconstruits (rien n'est recopié tel quel).
function sanitizeCookie(c) {
  if (!c || typeof c !== "object") return null;
  if (typeof c.name !== "string" || !COOKIE_NAME_RE.test(c.name)) return null;
  if (typeof c.value !== "string" || c.value.length > 4096 || UNSAFE_COOKIE_CHARS.test(c.value)) return null;
  if (typeof c.domain !== "string" || !isSoundcloudDomain(c.domain)) return null;

  const pathOk = typeof c.path === "string" && c.path.startsWith("/") && c.path.length <= 1024 && !UNSAFE_COOKIE_CHARS.test(c.path);
  const cookie = {
    name: c.name,
    value: c.value,
    domain: c.domain.toLowerCase(),
    path: pathOk ? c.path : "/",
    secure: true,
    httpOnly: c.httpOnly === true,
    hostOnly: c.hostOnly === true
  };
  if (SAME_SITE_VALUES.includes(c.sameSite)) cookie.sameSite = c.sameSite;
  if (Number.isFinite(c.expirationDate)) cookie.expirationDate = c.expirationDate;
  return cookie;
}

function hasSoundcloudAuthCookie(cookies) {
  if (!Array.isArray(cookies) || cookies.length === 0) return false;
  return cookies.some(c => c.name === "oauth_token" && typeof c.value === "string" && c.value.trim().length > 0);
}

async function getSoundcloudCookies() {
  const allCookies = [];
  for (const domain of SOUNDCLOUD_DOMAINS) {
    try {
      const cookies = await chrome.cookies.getAll({ domain: domain });
      for (const c of cookies) {
        if (!allCookies.some(existing => existing.name === c.name && existing.domain === c.domain && existing.path === c.path)) {
          allCookies.push(c);
        }
      }
    } catch (e) {
      console.warn(`Erreur lecture cookies domaine ${domain}:`, e);
    }
  }
  return allCookies;
}

async function clearSoundcloudCookies() {
  const cookies = await getSoundcloudCookies();
  for (const cookie of cookies) {
    const cleanDomain = cookie.domain.startsWith(".") ? cookie.domain.substring(1) : cookie.domain;
    const protocol = cookie.secure ? "https:" : "http:";
    const url = `${protocol}//${cleanDomain}${cookie.path}`;
    try {
      await chrome.cookies.remove({
        url: url,
        name: cookie.name,
        storeId: cookie.storeId
      });
    } catch (e) {
      console.warn(`Erreur suppression cookie ${cookie.name}:`, e);
    }
  }
}

async function setSoundcloudCookies(cookies) {
  for (const raw of cookies) {
    const cookie = sanitizeCookie(raw);
    if (!cookie) continue;

    const host = cookie.domain.replace(/^\./, "");
    const cookieDetails = {
      url: `https://${host}${cookie.path}`,
      name: cookie.name,
      value: cookie.value,
      path: cookie.path,
      secure: true,
      httpOnly: cookie.httpOnly
    };

    if (!cookie.hostOnly) cookieDetails.domain = cookie.domain;
    if (cookie.sameSite) cookieDetails.sameSite = cookie.sameSite;
    if (cookie.expirationDate) cookieDetails.expirationDate = cookie.expirationDate;

    try {
      await chrome.cookies.set(cookieDetails);
    } catch (e) {
      console.warn(`Erreur injection cookie ${cookie.name}:`, e);
    }
  }
}

// 6. ACTIONS MÉTIER

// Sauvegarde manuelle ou auto-détectée d'un profil
async function handleManualSave(preferredName) {
  const key = await requireKey();
  const cookies = await getSoundcloudCookies();
  if (!hasSoundcloudAuthCookie(cookies)) {
    return {
      success: false,
      error: "Aucune session active détectée. Connectez-vous d'abord sur SoundCloud."
    };
  }

  const oauthCookie = cookies.find(c => c.name === "oauth_token");
  const profile = await fetchSoundcloudUserProfile(oauthCookie?.value);

  // Nom final : nom spécifié par l'utilisateur ou nom SoundCloud détecté
  let finalName = (preferredName || "").trim();
  if (!finalName && profile && profile.username) {
    finalName = profile.username;
  }
  if (!finalName || finalName === "__proto__") {
    finalName = "Compte SoundCloud";
  }

  const data = await chrome.storage.local.get(["sc_accounts"]);
  const accounts = data.sc_accounts || {};

  accounts[finalName] = {
    name: finalName,
    username: profile?.username || finalName,
    avatarUrl: profile?.avatarUrl || null,
    permalinkUrl: profile?.permalinkUrl || null,
    secret: await encryptJson(key, cookies.map(sanitizeCookie).filter(Boolean)),
    savedAt: new Date().toISOString(),
    lastSynced: new Date().toISOString()
  };

  await chrome.storage.local.set({
    sc_accounts: accounts,
    sc_active_account: finalName
  });

  await updateExtensionBadge();
  return { success: true, name: finalName, profile: profile };
}

// Suppression d'un compte
async function handleDeleteAccount(name) {
  const cleanName = (name || "").trim();
  if (!cleanName) return { success: false, error: "Nom invalide." };

  const data = await chrome.storage.local.get(["sc_accounts", "sc_active_account"]);
  const accounts = data.sc_accounts || {};
  delete accounts[cleanName];

  const updates = { sc_accounts: accounts };
  if (data.sc_active_account === cleanName) {
    updates.sc_active_account = null;
  }

  await chrome.storage.local.set(updates);
  await updateExtensionBadge();
  return { success: true };
}

// Importation de comptes sauvegardés.
// Fichier chiffré (v1.2+) : déchiffré avec la passphrase du fichier.
// Ancien fichier en clair (v1.1.0) : accepté pour migration, mais nettoyé.
const MAX_IMPORT_ACCOUNTS = 50;
const AVATAR_URL_RE = /^https:\/\/[a-z0-9-]+\.sndcdn\.com\//i;

function cleanText(value, max) {
  if (typeof value !== "string") return "";
  return value.replace(/[\u0000-\u001F\u007F-\u009F]/g, "").trim().slice(0, max);
}

async function handleImportAccounts(file, passphrase) {
  const key = await requireKey();
  const imported = file?.accounts || file;
  if (!imported || typeof imported !== "object") {
    return { success: false, error: "Format de fichier invalide." };
  }

  let fileKey = null;
  if (file.vault) {
    try {
      fileKey = await deriveKey(String(passphrase || ""), fromB64(file.vault.salt));
      await decryptJson(fileKey, file.vault.check);
    } catch {
      return { success: false, error: "Passphrase du fichier incorrecte." };
    }
  }

  const data = await chrome.storage.local.get(["sc_accounts"]);
  const existing = data.sc_accounts || {};
  const now = new Date().toISOString();

  let count = 0;
  for (const acc of Object.values(imported).slice(0, MAX_IMPORT_ACCOUNTS)) {
    const name = cleanText(acc?.name, 50);
    if (!name || name === "__proto__") continue;

    let rawCookies;
    try {
      rawCookies = acc.secret && fileKey ? await decryptJson(fileKey, acc.secret) : acc.cookies;
    } catch {
      continue;
    }
    if (!Array.isArray(rawCookies)) continue;

    const cookies = rawCookies.slice(0, MAX_COOKIES_PER_ACCOUNT).map(sanitizeCookie).filter(Boolean);
    if (!hasSoundcloudAuthCookie(cookies)) continue;

    existing[name] = {
      name,
      username: cleanText(acc.username, 50) || name,
      avatarUrl: typeof acc.avatarUrl === "string" && AVATAR_URL_RE.test(acc.avatarUrl) ? acc.avatarUrl : null,
      permalinkUrl: typeof acc.permalinkUrl === "string" && acc.permalinkUrl.startsWith("https://soundcloud.com/") ? acc.permalinkUrl : null,
      secret: await encryptJson(key, cookies),
      savedAt: now,
      lastSynced: now
    };
    count++;
  }

  if (count === 0) {
    return { success: false, error: "Aucun profil valide trouvé dans le fichier importé." };
  }

  await chrome.storage.local.set({ sc_accounts: existing });
  await updateExtensionBadge();
  return { success: true, count: count };
}

// Bascule de compte avec actualisation cohérente des onglets SoundCloud
async function handleSwitchAccount(targetName) {
  isSwitching = true;

  try {
    const key = await requireKey();
    const data = await chrome.storage.local.get(["sc_accounts", "sc_active_account"]);
    const accounts = data.sc_accounts || {};
    const currentActive = data.sc_active_account;

    // Sauvegarder les cookies frais du compte actuel si connecté
    if (currentActive && Object.hasOwn(accounts, currentActive)) {
      const currentCookies = await getSoundcloudCookies();
      if (hasSoundcloudAuthCookie(currentCookies)) {
        accounts[currentActive].secret = await encryptJson(key, currentCookies.map(sanitizeCookie).filter(Boolean));
        delete accounts[currentActive].cookies;
        accounts[currentActive].lastSynced = new Date().toISOString();
      }
    }

    const targetAccount = Object.hasOwn(accounts, targetName) ? accounts[targetName] : null;
    if (!targetAccount?.secret) {
      throw new Error(`Le compte "${targetName}" est introuvable.`);
    }

    // Déchiffrer AVANT de toucher aux cookies : un échec ne déconnecte personne.
    const targetCookies = await decryptJson(key, targetAccount.secret);

    // 1. Vider les cookies existants
    await clearSoundcloudCookies();

    // 2. Injecter les cookies du nouveau profil
    await setSoundcloudCookies(targetCookies);

    // 3. Mettre à jour le compte actif
    await chrome.storage.local.set({
      sc_accounts: accounts,
      sc_active_account: targetName
    });

    await updateExtensionBadge();

    // 4. Synchroniser tous les onglets SoundCloud ouverts
    const tabs = await chrome.tabs.query({ url: "*://*.soundcloud.com/*" });
    if (tabs.length > 0) {
      const primaryTab = tabs[0];
      await chrome.tabs.update(primaryTab.id, { url: "https://soundcloud.com/discover", active: true });
      if (primaryTab.windowId) {
        await chrome.windows.update(primaryTab.windowId, { focused: true });
      }
      // Recharger les éventuels autres onglets SoundCloud pour rafraîchir leur session
      for (let i = 1; i < tabs.length; i++) {
        try {
          await chrome.tabs.reload(tabs[i].id);
        } catch (e) {}
      }
    } else {
      await chrome.tabs.create({ url: "https://soundcloud.com/discover", active: true });
    }
  } finally {
    setTimeout(() => {
      isSwitching = false;
    }, 1500);
  }
}

// Déconnexion propre
async function handleCleanLogout() {
  isSwitching = true;
  try {
    await clearSoundcloudCookies();
    await chrome.storage.local.remove(["sc_active_account"]);
    await updateExtensionBadge();

    const tabs = await chrome.tabs.query({ url: "*://*.soundcloud.com/*" });
    if (tabs.length > 0) {
      await chrome.tabs.update(tabs[0].id, { url: "https://soundcloud.com/discover", active: true });
    } else {
      await chrome.tabs.create({ url: "https://soundcloud.com/discover" });
    }
  } finally {
    setTimeout(() => {
      isSwitching = false;
    }, 1000);
  }
}
