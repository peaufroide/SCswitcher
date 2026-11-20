// DOM Elements
const accountNameInput = document.getElementById("accountName");
const saveBtn = document.getElementById("saveBtn");
const saveStatus = document.getElementById("saveStatus");
const accountsList = document.getElementById("accountsList");
const accountCount = document.getElementById("accountCount");
const openSoundcloudBtn = document.getElementById("openSoundcloudBtn");
const cleanLogoutBtn = document.getElementById("cleanLogoutBtn");
const exportBtn = document.getElementById("exportBtn");
const importBtn = document.getElementById("importBtn");
const importFileInput = document.getElementById("importFileInput");
const passDialog = document.getElementById("passDialog");
const passForm = document.getElementById("passForm");
const passTitle = document.getElementById("passTitle");
const passInput = document.getElementById("passInput");
const passConfirm = document.getElementById("passConfirm");
const passError = document.getElementById("passError");
const passReset = document.getElementById("passReset");

const LOCKED = "LOCKED";
const MAX_IMPORT_BYTES = 1_000_000;

// --- Coffre chiffré : passphrase -------------------------------------------

// Ouvre la boîte de dialogue ; résout avec la passphrase, ou null si annulé.
function askPassphrase({ title, create = false, allowReset = false, error = "" }) {
  return new Promise((resolve) => {
    passTitle.textContent = title;
    passError.textContent = error;
    passInput.value = "";
    passConfirm.value = "";
    passInput.minLength = create ? 8 : 0;
    passInput.autocomplete = create ? "new-password" : "current-password";
    passConfirm.hidden = !create;
    passConfirm.required = create;
    passReset.hidden = !allowReset;
    passDialog.returnValue = "";
    passDialog.onclose = () => resolve(passDialog.returnValue === "ok" ? passInput.value : null);
    passDialog.showModal();
  });
}

passForm.addEventListener("submit", (e) => {
  if (e.submitter?.value === "ok" && !passConfirm.hidden && passInput.value !== passConfirm.value) {
    e.preventDefault();
    passError.textContent = "Les passphrases ne correspondent pas";
  }
});

passReset.addEventListener("click", async () => {
  if (!confirm("Supprimer tous les comptes enregistrés et la passphrase ? Cette action est définitive.")) return;
  await chrome.runtime.sendMessage({ action: "RESET_VAULT" });
  passDialog.close("cancel");
  showStatus("Coffre réinitialisé", "success");
  loadAccounts();
});

// Déverrouille (ou crée) le coffre. Renvoie true si c'est fait.
async function unlockFlow() {
  const state = await chrome.runtime.sendMessage({ action: "GET_VAULT_STATE" });
  if (state?.unlocked) return true;

  let error = "";
  for (;;) {
    const passphrase = await askPassphrase(state?.hasVault
      ? { title: "Passphrase pour déverrouiller vos sessions", allowReset: true, error }
      : { title: "Choisissez une passphrase (8 car. min.) pour chiffrer vos sessions. Elle ne peut pas être récupérée.", create: true, error });
    if (passphrase === null) return false;

    const res = await chrome.runtime.sendMessage({ action: "UNLOCK", passphrase });
    if (res?.success) return true;
    error = res?.error || "Erreur de déverrouillage";
  }
}

// Envoie un message au background ; si le coffre est verrouillé, demande la
// passphrase puis relance une fois.
async function call(message) {
  let res = await chrome.runtime.sendMessage(message);
  if (res?.error === LOCKED && await unlockFlow()) {
    res = await chrome.runtime.sendMessage(message);
  }
  return res;
}

function errorText(res, fallback) {
  if (res?.error === LOCKED) return "Sessions verrouillées";
  return res?.error || fallback;
}

// Initialisation de la popup
document.addEventListener("DOMContentLoaded", async () => {
  loadAccounts();
  checkCurrentSoundCloudSession();

  // Anciennes sessions stockées en clair (v1.1.0) : chiffrer au plus vite.
  const state = await chrome.runtime.sendMessage({ action: "GET_VAULT_STATE" });
  if (state?.hasLegacy) unlockFlow().then(loadAccounts);

  saveBtn.addEventListener("click", handleSaveAccount);
  accountNameInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleSaveAccount();
    }
  });

  if (cleanLogoutBtn) {
    cleanLogoutBtn.addEventListener("click", () => {
      chrome.runtime.sendMessage({ action: "CLEAN_LOGOUT" }, (response) => {
        if (response && response.success) {
          showStatus("Déconnecté de SoundCloud", "success");
        } else {
          showStatus(response?.error || "Erreur de déconnexion", "error");
        }
        loadAccounts();
      });
    });
  }

  if (openSoundcloudBtn) {
    openSoundcloudBtn.addEventListener("click", () => {
      chrome.tabs.create({ url: "https://soundcloud.com/discover" });
    });
  }

  if (exportBtn) {
    exportBtn.addEventListener("click", handleExportAccounts);
  }

  if (importBtn && importFileInput) {
    importBtn.addEventListener("click", () => importFileInput.click());
    importFileInput.addEventListener("change", handleImportFile);
  }
});

// Pré-détecte la session SoundCloud active pour aider l'utilisateur
function checkCurrentSoundCloudSession() {
  chrome.runtime.sendMessage({ action: "GET_CURRENT_SC_PROFILE" }, (response) => {
    if (response && response.success && response.profile && response.profile.username) {
      if (!accountNameInput.value) {
        accountNameInput.placeholder = `Détecté : ${response.profile.username}`;
      }
    }
  });
}

// Sauvegarder le compte actif
function handleSaveAccount() {
  const rawName = accountNameInput.value.trim();

  if (rawName.length > 50) {
    showStatus("Nom trop long (max 50 car.)", "error");
    return;
  }

  const sanitizedName = rawName.replace(/[\u0000-\u001F\u007F-\u009F]/g, "");

  saveBtn.disabled = true;
  showStatus("Détection du profil SoundCloud...", "info");

  call({ action: "SAVE_ACTIVE_ACCOUNT", name: sanitizedName }).then((response) => {
    saveBtn.disabled = false;
    if (response && response.success) {
      accountNameInput.value = "";
      showStatus(`Compte "${response.name}" enregistré`, "success");
      loadAccounts();
    } else {
      showStatus(errorText(response, "Erreur lors de la sauvegarde"), "error");
    }
  });
}

// Basculer vers un compte
function switchToAccount(name) {
  showStatus(`Bascule vers "${name}"...`, "info");

  call({ action: "SWITCH_ACCOUNT", accountName: name }).then((response) => {
    if (response && response.success) {
      showStatus(`Actif : ${name}`, "success");
      loadAccounts();
    } else {
      showStatus(errorText(response, "Erreur lors de la bascule"), "error");
    }
  });
}

// Supprimer un compte avec confirmation
function deleteAccount(name) {
  if (!confirm(`Supprimer le compte "${name}" ?`)) return;

  chrome.runtime.sendMessage({
    action: "DELETE_ACCOUNT",
    name: name
  }, (response) => {
    if (response && response.success) {
      showStatus(`Compte "${name}" supprimé`, "success");
    }
    loadAccounts();
  });
}

// Exporter les profils en JSON. Les cookies restent chiffrés : le fichier ne
// s'ouvre qu'avec la passphrase du coffre (sel + témoin inclus dans "vault").
async function handleExportAccounts() {
  let data = await chrome.storage.local.get(["sc_accounts", "sc_vault"]);
  if (Object.keys(data.sc_accounts || {}).length === 0) {
    showStatus("Aucun profil à exporter", "error");
    return;
  }

  // Jamais d'export en clair : chiffrer d'abord les anciennes sessions.
  const hasPlaintext = Object.values(data.sc_accounts).some((a) => !a?.secret);
  if (!data.sc_vault || hasPlaintext) {
    if (!(await unlockFlow())) return;
    data = await chrome.storage.local.get(["sc_accounts", "sc_vault"]);
  }

  const accounts = {};
  for (const [name, acc] of Object.entries(data.sc_accounts || {})) {
    if (!acc?.secret) continue;
    accounts[name] = {
      name: acc.name,
      username: acc.username,
      avatarUrl: acc.avatarUrl,
      permalinkUrl: acc.permalinkUrl,
      secret: acc.secret,
      savedAt: acc.savedAt
    };
  }

  const payload = {
    app: "SC_Account_Switcher",
    version: chrome.runtime.getManifest().version,
    exportedAt: new Date().toISOString(),
    vault: data.sc_vault,
    accounts
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `soundcloud_switcher_backup_${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showStatus(`${Object.keys(accounts).length} profil(s) exporté(s) (chiffré)`, "success");
}

// Importer des profils depuis un fichier JSON
function handleImportFile(event) {
  const file = event.target.files?.[0];
  // Réinitialiser le file input pour permettre une réimportation si besoin
  importFileInput.value = "";
  if (!file) return;
  if (file.size > MAX_IMPORT_BYTES) {
    showStatus("Fichier trop volumineux", "error");
    return;
  }

  const reader = new FileReader();
  reader.onload = async (e) => {
    let data;
    try {
      data = JSON.parse(e.target.result);
    } catch (err) {
      showStatus("Fichier JSON non valide", "error");
      return;
    }

    let passphrase = null;
    if (data?.vault) {
      passphrase = await askPassphrase({ title: "Passphrase du fichier de sauvegarde" });
      if (passphrase === null) return;
    }

    const res = await call({ action: "IMPORT_ACCOUNTS", file: data, passphrase });
    if (res && res.success) {
      showStatus(`${res.count} compte(s) importé(s)`, "success");
      loadAccounts();
    } else {
      showStatus(errorText(res, "Format de fichier invalide"), "error");
    }
  };
  reader.readAsText(file);
}

// Création sécurisée de l'icône SVG poubelle
function createTrashIcon() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("width", "13");
  svg.setAttribute("height", "13");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");

  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "M3 6h18m-2 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2");
  svg.appendChild(path);

  return svg;
}

// Chargement sécurisé de la liste des comptes dans le DOM
function loadAccounts() {
  chrome.storage.local.get(["sc_accounts", "sc_active_account"], (result) => {
    const accounts = result.sc_accounts || {};
    const activeAccount = result.sc_active_account;
    const names = Object.keys(accounts);

    accountCount.textContent = String(names.length);
    accountsList.replaceChildren();

    if (names.length === 0) {
      const emptyDiv = document.createElement("div");
      emptyDiv.className = "empty-state";
      const emptyText = document.createElement("p");
      emptyText.textContent = "Aucun compte enregistré";
      emptyDiv.appendChild(emptyText);
      accountsList.appendChild(emptyDiv);
      return;
    }

    names.forEach((name) => {
      const account = accounts[name] || {};
      const isActive = activeAccount === name;

      const item = document.createElement("div");
      item.className = `account-item ${isActive ? "is-active" : ""}`;

      // Section Info
      const infoDiv = document.createElement("div");
      infoDiv.className = "account-info";

      // Avatar
      const avatarWrap = document.createElement("div");
      avatarWrap.className = "account-avatar-wrap";

      if (account.avatarUrl && typeof account.avatarUrl === "string") {
        const img = document.createElement("img");
        img.className = "account-avatar-img";
        img.src = account.avatarUrl;
        img.alt = name;
        img.onerror = () => {
          img.remove();
          const initial = document.createElement("span");
          initial.className = "account-avatar-initial";
          initial.textContent = name.charAt(0).toUpperCase() || "A";
          avatarWrap.appendChild(initial);
        };
        avatarWrap.appendChild(img);
      } else {
        const initial = document.createElement("span");
        initial.className = "account-avatar-initial";
        initial.textContent = name.charAt(0).toUpperCase() || "A";
        avatarWrap.appendChild(initial);
      }

      // Nom & handle
      const textWrap = document.createElement("div");
      textWrap.className = "account-text-wrap";

      const nameSpan = document.createElement("span");
      nameSpan.className = "account-name";
      nameSpan.title = name;
      nameSpan.textContent = name;

      textWrap.appendChild(nameSpan);

      if (account.username && account.username !== name) {
        const subSpan = document.createElement("span");
        subSpan.className = "account-subtext";
        subSpan.textContent = `@${account.username}`;
        textWrap.appendChild(subSpan);
      }

      infoDiv.appendChild(avatarWrap);
      infoDiv.appendChild(textWrap);

      if (isActive) {
        const dot = document.createElement("span");
        dot.className = "active-dot";
        dot.title = "Compte actif";
        infoDiv.appendChild(dot);
      }

      // Actions
      const actionsDiv = document.createElement("div");
      actionsDiv.className = "account-actions";

      const switchBtn = document.createElement("button");
      switchBtn.className = `btn btn-switch ${isActive ? "btn-active-state" : ""}`;
      switchBtn.textContent = isActive ? "Actif" : "Activer";
      switchBtn.setAttribute("aria-label", `Basculer vers ${name}`);
      switchBtn.addEventListener("click", () => switchToAccount(name));

      const deleteBtn = document.createElement("button");
      deleteBtn.className = "btn-delete";
      deleteBtn.title = "Supprimer";
      deleteBtn.setAttribute("aria-label", `Supprimer le compte ${name}`);
      deleteBtn.appendChild(createTrashIcon());
      deleteBtn.addEventListener("click", () => deleteAccount(name));

      actionsDiv.appendChild(switchBtn);
      actionsDiv.appendChild(deleteBtn);

      item.appendChild(infoDiv);
      item.appendChild(actionsDiv);

      accountsList.appendChild(item);
    });
  });
}

let statusTimeout = null;
function showStatus(text, type) {
  if (statusTimeout) clearTimeout(statusTimeout);
  saveStatus.textContent = text;
  saveStatus.className = `status-msg ${type || ""}`;

  statusTimeout = setTimeout(() => {
    saveStatus.textContent = "";
    saveStatus.className = "status-msg";
  }, 3200);
}
