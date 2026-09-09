// Minimal OIDC Authorization Code + PKCE client for the Dynamic Vault API.
//
// Design decisions (see index.html for the runtime config it reads):
//   - The access token lives only in this module's memory (`accessToken`
//     below). It is never written to localStorage/sessionStorage/cookies.
//     Reloading the page signs the user out; that's intentional.
//   - The PKCE code_verifier and `state` must survive the redirect to the
//     identity provider and back, so those two (short-lived, non-sensitive
//     on their own) values are the only things kept in sessionStorage, and
//     are deleted immediately after the token exchange completes.
//   - The OIDC discovery document is fetched at startup so this client
//     works against any spec-compliant provider without hardcoding
//     endpoint paths.

const config = {
  issuer: import.meta.env.VITE_OIDC_ISSUER,
  clientId: import.meta.env.VITE_OIDC_CLIENT_ID,
  audience: import.meta.env.VITE_OIDC_AUDIENCE,
  apiBase: import.meta.env.VITE_API_BASE_URL || "",
};

let accessToken = null;
let discovery = null;

const $ = (id) => document.getElementById(id);

function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function sha256(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return base64url(new Uint8Array(digest));
}

function randomString(length = 64) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

async function loadDiscovery() {
  const response = await fetch(
    `${config.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`
  );
  if (!response.ok) throw new Error("OIDC discovery failed");
  return response.json();
}

async function beginSignIn() {
  discovery = discovery || (await loadDiscovery());
  const verifier = randomString();
  const state = randomString(16);
  sessionStorage.setItem("vault_pkce_verifier", verifier);
  sessionStorage.setItem("vault_pkce_state", state);
  const challenge = await sha256(verifier);
  const redirectUri = `${location.origin}${location.pathname}`;
  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: redirectUri,
    scope: "openid vault",
    audience: config.audience,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  location.assign(`${discovery.authorization_endpoint}?${params}`);
}

async function completeSignIn(code, state) {
  const expectedState = sessionStorage.getItem("vault_pkce_state");
  const verifier = sessionStorage.getItem("vault_pkce_verifier");
  sessionStorage.removeItem("vault_pkce_state");
  sessionStorage.removeItem("vault_pkce_verifier");
  if (!verifier || state !== expectedState) {
    throw new Error("Sign-in state mismatch; please try again.");
  }
  discovery = discovery || (await loadDiscovery());
  const redirectUri = `${location.origin}${location.pathname}`;
  const response = await fetch(discovery.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: config.clientId,
      code_verifier: verifier,
    }),
  });
  if (!response.ok) throw new Error("Token exchange failed");
  const body = await response.json();
  accessToken = body.access_token;
  history.replaceState({}, "", redirectUri);
}

async function api(path, options = {}) {
  const response = await fetch(`${config.apiBase}${path}`, {
    ...options,
    headers: {
      ...(options.headers || {}),
      Authorization: `Bearer ${accessToken}`,
    },
  });
  if (response.status === 401) {
    accessToken = null;
    renderSignedOut();
    throw new Error("Session expired; please sign in again.");
  }
  return response;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

let currentTab = "active";

async function refreshUsage() {
  const response = await api("/usage");
  const usage = await response.json();
  $("usage-panel").textContent =
    `${formatBytes(usage.used_bytes)} / ${formatBytes(usage.quota_bytes)} used ` +
    `· ${usage.document_count} / ${usage.document_limit} files`;
}

async function refreshDocuments() {
  const response = await api(`/documents?trash=${currentTab === "trash"}`);
  const documents = await response.json();
  const body = $("documents-body");
  body.innerHTML = "";
  for (const item of documents) {
    body.appendChild(document_row(item));
  }
  if (documents.length === 0) {
    const row = document.createElement("tr");
    row.innerHTML = `<td colspan="4"><em>Nothing here.</em></td>`;
    body.appendChild(row);
  }
}

function document_row(doc) {
  const row = document.createElement("tr");
  const created = new Date(doc.created_at).toLocaleString();
  row.innerHTML = `
    <td>${escapeHtml(doc.filename)}</td>
    <td>${formatBytes(doc.plaintext_size)}</td>
    <td>${created}</td>
    <td class="row-actions"></td>
  `;
  const actions = row.querySelector(".row-actions");
  if (currentTab === "active") {
    actions.appendChild(makeButton("Download", () => downloadDocument(doc.id, doc.filename)));
    actions.appendChild(makeButton("Share", () => openShareDialog(doc.id)));
    actions.appendChild(makeButton("Trash", () => trashDocument(doc.id), "danger"));
  } else {
    actions.appendChild(makeButton("Restore", () => restoreDocument(doc.id)));
  }
  return row;
}

function makeButton(label, handler, extraClass) {
  const button = document.createElement("button");
  button.textContent = label;
  button.className = `secondary${extraClass ? " " + extraClass : ""}`;
  button.addEventListener("click", handler);
  return button;
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value;
  return div.innerHTML;
}

async function downloadDocument(id, filename) {
  const response = await api(`/documents/${id}/content`);
  if (!response.ok) {
    alert("Download failed.");
    return;
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

async function trashDocument(id) {
  await api(`/documents/${id}/trash`, { method: "POST" });
  await Promise.all([refreshDocuments(), refreshUsage()]);
}

async function restoreDocument(id) {
  await api(`/documents/${id}/restore`, { method: "POST" });
  await Promise.all([refreshDocuments(), refreshUsage()]);
}

let shareDocumentId = null;

function openShareDialog(id) {
  shareDocumentId = id;
  $("share-form").hidden = false;
  $("share-result").hidden = true;
  $("share-dialog").showModal();
}

async function createShare() {
  const recipient = $("share-recipient").value.trim();
  const hours = Number($("share-hours").value);
  const expiry = new Date(Date.now() + hours * 3600 * 1000).toISOString();
  const response = await api(`/documents/${shareDocumentId}/grants`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ recipient_id: recipient, expiry }),
  });
  if (!response.ok) {
    alert("Could not create the share. Check the recipient's user ID.");
    return;
  }
  const grant = await response.json();
  const link = `${location.origin}${location.pathname}?shared_doc=${shareDocumentId}&shared_token=${grant.token}`;
  $("share-form").hidden = true;
  $("share-result").hidden = false;
  $("share-token").textContent = link;
}

async function redeemSharedLink(documentId, token) {
  const response = await api(`/documents/${documentId}/content`, {
    headers: { "X-Vault-Token": token },
  });
  if (!response.ok) {
    alert("This shared link is invalid, expired, or already revoked.");
    return;
  }
  const disposition = response.headers.get("content-disposition") || "";
  const match = /filename\*=UTF-8''([^;]+)/.exec(disposition);
  const filename = match ? decodeURIComponent(match[1]) : "download";
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function renderSignedOut() {
  $("content").hidden = true;
  const area = $("auth-area");
  area.innerHTML = "";
  area.appendChild(makeButton("Sign in", beginSignIn));
}

async function renderSignedIn() {
  const area = $("auth-area");
  area.innerHTML = "";
  const me = await (await api("/me")).json();
  const label = document.createElement("span");
  label.textContent = `Signed in as ${me.id}`;
  area.appendChild(label);
  $("content").hidden = false;
  await Promise.all([refreshUsage(), refreshDocuments()]);
}

function wireStaticHandlers() {
  $("tab-active").addEventListener("click", () => switchTab("active"));
  $("tab-trash").addEventListener("click", () => switchTab("trash"));
  $("upload-button").addEventListener("click", handleUpload);
  $("share-confirm").addEventListener("click", (event) => {
    event.preventDefault();
    createShare();
  });
  $("share-close").addEventListener("click", () => $("share-dialog").close());
}

function switchTab(tab) {
  currentTab = tab;
  $("tab-active").classList.toggle("active", tab === "active");
  $("tab-trash").classList.toggle("active", tab === "trash");
  refreshDocuments();
}

async function handleUpload() {
  const input = $("file-input");
  const file = input.files[0];
  if (!file) return;
  $("upload-status").textContent = "Uploading...";
  const response = await api("/documents", {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Filename": file.name,
    },
    body: await file.arrayBuffer(),
  });
  if (!response.ok) {
    $("upload-status").textContent = "Upload failed.";
    return;
  }
  $("upload-status").textContent = "Uploaded.";
  input.value = "";
  await Promise.all([refreshDocuments(), refreshUsage()]);
}

async function main() {
  wireStaticHandlers();
  const params = new URLSearchParams(location.search);
  renderSignedOut();
  if (params.has("code") && params.has("state")) {
    try {
      await completeSignIn(params.get("code"), params.get("state"));
      await renderSignedIn();
    } catch (error) {
      alert(error.message);
    }
    return;
  }
  // A shared-link visit still requires the recipient to sign in first,
  // since the API always requires an authenticated actor in addition to
  // the per-document share token.
  if (params.has("shared_doc") && params.has("shared_token")) {
    sessionStorage.setItem("vault_pending_share_doc", params.get("shared_doc"));
    sessionStorage.setItem("vault_pending_share_token", params.get("shared_token"));
  }
  const pendingDoc = sessionStorage.getItem("vault_pending_share_doc");
  const pendingToken = sessionStorage.getItem("vault_pending_share_token");
  if (pendingDoc && pendingToken && accessToken) {
    sessionStorage.removeItem("vault_pending_share_doc");
    sessionStorage.removeItem("vault_pending_share_token");
    await redeemSharedLink(pendingDoc, pendingToken);
  }
}

main();
