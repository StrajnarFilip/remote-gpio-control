"use strict";

// Protocol constants: keep in sync with gpio_server/protocol.py (see PROTOCOL.md).
const REQUEST_AAD = new TextEncoder().encode("gpio-server/v1 request");
const RESPONSE_AAD = new TextEncoder().encode("gpio-server/v1 response");
const NONCE_SIZE = 12;
const SERVICE_UUID = "79fc9371-0370-434e-b6a2-c245e12d7514";
const CHALLENGE_UUID = "7c5b0353-76f0-417c-b3b8-4d872b3134a9";
const RPC_UUID = "4bdc484e-1469-47fc-8f3f-caaa38c618e8";
const POLL_MS = 2000;

// Physical pin on the 40-pin Raspberry Pi header, so nobody needs a pinout.
const HEADER_PIN = {
  GPIO2: 3, GPIO3: 5, GPIO4: 7, GPIO14: 8, GPIO15: 10, GPIO17: 11, GPIO18: 12,
  GPIO27: 13, GPIO22: 15, GPIO23: 16, GPIO24: 18, GPIO10: 19, GPIO9: 21,
  GPIO25: 22, GPIO11: 23, GPIO8: 24, GPIO7: 26, GPIO0: 27, GPIO1: 28, GPIO5: 29,
  GPIO6: 31, GPIO12: 32, GPIO13: 33, GPIO19: 35, GPIO16: 36, GPIO26: 37,
  GPIO20: 38, GPIO21: 40,
};

const $ = (id) => document.getElementById(id);
const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (text) => Uint8Array.from(text.match(/../g), (h) => parseInt(h, 16));
const bytesOf = (view) => new Uint8Array(view.buffer, view.byteOffset, view.byteLength);

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

// ---- Key ---------------------------------------------------------------

let keyHex = null;
let cryptoKey = null;

function storage(action, value) {
  try {
    if (action === "get") return localStorage.getItem("gpio-key");
    if (action === "set") localStorage.setItem("gpio-key", value);
    if (action === "remove") localStorage.removeItem("gpio-key");
  } catch {
    return null; // storage blocked: the key lives in memory for this visit
  }
}

async function useKey(text) {
  text = text.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(text)) throw new Error("The key must be 64 hex characters.");
  cryptoKey = await crypto.subtle.importKey("raw", fromHex(text), "AES-GCM", false, ["encrypt", "decrypt"]);
  keyHex = text;
  storage("set", text);
}

// ---- Envelopes (same as seal/unseal in protocol.py) --------------------

async function seal(aad, message) {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
  const plaintext = new TextEncoder().encode(JSON.stringify(message));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, cryptoKey, plaintext);
  return concat(nonce, new Uint8Array(ciphertext));
}

async function unseal(aad, envelope) {
  const iv = envelope.slice(0, NONCE_SIZE);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, cryptoKey, envelope.slice(NONCE_SIZE));
  return JSON.parse(new TextDecoder().decode(plaintext));
}

// ---- Transports: each moves the same bytes ------------------------------

const httpTransport = {
  name: "network",
  async challenge() {
    const response = await fetch("challenge", { cache: "no-store" });
    if (!response.ok) throw new Error(`challenge failed: HTTP ${response.status}`);
    return new Uint8Array(await response.arrayBuffer());
  },
  async rpc(envelope) {
    const response = await fetch("rpc", { method: "POST", body: envelope });
    if (response.status === 403) throw new Error("Rejected by the server. Is the key right?");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return new Uint8Array(await response.arrayBuffer());
  },
};

async function connectBluetooth() {
  const device = await navigator.bluetooth.requestDevice({ filters: [{ services: [SERVICE_UUID] }] });
  const service = await (await device.gatt.connect()).getPrimaryService(SERVICE_UUID);
  const challengeChar = await service.getCharacteristic(CHALLENGE_UUID);
  const rpcChar = await service.getCharacteristic(RPC_UUID);
  device.addEventListener("gattserverdisconnected", () => {
    if (transport.device === device) {
      transport = httpTransport;
      setStatus("Bluetooth disconnected, back on the network");
    }
  });
  return {
    name: "Bluetooth",
    device,
    async challenge() {
      return bytesOf(await challengeChar.readValue());
    },
    async rpc(envelope) {
      // Framing: 2-byte big-endian length, then the envelope. The reply comes
      // back in pieces; keep reading until the whole frame has arrived.
      const frame = concat(new Uint8Array([envelope.length >> 8, envelope.length & 255]), envelope);
      try {
        await rpcChar.writeValueWithResponse(frame);
      } catch (e) {
        throw new Error(e.name === "NotAllowedError" ? "Rejected by the server. Is the key right?" : e.message);
      }
      let data = new Uint8Array(0);
      for (;;) {
        const piece = bytesOf(await rpcChar.readValue());
        if (piece.length === 0) throw new Error("incomplete reply");
        data = concat(data, piece);
        const length = (data[0] << 8) | data[1];
        if (data.length >= 2 + length) return data.slice(2, 2 + length);
      }
    },
  };
}

// ---- Calls -------------------------------------------------------------

let transport = httpTransport;
let queue = Promise.resolve(); // one call at a time: GATT can't overlap operations
let pending = 0;

function call(op, args = {}) {
  const run = async () => {
    const challenge = await transport.challenge();
    const envelope = await seal(REQUEST_AAD, { challenge: toHex(challenge), op, ...args });
    const replyEnvelope = await transport.rpc(envelope);
    let reply;
    try {
      // The reply is bound to this request's nonce, so a replayed reply fails here.
      reply = await unseal(concat(RESPONSE_AAD, envelope.slice(0, NONCE_SIZE)), replyEnvelope);
    } catch {
      throw new Error("The reply failed authentication.");
    }
    render(reply.lines);
    if (!reply.ok) throw new Error(reply.error);
    return reply;
  };
  pending++;
  const result = queue.then(run).finally(() => pending--);
  queue = result.catch(() => {});
  return result;
}

function act(op, args) {
  return call(op, args).then(
    () => setStatus(`Connected via ${transport.name}`),
    (e) => setStatus(e.message, true),
  );
}

function setStatus(text, isError = false) {
  $("status").textContent = text;
  $("status").classList.toggle("error", isError);
}

// ---- Rendering ---------------------------------------------------------

const cards = new Map();

function render(lines) {
  for (const line of lines) {
    if (!cards.has(line.name)) {
      const card = createCard(line.name);
      cards.set(line.name, card);
      $("lines").append(card.root);
    }
    updateCard(cards.get(line.name), line);
  }
}

function createCard(name) {
  const root = $("line-template").content.firstElementChild.cloneNode(true);
  const q = (selector) => root.querySelector(selector);
  const card = {
    root, line: null,
    label: q(".label"), mode: q(".mode"), value: q(".value"), toggle: q(".toggle"),
    ms: q(".ms"), bias: q(".bias"), activeLow: q(".active-low input"), busy: q(".busy-note"),
  };
  q(".name").textContent = name;
  q(".pin").textContent = HEADER_PIN[name] ? `pin ${HEADER_PIN[name]}` : "";

  const configure = (changes) => act("configure", { line: name, ...changes });
  card.mode.addEventListener("change", () => configure({ mode: card.mode.value }));
  card.bias.addEventListener("change", () => configure({ bias: card.bias.value }));
  card.activeLow.addEventListener("change", () => configure({ active_low: card.activeLow.checked }));
  card.label.addEventListener("change", () => configure({ label: card.label.value }));
  card.label.addEventListener("keydown", (e) => e.key === "Enter" && card.label.blur());
  card.toggle.addEventListener("click", () => act("set", { line: name, value: card.line.value ? 0 : 1 }));
  q(".pulse-button").addEventListener("click", () => act("pulse", { line: name, ms: Number(card.ms.value) }));
  return card;
}

function updateCard(card, line) {
  card.line = line;
  card.root.dataset.mode = line.mode;
  card.root.classList.toggle("busy", Boolean(line.busy));
  card.root.classList.toggle("on", line.value === 1);
  card.busy.textContent = line.busy ? `in use by ${line.busy}` : "";
  for (const el of card.root.querySelectorAll("input, select, button")) el.disabled = Boolean(line.busy);
  if (document.activeElement !== card.label) card.label.value = line.label;
  card.mode.value = line.mode;
  card.bias.value = line.bias;
  card.activeLow.checked = line.active_low;
  card.value.textContent = line.value ? "HIGH" : "LOW";
  card.toggle.textContent = line.value ? "ON" : "OFF";
  card.toggle.setAttribute("aria-pressed", String(line.value === 1));
}

// ---- Share dialog ------------------------------------------------------

function openShare() {
  const url = `${location.origin}${location.pathname}#key=${keyHex}`;
  const qr = qrcode(0, "M");
  qr.addData(url);
  qr.make();
  $("qr").innerHTML = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
  $("key-text").textContent = keyHex;
  $("share").showModal();
}

// ---- Start -------------------------------------------------------------

async function start() {
  if (!window.crypto?.subtle) {
    setStatus("Open this page over https:// (browsers only allow WebCrypto there).", true);
    return;
  }
  // A key in the URL fragment (from a QR code) is never sent to the server.
  const fromUrl = new URLSearchParams(location.hash.slice(1)).get("key");
  if (fromUrl) history.replaceState(null, "", location.pathname + location.search);
  try {
    await useKey(fromUrl || storage("get") || "");
  } catch {
    $("setup").hidden = false;
    return;
  }
  connect();
}

function connect() {
  $("share-open").hidden = false;
  $("ble-connect").hidden = !navigator.bluetooth;
  act("state");
  setInterval(() => {
    if (document.visibilityState === "visible" && pending === 0) act("state");
  }, POLL_MS);
}

$("key-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await useKey($("key-input").value);
    $("setup").hidden = true;
    connect();
  } catch (err) {
    setStatus(err.message, true);
  }
});

$("ble-connect").addEventListener("click", async () => {
  try {
    transport = await connectBluetooth();
    act("state");
  } catch (e) {
    setStatus(`Bluetooth: ${e.message}`, true);
  }
});

$("share-open").addEventListener("click", openShare);
$("share-close").addEventListener("click", () => $("share").close());
$("copy").addEventListener("click", () => navigator.clipboard.writeText(keyHex).then(() => setStatus("Key copied")));
$("forget").addEventListener("click", () => {
  storage("remove");
  location.reload();
});

start();
