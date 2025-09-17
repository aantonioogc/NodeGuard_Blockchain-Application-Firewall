require("dotenv").config();
const axios = require("axios");
const { EventSource } = require("eventsource");
const crypto = require("crypto");

const TELEGRAM_TOKEN = process.env.TG_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TG_CHAT_ID;
const EVENTS_URL = process.env.EVENTS_URL || "http://localhost:3000/events";

if (!TELEGRAM_TOKEN || !TELEGRAM_CHAT_ID) {
  console.error("Falta TG_BOT_TOKEN o TG_CHAT_ID en las variables de entorno. Abortando.");
  process.exit(1);
}

const TELEGRAM_API_BASE = `https://api.telegram.org/bot${TELEGRAM_TOKEN}`;

const axiosTelegram = axios.create({
  baseURL: TELEGRAM_API_BASE,
  timeout: 15000,
});

// --- Configurables ---
const MAX_DUP_CACHE = 500; // cuántos eventos recordar para evitar duplicados
const DUP_EXPIRE_MS = 1000 * 60 * 10; // 10 minutos
const MAX_SEND_RETRIES = 3;
const RATE_LIMIT_TOKENS = Number(process.env.TG_TOKENS) || 20; // tokens por minuto
const RATE_LIMIT_REFILL_MS = 60 * 1000;

// --- Estado runtime ---
let dupCache = new Map(); // eventId -> timestamp
let tokenBucket = {
  tokens: RATE_LIMIT_TOKENS,
  lastRefill: Date.now(),
};

// repone tokens periódicamente
setInterval(() => {
  const now = Date.now();
  const elapsed = now - tokenBucket.lastRefill;
  if (elapsed >= RATE_LIMIT_REFILL_MS) {
    tokenBucket.tokens = RATE_LIMIT_TOKENS;
    tokenBucket.lastRefill = now;
  }
}, 1000);

// limpia cache duplicados periódicamente
setInterval(() => {
  const now = Date.now();
  for (const [k, ts] of dupCache.entries()) {
    if (now - ts > DUP_EXPIRE_MS) dupCache.delete(k);
  }
  // mantener tamaño razonable
  if (dupCache.size > MAX_DUP_CACHE) {
    const keys = Array.from(dupCache.keys()).slice(0, dupCache.size - MAX_DUP_CACHE);
    for (const k of keys) dupCache.delete(k);
  }
}, 60 * 1000);

// --- utilidades ---
function escapeHtml(str = "") {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function shortIdForEvent(data) {
  if (data.id) return String(data.id);
  if (data.eventId) return String(data.eventId);
  // fallback: hash corto del payload
  const h = crypto.createHash("sha256").update(JSON.stringify(data)).digest("hex");
  return h.slice(0, 10);
}

function severityEmoji(sev) {
  if (!sev) return "ℹ️";
  const s = String(sev).toLowerCase();
  if (["critical", "high", "urgent"].some(x => s.includes(x))) return "🔴";
  if (["medium", "warning", "warn"].some(x => s.includes(x))) return "🟠";
  if (["low", "info", "informational"].some(x => s.includes(x))) return "🟢";
  return "⚪️";
}

async function sendTelegramMessage(payload, attempt = 1) {
  // Rate limiting local
  if (tokenBucket.tokens <= 0) {
    console.warn("Rate limit local alcanzado. Mensaje descartado temporalmente.");
    return { ok: false, reason: "rate_limited_local" };
  }
  tokenBucket.tokens--;

  try {
    const res = await axiosTelegram.post("/sendMessage", payload);
    return res.data;
  } catch (err) {
    const shouldRetry = attempt < MAX_SEND_RETRIES;
    const status = err.response?.status;
    console.error(`Error enviando a Telegram (intento ${attempt}):`, err.message, status ? `status=${status}` : "");
    if (shouldRetry) {
      const wait = 500 * Math.pow(2, attempt); // backoff exponencial
      console.log(`Reintentando en ${wait}ms...`);
      await new Promise(r => setTimeout(r, wait));
      return sendTelegramMessage(payload, attempt + 1);
    } else {
      console.error("Max reintentos alcanzado. Mensaje no enviado.");
      return { ok: false, reason: err.message || "unknown" };
    }
  }
}

// --- Formateo principal ---
function buildHtmlMessage(data) {
  // extraer campos con fallback
  const id = shortIdForEvent(data);
  const type = data.type || data.event || data.name || "evento";
  const reason = data.reason || data.detail || data.message || "-";
  const clientIp = data.clientIp || data.ip || data.remoteAddr || "-";
  const ts = data.timestamp ? new Date(data.timestamp).toLocaleString() : new Date().toLocaleString();
  const severity = data.severity || data.level || "info";
  const txHash = data.txHash || data.transactionHash || null;
  const extra = data.extra || data.metadata || data.details || {};

  // construir cuerpo con escape de HTML
  let body = [];
  body.push(`${severityEmoji(severity)} <b><u>BAF ALERT</u></b>`);
  body.push(`<b>ID:</b> ${escapeHtml(id)}`);
  body.push(`<b>Tipo:</b> ${escapeHtml(type)}`);
  body.push(`<b>Severidad:</b> ${escapeHtml(severity)}`);
  body.push(`<b>Razón:</b> ${escapeHtml(reason)}`);
  body.push(`<b>IP origen:</b> ${escapeHtml(clientIp)}`);
  body.push(`<b>Hora:</b> ${escapeHtml(ts)}`);

  // añadir datos relevantes si existen
  if (txHash) body.push(`<b>Tx:</b> <code>${escapeHtml(txHash)}</code>`);
  if (data.account || data.wallet) body.push(`<b>Cuenta:</b> ${escapeHtml(data.account || data.wallet)}`);
  if (data.method) body.push(`<b>Método:</b> ${escapeHtml(data.method)}`);
  if (data.endpoint) body.push(`<b>Endpoint:</b> ${escapeHtml(data.endpoint)}`);

  // incluir algunos campos de extra (limitar a unos pocos)
  const keys = Object.keys(extra || {}).slice(0, 6);
  if (keys.length) {
    body.push("<b>Contexto:</b>");
    for (const k of keys) {
      let v = extra[k];
      const val = typeof v === "object" ? JSON.stringify(v) : String(v);
      if (val.length > 200) v = `${val.slice(0, 200)}...`;
      body.push(`<i>${escapeHtml(k)}:</i> ${escapeHtml(String(v))}`);
    }
  }

  body.push("───────────────");
  body.push(`🔐 <i>Firewall activo y protegiendo</i>`);

  return body.join("\n");
}

// --- Envío con inline button si hay URL ---
async function notifyTelegram(data) {
  const id = shortIdForEvent(data);
  // deduplicado simple
  if (dupCache.has(id)) {
    console.debug("Evento duplicado detectado, ignorando:", id);
    return;
  }
  dupCache.set(id, Date.now());

  const text = buildHtmlMessage(data);

  // build payload
  const payload = {
    chat_id: TELEGRAM_CHAT_ID,
    text,
    parse_mode: "HTML",
    disable_web_page_preview: true,
  };

  // botón de detalle si existe URL o txHash
  const detailUrl = data.detailUrl || data.url || data.link;
  const txHash = data.txHash || data.transactionHash;
  if (detailUrl || txHash) {
    const buttons = [];
    if (detailUrl) buttons.push({ text: "Ver detalle", url: detailUrl });
    else if (txHash) {
      // sin chainId no podemos asegurar explorer, así que mostramos enlace genérico si viene
      if (data.explorerTxUrl) {
        buttons.push({ text: "Ver tx", url: data.explorerTxUrl });
      } else {
        // intento de construir Etherscan para mainnet si chainId = 1 (opcional)
        if (data.chainId && Number(data.chainId) === 1) {
          buttons.push({ text: "Ver tx (Etherscan)", url: `https://etherscan.io/tx/${txHash}` });
        } else {
          // si no hay URL fiable, incluir tx en el mensaje como code (ya lo hemos incluido arriba)
        }
      }
    }
    if (buttons.length) {
      payload.reply_markup = { inline_keyboard: [buttons.map(b => ({ text: b.text, url: b.url }))] };
    }
  }

  const res = await sendTelegramMessage(payload);
  if (res && res.ok) {
    console.info("Alerta enviada:", id, "->", data.type || "<sin tipo>");
  } else {
    console.warn("No se envió alerta:", id, res?.reason || "sin detalle");
  }
}

// --- Conexión SSE con reconexión básica ---
console.log(`Conectando a SSE en ${EVENTS_URL}`);
let es;
let reconnectAttempts = 0;
function connectSSE() {
  es = new EventSource(EVENTS_URL);

  es.onopen = () => {
    reconnectAttempts = 0;
    console.log("✅ Conectado a SSE");
  };

  es.onerror = (err) => {
    console.error("❌ SSE error:", err && err.message ? err.message : err);
    // EventSource del paquete intenta reconectar automáticamente, pero añadimos log y backoff si fallos repetidos
    if (es && es.readyState === EventSource.CLOSED) {
      const delay = Math.min(30000, 1000 * Math.pow(2, reconnectAttempts));
      reconnectAttempts++;
      console.log(`SSE cerrado, reconectando en ${delay}ms (intento ${reconnectAttempts})`);
      setTimeout(connectSSE, delay);
    }
  };

  es.onmessage = async (event) => {
    if (!event || !event.data) return;
    let payload;
    try {
      payload = JSON.parse(event.data);
    } catch (err) {
      // si no es JSON, enviar como texto
      payload = { type: "raw", reason: event.data, timestamp: Date.now() };
    }
    try {
      console.log("📥 Evento recibido:", shortIdForEvent(payload), payload.type || payload.event || "");
      await notifyTelegram(payload);
    } catch (err) {
      console.error("Error procesando evento:", err?.message || err);
    }
  };
}

connectSSE();

// --- cierre limpio ---
function shutdown(signal) {
  console.log(`Recibido ${signal}, cerrando conexión SSE...`);
  try {
    if (es && typeof es.close === "function") es.close();
  } catch (err) {
    // ignore
  }
  // esperar unos instantes para que los logs se vacíen
  setTimeout(() => process.exit(0), 500);
}
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

module.exports = {
  // export para tests si hace falta
  buildHtmlMessage,
  notifyTelegram,
};
