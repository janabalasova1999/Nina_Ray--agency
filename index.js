const express = require('express');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const dotenv = require('dotenv');

// Load environment variables from a .env file when available.
dotenv.config();

// Read environment variables (with fallbacks for older names)
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const NINA_CHAT_BEARER_TOKEN = process.env.NINA_CHAT_BEARER_TOKEN || process.env.BEARER_NINA_CHAT_TOKEN || process.env.BEARER_NINA_CHAT;
const IG_BEARER_TOKEN = process.env.IG_BEARER_TOKEN || process.env.BEARER_IG_TOKEN;
const OF_BEARER_TOKEN = process.env.OF_BEARER_TOKEN || process.env.BEARER_OF_TOKEN;
const FANSLY_BEARER_TOKEN = process.env.FANSLY_BEARER_TOKEN || process.env.BEARER_FANSLY_TOKEN;
const FANVUE_BEARER_TOKEN = process.env.FANVUE_BEARER_TOKEN || process.env.BEARER_FANVUE_TOKEN;
const FB_BEARER_TOKEN = process.env.FB_BEARER_TOKEN || process.env.BEARER_FB_TOKEN;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !WEBHOOK_SECRET) {
  throw new Error(
    'Missing required environment variables: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, WEBHOOK_SECRET'
  );
}

// Initialize Supabase client.
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

// Mapping of platform names to their respective bearer tokens.
const PLATFORM_TOKEN_MAP = {
  nina_chat: NINA_CHAT_BEARER_TOKEN,
  ig: IG_BEARER_TOKEN,
  of: OF_BEARER_TOKEN,
  fansly: FANSLY_BEARER_TOKEN,
  fanvue: FANVUE_BEARER_TOKEN,
  fb: FB_BEARER_TOKEN,
};

// Helper to compute an HMAC SHA256 signature of a message using the provided secret.
function computeHmacSha256(message, secret) {
  return crypto.createHmac('sha256', secret).update(message).digest('hex');
}

// Helper to compare user states and return whichever is greater in the funnel hierarchy.
function stateAtLeast(current = 'cold', candidate = 'cold') {
  const order = { cold: 0, warm: 1, hot: 2 };
  return order[candidate] > (order[current] || 0) ? candidate : current;
}

// Create the Express application. We capture the raw request body on JSON
// payloads so that we can verify the HMAC signature.
const app = express();
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString('utf8');
    },
  })
);

// Parse timestamp header helper (accepts ISO or milliseconds)
function parseTimestampHeader(ts) {
  if (!ts) return null;
  // numeric ms
  if (/^\d+$/.test(ts)) return Number(ts);
  const parsed = Date.parse(ts);
  return Number.isNaN(parsed) ? null : parsed;
}

/**
 * Middleware that verifies the request signature, timestamp and bearer token.
 */
async function verifyAuth(req, res, next) {
  if (req.method !== 'POST') return next();
  try {
    const rawBody = req.rawBody || '';

    // Replay protection: require X-Timestamp header within tolerance
    const tsHeader = req.headers['x-timestamp'];
    const tsMs = parseTimestampHeader(tsHeader);
    if (!tsMs) {
      return res.status(401).json({ ok: false, error: 'Missing or invalid X-Timestamp header' });
    }
    const now = Date.now();
    const toleranceMs = 5 * 60 * 1000; // 5 minutes
    if (Math.abs(now - tsMs) > toleranceMs) {
      return res.status(401).json({ ok: false, error: 'Stale request (timestamp outside tolerance)' });
    }

    // Verify HMAC signature
    const signatureHeader = (req.headers['x-signature'] || '').toString().trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(signatureHeader)) {
      return res.status(401).json({ ok: false, error: 'Missing or invalid X-Signature header' });
    }
    const computedHex = computeHmacSha256(rawBody + tsMs.toString(), WEBHOOK_SECRET);
    // Note: include timestamp in HMAC to prevent replay if desired.
    const a = Buffer.from(computedHex, 'hex');
    const b = Buffer.from(signatureHeader, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(401).json({ ok: false, error: 'Invalid signature' });
    }

    // Parse body and verify bearer token for the platform.
    const body = req.body || {};
    const platform = body.platform;
    const expectedToken = PLATFORM_TOKEN_MAP[platform];
    if (!expectedToken) {
      return res.status(401).json({ ok: false, error: `No bearer token configured for platform: ${platform}` });
    }
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice('Bearer '.length).trim() : '';
    if (!token) {
      return res.status(401).json({ ok: false, error: 'Missing bearer token' });
    }
    if (token !== expectedToken) {
      return res.status(401).json({ ok: false, error: 'Invalid bearer token' });
    }

    req.authPlatform = platform;
    next();
  } catch (err) {
    console.error('auth verification error', err);
    res.status(500).json({ ok: false, error: 'Internal auth error' });
  }
}

// Apply authentication verification middleware to log and redirect endpoints.
app.post('/api/log-message', verifyAuth);
app.post('/api/redirect-event', verifyAuth);

// Admin middleware for GET endpoints
function adminAuth(req, res, next) {
  if (!ADMIN_API_KEY) {
    return res.status(500).json({ ok: false, error: 'Server misconfiguration: ADMIN_API_KEY not set' });
  }
  const key = req.headers['x-admin-key'] || '';
  if (key !== ADMIN_API_KEY) {
    return res.status(401).json({ ok: false, error: 'Missing or invalid X-Admin-Key' });
  }
  next();
}

// Protect admin endpoints
app.get('/api/stats', adminAuth, async (_req, res) => {
  try {
    const now = new Date();
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    function formatDate(date) { return date.toISOString().slice(0, 10); }
    const { data: redirectEvents, error: eventsErr } = await supabase
      .from('events')
      .select('created_at, reason, tags')
      .eq('type', 'redirect')
      .gte('created_at', sevenDaysAgo.toISOString());
    if (eventsErr) throw eventsErr;
    const countsByDay = {};
    const reasonCounts = {};
    const tagCounts = {};
    for (const event of redirectEvents || []) {
      const date = formatDate(new Date(event.created_at));
      countsByDay[date] = (countsByDay[date] || 0) + 1;
      if (event.reason) reasonCounts[event.reason] = (reasonCounts[event.reason] || 0) + 1;
      const tags = event.tags || [];
      for (const tag of tags) tagCounts[tag] = (tagCounts[tag] || 0) + 1;
    }
    return res.json({ ok: true, countsByDay, reasonCounts, tagCounts });
  } catch (err) {
    console.error('stats error', err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

app.get('/api/clients', adminAuth, async (_req, res) => {
  try {
    const { data: users, error: usersErr } = await supabase
      .from('users')
      .select('id, platform, external_user_id, username, state, interest_score, tags')
      .order('updated_at', { ascending: false });
    if (usersErr) throw usersErr;
    const clients = [];
    for (const user of users || []) {
      const { data: lastMessages, error: msgErr } = await supabase
        .from('messages')
        .select('content, created_at, direction')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false })
        .limit(1);
      if (msgErr) throw msgErr;
      const lastMessage = lastMessages && lastMessages[0];
      let stage = 'chat only';
      if (user.state === 'warm') stage = 'poslán na OF';
      if (user.state === 'hot') stage = 'aktivní na OF';
      clients.push({ id: user.id, platform: user.platform, external_user_id: user.external_user_id, username: user.username, state: user.state, interest_score: user.interest_score, tags: user.tags, lastMessage, stage });
    }
    return res.json({ ok: true, clients });
  } catch (err) {
    console.error('clients error', err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// Routes that were previously defined as POST handlers (we re-declare them to reuse original logic)
app.post('/api/log-message', async (req, res) => {
  const body = req.body || {};
  const platform = body.platform;
  const extId = body.external_user_id;
  const direction = body.direction;
  const content = body.content;
  const now = new Date().toISOString();
  if (!platform || !extId || !direction || !content) {
    return res.status(400).json({ ok: false, error: 'Missing required fields' });
  }
  try {
    const userUpsert = { platform, external_user_id: extId, username: body.username ?? null, updated_at: now };
    const { data: upsertData, error: upsertErr } = await supabase
      .from('users')
      .upsert(userUpsert, { onConflict: 'platform,external_user_id' })
      .select()
      .limit(1);
    if (upsertErr) throw upsertErr;
    const user = Array.isArray(upsertData) ? upsertData[0] : upsertData;
    if (!user || !user.id) return res.status(500).json({ ok: false, error: 'User upsert failed' });
    const { error: msgErr } = await supabase.from('messages').insert([{ user_id: user.id, platform, direction, content, meta: body.meta ?? {}, created_at: body.timestamp ?? now }]);
    if (msgErr) throw msgErr;
    let interestDelta = 0; let newState = user.state || 'cold'; let recommendation = null;
    if (direction === 'incoming') {
      const text = content.toLowerCase();
      const priceKeywords = ['kolik', 'price', 'cena', 'cost'];
      const strongIntentKeywords = ['where pay', 'link', 'onlyfans', 'subscribe', 'payment', 'pay'];
      const hasStrong = strongIntentKeywords.some((k) => text.includes(k));
      const hasPrice = priceKeywords.some((k) => text.includes(k));
      if (hasStrong) { interestDelta += 30; newState = stateAtLeast(newState, 'warm'); }
      else if (hasPrice) { interestDelta += 20; newState = stateAtLeast(newState, 'warm'); }
      else { interestDelta += 5; }
      const { data: updatedUsers, error: updateErr } = await supabase
        .from('users')
        .update({ interest_score: (user.interest_score || 0) + interestDelta, state: newState, updated_at: now })
        .eq('id', user.id)
        .select()
        .limit(1);
      if (updateErr) throw updateErr;
      const refreshed = Array.isArray(updatedUsers) ? updatedUsers[0] : updatedUsers;
      if (refreshed) Object.assign(user, refreshed);
      if (hasStrong) {
        recommendation = { action: 'reply', payload: { text: 'Díky za zájem! Tady je odkaz na placený profil: https://onlyfans.example/your-profile' } };
      } else {
        recommendation = { action: 'wait', payload: {} };
      }
      const { error: recErr } = await supabase.from('recommendations').insert([{ user_id: user.id, action: recommendation.action, payload: recommendation.payload, created_at: now }]);
      if (recErr) console.error('insert recommendation error', recErr);
    }
    return res.json({ ok: true, user: { id: user.id, state: user.state, interest_score: user.interest_score, tags: user.tags }, recommendation });
  } catch (err) {
    console.error('log-message error', err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

app.post('/api/redirect-event', async (req, res) => {
  const body = req.body || {};
  const platform = body.platform;
  const extId = body.external_user_id;
  const type = body.type;
  const target = body.target;
  const now = new Date().toISOString();
  if (!platform || !extId || !type || !target) return res.status(400).json({ ok: false, error: 'Missing required fields' });
  try {
    const { data: upsertData, error: upsertErr } = await supabase
      .from('users')
      .upsert({ platform, external_user_id: extId, updated_at: now }, { onConflict: 'platform,external_user_id' })
      .select()
      .limit(1);
    if (upsertErr) throw upsertErr;
    const user = Array.isArray(upsertData) ? upsertData[0] : upsertData;
    if (!user || !user.id) return res.status(500).json({ ok: false, error: 'User upsert failed' });
    const { error: eventErr } = await supabase.from('events').insert([{ user_id: user.id, platform, type, target, reason: body.reason ?? null, tags: body.tags ?? [], meta: body.meta ?? {}, created_at: now }]);
    if (eventErr) throw eventErr;
    let interestDelta = 0; let newState = user.state || 'cold';
    if (type === 'redirect') { interestDelta += 50; newState = stateAtLeast(newState, 'hot'); }
    if (interestDelta !== 0 || newState !== user.state) {
      const { data: updatedUsers, error: updateErr } = await supabase
        .from('users')
        .update({ interest_score: (user.interest_score || 0) + interestDelta, state: newState, updated_at: now })
        .eq('id', user.id)
        .select()
        .limit(1);
      if (updateErr) throw updateErr;
      const refreshed = Array.isArray(updatedUsers) ? updatedUsers[0] : updatedUsers;
      if (refreshed) Object.assign(user, refreshed);
    }
    return res.json({ ok: true, user: { id: user.id, state: user.state, interest_score: user.interest_score, tags: user.tags } });
  } catch (err) {
    console.error('redirect-event error', err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// Start the server when this file is executed directly (not required for tests)
if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => { console.log(`Unified app listening on port ${port}`); });
}

module.exports = app;