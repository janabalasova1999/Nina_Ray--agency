/*
 * Unified chat agency application
 *
 * This Express server exposes endpoints to log chat messages, handle redirect events,
 * and provide basic statistics and client information. It consolidates the logic
 * previously implemented as separate Supabase Edge Functions into a single Node.js
 * application. Use environment variables (see .env.example) to configure
 * connections and authentication.
 */

const express = require('express');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const dotenv = require('dotenv');

// Load environment variables from a .env file when available.
dotenv.config();

// Ensure required environment variables are present.
const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  WEBHOOK_SECRET,
  NINA_CHAT_BEARER_TOKEN,
  IG_BEARER_TOKEN,
  OF_BEARER_TOKEN,
  FANSLY_BEARER_TOKEN,
  FANVUE_BEARER_TOKEN,
  FB_BEARER_TOKEN,
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !WEBHOOK_SECRET) {
  throw new Error(
    'Missing required environment variables: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, WEBHOOK_SECRET'
  );
}

// Initialize Supabase client. We disable persisted sessions because we only need
// service-level access to the Postgres database.
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

// Mapping of platform names to their respective bearer tokens. Extend this map
// to support additional platforms (e.g. Instagram, OnlyFans, etc.).
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
// Possible states: cold < warm < hot.
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

/**
 * Middleware that verifies the request signature and bearer token.
 * If verification fails, it sends an appropriate HTTP error response and
 * terminates request processing. Otherwise, it populates req.authPlatform
 * with the platform specified in the JSON body and moves on.
 */
async function verifyAuth(req, res, next) {
  // We only enforce verification on POST routes for this middleware.
  if (req.method !== 'POST') return next();
  try {
    // Check presence of rawBody captured by the body parser.
    const rawBody = req.rawBody || '';
    // Verify HMAC signature.
    const signature = req.headers['x-signature'];
    if (!signature) {
      return res.status(401).json({ ok: false, error: 'Missing X-Signature header' });
    }
    const computedSig = computeHmacSha256(rawBody, WEBHOOK_SECRET);
    if (computedSig !== signature) {
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
    // Save platform for downstream handlers.
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

/**
 * POST /api/log-message
 * Log a chat message for a given user. The payload should include:
 *  - platform: string
 *  - external_user_id: string
 *  - username: string (optional)
 *  - direction: 'incoming' | 'outgoing'
 *  - content: string
 *  - conversation_id: string (optional)
 *  - timestamp: ISO string (optional)
 *  - meta: object (optional)
 *
 * The endpoint will upsert the user, insert the message and update interest
 * scoring when the message is incoming. It responds with the user info and
 * an optional recommendation.
 */
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
    // Upsert user record. Include username if provided.
    const userUpsert = {
      platform,
      external_user_id: extId,
      username: body.username ?? null,
      updated_at: now,
    };
    const { data: upsertData, error: upsertErr } = await supabase
      .from('users')
      .upsert(userUpsert, { onConflict: 'platform,external_user_id' })
      .select()
      .limit(1);
    if (upsertErr) throw upsertErr;
    const user = Array.isArray(upsertData) ? upsertData[0] : upsertData;
    if (!user || !user.id) {
      return res.status(500).json({ ok: false, error: 'User upsert failed' });
    }
    // Insert message row.
    const { error: msgErr } = await supabase.from('messages').insert([
      {
        user_id: user.id,
        platform,
        direction,
        content,
        meta: body.meta ?? {},
        created_at: body.timestamp ?? now,
      },
    ]);
    if (msgErr) throw msgErr;
    // Scoring and recommendation logic only for incoming messages.
    let interestDelta = 0;
    let newState = user.state || 'cold';
    let recommendation = null;
    if (direction === 'incoming') {
      const text = content.toLowerCase();
      const priceKeywords = ['kolik', 'price', 'cena', 'cost'];
      const strongIntentKeywords = ['where pay', 'link', 'onlyfans', 'subscribe', 'payment', 'pay'];
      const hasStrong = strongIntentKeywords.some((k) => text.includes(k));
      const hasPrice = priceKeywords.some((k) => text.includes(k));
      if (hasStrong) {
        interestDelta += 30;
        newState = stateAtLeast(newState, 'warm');
      } else if (hasPrice) {
        interestDelta += 20;
        newState = stateAtLeast(newState, 'warm');
      } else {
        interestDelta += 5;
      }
      // Update user state and interest score.
      const { data: updatedUsers, error: updateErr } = await supabase
        .from('users')
        .update({
          interest_score: (user.interest_score || 0) + interestDelta,
          state: newState,
          updated_at: now,
        })
        .eq('id', user.id)
        .select()
        .limit(1);
      if (updateErr) throw updateErr;
      const refreshed = Array.isArray(updatedUsers) ? updatedUsers[0] : updatedUsers;
      if (refreshed) Object.assign(user, refreshed);
      // Simple recommendation logic: if strong intent, propose redirect link; else wait.
      if (hasStrong) {
        recommendation = {
          action: 'reply',
          payload: {
            text: 'Díky za zájem! Tady je odkaz na placený profil: https://onlyfans.example/your-profile',
          },
        };
      } else {
        recommendation = { action: 'wait', payload: {} };
      }
      // Save recommendation to database (best effort). If this fails, we log but still return success.
      const { error: recErr } = await supabase.from('recommendations').insert([
        {
          user_id: user.id,
          action: recommendation.action,
          payload: recommendation.payload,
          created_at: now,
        },
      ]);
      if (recErr) console.error('insert recommendation error', recErr);
    }
    return res.json({
      ok: true,
      user: {
        id: user.id,
        state: user.state,
        interest_score: user.interest_score,
        tags: user.tags,
      },
      recommendation,
    });
  } catch (err) {
    console.error('log-message error', err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

/**
 * POST /api/redirect-event
 * Record a redirect event (e.g. user clicked OnlyFans link). The payload must include:
 *  - platform: string
 *  - external_user_id: string
 *  - type: string (e.g. 'redirect')
 *  - target: string (e.g. 'OnlyFans')
 *  - reason: string (optional)
 *  - tags: array of strings (optional)
 *  - meta: object (optional)
 *
 * This endpoint upserts the user, inserts the event row and updates interest score
 * when type is 'redirect'.
 */
app.post('/api/redirect-event', async (req, res) => {
  const body = req.body || {};
  const platform = body.platform;
  const extId = body.external_user_id;
  const type = body.type;
  const target = body.target;
  const now = new Date().toISOString();
  if (!platform || !extId || !type || !target) {
    return res.status(400).json({ ok: false, error: 'Missing required fields' });
  }
  try {
    // Upsert user to ensure existence.
    const { data: upsertData, error: upsertErr } = await supabase
      .from('users')
      .upsert(
        { platform, external_user_id: extId, updated_at: now },
        { onConflict: 'platform,external_user_id' }
      )
      .select()
      .limit(1);
    if (upsertErr) throw upsertErr;
    const user = Array.isArray(upsertData) ? upsertData[0] : upsertData;
    if (!user || !user.id) {
      return res.status(500).json({ ok: false, error: 'User upsert failed' });
    }
    // Insert event row.
    const { error: eventErr } = await supabase.from('events').insert([
      {
        user_id: user.id,
        platform,
        type,
        target,
        reason: body.reason ?? null,
        tags: body.tags ?? [],
        meta: body.meta ?? {},
        created_at: now,
      },
    ]);
    if (eventErr) throw eventErr;
    // Update interest if this is a redirect.
    let interestDelta = 0;
    let newState = user.state || 'cold';
    if (type === 'redirect') {
      interestDelta += 50;
      newState = stateAtLeast(newState, 'hot');
    }
    if (interestDelta !== 0 || newState !== user.state) {
      const { data: updatedUsers, error: updateErr } = await supabase
        .from('users')
        .update({
          interest_score: (user.interest_score || 0) + interestDelta,
          state: newState,
          updated_at: now,
        })
        .eq('id', user.id)
        .select()
        .limit(1);
      if (updateErr) throw updateErr;
      const refreshed = Array.isArray(updatedUsers) ? updatedUsers[0] : updatedUsers;
      if (refreshed) Object.assign(user, refreshed);
    }
    return res.json({
      ok: true,
      user: {
        id: user.id,
        state: user.state,
        interest_score: user.interest_score,
        tags: user.tags,
      },
    });
  } catch (err) {
    console.error('redirect-event error', err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

/**
 * GET /api/stats
 * Return basic statistics for the dashboard. It aggregates the number of
 * redirect events per day (last 7 days), the most common redirect reasons
 * and the most common tags. This endpoint does not require authentication.
 */
app.get('/api/stats', async (_req, res) => {
  try {
    // Count redirects by date for the last 7 days. We group by the date part
    // of created_at. Supabase does not support complex SQL functions via the
    // client library, so we compute the day boundaries in JavaScript.
    const now = new Date();
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    // Format dates as ISO strings truncated to date (YYYY-MM-DD).
    function formatDate(date) {
      return date.toISOString().slice(0, 10);
    }
    const { data: redirectEvents, error: eventsErr } = await supabase
      .from('events')
      .select('created_at, reason, tags')
      .eq('type', 'redirect')
      .gte('created_at', sevenDaysAgo.toISOString());
    if (eventsErr) throw eventsErr;
    // Aggregate counts.
    const countsByDay = {};
    const reasonCounts = {};
    const tagCounts = {};
    for (const event of redirectEvents || []) {
      const date = formatDate(new Date(event.created_at));
      countsByDay[date] = (countsByDay[date] || 0) + 1;
      if (event.reason) {
        reasonCounts[event.reason] = (reasonCounts[event.reason] || 0) + 1;
      }
      const tags = event.tags || [];
      for (const tag of tags) {
        tagCounts[tag] = (tagCounts[tag] || 0) + 1;
      }
    }
    return res.json({ ok: true, countsByDay, reasonCounts, tagCounts });
  } catch (err) {
    console.error('stats error', err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

/**
 * GET /api/clients
 * Return a list of users with their state, interest score, tags, last message and
 * current funnel stage. This endpoint is intended for the dashboard. It does
 * not require authentication but should be protected in production.
 */
app.get('/api/clients', async (_req, res) => {
  try {
    // Fetch users with basic info.
    const { data: users, error: usersErr } = await supabase
      .from('users')
      .select('id, platform, external_user_id, username, state, interest_score, tags')
      .order('updated_at', { ascending: false });
    if (usersErr) throw usersErr;
    // For each user, fetch the last message and determine funnel stage.
    const clients = [];
    for (const user of users || []) {
      // Fetch last message content and timestamp.
      const { data: lastMessages, error: msgErr } = await supabase
        .from('messages')
        .select('content, created_at, direction')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false })
        .limit(1);
      if (msgErr) throw msgErr;
      const lastMessage = lastMessages && lastMessages[0];
      // Determine funnel stage. For simplicity we derive from state: cold=chat only,
      // warm=poslán na OF, hot=aktivní na OF. This can be expanded later.
      let stage = 'chat only';
      if (user.state === 'warm') stage = 'poslán na OF';
      if (user.state === 'hot') stage = 'aktivní na OF';
      clients.push({
        id: user.id,
        platform: user.platform,
        external_user_id: user.external_user_id,
        username: user.username,
        state: user.state,
        interest_score: user.interest_score,
        tags: user.tags,
        lastMessage,
        stage,
      });
    }
    return res.json({ ok: true, clients });
  } catch (err) {
    console.error('clients error', err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// Start the server when this file is executed directly (not required for tests)
if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`Unified app listening on port ${port}`);
  });
}

module.exports = app;