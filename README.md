# Unified "Agentura" for Nina chat (Unified app + Supabase)

Toto repozitář obsahuje sjednocenou Node.js/Express aplikaci, která loguje zprávy a redirect eventy z Nina chatu do Supabase Postgresu a poskytuje základní scoring + doporučení.

Obsah repozitáře:
- index.js — hlavní Express aplikace (endpoints: /api/log-message, /api/redirect-event, /api/stats, /api/clients)
- package.json — závislosti a start script
- .env.example — příklad environmentálních proměnných
- render.yaml — Render blueprint pro automatické nasazení
- deploy.sh — pomocný skript pro migrace / lokální deploy
- supabase/migrations/001_init.sql — SQL migrace (pokud soubor chybí, přidejte vlastní)

Bezpečnostní poznámky
- SUPABASE_SERVICE_ROLE_KEY a ADMIN_API_KEY musí zůstat server-side (nikdy je neposílejte klientům).
- WEBHOOK_SECRET a Bearer tokeny jsou povinné pro všechny POST požadavky.
- Požadavky POST musí obsahovat hlavičky:
  - Authorization: Bearer <PLATFORM_TOKEN>
  - X-Timestamp: <unix-ms-or-ISO> (required, used for replay protection)
  - X-Signature: <hex-hmac-sha256-of-raw-body+timestamp> (lower-case hex)

Jak funguje HMAC & replay protection
- Server očekává podpis HMAC-SHA256 nad raw JSON body concatenated with timestamp string: `hmac_sha256(WEBHOOK_SECRET, raw_body + timestamp_string)`.
- Tento podpis se umístí do hlavičky `X-Signature` jako lower-case hex (64 chars).
- Hlavička `X-Timestamp` může být unix ms (e.g. 1670000000000) nebo ISO 8601.
- Tolerance timestampu je ±5 minut (lze změnit v kódu).

Rychlý příklad (Node) pro výpočet podpisu:

```js
const crypto = require('crypto');
const raw = JSON.stringify({ platform: 'nina_chat', external_user_id: 'u123', direction: 'incoming', content: 'kolik to stoji?' });
const ts = Date.now().toString();
const sig = crypto.createHmac('sha256', process.env.WEBHOOK_SECRET).update(raw + ts).digest('hex');
console.log('X-Timestamp:', ts);
console.log('X-Signature:', sig);
```

curl příklad (Linux/macOS):

```bash
RAW='{"platform":"nina_chat","external_user_id":"u123","direction":"incoming","content":"kolik to stoji?"}'
TS=$(date +%s%3N)
SIG=$(printf '%s' "$RAW$TS" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | sed 's/^.* //')
curl -X POST "https://<váš-host>/api/log-message" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $NINA_CHAT_BEARER_TOKEN" \
  -H "X-Timestamp: $TS" \
  -H "X-Signature: $SIG" \
  -d "$RAW"
```

Nasazení na Render (recommended)
1. Vytvořte repozitář na GitHubu (pokud ještě není) a pushněte kód.
2. V Render zvolte New -> Web Service nebo Blueprints a propojte s tímto repozitářem.
3. V Render nastavte environment variables podle `.env.example` (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, WEBHOOK_SECRET, NINA_CHAT_BEARER_TOKEN, ADMIN_API_KEY, ...).
4. Render spustí `npm install` a `npm start` (package.json start je `node index.js`).

Lokální spuštění
1. Zkopírujte `.env.example` do `.env` a doplňte hodnoty.
2. npm install
3. npm start

Migrace
- Spusťte SQL migrace (supabase/migrations/001_init.sql) do vaší Postgres databáze.

Další možnosti
- Přidat monitoring (Sentry), rate-limiting nebo další ochrany.
