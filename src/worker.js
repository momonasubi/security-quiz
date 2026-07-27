/**
 * 情報セキュリティ試験対策クイズ — 進捗同期API
 *
 * POST /api/sync  { user, pin, stats }
 *   なまえ＋4桁PINから作った鍵でKVに保存。既存データがあれば問題ごとにマージして返す。
 *   マージ規則：ts（最後に解答した時刻）が新しい方の lastOk を採用、seen/ok は大きい方。
 * GET  /api/ping   疎通確認
 * それ以外は静的アセット（index.html）へ。
 */

const MAX_BODY = 512 * 1024;      // 512KB を超えるリクエストは拒否
const SALT = "secquiz-v1";        // 鍵導出用（KVキーを推測しにくくするためだけのもの）

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, GET, OPTIONS",
  "access-control-allow-headers": "content-type",
  "access-control-max-age": "86400",
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...CORS },
  });
}

async function keyFor(user, pin) {
  const norm = String(user).trim().toLowerCase().normalize("NFKC");
  const buf = new TextEncoder().encode(`${norm}|${pin}|${SALT}`);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return "u:" + [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

// 受け取った統計を検証しつつ正規化（想定外の巨大データ・不正な型を弾く）
function sanitize(stats) {
  const out = { q: {} };
  const q = (stats && stats.q) || {};
  const ids = Object.keys(q).slice(0, 5000);
  for (const id of ids) {
    const r = q[id];
    if (!r || typeof r !== "object") continue;
    out.q[String(id).slice(0, 400)] = {
      seen: Math.max(0, Math.min(1e6, Number(r.seen) || 0)),
      ok: Math.max(0, Math.min(1e6, Number(r.ok) || 0)),
      lastOk: r.lastOk === true ? true : r.lastOk === false ? false : null,
      ts: Math.max(0, Number(r.ts) || 0),
    };
  }
  return out;
}

function merge(a, b) {
  const out = { q: {} };
  const A = (a && a.q) || {}, B = (b && b.q) || {};
  for (const id of new Set([...Object.keys(A), ...Object.keys(B)])) {
    const x = A[id], y = B[id];
    if (!x) { out.q[id] = y; continue; }
    if (!y) { out.q[id] = x; continue; }
    const newer = (y.ts || 0) > (x.ts || 0) ? y : x;
    out.q[id] = {
      seen: Math.max(x.seen || 0, y.seen || 0),
      ok: Math.max(x.ok || 0, y.ok || 0),
      lastOk: newer.lastOk,
      ts: Math.max(x.ts || 0, y.ts || 0),
    };
  }
  return out;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (url.pathname === "/api/ping") return json({ ok: true, kv: !!env.PROGRESS });

    if (url.pathname === "/api/sync") {
      if (request.method !== "POST") return json({ ok: false, error: "method not allowed" }, 405);
      if (!env.PROGRESS) return json({ ok: false, error: "storage not configured" }, 500);

      const len = Number(request.headers.get("content-length") || 0);
      if (len > MAX_BODY) return json({ ok: false, error: "too large" }, 413);

      let body;
      try { body = await request.json(); }
      catch { return json({ ok: false, error: "invalid json" }, 400); }

      const user = String(body.user || "").trim();
      const pin = String(body.pin || "").trim();
      if (!user || user.length > 20) return json({ ok: false, error: "invalid user" }, 400);
      if (!/^\d{4}$/.test(pin)) return json({ ok: false, error: "invalid pin" }, 400);

      const key = await keyFor(user, pin);
      const stored = await env.PROGRESS.get(key, "json");
      const merged = merge(stored && stored.stats, sanitize(body.stats));

      // 内容が変わっていなければ書き込まない（無料枠の書き込み上限を節約：読み出しだけの同期は0書き込み）
      const changed = !stored || JSON.stringify(stored.stats) !== JSON.stringify(merged);
      if (changed) {
        await env.PROGRESS.put(key, JSON.stringify({ stats: merged, updatedAt: Date.now(), name: user.slice(0, 20) }));
      }

      return json({
        ok: true,
        created: !stored,
        written: changed,
        count: Object.keys(merged.q).length,
        stats: merged,
      });
    }

    if (url.pathname === "/api/delete") {
      if (request.method !== "POST") return json({ ok: false, error: "method not allowed" }, 405);
      if (!env.PROGRESS) return json({ ok: false, error: "storage not configured" }, 500);

      let body;
      try { body = await request.json(); }
      catch { return json({ ok: false, error: "invalid json" }, 400); }

      const user = String(body.user || "").trim();
      const pin = String(body.pin || "").trim();
      if (!user || user.length > 20) return json({ ok: false, error: "invalid user" }, 400);
      if (!/^\d{4}$/.test(pin)) return json({ ok: false, error: "invalid pin" }, 400);

      const key = await keyFor(user, pin);
      const stored = await env.PROGRESS.get(key, "json");
      await env.PROGRESS.delete(key);
      return json({ ok: true, existed: !!stored });
    }

    return json({ ok: false, error: "not found" }, 404);
  },
};
