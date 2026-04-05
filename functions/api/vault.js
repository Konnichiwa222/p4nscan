/**
 * Vault API — Cloudflare Pages Function
 * Kiến trúc: password xác thực server-side (như nekowo.site)
 * Data lưu plaintext JSON trong KV → không có crypto client-side
 * → hoạt động nhất quán trên mọi trình duyệt
 *
 * Cần bind KV namespace tên: VAULT_KV
 * CF Dashboard → Pages → vault → Settings → Functions → KV namespace bindings
 */

const KEY_DATA = 'vault:entries';
const KEY_HASH = 'vault:pwd_hash';

async function sha256(str) {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(str)
  );
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

export async function onRequest({ request, env }) {
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      },
    });
  }

  if (request.method !== 'POST') {
    return json({ ok: false, msg: 'Method not allowed' }, 405);
  }

  if (!env.VAULT_KV) {
    return json({
      ok: false,
      msg: 'VAULT_KV chưa được bind. Vào CF Pages → Settings → Functions → KV namespace bindings → thêm VAULT_KV',
    }, 500);
  }

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, msg: 'Invalid JSON' }, 400); }

  const { action, password, data } = body;
  if (!password || typeof password !== 'string') {
    return json({ ok: false, msg: 'Thiếu mật khẩu' }, 400);
  }

  const inputHash = await sha256(password.trim());

  // Lần đầu dùng: chưa có hash → lưu hash mới + tạo vault trống
  let storedHash = await env.VAULT_KV.get(KEY_HASH);
  if (!storedHash) {
    await env.VAULT_KV.put(KEY_HASH, inputHash);
    await env.VAULT_KV.put(KEY_DATA, '[]');
    storedHash = inputHash;
  }

  // Xác thực password
  if (inputHash !== storedHash) {
    return json({ ok: false, msg: 'Sai mật khẩu!' }, 401);
  }

  // ── Actions ──────────────────────────────────────────────
  switch (action) {
    case 'auth':
      return json({ ok: true });

    case 'load': {
      const raw = await env.VAULT_KV.get(KEY_DATA);
      let entries = [];
      try { entries = JSON.parse(raw || '[]'); } catch {}
      if (!Array.isArray(entries)) entries = [];
      return json({ ok: true, entries });
    }

    case 'save': {
      if (!Array.isArray(data)) {
        return json({ ok: false, msg: 'data phải là array' }, 400);
      }
      const str = JSON.stringify(data);
      if (str.length > 20 * 1024 * 1024) {
        return json({ ok: false, msg: 'Dữ liệu quá lớn (>20MB)' }, 413);
      }
      await env.VAULT_KV.put(KEY_DATA, str);
      return json({ ok: true });
    }

    case 'reset_password': {
      // Đặt lại mật khẩu (cần gửi new_password)
      const newPwd = body.new_password;
      if (!newPwd || typeof newPwd !== 'string' || newPwd.trim().length < 4) {
        return json({ ok: false, msg: 'Mật khẩu mới phải ít nhất 4 ký tự' }, 400);
      }
      const newHash = await sha256(newPwd.trim());
      await env.VAULT_KV.put(KEY_HASH, newHash);
      return json({ ok: true });
    }

    default:
      return json({ ok: false, msg: 'Action không hợp lệ' }, 400);
  }
}
