// Grocery List — Cloudflare Worker + SQLite Durable Object
// קבצי האתר נמצאים ב-/public. כל מה שמתחת ל-/api/* מטופל כאן ונשמר במסד נתונים אמיתי.

import { DurableObject } from 'cloudflare:workers';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      const stub = env.DB.get(env.DB.idFromName('main'));
      return stub.fetch(request);
    }
    return env.ASSETS.fetch(request);
  }
};

const COLORS = ['#8fb3d9', '#f0a48c', '#9cc59a', '#c2a7dd', '#f2c66d', '#7fc3b8', '#e99ab0'];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const CODE_ABC = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = (msg) => { throw new HttpError(400, msg); };
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
});
const norm = (s, max = 40) => String(s || '').trim().replace(/\s+/g, ' ').slice(0, max);

function randomId(bytes = 9) {
  const a = new Uint8Array(bytes); crypto.getRandomValues(a);
  return btoa(String.fromCharCode(...a)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function toHex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }
async function hashPassword(password, saltHex) {
  const salt = new Uint8Array(saltHex.match(/../g).map(h => parseInt(h, 16)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return toHex(bits);
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export class GroceryDB extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.migrate();
  }
  q(query, ...binds) { return this.sql.exec(query, ...binds).toArray(); }
  one(query, ...binds) { return this.q(query, ...binds)[0] || null; }

  migrate() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        pass_hash TEXT NOT NULL, salt TEXT NOT NULL,
        color TEXT NOT NULL, photo TEXT, photo_v INTEGER NOT NULL DEFAULT 0,
        created INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS lists (
        id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', code TEXT NOT NULL UNIQUE,
        owner INTEGER NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS members (list_id TEXT NOT NULL, user_id INTEGER NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (list_id, user_id));
      CREATE TABLE IF NOT EXISTS items (
        id TEXT PRIMARY KEY, list_id TEXT NOT NULL, name TEXT NOT NULL, qty INTEGER NOT NULL DEFAULT 1,
        cat TEXT NOT NULL DEFAULT 'other', by_user INTEGER NOT NULL, miss INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS history (list_id TEXT NOT NULL, name TEXT NOT NULL, cat TEXT NOT NULL, count INTEGER NOT NULL, last INTEGER NOT NULL, PRIMARY KEY (list_id, name));
      CREATE INDEX IF NOT EXISTS items_list ON items(list_id);
      CREATE INDEX IF NOT EXISTS members_user ON members(user_id);
    `);
    // מוצרים קבועים: fixed = לא נמחק אחרי קנייה, done = נקנה (מוצג עם קו וכמות 0)
    const icols = this.q('PRAGMA table_info(items)').map(c => c.name);
    if (!icols.includes('fixed')) this.sql.exec('ALTER TABLE items ADD COLUMN fixed INTEGER NOT NULL DEFAULT 0');
    if (!icols.includes('done')) this.sql.exec('ALTER TABLE items ADD COLUMN done INTEGER NOT NULL DEFAULT 0');
    if (!this.q('PRAGMA table_info(users)').some(c => c.name === 'email')) this.sql.exec('ALTER TABLE users ADD COLUMN email TEXT');
    this.sql.exec('CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users(email)');
  }

  async fetch(request) {
    try { return await this.handle(request); }
    catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      return json({ error: 'משהו נכשל בשרת. נסה שוב' }, 500);
    }
  }

  // ---------- עזרים ----------
  meUser(u) { return { ...this.pubUser(u), email: u.email || '' }; }
  pubUser(u) { return { id: u.id, name: u.username, color: u.color, photo: u.photo_v ? `/api/u/${u.id}/photo?v=${u.photo_v}` : null }; }
  auth(request) {
    const h = request.headers.get('authorization') || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : '';
    const row = token && this.one('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?', token);
    if (!row) throw new HttpError(401, 'צריך להתחבר');
    return row;
  }
  newSession(userId) {
    const token = randomId(24);
    this.sql.exec('INSERT INTO sessions (token, user_id, created) VALUES (?, ?, ?)', token, userId, Date.now());
    return token;
  }
  needMember(lid, uid) {
    const l = this.one('SELECT l.* FROM lists l JOIN members m ON m.list_id = l.id WHERE l.id = ? AND m.user_id = ?', lid, uid);
    if (!l) throw new HttpError(403, 'הרשימה הזאת לא אצלך');
    return l;
  }
  makeCode() {
    for (;;) {
      const a = new Uint8Array(6); crypto.getRandomValues(a);
      const c = [...a].map(x => CODE_ABC[x % CODE_ABC.length]).join('');
      if (!this.one('SELECT id FROM lists WHERE code = ?', c)) return c;
    }
  }
  createList(uid, name) {
    const id = randomId(9), now = Date.now();
    this.sql.exec('INSERT INTO lists (id, name, code, owner, created, updated) VALUES (?, ?, ?, ?, ?, ?)', id, norm(name, 26), this.makeCode(), uid, now, now);
    this.sql.exec('INSERT INTO members (list_id, user_id, created) VALUES (?, ?, ?)', id, uid, now);
    return id;
  }
  touch(lid) { this.sql.exec('UPDATE lists SET updated = ? WHERE id = ?', Date.now(), lid); }
  members(lid) { return this.q('SELECT u.* FROM members m JOIN users u ON u.id = m.user_id WHERE m.list_id = ? ORDER BY m.created', lid).map(u => this.pubUser(u)); }
  items(lid) { return this.q('SELECT id, name, qty, cat, by_user AS "by", miss, fixed, done, created FROM items WHERE list_id = ? ORDER BY created DESC', lid).map(x => ({ ...x, miss: !!x.miss, fixed: !!x.fixed, done: !!x.done })); }
  listFull(l) {
    return { id: l.id, name: l.name, code: l.code, updated: l.updated, members: this.members(l.id), items: this.items(l.id),
      history: this.q('SELECT name, cat FROM history WHERE list_id = ?', l.id) };
  }
  home(me) {
    let lists = this.q('SELECT l.* FROM lists l JOIN members m ON m.list_id = l.id WHERE m.user_id = ? ORDER BY l.created', me.id);
    if (!lists.length) { this.createList(me.id, ''); lists = this.q('SELECT l.* FROM lists l JOIN members m ON m.list_id = l.id WHERE m.user_id = ?', me.id); }
    return { me: this.meUser(me), lists: lists.map(l => ({ id: l.id, name: l.name, updated: l.updated, members: this.members(l.id),
      count: this.one('SELECT COUNT(*) AS c FROM items WHERE list_id = ? AND done = 0', l.id).c,
      preview: this.q('SELECT name, qty FROM items WHERE list_id = ? ORDER BY created DESC LIMIT 4', l.id) })) };
  }
  deleteList(lid) {
    for (const t of ['items', 'members', 'history']) this.sql.exec(`DELETE FROM ${t} WHERE list_id = ?`, lid);
    this.sql.exec('DELETE FROM lists WHERE id = ?', lid);
  }
  addItems(lid, uid, arr) {
    const now = Date.now();
    (Array.isArray(arr) ? arr : []).slice(0, 60).forEach((x, i) => {
      const name = norm(x.name, 40); if (!name) return;
      const qty = Math.max(1, Math.min(99, parseInt(x.qty) || 1));
      const cat = /^[a-z]{2,10}$/.test(x.cat || '') ? x.cat : 'other';
      const ex = this.one('SELECT id, qty, done FROM items WHERE list_id = ? AND name = ?', lid, name);
      if (ex && !x.id) {
        // מוצר קבוע שכבר נקנה חוזר לרשימה; מוצר שכבר ברשימה מקבל עוד כמות
        if (ex.done) this.sql.exec('UPDATE items SET done = 0, miss = 0, qty = ? WHERE id = ?', x.explicit === false ? ex.qty : qty, ex.id);
        else this.sql.exec('UPDATE items SET qty = ? WHERE id = ?', Math.min(99, ex.qty + qty), ex.id);
      }
      else if (!ex) this.sql.exec('INSERT INTO items (id, list_id, name, qty, cat, by_user, miss, fixed, done, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (x.id && /^[\w-]{6,20}$/.test(x.id)) ? x.id : randomId(9), lid, name, qty, cat, x.by ? +x.by : uid, x.miss ? 1 : 0, (x.fixed === false || x.fixed === 0) ? 0 : 1, x.done ? 1 : 0, x.created ? +x.created : now + i);
    });
    this.touch(lid);
  }

  async handle(request) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '');
    const method = request.method;
    let body = {};
    if (method === 'POST') { try { body = await request.json(); } catch (e) { body = {}; } }
    let m;

    // ----- חשבונות -----
    if (path === '/api/signup' && method === 'POST') {
      const username = norm(body.username, 18), password = String(body.password || '');
      const email = String(body.email || '').trim().toLowerCase();
      if (username.length < 2) bad('שם משתמש צריך לפחות 2 תווים');
      if (username.includes('@')) bad('שם המשתמש לא יכול לכלול @');
      if (!EMAIL_RE.test(email) || email.length > 120) bad('כתובת המייל לא נראית תקינה');
      if (this.one('SELECT id FROM users WHERE email = ?', email)) bad('כבר יש משתמש עם המייל הזה. נסה להתחבר');
      if (password.length < 4) bad('הסיסמה צריכה להיות לפחות 4 תווים');
      if (this.one('SELECT id FROM users WHERE username = ?', username)) bad('השם הזה כבר תפוס. נסה שם אחר או התחבר');
      const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
      const color = COLORS[this.one('SELECT COUNT(*) AS c FROM users').c % COLORS.length];
      this.sql.exec('INSERT INTO users (username, pass_hash, salt, color, created, email) VALUES (?, ?, ?, ?, ?, ?)', username, await hashPassword(password, salt), salt, color, Date.now(), email);
      const u = this.one('SELECT * FROM users WHERE username = ?', username);
      this.createList(u.id, '');
      return json({ token: this.newSession(u.id) });
    }
    if (path === '/api/login' && method === 'POST') {
      // כניסה עם שם משתמש או מייל
      const id = norm(body.username, 120);
      const u = id.includes('@') ? this.one('SELECT * FROM users WHERE email = ?', id.toLowerCase()) : this.one('SELECT * FROM users WHERE username = ?', id);
      if (!u || !safeEqual(await hashPassword(String(body.password || ''), u.salt), u.pass_hash)) bad('הפרטים לא נכונים. בדוק את השם או המייל והסיסמה');
      return json({ token: this.newSession(u.id) });
    }
    if ((m = path.match(/^\/api\/u\/(\d+)\/photo$/)) && method === 'GET') {
      const u = this.one('SELECT photo FROM users WHERE id = ?', +m[1]);
      if (!u || !u.photo) throw new HttpError(404, 'אין תמונה');
      const bin = Uint8Array.from(atob(u.photo), c => c.charCodeAt(0));
      return new Response(bin, { headers: { 'content-type': 'image/jpeg', 'cache-control': 'public, max-age=31536000, immutable' } });
    }

    const me = this.auth(request);
    if (path === '/api/logout' && method === 'POST') {
      this.sql.exec('DELETE FROM sessions WHERE token = ?', (request.headers.get('authorization') || '').slice(7));
      return json({ ok: true });
    }
    if (path === '/api/home' && method === 'GET') return json(this.home(me));

    // ----- פרופיל -----
    if (path === '/api/profile' && method === 'POST') {
      const username = norm(body.name, 18);
      if (username.length < 2) bad('שם משתמש צריך לפחות 2 תווים');
      const taken = this.one('SELECT id FROM users WHERE username = ?', username);
      if (taken && taken.id !== me.id) bad('השם הזה כבר תפוס');
      if (username.includes('@')) bad('שם המשתמש לא יכול לכלול @');
      const email = String(body.email ?? me.email ?? '').trim().toLowerCase();
      if (!EMAIL_RE.test(email)) bad('כתובת המייל לא נראית תקינה');
      const takenMail = this.one('SELECT id FROM users WHERE email = ?', email);
      if (takenMail && takenMail.id !== me.id) bad('המייל הזה כבר רשום למשתמש אחר');
      const color = COLORS.includes(body.color) ? body.color : me.color;
      this.sql.exec('UPDATE users SET username = ?, color = ?, email = ? WHERE id = ?', username, color, email, me.id);
      if (body.photo === null) this.sql.exec('UPDATE users SET photo = NULL, photo_v = 0 WHERE id = ?', me.id);
      else if (typeof body.photo === 'string' && body.photo.startsWith('data:image/jpeg;base64,')) {
        const b64 = body.photo.slice(23);
        if (b64.length > 200000) bad('התמונה גדולה מדי');
        this.sql.exec('UPDATE users SET photo = ?, photo_v = photo_v + 1 WHERE id = ?', b64, me.id);
      }
      if (body.newPass) {
        if (!safeEqual(await hashPassword(String(body.oldPass || ''), me.salt), me.pass_hash)) bad('הסיסמה הנוכחית לא נכונה');
        if (String(body.newPass).length < 4) bad('הסיסמה החדשה צריכה להיות לפחות 4 תווים');
        const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
        this.sql.exec('UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?', await hashPassword(String(body.newPass), salt), salt, me.id);
      }
      return json(this.home(this.one('SELECT * FROM users WHERE id = ?', me.id)));
    }

    // ----- רשימות -----
    if (path === '/api/lists' && method === 'POST') return json({ id: this.createList(me.id, body.name) });
    if (path === '/api/lists/join' && method === 'POST') {
      const l = this.one('SELECT * FROM lists WHERE code = ?', String(body.code || '').trim().toUpperCase());
      if (!l) bad('לא מצאנו רשימה עם הקוד הזה. בדוק שוב את התווים');
      if (this.one('SELECT 1 AS x FROM members WHERE list_id = ? AND user_id = ?', l.id, me.id)) bad('הרשימה הזאת כבר אצלך');
      this.sql.exec('INSERT INTO members (list_id, user_id, created) VALUES (?, ?, ?)', l.id, me.id, Date.now());
      const owner = this.one('SELECT username FROM users WHERE id = ?', l.owner);
      return json({ id: l.id, owner: owner ? owner.username : '' });
    }
    if ((m = path.match(/^\/api\/lists\/([\w-]+)(?:\/(\w+))?$/))) {
      const lid = m[1], act = m[2] || '';
      const l = this.needMember(lid, me.id);
      if (!act && method === 'GET') return json(this.listFull(l));
      if (act === 'delete' && method === 'POST') { this.deleteList(lid); return json({ ok: true }); }
      if (act === 'leave' && method === 'POST') {
        this.sql.exec('DELETE FROM members WHERE list_id = ? AND user_id = ?', lid, me.id);
        if (!this.one('SELECT 1 AS x FROM members WHERE list_id = ?', lid)) this.deleteList(lid);
        return json({ ok: true });
      }
      if (act === 'name' && method === 'POST') { this.sql.exec('UPDATE lists SET name = ? WHERE id = ?', norm(body.name, 26), lid); this.touch(lid); return json({ ok: true }); }
      if (act === 'items' && method === 'POST') { this.addItems(lid, me.id, body.items); return json(this.listFull(this.one('SELECT * FROM lists WHERE id = ?', lid))); }
      if (act === 'reset' && method === 'POST') { this.sql.exec('DELETE FROM items WHERE list_id = ?', lid); this.touch(lid); return json(this.listFull(l)); }
      if (act === 'restore' && method === 'POST') {
        // ביטול פעולה: מחזירים מוצרים כמו שהיו
        if (Array.isArray(body.replace)) this.sql.exec('DELETE FROM items WHERE list_id = ?', lid);
        this.addItems(lid, me.id, body.replace || body.items);
        return json(this.listFull(this.one('SELECT * FROM lists WHERE id = ?', lid)));
      }
      if (act === 'finish' && method === 'POST') {
        const now = Date.now();
        for (const x of this.q('SELECT name, cat FROM items WHERE list_id = ? AND miss = 0 AND done = 0', lid))
          this.sql.exec('INSERT INTO history (list_id, name, cat, count, last) VALUES (?, ?, ?, 1, ?) ON CONFLICT(list_id, name) DO UPDATE SET count = count + 1, cat = excluded.cat, last = excluded.last', lid, x.name, x.cat, now);
        // כל מה שנקנה נשאר ברשימה עם קו (מחזירים בכפתור או כשכותבים אותו שוב); מה שלא נמצא נשאר לקנייה הבאה
        this.sql.exec('UPDATE items SET done = 1 WHERE list_id = ? AND miss = 0', lid);
        this.sql.exec('UPDATE items SET miss = 0 WHERE list_id = ?', lid);
        this.touch(lid);
        return json(this.listFull(l));
      }
    }
    if ((m = path.match(/^\/api\/items\/([\w-]+)\/(miss|delete|qty|fixed|back)$/)) && method === 'POST') {
      const it = this.one('SELECT * FROM items WHERE id = ?', m[1]);
      if (!it) throw new HttpError(404, 'המוצר כבר לא ברשימה');
      const l = this.needMember(it.list_id, me.id);
      if (m[2] === 'miss') this.sql.exec('UPDATE items SET miss = ? WHERE id = ?', body.miss ? 1 : 0, it.id);
      else if (m[2] === 'qty') this.sql.exec('UPDATE items SET qty = ? WHERE id = ?', Math.max(1, Math.min(99, parseInt(body.qty) || 1)), it.id);
      else if (m[2] === 'fixed') this.sql.exec('UPDATE items SET fixed = ? WHERE id = ?', body.fixed ? 1 : 0, it.id);
      else if (m[2] === 'back') this.sql.exec('UPDATE items SET done = 0, miss = 0 WHERE id = ?', it.id);
      else this.sql.exec('DELETE FROM items WHERE id = ?', it.id);
      this.touch(l.id);
      return json(this.listFull(this.one('SELECT * FROM lists WHERE id = ?', l.id)));
    }
    throw new HttpError(404, 'לא נמצא');
  }
}
