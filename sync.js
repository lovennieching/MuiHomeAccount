/* 貓之家會計系統：多人／多裝置同步
 * 做法：每部裝置照常用 localStorage；同步時把整份資料用密碼加密（AES-256-GCM）後，
 * 放到 Firebase Realtime Database 一個「房間」。多部裝置之間按 id 做三方合併，
 * 唔會因為同時修改而互相覆蓋。雲端只有密文，冇密碼睇唔到內容。
 * 載入方式：index.html 最後 </body> 前加  <script src="sync.js"></script>
 */
(() => {
'use strict';

/* ---------- 合併邏輯（不依賴瀏覽器） ---------- */
const canon = v => JSON.stringify(v, (k, x) =>
  x && typeof x === 'object' && !Array.isArray(x)
    ? Object.keys(x).sort().reduce((o, q) => (o[q] = x[q], o), {}) : x);
const clone = v => JSON.parse(JSON.stringify(v));

// 三方合併：b=上次同步時、l=本機現在、r=雲端現在。以 key 對應同一筆。
function mergeArr(b, l, r, key) {
  const kf = x => { const k = key(x); return k === undefined ? canon(x) : k };
  const bm = new Map((b || []).map(x => [kf(x), canon(x)]));
  const lm = new Map((l || []).map(x => [kf(x), x]));
  const seen = new Set(), out = [];
  for (const x of r || []) {
    const k = kf(x); seen.add(k);
    if (lm.has(k)) {                       // 兩邊都有
      const lx = lm.get(k);
      out.push(!bm.has(k) || canon(lx) !== bm.get(k) ? lx : x);   // 本機有改→用本機；否則用雲端（可能別人改過）
    } else if (!bm.has(k)) out.push(x);    // 雲端新增
    /* else：本機刪除了 → 不放入 */
  }
  for (const x of l || []) {
    const k = kf(x);
    if (seen.has(k)) continue;
    if (!bm.has(k) || canon(x) !== bm.get(k)) out.push(x);        // 本機新增（或本機有改但雲端已刪）
    /* else：雲端刪除了，本機冇改 → 跟隨刪除 */
  }
  return out;
}
function mergeRent(b, l, r) {
  if (!l) return r;
  if (!r) return l;
  if (!b) return r;                        // 第一次加入：以雲端為準
  const cl = canon(l), cb = canon(b), cr = canon(r);
  if (cl === cb) return r;
  if (cr === cb) return l;
  const o = { ...r, ...l };                // 兩邊都改過：房間／開支按名稱逐項合併
  o.rooms = mergeArr(b.rooms, l.rooms, r.rooms, x => x.n);
  o.costs = mergeArr(b.costs, l.costs, r.costs, x => x.n);
  return o;
}
function mergeState(b, l, r) {
  b = b || {};
  const o = { ...r, ...l };
  o.recs = mergeArr(b.recs, l.recs, r.recs, x => x.id);
  o.dues = mergeArr(b.dues, l.dues, r.dues, x => x.id);
  o.rent = mergeRent(b.rent, l.rent, r.rent);
  const seen = new Set();                  // 兩部裝置同時結清同一項重複提醒，會各自生成下一期，這裡去重
  o.dues = o.dues.filter(d => {
    if (String(d.status || '').startsWith('已')) return true;
    const k = [d.dir, d.who, d.item, d.due].join('|');
    if (seen.has(k)) return false;
    seen.add(k); return true;
  });
  return o;
}
if (typeof module !== 'undefined' && module.exports) { module.exports = { mergeState, mergeArr, canon }; return; }

/* ---------- 設定與狀態 ---------- */
const CK = 'catHouseSync.v1', BK = 'catHouseSync.base', RK = 'catHouseSync.rev';
const J = s => { try { return JSON.parse(s) } catch (e) { return null } };
let cfg = J(localStorage.getItem(CK)) || {};          // {url, room, pw}
let base = J(localStorage.getItem(BK));               // 上次成功同步後嘅資料
let rev = +localStorage.getItem(RK) || 0;             // 上次見到嘅雲端版本
let busy = false, again = false, timer = null, keyCache = null;
const $$ = id => document.getElementById(id);
const ok = () => !!(cfg.url && cfg.room && cfg.pw);
const ep = p => cfg.url.trim().replace(/\/+$/, '') + '/' + encodeURIComponent(cfg.room.trim()) + (p ? '/' + p : '') + '.json';
const snap = () => clone(S);
const hhmm = () => new Date().toTimeString().slice(0, 5);
const saveCfg = () => localStorage.setItem(CK, JSON.stringify(cfg));
const saveBase = () => { try { localStorage.setItem(BK, JSON.stringify(base)); localStorage.setItem(RK, String(rev)) } catch (e) {} };
const dialogOpen = () => ['dlg', 'cf'].some(i => { const d = $$(i); return d && d.open });

let stText = '', stCls = '';
function setSt(t, cls) {
  stText = t; stCls = cls || '';
  const a = $$('syncst'), b = $$('sybadge');
  if (a) { a.textContent = t; a.style.color = cls === 'err' ? 'var(--out)' : cls === 'ok' ? 'var(--in)' : 'var(--mut)' }
  if (b) b.textContent = ok() ? '☁ ' + t : '';
}
function fail(msg) { setSt(msg, 'err'); return false }

/* ---------- 加密 ---------- */
const B64 = u => { let t = ''; for (let i = 0; i < u.length; i += 8192) t += String.fromCharCode.apply(null, u.subarray(i, i + 8192)); return btoa(t) };
const UB = t => Uint8Array.from(atob(t), c => c.charCodeAt(0));
async function getKey(salt) {
  const id = cfg.pw + '|' + salt;
  if (keyCache && keyCache.id === id) return keyCache.k;
  const m = await crypto.subtle.importKey('raw', new TextEncoder().encode(cfg.pw), 'PBKDF2', false, ['deriveKey']);
  const k = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: UB(salt), iterations: 250000, hash: 'SHA-256' }, m, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  keyCache = { id, k }; return k;
}
async function encode(state, salt, r) {
  const iv = crypto.getRandomValues(new Uint8Array(12)), k = await getKey(salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(JSON.stringify(state))));
  return { v: 2, rev: r, s: salt, i: B64(iv), d: B64(ct), t: Date.now() };
}
async function decode(o) {
  const k = await getKey(o.s);
  return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: UB(o.i) }, k, UB(o.d))));
}

/* ---------- 同步 ---------- */
function apply(m) {
  if (canon(snap()) === canon(m)) return;
  Object.keys(S).forEach(k => delete S[k]);
  Object.assign(S, clone(m));
  try { localStorage.setItem(KEY, JSON.stringify(S)) } catch (e) {}
  render();
}
function schedule(ms) { clearTimeout(timer); if (ok()) timer = setTimeout(sync, ms) }

async function sync() {
  if (!ok()) return;
  if (busy) { again = true; return }
  if (dialogOpen()) { schedule(4000); return }
  busy = true;
  try {
    for (let attempt = 0; attempt < 4; attempt++) {
      setSt('同步中…');
      const res = await fetch(ep());
      if (!res.ok) throw new Error('讀取雲端失敗（' + res.status + '）。請檢查網址同 Firebase 規則。');
      const doc = await res.json();
      let remote = null, salt;
      if (doc && doc.d) {
        try { remote = await decode(doc) } catch (e) { keyCache = null; return fail('同步密碼不正確，或雲端資料損毀') }
        salt = doc.s;
      } else { salt = B64(crypto.getRandomValues(new Uint8Array(16))); base = null }

      const local = snap();
      let merged = mergeState(base, local, remote || { recs: [], dues: [] });

      // 安全閘：本機一次過刪走大量記錄（例如匯入備份／清除）→ 先問清楚
      if (base && base.recs && remote) {
        const ls = new Set((local.recs || []).map(x => x.id));
        const gone = base.recs.filter(x => !ls.has(x.id)).length;
        if (gone >= 20 && gone > base.recs.length * 0.3) {
          const go = await ask('這部裝置少咗 ' + gone + ' 筆記錄，同步後所有人都會少咗。\n確定＝照樣同步；取消＝用雲端資料還原這部裝置。');
          if (!go) merged = remote;
        }
      }

      const curRev = (doc && doc.rev) || 0;
      if (!remote || canon(merged) !== canon(remote)) {
        const out = await encode(merged, salt, curRev + 1);
        const put = await fetch(ep(), { method: 'PUT', body: JSON.stringify(out) });
        if (put.status === 401 || put.status === 403 || put.status === 412) {
          if (attempt < 3) continue;            // 多數係同時有人寫入 → 重新讀取再合併
          throw new Error('寫入被拒絕（' + put.status + '），請檢查 Firebase 規則是否貼咗最新版本。');
        }
        if (!put.ok) throw new Error('寫入雲端失敗（' + put.status + '）');
        rev = out.rev;
      } else rev = curRev;

      if (dialogOpen()) { schedule(4000); setSt('稍後完成同步'); return }   // 唔好喺使用者填表時換走資料
      apply(merged);
      base = clone(merged); saveBase();
      setSt('已同步 ' + hhmm(), 'ok');
      return true;
    }
  } catch (e) {
    fail(/Failed to fetch|NetworkError|Load failed/i.test(e.message) ? '連線唔到雲端（離線？）資料已存喺本機，有網絡時會自動同步' : e.message);
  } finally {
    busy = false;
    if (again) { again = false; schedule(500) }
  }
}

// 輕量檢查：只讀雲端版本號（幾個字節），有變先下載全部
async function tick() {
  if (!ok() || document.hidden || busy) return;
  try {
    if (base && canon(snap()) !== canon(base)) return sync();
    const r = await fetch(ep('rev'));
    if (!r.ok) return;
    const v = await r.json();
    if (v !== null && v !== rev) sync();
  } catch (e) {}
}

/* ---------- 介面 ---------- */
function randRoom() {
  const a = crypto.getRandomValues(new Uint8Array(20));
  return Array.from(a, x => 'abcdefghijkmnpqrstuvwxyz23456789'[x % 32]).join('');
}
function buildUI() {
  const box = $$('set');
  if (!box || $$('syncbox')) return;
  const hd = document.querySelector('header');
  if (hd) hd.insertAdjacentHTML('beforeend', '<div id="sybadge" style="color:var(--mut);font-size:12px"></div>');
  box.insertAdjacentHTML('afterbegin', `<h2>多人／多裝置同步</h2><div class="cc" id="syncbox">
<div id="syncst" class="s" style="margin-bottom:6px"></div>
<label>Firebase 資料庫網址<input id="sy_url" inputmode="url" autocomplete="off" placeholder="https://xxxx-default-rtdb.firebaseio.com"></label>
<label>房間代碼（第一部裝置自動產生，其他人用邀請連結）<input id="sy_room" autocomplete="off"></label>
<label>同步密碼（同時係加密密碼，所有人要一樣）<input id="sy_pw" type="password" autocomplete="off"></label>
<div class="row2"><button class="b" id="sy_on">儲存並開始同步</button><button class="b g" id="sy_now">立即同步</button><button class="b g" id="sy_link">複製邀請連結</button><button class="b d" id="sy_off">停止同步</button></div>
<p class="s" style="color:var(--mut);font-size:13px;margin-bottom:0">資料會加密後先上雲端，冇密碼睇唔到。邀請連結只包含網址同房間代碼，唔包含密碼，請另外話俾姊妹知。同步後唔使再手動匯出匯入，但仍建議定期匯出備份。</p></div>`);
  $$('sy_url').value = cfg.url || '';
  $$('sy_room').value = cfg.room || '';
  $$('sy_pw').value = cfg.pw || '';
  setSt(ok() ? (stText || '已設定') : '未開啟同步');
}
document.addEventListener('click', async e => {
  const t = e.target.closest && e.target.closest('button'); if (!t) return;
  if (t.id === 'sy_on') {
    const u = $$('sy_url').value.trim(), pw = $$('sy_pw').value; let r = $$('sy_room').value.trim();
    if (!/^https:\/\/.+\.(firebaseio\.com|firebasedatabase\.app)\/?$/.test(u)) return say('網址格式唔啱，應該似 https://xxxx-default-rtdb.firebaseio.com');
    if (pw.length < 8) return say('同步密碼請用 8 個字元以上');
    if (!r) r = randRoom();
    if (r.length < 16) return say('房間代碼至少 16 位');
    cfg = { url: u, room: r, pw }; keyCache = null; saveCfg(); $$('sy_room').value = r;
    setSt('準備同步…'); sync();
  } else if (t.id === 'sy_now') {
    if (!ok()) return say('請先填好網址、房間代碼同密碼，再按「儲存並開始同步」');
    sync();
  } else if (t.id === 'sy_link') {
    if (!cfg.url || !cfg.room) return say('請先開始同步');
    const link = location.href.split('#')[0] + '#sync=' + encodeURIComponent(btoa(JSON.stringify({ u: cfg.url, r: cfg.room })));
    try { await navigator.clipboard.writeText(link); say('已複製邀請連結（唔包含密碼）') } catch (x) { prompt('複製下面連結：', link) }
  } else if (t.id === 'sy_off') {
    if (!await ask('停止同步？這部裝置會保留現有資料，但之後唔再同其他人同步。')) return;
    cfg = {}; base = null; rev = 0; keyCache = null;
    [CK, BK, RK].forEach(k => localStorage.removeItem(k));
    $$('sy_url').value = $$('sy_room').value = $$('sy_pw').value = '';
    setSt('未開啟同步'); say('已停止同步');
  }
});
// 同步開啟期間，「清除本機資料」會變成清除所有人，所以先攔住
document.addEventListener('click', e => {
  const t = e.target.closest && e.target.closest('#clr');
  if (t && ok()) { e.stopImmediatePropagation(); e.preventDefault(); say('同步開啟中：請先按「停止同步」，再清除本機資料') }
}, true);

/* ---------- 掛入主程式 ---------- */
const _save = window.save;
window.save = function () { const r = _save.apply(this, arguments); schedule(1500); return r };

buildUI();
try {                                           // 邀請連結：#sync=...
  const m = /[#&]sync=([^&]+)/.exec(location.hash);
  if (m) {
    const o = JSON.parse(atob(decodeURIComponent(m[1])));
    if (o && o.u && o.r) {
      cfg = { ...cfg, url: o.u, room: o.r }; saveCfg();
      $$('sy_url').value = o.u; $$('sy_room').value = o.r;
      history.replaceState(null, '', location.pathname + location.search);
      const tab = document.querySelector('#tabs [data-t=set]'); if (tab) tab.click();
      say('已加入同步設定，請輸入同步密碼，再按「儲存並開始同步」');
      setTimeout(() => $$('sy_pw').focus(), 300);
    }
  }
} catch (e) {}

document.addEventListener('visibilitychange', () => { if (!document.hidden) schedule(300) });
window.addEventListener('online', () => schedule(500));
setInterval(tick, 30000);
if (ok()) schedule(800);
window.catSync = { sync, mergeState, status: () => ({ stText, stCls, rev }) };
})();
