'use strict';
/*
 * الاشتراكات والمدفوعات وبوابة المستخدم ولوحة المطوّر.
 * بيتربط بـ api/index.js عن طريق create({...}).
 */
const crypto = require('crypto');
const client = require('./client');

const DAY = 86400000;
const env = process.env;
const PLAN_KEYS = ['monthly', 'semi', 'yearly'];
const MANUAL = ['instapay', 'vodafone', 'bank'];
const PM = 'https://accept.paymob.com/api';

const num = (v, f) => (v !== undefined && v !== '' && isFinite(Number(v)) ? Number(v) : f);
const str = (v, n = 200) => String(v == null ? '' : v).trim().slice(0, n);
const clamp = (v, lo, hi, f) => { v = Number(v); return isFinite(v) ? Math.min(hi, Math.max(lo, v)) : f; };
const nowIso = () => new Date().toISOString();
const bearer = req => String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
const clientIp = req => String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
const sha = t => crypto.createHash('sha256').update(String(t)).digest('hex');
const safeEq = (a, b) => {
    const x = Buffer.from(String(a)), y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
};
/* مقارنة الإصدارات (1.10.0 > 1.9.0). بترجع -1/0/1 أو NaN لو الصيغة غير صالحة */
const VER_RE = /^\d+(\.\d+){1,3}$/;
const verCmp = (a, b) => {
    a = String(a || '').trim(); b = String(b || '').trim();
    if (!VER_RE.test(a) || !VER_RE.test(b)) return NaN;
    const x = a.split('.').map(Number), y = b.split('.').map(Number);
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
        const d = (x[i] || 0) - (y[i] || 0);
        if (d) return d < 0 ? -1 : 1;
    }
    return 0;
};
const validMs = iso => { const t = new Date(iso).getTime(); return isFinite(t) ? t : 0; };
const addMonths = (ms, m) => {
    const d = new Date(ms), day = d.getUTCDate();
    d.setUTCDate(1); d.setUTCMonth(d.getUTCMonth() + m);
    const last = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
    d.setUTCDate(Math.min(day, last));
    return d.getTime();
};
const cardReady = () => !!(env.PAYMOB_API_KEY && env.PAYMOB_INTEGRATION_ID && env.PAYMOB_IFRAME_ID && env.PAYMOB_HMAC);

const HMAC_FIELDS = ['amount_cents', 'created_at', 'currency', 'error_occured', 'has_parent_transaction', 'id', 'integration_id',
    'is_3d_secure', 'is_auto_captured', 'is_capture', 'is_refunded', 'is_standalone_payment', 'is_voided', 'order.id', 'owner',
    'pending', 'source_data.pan', 'source_data.sub_type', 'source_data.type', 'success'];
const getPath = (o, p) => p.split('.').reduce((a, k) => (a == null ? a : a[k]), o);

function create(d) {
    const { redis, sendJson, sendHtml, readJson, hashPassword, esc, shell, rateLimit, normalizePhone, sendWhatsApp, waEnabled } = d;

    const redirect = (res, url) => { res.statusCode = 302; res.setHeader('Location', url); res.end(); };
    const page = (title, cfg, fn) => shell(title, `<style>${client.CSS}</style><div id="app"></div>`, client.build(cfg, fn));

    /* ---------------- الإعدادات ---------------- */
    let _cache = null, _at = 0;
    const defaults = () => ({
        company_name: env.COMPANY_NAME || 'ميزان',
        whatsapp: String(env.PAY_WHATSAPP || '').replace(/\D/g, ''),
        currency: env.SUB_CURRENCY || 'جنيه',
        trial_days: num(env.TRIAL_DAYS, 14),
        grace_days: num(env.GRACE_DAYS, 0),
        plans: {
            monthly: { label: 'شهري', months: 1, price: num(env.PRICE_MONTHLY, 300), enabled: true },
            semi: { label: 'نصف سنوي', months: 6, price: num(env.PRICE_SEMI, 1600), enabled: true },
            yearly: { label: 'سنوي', months: 12, price: num(env.PRICE_YEARLY, 3000), enabled: true }
        },
        methods: {
            instapay: { label: 'إنستا باي', enabled: !!env.PAY_INSTAPAY, details: env.PAY_INSTAPAY || '' },
            vodafone: { label: 'فودافون كاش', enabled: !!env.PAY_VODAFONE, details: env.PAY_VODAFONE || '' },
            bank: { label: 'تحويل بنكي', enabled: !!env.PAY_BANK, details: env.PAY_BANK || '' },
            card: { label: 'فيزا / ماستر كارد', enabled: true }
        }
    });
    async function getSettings(force) {
        if (!force && _cache && Date.now() - _at < 15000) return _cache;
        const def = defaults(), st = (await redis.get('config:settings')) || {};
        const s = { ...def };
        ['company_name', 'whatsapp', 'currency', 'trial_days', 'grace_days'].forEach(k => { if (st[k] !== undefined) s[k] = st[k]; });
        s.plans = {}; PLAN_KEYS.forEach(k => { s.plans[k] = { ...def.plans[k], ...((st.plans || {})[k] || {}) }; });
        s.methods = {}; [...MANUAL, 'card'].forEach(k => { s.methods[k] = { ...def.methods[k], ...((st.methods || {})[k] || {}) }; });
        s.methods.card.pref = s.methods.card.enabled;
        s.methods.card.enabled = !!s.methods.card.pref && cardReady();
        _cache = s; _at = Date.now();
        return s;
    }
    async function saveSettings(input) {
        const st = (await redis.get('config:settings')) || {};
        const i = input || {};
        if (i.company_name !== undefined) st.company_name = str(i.company_name, 60) || 'ميزان';
        if (i.whatsapp !== undefined) st.whatsapp = String(i.whatsapp).replace(/\D/g, '').slice(0, 15);
        if (i.currency !== undefined) st.currency = str(i.currency, 12) || 'جنيه';
        if (i.trial_days !== undefined) st.trial_days = clamp(i.trial_days, 0, 365, 14);
        if (i.grace_days !== undefined) st.grace_days = clamp(i.grace_days, 0, 90, 0);
        st.plans = st.plans || {}; st.methods = st.methods || {};
        PLAN_KEYS.forEach(k => {
            const p = (i.plans || {})[k]; if (!p) return;
            st.plans[k] = { enabled: !!p.enabled, label: str(p.label, 30) || k, months: Math.round(clamp(p.months, 1, 36, 1)), price: clamp(p.price, 0, 10000000, 0) };
        });
        MANUAL.forEach(k => {
            const m = (i.methods || {})[k]; if (!m) return;
            st.methods[k] = { enabled: !!m.enabled, details: str(m.details, 500) };
        });
        if ((i.methods || {}).card) st.methods.card = { enabled: !!i.methods.card.enabled };
        if (!PLAN_KEYS.some(k => ((st.plans[k] || defaults().plans[k]).enabled))) throw new Error('لازم باقة واحدة على الأقل تكون مفعّلة.');
        await redis.set('config:settings', st);
        return getSettings(true);
    }
    const publicCfg = S => {
        const plans = {}, methods = {};
        PLAN_KEYS.forEach(k => { const p = S.plans[k]; plans[k] = { label: p.label, months: p.months, price: p.price, enabled: !!p.enabled }; });
        [...MANUAL, 'card'].forEach(k => { const m = S.methods[k]; methods[k] = { label: m.label, enabled: !!m.enabled, details: MANUAL.includes(k) ? m.details : '' }; });
        return { company: S.company_name, whatsapp: S.whatsapp, currency: S.currency, plans, methods };
    };

    /* ---------------- سجل النشاط ---------------- */
    async function audit(actor, action, target, detail) {
        try { await redis.lpush('audit', { at: nowIso(), actor, action, target: target || '', detail: detail || '' }); await redis.ltrim('audit', 0, 499); } catch (e) { /* لا نوقف العملية */ }
    }

    /* ---------------- المستخدمون والاشتراكات ---------------- */
    const getUser = async u => (u ? redis.get(`user:${String(u).trim().toLowerCase()}`) : null);
    async function userByKey(key) {
        const owner = await redis.get(`keyidx:${key}`);
        return owner && owner !== 'desktop_client' ? getUser(owner) : null;
    }
    async function ensureSub(key, S) {
        let sub = await redis.get(`sub:${key}`);
        if (!sub) {
            sub = { status: 'active', trial: true, created_at: nowIso(), paid_until: new Date(Date.now() + S.trial_days * DAY).toISOString() };
            await redis.set(`sub:${key}`, sub, { nx: true });
        }
        return sub;
    }
    const daysLeft = sub => (sub && validMs(sub.paid_until) ? Math.ceil((validMs(sub.paid_until) - Date.now()) / DAY) : null);
    function stateOf(user, sub, S) {
        if (!user.verified) return 'pending';
        if (user.disabled) return 'disabled';
        if (sub && sub.status === 'locked') return 'locked';
        if (sub && validMs(sub.paid_until) + S.grace_days * DAY < Date.now()) return 'expired';
        if (!sub || sub.trial) return 'trial';
        return 'active';
    }
    async function extendSub(key, o) {
        const cur = (await redis.get(`sub:${key}`)) || {};
        let t;
        if (o.until != null) t = o.until;
        else {
            t = Math.max(Date.now(), validMs(cur.paid_until));
            if (o.months) t = addMonths(t, o.months);
            if (o.days) t += o.days * DAY;
        }
        const sub = { ...cur, ...(o.extra || {}), status: o.keepLock && cur.status === 'locked' ? 'locked' : 'active', trial: false, paid_until: new Date(t).toISOString() };
        await redis.set(`sub:${key}`, sub);
        return sub;
    }
    async function gateAgency(key) {
        if (!key) return { ok: true };
        const owner = await redis.get(`keyidx:${key}`);
        if (!owner) return { ok: true };
        if (owner !== 'desktop_client') {
            const u = await getUser(owner);
            if (u && u.disabled) return { ok: false, disabled: true };
        }
        const S = await getSettings();
        const sub = await ensureSub(key, S);
        const ok = sub.status !== 'locked' && Date.now() <= validMs(sub.paid_until) + S.grace_days * DAY;
        return { ok, sub };
    }
    const payRequired = (res, key) => sendJson(res, 402, {
        success: false, code: 'SUBSCRIPTION_REQUIRED',
        message: 'انتهى الاشتراك. برجاء التجديد لإعادة تشغيل الخدمة.',
        pay_url: `/pay?key=${encodeURIComponent(key)}`
    });

    async function deleteAccount(u) {
        await Promise.all([
            redis.del(`user:${u.username}`), redis.del(`email:${u.email}`), u.phone ? redis.del(`phone:${u.phone}`) : null,
            redis.del(`keyidx:${u.agency_key}`), redis.del(`agency:${u.agency_key}`), redis.del(`sub:${u.agency_key}`),
            redis.del(`orders_queue:${u.agency_key}`), redis.del(`otp:${u.username}`), redis.del(`reset:${u.username}`)
        ]);
    }
    async function mgetChunks(keys) {
        const out = [];
        for (let i = 0; i < keys.length; i += 100) out.push(...(await redis.mget(...keys.slice(i, i + 100))));
        return out;
    }
    async function userRows(S) {
        const keys = await redis.keys('user:*');
        if (!keys.length) return [];
        const users = (await mgetChunks(keys)).filter(Boolean);
        const subs = await mgetChunks(users.map(u => `sub:${u.agency_key}`));
        return users.map((u, i) => {
            const sub = subs[i];
            return { username: u.username, agency_name: u.agency_name, email: u.email, phone: u.phone || null, created_at: u.created_at, verified: !!u.verified,
                disabled: !!u.disabled, agency_key: u.agency_key, state: stateOf(u, sub, S), paid_until: sub ? sub.paid_until : null, days_left: daysLeft(sub),
                plan: sub ? sub.plan || (sub.trial ? 'trial' : null) : null, note: sub ? sub.note || '' : '', sub, _u: u };
        }).sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    }

    /* ---------------- الجلسات ---------------- */
    async function createSession(user) {
        const t = crypto.randomBytes(32).toString('hex');
        await redis.set(`sess:${sha(t)}`, { u: user.username, pv: user.pv || 0 }, { ex: 30 * 86400 });
        return t;
    }
    async function sessionUser(req) {
        const t = bearer(req);
        if (!/^[a-f0-9]{64}$/.test(t)) return null;
        const s = await redis.get(`sess:${sha(t)}`);
        if (!s) return null;
        const u = await getUser(s.u);
        return !u || (u.pv || 0) !== s.pv || u.disabled ? null : u;
    }

    /* ---------------- طلبات الدفع ---------------- */
    const getPay = async id => (id ? redis.get(`pay:${id}`) : null);
    const savePay = p => redis.set(`pay:${p.id}`, p);
    async function listPays(limit, key) {
        const ids = await redis.lrange(key ? `payidx:${key}` : 'payidx', 0, limit - 1);
        if (!ids || !ids.length) return [];
        return (await mgetChunks(ids.map(i => `pay:${i}`))).filter(Boolean);
    }
    async function newPay(user, S, planKey, method, extra) {
        const plan = S.plans[planKey];
        const id = 'P' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(2).toString('hex').toUpperCase();
        const pay = { id, agency_key: user.agency_key, username: user.username, agency_name: user.agency_name, plan: planKey, months: plan.months, amount: plan.price,
            currency: S.currency, method, status: 'pending', created_at: nowIso(), ...extra };
        await savePay(pay);
        await redis.lpush('payidx', id); await redis.ltrim('payidx', 0, 1999);
        await redis.lpush(`payidx:${user.agency_key}`, id); await redis.ltrim(`payidx:${user.agency_key}`, 0, 199);
        return pay;
    }
    async function approvePay(pay, actor, months) {
        if (pay.status === 'approved') return pay;
        const m = Math.round(clamp(months || pay.months, 1, 36, pay.months));
        await extendSub(pay.agency_key, { months: m, extra: { plan: pay.plan, last_payment: nowIso(), last_payment_id: pay.id } });
        Object.assign(pay, { status: 'approved', approved_at: nowIso(), decided_by: actor, months_applied: m });
        await savePay(pay);
        await audit(actor, 'pay_approve', pay.username, `${pay.id} ${pay.plan} ${pay.amount}`);
        return pay;
    }

    /* ---------------- Paymob (الدفع بالكارت داخل الموقع) ---------------- */
    async function pm(path, body) {
        const r = await fetch(PM + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(`Paymob ${path} ${r.status}: ${JSON.stringify(j).slice(0, 200)}`);
        return j;
    }
    async function paymobIframe(pay, user) {
        const cents = Math.round(pay.amount * 100);
        const auth = await pm('/auth/tokens', { api_key: env.PAYMOB_API_KEY });
        const order = await pm('/ecommerce/orders', { auth_token: auth.token, delivery_needed: false, amount_cents: cents, currency: 'EGP', merchant_order_id: pay.id, items: [] });
        const na = 'NA';
        const key = await pm('/acceptance/payment_keys', {
            auth_token: auth.token, amount_cents: cents, expiration: 3600, order_id: order.id, currency: 'EGP', integration_id: Number(env.PAYMOB_INTEGRATION_ID),
            billing_data: { apartment: na, email: user.email || 'na@na.com', floor: na, first_name: (user.agency_name || 'Customer').slice(0, 40), street: na, building: na,
                phone_number: user.phone ? '+' + user.phone : '+201000000000', shipping_method: na, postal_code: na, city: na, country: 'EG', last_name: 'Mizan', state: na }
        });
        return `${PM}/acceptance/iframes/${env.PAYMOB_IFRAME_ID}?payment_token=${key.token}`;
    }
    const paymobHmac = obj => crypto.createHmac('sha512', env.PAYMOB_HMAC || '').update(HMAC_FIELDS.map(f => { const v = getPath(obj, f); return v == null ? '' : String(v); }).join('')).digest('hex');

    /* ---------------- البريد ---------------- */
    async function sendMail(to, subject, html) {
        if (env.RESEND_API_KEY) {
            const r = await fetch('https://api.resend.com/emails', { method: 'POST',
                headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ from: env.MAIL_FROM || 'Mizan <onboarding@resend.dev>', to: [to], subject, html }) });
            if (!r.ok) throw new Error(`Resend ${r.status}`);
        } else if (env.SMTP_USER && env.SMTP_PASS) {
            const nodemailer = require('nodemailer');
            await nodemailer.createTransport({ service: 'gmail', auth: { user: env.SMTP_USER, pass: env.SMTP_PASS } })
                .sendMail({ from: env.MAIL_FROM || `"ميزان" <${env.SMTP_USER}>`, to, subject, html });
        } else throw new Error('no mail provider');
    }

    /* ---------------- التحديثات ---------------- */
    const getUpdateInfo = async () => (await redis.get('config:update')) || null;
    const relOf = v => redis.get(`update:rel:${v}`);
    const chItems = t => String(t || '').split(/\r?\n/).map(x => x.replace(/^[\s\-•*]+/, '').trim()).filter(Boolean);
    async function notifyBatch(S, version, limit) {
        const rows = (await userRows(S)).filter(r => ['active', 'trial'].includes(r.state) && r.email);
        const done = `updnotif:${version}`;
        const todo = [];
        for (const r of rows) if (!(await redis.sismember(done, r.username))) todo.push(r);
        const batch = todo.slice(0, limit), cur = (await getUpdateInfo()) || {};
        let sent = 0, failed = 0;
        for (let i = 0; i < batch.length; i += 5) {
            await Promise.all(batch.slice(i, i + 5).map(async r => {
                try {
                    const items = chItems(cur.changelog).map(x => `<li>${esc(x)}</li>`).join('');
                    await sendMail(r.email, `تحديث جديد لبرنامج ${S.company_name} - الإصدار ${version}`,
                        `<div dir="rtl" style="font-family:Tahoma,Arial;font-size:16px"><p>مرحباً ${esc(r.agency_name)}،</p>` +
                        `<p>تم إصدار نسخة جديدة من برنامج الديسك توب: <b>${esc(version)}</b>${cur.mandatory ? ' <b style="color:#b91c1c">(تحديث إجباري)</b>' : ''}.</p>` +
                        (items ? `<p>الجديد في هذا الإصدار:</p><ul>${items}</ul>` : '') +
                        `<p>هيظهر لك إشعار التحديث تلقائياً عند فتح البرنامج، أو حمّل النسخة الجديدة من هنا:</p>` +
                        (cur.download_url ? `<p><a href="${esc(cur.download_url)}" style="background:#5A0817;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">⬇️ تحميل الإصدار ${esc(version)}</a></p>` : '') +
                        `<p style="color:#666">بياناتك محفوظة ولا تتأثر بالتحديث.</p></div>`);
                    await redis.sadd(done, r.username); sent++;
                } catch (e) { failed++; console.error('update notify failed:', e.message); }
            }));
        }
        return { sent, failed, remaining: Math.max(0, todo.length - sent), total: rows.length, already: rows.length - todo.length };
    }

    /* ---------------- المطوّر ---------------- */
    async function adminOk(req, res) {
        const ip = clientIp(req);
        if ((Number(await redis.get(`rl:adminfail:${ip}`)) || 0) >= 20) { sendJson(res, 429, { success: false, message: 'محاولات كثيرة.' }); return false; }
        if (env.ADMIN_TOKEN && safeEq(bearer(req), env.ADMIN_TOKEN)) return true;
        await rateLimit(req, 'adminfail', 1000, 900);
        sendJson(res, 401, { success: false, message: 'unauthorized' });
        return false;
    }
    async function resolveUser(b) {
        if (b.username) return getUser(b.username);
        if (b.agency_key) return userByKey(String(b.agency_key).trim());
        return null;
    }
    const strip = u => { const { password_hash, salt, ...rest } = u; return rest; };

    /* =============================================================== */
    async function handle(req, res, pathname, query) {
        if (!/^\/(pay|account|admin|forgot)$|^\/api\/(pay\/|account\/|admin\/|forgot|reset|health|payment\/|cron\/)/.test(pathname)) return false;
        const m = req.method;
        const S = await getSettings();

        if (pathname === '/api/health') {
            let ok = true; try { await redis.get('health:probe'); } catch (e) { ok = false; }
            return sendJson(res, ok ? 200 : 503, { ok, time: nowIso() }), true;
        }

        /* ---------- صفحات ---------- */
        if (pathname === '/pay' && m === 'GET') {
            const key = String(query.key || '').trim();
            const g = await gateAgency(key);
            if (g.ok) return redirect(res, `/app?key=${encodeURIComponent(key)}`), true;
            if (g.disabled) return sendHtml(res, 403, shell('حساب معطّل | ميزان', `<div class="box" style="text-align:center"><h2>⛔ الحساب معطّل</h2><p style="color:#C8B8B5">تواصل مع الدعم${S.whatsapp ? ` على واتساب: <b>${esc(S.whatsapp)}</b>` : ''}.</p></div>`)), true;
            const user = await userByKey(key);
            return sendHtml(res, 402, page('تجديد الاشتراك | ميزان', { ...publicCfg(S), key, agency_name: user ? user.agency_name : '', locked: !!(g.sub && g.sub.status === 'locked') }, client.payPage)), true;
        }
        if (pathname === '/account' && m === 'GET') return sendHtml(res, 200, page('حسابي | ميزان', {}, client.accountPage)), true;
        if (pathname === '/forgot' && m === 'GET') return sendHtml(res, 200, page('استرجاع كلمة المرور | ميزان', {}, client.forgotPage)), true;
        if (pathname === '/admin' && m === 'GET') return sendHtml(res, 200, page('لوحة المطوّر | ميزان', {}, client.adminPage)), true;

        /* ---------- الدفع من داخل الموقع ---------- */
        if (pathname === '/api/pay/request' && m === 'POST') {
            if (!(await rateLimit(req, 'payreq', 10))) return sendJson(res, 429, { success: false, message: 'محاولات كثيرة، حاول لاحقاً.' }), true;
            const b = await readJson(req);
            const key = String(b.agency_key || '').trim();
            const user = /^[a-f0-9]{48}$/.test(key) ? await userByKey(key) : null;
            if (!user) return sendJson(res, 404, { success: false, message: 'الوكالة غير موجودة.' }), true;
            const plan = S.plans[b.plan];
            if (!plan || !plan.enabled) return sendJson(res, 400, { success: false, message: 'باقة غير صحيحة.' }), true;
            const method = String(b.method || '');
            if (!MANUAL.includes(method) || !S.methods[method].enabled) return sendJson(res, 400, { success: false, message: 'طريقة الدفع غير متاحة.' }), true;
            if ((await listPays(20, key)).filter(p => p.status === 'pending').length >= 3)
                return sendJson(res, 429, { success: false, message: 'عندك طلبات دفع قيد المراجعة بالفعل.' }), true;
            let receipt = null;
            if (b.receipt) {
                if (typeof b.receipt !== 'string' || !b.receipt.startsWith('data:image/jpeg;base64,') || b.receipt.length > 600000)
                    return sendJson(res, 400, { success: false, message: 'صورة الإيصال غير صالحة أو كبيرة.' }), true;
                receipt = b.receipt;
            }
            const pay = await newPay(user, S, b.plan, method, { payer: str(b.payer, 80), reference: str(b.reference, 60), note: str(b.note, 200), has_receipt: !!receipt });
            if (receipt) await redis.set(`rcpt:${pay.id}`, receipt, { ex: 180 * 86400 });
            await audit('user:' + user.username, 'pay_request', user.username, `${pay.id} ${b.plan} ${method}`);
            return sendJson(res, 200, { success: true, id: pay.id }), true;
        }

        if (pathname === '/api/pay/card' && m === 'POST') {
            if (!(await rateLimit(req, 'paycard', 10))) return sendJson(res, 429, { success: false, message: 'محاولات كثيرة، حاول لاحقاً.' }), true;
            const b = await readJson(req);
            const key = String(b.agency_key || '').trim();
            const user = /^[a-f0-9]{48}$/.test(key) ? await userByKey(key) : null;
            if (!user) return sendJson(res, 404, { success: false, message: 'الوكالة غير موجودة.' }), true;
            const plan = S.plans[b.plan];
            if (!plan || !plan.enabled) return sendJson(res, 400, { success: false, message: 'باقة غير صحيحة.' }), true;
            if (!S.methods.card.enabled) return sendJson(res, 400, { success: false, message: 'الدفع بالكارت غير متاح حالياً.' }), true;
            const pay = await newPay(user, S, b.plan, 'card', { provider: 'paymob' });
            try {
                const iframe_url = await paymobIframe(pay, user);
                return sendJson(res, 200, { success: true, id: pay.id, iframe_url }), true;
            } catch (e) {
                console.error(e.message);
                pay.status = 'failed'; pay.reason = 'تعذر الاتصال ببوابة الدفع'; await savePay(pay);
                return sendJson(res, 502, { success: false, message: 'تعذر بدء الدفع بالكارت الآن، جرّب طريقة أخرى.' }), true;
            }
        }

        if (pathname === '/api/pay/status' && m === 'GET') {
            const pay = await getPay(String(query.id || ''));
            if (!pay || pay.agency_key !== String(query.key || '')) return sendJson(res, 404, { success: false, message: 'غير موجود.' }), true;
            const sub = pay.status === 'approved' ? await redis.get(`sub:${pay.agency_key}`) : null;
            return sendJson(res, 200, { success: true, status_text: pay.status, reason: pay.reason || '', paid_until: sub ? sub.paid_until : null }), true;
        }

        if (pathname === '/api/pay/paymob-callback' && m === 'POST') {
            if (!cardReady()) return sendJson(res, 404, { success: false }), true;
            const b = await readJson(req);
            const obj = b.obj || b;
            const given = String(query.hmac || b.hmac || '');
            if (!given || !safeEq(paymobHmac(obj), given)) return sendJson(res, 401, { success: false, message: 'bad signature' }), true;
            const pay = await getPay(String(getPath(obj, 'order.merchant_order_id') || ''));
            if (pay && pay.status === 'pending') {
                const paid = obj.success === true && obj.pending !== true && !obj.is_refunded && !obj.is_voided && Number(obj.amount_cents) === Math.round(pay.amount * 100);
                if (paid) { pay.provider_txn = obj.id; await approvePay(pay, 'paymob'); }
                else if (obj.success === false && obj.pending === false) { pay.status = 'failed'; pay.reason = 'لم تتم عملية الدفع'; await savePay(pay); }
            }
            return sendJson(res, 200, { success: true }), true;
        }

        // Webhook عام (لأي بوابة تانية) بسر مشترك
        if (pathname === '/api/payment/webhook' && m === 'POST') {
            if (!env.PAY_WEBHOOK_SECRET || !safeEq(req.headers['x-webhook-secret'] || '', env.PAY_WEBHOOK_SECRET))
                return sendJson(res, 401, { success: false, message: 'unauthorized' }), true;
            const b = await readJson(req);
            const u = await resolveUser(b);
            if (!u) return sendJson(res, 404, { success: false, message: 'الوكالة غير موجودة.' }), true;
            if (b.payment_id && !(await redis.set(`pay:ext:${b.payment_id}`, 1, { nx: true, ex: 90 * 86400 }))) return sendJson(res, 200, { success: true, duplicate: true }), true;
            const months = Math.round(clamp(b.months, 1, 36, 1));
            const sub = await extendSub(u.agency_key, { months, extra: { last_payment: nowIso(), last_payment_id: b.payment_id || null } });
            await audit('webhook', 'pay_webhook', u.username, `${months} شهر`);
            return sendJson(res, 200, { success: true, paid_until: sub.paid_until }), true;
        }

        /* ---------- حساب المستخدم ---------- */
        if (pathname.startsWith('/api/account/')) {
            const u = await sessionUser(req);
            if (!u) return sendJson(res, 401, { success: false, message: 'سجّل الدخول من جديد.' }), true;

            if (pathname === '/api/account/me' && m === 'GET') {
                const sub = await ensureSub(u.agency_key, S);
                const pays = (await listPays(50, u.agency_key)).map(p => ({ id: p.id, created_at: p.created_at, plan: p.plan, amount: p.amount, currency: p.currency, method: p.method, status: p.status }));
                const cycle = sub.plan && S.plans[sub.plan] ? S.plans[sub.plan].months * 30 : 30;
                return sendJson(res, 200, { success: true,
                    user: { username: u.username, agency_name: u.agency_name, email: u.email, phone: u.phone || '', agency_key: u.agency_key, created_at: u.created_at },
                    sub: { state: stateOf(u, sub, S), paid_until: sub.paid_until, days_left: daysLeft(sub), plan: sub.plan || null, cycle_days: cycle },
                    payments: pays, cfg: publicCfg(S) }), true;
            }
            if (pathname === '/api/account/logout' && m === 'POST') { await redis.del(`sess:${sha(bearer(req))}`); return sendJson(res, 200, { success: true }), true; }

            if (pathname === '/api/account/profile' && m === 'POST') {
                const b = await readJson(req);
                const name = str(b.agency_name, 60);
                if (name.length < 2) return sendJson(res, 400, { success: false, message: 'اسم الوكالة قصير.' }), true;
                const next = { ...u, agency_name: name };
                const raw = str(b.phone, 30);
                if (raw) {
                    const ph = normalizePhone(raw);
                    if (!ph) return sendJson(res, 400, { success: false, message: 'رقم الموبايل غير صحيح.' }), true;
                    if (ph !== u.phone) {
                        if (!(await redis.set(`phone:${ph}`, u.username, { nx: true }))) return sendJson(res, 409, { success: false, message: 'الرقم مستخدم في حساب آخر.' }), true;
                        if (u.phone) await redis.del(`phone:${u.phone}`);
                        next.phone = ph;
                    }
                } else if (u.phone && u.verify_channel !== 'whatsapp') { await redis.del(`phone:${u.phone}`); next.phone = null; }
                await redis.set(`user:${u.username}`, next);
                return sendJson(res, 200, { success: true }), true;
            }
            if (pathname === '/api/account/password' && m === 'POST') {
                if (!(await rateLimit(req, 'chpw', 10))) return sendJson(res, 429, { success: false, message: 'محاولات كثيرة.' }), true;
                const b = await readJson(req);
                if (String(b.new_password || '').length < 8) return sendJson(res, 400, { success: false, message: 'كلمة المرور الجديدة قصيرة (8 أحرف على الأقل).' }), true;
                if ((await hashPassword(String(b.old_password || ''), u.salt)) !== u.password_hash) return sendJson(res, 401, { success: false, message: 'كلمة المرور الحالية غير صحيحة.' }), true;
                const salt = crypto.randomBytes(16).toString('hex');
                await redis.set(`user:${u.username}`, { ...u, salt, password_hash: await hashPassword(String(b.new_password), salt), pv: (u.pv || 0) + 1 });
                return sendJson(res, 200, { success: true }), true;
            }
            if (pathname === '/api/account/delete' && m === 'POST') {
                const b = await readJson(req);
                if (String(b.confirm || '') !== u.username) return sendJson(res, 400, { success: false, message: 'اكتب اسم المستخدم للتأكيد.' }), true;
                if ((await hashPassword(String(b.password || ''), u.salt)) !== u.password_hash) return sendJson(res, 401, { success: false, message: 'كلمة المرور غير صحيحة.' }), true;
                await deleteAccount(u); await audit('user:' + u.username, 'account_delete', u.username);
                return sendJson(res, 200, { success: true }), true;
            }
            return sendJson(res, 404, { success: false }), true;
        }

        /* ---------- نسيت كلمة المرور ---------- */
        if (pathname === '/api/forgot' && m === 'POST') {
            if (!(await rateLimit(req, 'forgot', 5))) return sendJson(res, 429, { success: false, message: 'محاولات كثيرة، حاول لاحقاً.' }), true;
            const b = await readJson(req);
            const id = str(b.identity, 120).toLowerCase();
            const uname = id.includes('@') ? await redis.get(`email:${id}`) : id;
            const u = await getUser(uname);
            if (u && u.verified && !u.disabled && (await redis.set(`reset_cool:${u.username}`, 1, { nx: true, ex: 60 }))) {
                const code = String(crypto.randomInt(100000, 1000000));
                try {
                    if (u.verify_channel === 'whatsapp' && u.phone && waEnabled()) await sendWhatsApp(u.phone, code);
                    else await sendMail(u.email, 'كود استرجاع كلمة المرور - ميزان', `<div dir="rtl" style="font-family:Tahoma,Arial;font-size:16px"><p>كود استرجاع كلمة المرور:</p><p style="font-size:32px;letter-spacing:6px;font-weight:bold">${code}</p><p style="color:#666">صالح 10 دقائق. لو ماطلبتش ده تجاهل الرسالة.</p></div>`);
                    await redis.set(`reset:${u.username}`, { hash: crypto.createHmac('sha256', u.salt).update(code).digest('hex'), attempts: 0 }, { ex: 600 });
                } catch (e) { console.error('forgot send failed:', e.message); }
            }
            return sendJson(res, 200, { success: true, message: 'لو الحساب موجود هيوصلك كود على وسيلة التواصل المسجلة (صالح 10 دقائق).' }), true;
        }
        if (pathname === '/api/reset' && m === 'POST') {
            if (!(await rateLimit(req, 'reset', 10))) return sendJson(res, 429, { success: false, message: 'محاولات كثيرة.' }), true;
            const b = await readJson(req);
            const id = str(b.identity, 120).toLowerCase();
            const u = await getUser(id.includes('@') ? await redis.get(`email:${id}`) : id);
            const bad = { success: false, message: 'الكود غير صحيح أو منتهي.' };
            if (!u || String(b.password || '').length < 8) return sendJson(res, 400, u ? { success: false, message: 'كلمة المرور قصيرة (8 أحرف على الأقل).' } : bad), true;
            const r = await redis.get(`reset:${u.username}`);
            if (!r || r.attempts >= 5) return sendJson(res, 400, bad), true;
            const ok = safeEq(crypto.createHmac('sha256', u.salt).update(String(b.code || '')).digest('hex'), r.hash);
            if (!ok) { await redis.set(`reset:${u.username}`, { ...r, attempts: r.attempts + 1 }, { ex: 600 }); return sendJson(res, 400, bad), true; }
            const salt = crypto.randomBytes(16).toString('hex');
            await redis.set(`user:${u.username}`, { ...u, salt, password_hash: await hashPassword(String(b.password), salt), pv: (u.pv || 0) + 1 });
            await redis.del(`reset:${u.username}`);
            await audit('user:' + u.username, 'password_reset', u.username);
            return sendJson(res, 200, { success: true }), true;
        }

        /* ---------- تذكير الانتهاء (Vercel Cron) ---------- */
        if (pathname === '/api/cron/reminders') {
            const tok = bearer(req);
            const okCron = (env.CRON_SECRET && safeEq(tok, env.CRON_SECRET)) || (env.ADMIN_TOKEN && safeEq(tok, env.ADMIN_TOKEN));
            if (!okCron) return sendJson(res, 401, { success: false }), true;
            let sent = 0;
            for (const r of await userRows(S)) {
                if (!['active', 'trial'].includes(r.state) || r.days_left == null || r.days_left < 0 || r.days_left > 3 || !r.sub || r.sub.reminded_for === r.paid_until) continue;
                try {
                    await sendMail(r.email, `اشتراكك في ${S.company_name} ينتهي قريباً`, `<div dir="rtl" style="font-family:Tahoma,Arial;font-size:16px"><p>مرحباً ${esc(r.agency_name)}،</p><p>اشتراكك السحابي ينتهي بعد <b>${r.days_left}</b> يوم (${esc(String(r.paid_until).slice(0, 10))}).</p><p>للتجديد: ادخل على حسابك من صفحة الدخول ثم "الاشتراك والدفع".</p><p style="color:#666">برنامج الديسك توب مجاني ولا يتأثر.</p></div>`);
                    await redis.set(`sub:${r.agency_key}`, { ...r.sub, reminded_for: r.paid_until }); sent++;
                } catch (e) { console.error('reminder failed:', e.message); }
            }
            return sendJson(res, 200, { success: true, sent }), true;
        }

        /* ---------- API المطوّر ---------- */
        if (pathname.startsWith('/api/admin/')) {
            if (!(await adminOk(req, res))) return true;

            if (pathname === '/api/admin/overview' && m === 'GET') {
                const rows = await userRows(S), pays = await listPays(1000);
                const counts = { total: rows.length, active: 0, trial: 0, expired: 0, locked: 0, disabled: 0 };
                rows.forEach(r => { if (counts[r.state] !== undefined) counts[r.state]++; });
                const ym = nowIso().slice(0, 7);
                const ok = pays.filter(p => p.status === 'approved');
                return sendJson(res, 200, { success: true, counts, currency: S.currency, pending_payments: pays.filter(p => p.status === 'pending').length,
                    revenue_month: ok.filter(p => String(p.approved_at).startsWith(ym)).reduce((a, p) => a + p.amount, 0), revenue_total: ok.reduce((a, p) => a + p.amount, 0),
                    expiring: rows.filter(r => ['active', 'trial'].includes(r.state) && r.days_left != null && r.days_left >= 0 && r.days_left <= 7)
                        .sort((a, b) => a.days_left - b.days_left).map(r => ({ username: r.username, agency_name: r.agency_name, paid_until: r.paid_until, days_left: r.days_left })) }), true;
            }
            if (pathname === '/api/admin/list' && m === 'GET') {
                const rows = await userRows(S);
                return sendJson(res, 200, { success: true, users: rows.map(({ sub, _u, agency_key, ...r }) => r) }), true;
            }
            if (pathname === '/api/admin/user' && m === 'GET') {
                const u = await getUser(query.username);
                if (!u) return sendJson(res, 404, { success: false, message: 'غير موجود.' }), true;
                const sub = await redis.get(`sub:${u.agency_key}`);
                const ag = (await redis.get(`agency:${u.agency_key}`)) || {};
                const len = x => (Array.isArray(x) ? x.length : 0);
                return sendJson(res, 200, { success: true, user: strip(u), sub, state: stateOf(u, sub, S), days_left: daysLeft(sub), payments: await listPays(30, u.agency_key),
                    agency: { last_sync: ag.last_sync || null, customers: len(ag.customers), suppliers: len(ag.suppliers), items: len(ag.items), users: len(ag.users) } }), true;
            }

            if (pathname === '/api/admin/subscription' && m === 'POST') {
                const b = await readJson(req);
                const u = await resolveUser(b);
                if (!u) return sendJson(res, 404, { success: false, message: 'الحساب غير موجود.' }), true;
                const key = u.agency_key, a = String(b.action || '');
                let sub = await redis.get(`sub:${key}`), extra = {};
                if (a === 'extend') {
                    const days = Math.round(clamp(b.days, 0, 3650, 0)), months = Math.round(clamp(b.months, 0, 120, 0));
                    if (!days && !months) return sendJson(res, 400, { success: false, message: 'حدد مدة التمديد.' }), true;
                    sub = await extendSub(key, { days, months, keepLock: true, extra: { unlocked_by: 'admin' } });
                    await audit('admin', 'extend', u.username, `${months ? months + ' شهر ' : ''}${days ? days + ' يوم' : ''}`);
                } else if (a === 'set_until') {
                    const t = new Date(String(b.until) + 'T23:59:59Z').getTime();
                    if (!isFinite(t)) return sendJson(res, 400, { success: false, message: 'تاريخ غير صحيح.' }), true;
                    sub = await extendSub(key, { until: t, keepLock: true });
                    await audit('admin', 'set_until', u.username, String(b.until));
                } else if (a === 'expire') {
                    sub = { ...(sub || {}), trial: false, paid_until: new Date(Date.now() - 1000).toISOString() };
                    await redis.set(`sub:${key}`, sub); await audit('admin', 'expire', u.username);
                } else if (a === 'lock') {
                    sub = { ...(sub || {}), status: 'locked', locked_at: nowIso() };
                    await redis.set(`sub:${key}`, sub); await audit('admin', 'lock', u.username);
                } else if (a === 'unlock') {
                    const expired = !(validMs(sub && sub.paid_until) > Date.now());
                    sub = await extendSub(key, expired ? { days: Math.round(clamp(b.days, 1, 3650, 30)) } : {});
                    await audit('admin', 'unlock', u.username);
                } else if (a === 'disable' || a === 'enable') {
                    if (!u.verified) return sendJson(res, 400, { success: false, message: 'الحساب غير مفعّل.' }), true;
                    await redis.set(`user:${u.username}`, { ...u, disabled: a === 'disable' });
                    await audit('admin', a, u.username);
                } else if (a === 'note') {
                    sub = { ...(sub || {}), note: str(b.note, 500) }; await redis.set(`sub:${key}`, sub); await audit('admin', 'note', u.username);
                } else if (a === 'set_plan') {
                    if (!S.plans[b.plan]) return sendJson(res, 400, { success: false, message: 'باقة غير صحيحة.' }), true;
                    sub = { ...(sub || {}), plan: b.plan }; await redis.set(`sub:${key}`, sub); await audit('admin', 'set_plan', u.username, b.plan);
                } else if (a === 'reset_password') {
                    const temp = crypto.randomBytes(9).toString('base64').replace(/[^a-zA-Z0-9]/g, 'x').slice(0, 10);
                    const salt = crypto.randomBytes(16).toString('hex');
                    await redis.set(`user:${u.username}`, { ...u, salt, password_hash: await hashPassword(temp, salt), pv: (u.pv || 0) + 1 });
                    await audit('admin', 'reset_password', u.username); extra = { temp_password: temp };
                } else if (a === 'delete') {
                    await deleteAccount(u); await audit('admin', 'delete', u.username); extra = { deleted: true };
                } else return sendJson(res, 400, { success: false, message: 'إجراء غير معروف.' }), true;
                return sendJson(res, 200, { success: true, subscription: sub || null, ...extra }), true;
            }

            if (pathname === '/api/admin/payments' && m === 'GET') {
                const st = String(query.status || '');
                const rows = (await listPays(500)).filter(p => !st || p.status === st);
                return sendJson(res, 200, { success: true, payments: rows }), true;
            }
            if (pathname === '/api/admin/receipt' && m === 'GET') {
                const r = await redis.get(`rcpt:${String(query.id || '')}`);
                return r ? sendJson(res, 200, { success: true, receipt: r }) : sendJson(res, 404, { success: false, message: 'لا يوجد إيصال.' }), true;
            }
            if (pathname === '/api/admin/payment' && m === 'POST') {
                const b = await readJson(req);
                const pay = await getPay(String(b.id || ''));
                if (!pay) return sendJson(res, 404, { success: false, message: 'الطلب غير موجود.' }), true;
                if (b.action === 'approve') { if (pay.status === 'rejected') pay.status = 'pending'; await approvePay(pay, 'admin', b.months); }
                else if (b.action === 'reject') {
                    if (pay.status === 'approved') return sendJson(res, 400, { success: false, message: 'الطلب معتمد بالفعل.' }), true;
                    Object.assign(pay, { status: 'rejected', reason: str(b.reason, 200), decided_by: 'admin', decided_at: nowIso() });
                    await savePay(pay); await audit('admin', 'pay_reject', pay.username, pay.id);
                } else return sendJson(res, 400, { success: false, message: 'إجراء غير معروف.' }), true;
                return sendJson(res, 200, { success: true }), true;
            }

            if (pathname === '/api/admin/settings') {
                if (m === 'GET') return sendJson(res, 200, { success: true, settings: S, card_ready: cardReady() }), true;
                if (m === 'POST') {
                    const b = await readJson(req);
                    try { await saveSettings(b.settings); } catch (e) { return sendJson(res, 400, { success: false, message: e.message }), true; }
                    await audit('admin', 'settings', '', '');
                    return sendJson(res, 200, { success: true }), true;
                }
            }
            /* ---------- التحديثات ---------- */
            if (pathname === '/api/admin/update' && m === 'GET') {
                const cur = await getUpdateInfo();
                const vers = (await redis.lrange('update:versions', 0, 49)) || [];
                const history = [];
                for (const v of vers) { const r = await relOf(v); if (r) history.push(r); }
                const notified = cur ? await redis.scard(`updnotif:${cur.version}`) : 0;
                return sendJson(res, 200, { success: true, current: cur, history, notified, blob_ready: !!env.BLOB_READ_WRITE_TOKEN, mail_ready: !!(env.RESEND_API_KEY || (env.SMTP_USER && env.SMTP_PASS)) }), true;
            }
            if (pathname === '/api/admin/update' && m === 'POST') {
                const b = await readJson(req), act = String(b.action || 'publish');
                const version = str(b.version, 20);
                if (!VER_RE.test(version)) return sendJson(res, 400, { success: false, message: 'رقم الإصدار غير صالح (مثال: 1.2.0).' }), true;
                if (act === 'activate' || act === 'delete') {
                    const rel = await relOf(version);
                    if (!rel) return sendJson(res, 404, { success: false, message: 'الإصدار غير موجود.' }), true;
                    const cur = await getUpdateInfo();
                    if (act === 'activate') { await redis.set('config:update', rel); await audit('admin', 'update_activate', '', version); }
                    else {
                        if (cur && cur.version === version) return sendJson(res, 400, { success: false, message: 'مينفعش تحذف الإصدار المنشور حالياً.' }), true;
                        await redis.del(`update:rel:${version}`); await redis.lrem('update:versions', 0, version); await audit('admin', 'update_delete', '', version);
                    }
                    return sendJson(res, 200, { success: true }), true;
                }
                const url = str(b.download_url, 600);
                if (!/^https:\/\/[^\s"'<>]+$/i.test(url)) return sendJson(res, 400, { success: false, message: 'رابط التحميل لازم يبدأ بـ https://' }), true;
                const minv = str(b.min_version, 20);
                if (minv && !VER_RE.test(minv)) return sendJson(res, 400, { success: false, message: 'أقل إصدار مسموح غير صالح.' }), true;
                const sha = str(b.sha256, 64).toLowerCase();
                if (sha && !/^[a-f0-9]{64}$/.test(sha)) return sendJson(res, 400, { success: false, message: 'بصمة SHA-256 غير صالحة.' }), true;
                const prev = await getUpdateInfo();
                if (prev && verCmp(version, prev.version) < 0 && !b.allow_downgrade)
                    return sendJson(res, 409, { success: false, need_confirm: true, message: `الإصدار ${version} أقدم من المنشور حالياً (${prev.version}).` }), true;
                const rel = { version, download_url: url, changelog: str(b.changelog, 4000), mandatory: !!b.mandatory, min_version: minv, sha256: sha,
                    size: num(b.size, 0), file_name: str(b.file_name, 200), published_at: nowIso() };
                await redis.set(`update:rel:${version}`, rel);
                await redis.lrem('update:versions', 0, version);
                await redis.lpush('update:versions', version);
                await redis.set('config:update', rel);
                await audit('admin', 'update_publish', '', version);
                return sendJson(res, 200, { success: true, release: rel }), true;
            }
            if (pathname === '/api/admin/update/notify' && m === 'POST') {
                const b = await readJson(req), cur = await getUpdateInfo();
                if (!cur || cur.version !== str(b.version, 20)) return sendJson(res, 400, { success: false, message: 'الإشعار بيتبعت للإصدار المنشور حالياً بس.' }), true;
                if (!(env.RESEND_API_KEY || (env.SMTP_USER && env.SMTP_PASS))) return sendJson(res, 501, { success: false, message: 'خدمة البريد غير مفعّلة (RESEND_API_KEY أو SMTP_USER/SMTP_PASS).' }), true;
                if (b.reset) await redis.del(`updnotif:${cur.version}`);
                const r = await notifyBatch(S, cur.version, clamp(b.limit, 1, 40, 20));
                await audit('admin', 'update_notify', '', `${cur.version}: ${r.sent} ok / ${r.failed} fail`);
                return sendJson(res, 200, Object.assign({ success: true }, r)), true;
            }
            if (pathname === '/api/admin/update/upload' && m === 'POST') {
                if (!env.BLOB_READ_WRITE_TOKEN) return sendJson(res, 501, { success: false, message: 'رفع الملفات غير مفعّل: فعّل Vercel Blob (Storage) وأضف BLOB_READ_WRITE_TOKEN.' }), true;
                let handleUpload;
                try { ({ handleUpload } = require('@vercel/blob/client')); } catch (e) { return sendJson(res, 501, { success: false, message: 'مكتبة @vercel/blob غير مثبتة.' }), true; }
                try {
                    const out = await handleUpload({
                        body: await readJson(req), request: req,
                        onBeforeGenerateToken: async pathname2 => {
                            if (!/^updates\/[\w.\-]+\.(exe|msi|msix|zip|7z)$/i.test(pathname2)) throw new Error('امتداد/مسار الملف غير مسموح (exe, msi, msix, zip, 7z).');
                            return { maximumSizeInBytes: 500 * 1024 * 1024, addRandomSuffix: true };
                        }
                    });
                    return sendJson(res, 200, out), true;
                } catch (e) { return sendJson(res, 400, { success: false, message: e.message }), true; }
            }
            if (pathname === '/api/admin/audit' && m === 'GET') return sendJson(res, 200, { success: true, items: (await redis.lrange('audit', 0, 199)) || [] }), true;

            if (pathname === '/api/admin/export' && m === 'GET') {
                const rows = await userRows(S), subs = {};
                rows.forEach(r => { if (r.sub) subs[r.agency_key] = r.sub; });
                res.setHeader('Content-Disposition', 'attachment; filename="mizan-backup.json"');
                return sendJson(res, 200, { version: 1, exported_at: nowIso(), users: rows.map(r => r._u), subs, payments: await listPays(2000), settings: (await redis.get('config:settings')) || {} }), true;
            }
            if (pathname === '/api/admin/import' && m === 'POST') {
                const b = await readJson(req);
                if (!b || !Array.isArray(b.users)) return sendJson(res, 400, { success: false, message: 'ملف غير صالح.' }), true;
                let added = 0;
                for (const u of b.users) {
                    if (!u || !u.username || !u.agency_key) continue;
                    if (await redis.set(`user:${u.username}`, u, { nx: true })) {
                        added++;
                        await redis.set(`email:${u.email}`, u.username, { nx: true });
                        if (u.phone) await redis.set(`phone:${u.phone}`, u.username, { nx: true });
                        await redis.set(`keyidx:${u.agency_key}`, u.username, { nx: true });
                    }
                }
                for (const k of Object.keys(b.subs || {})) if (await redis.set(`sub:${k}`, b.subs[k], { nx: true })) added++;
                for (const p of [...(b.payments || [])].reverse()) {
                    if (p && p.id && (await redis.set(`pay:${p.id}`, p, { nx: true }))) { added++; await redis.lpush('payidx', p.id); await redis.lpush(`payidx:${p.agency_key}`, p.id); }
                }
                if (b.settings && !(await redis.get('config:settings'))) await redis.set('config:settings', b.settings);
                await audit('admin', 'import', '', `${added} سجل`);
                return sendJson(res, 200, { success: true, added }), true;
            }
            return sendJson(res, 404, { success: false, message: 'غير موجود.' }), true;
        }

        return false;
    }

    return { handle, gateAgency, payRequired, redirect, createSession, getSettings, getUpdateInfo, verCmp };
}

module.exports = { create };
