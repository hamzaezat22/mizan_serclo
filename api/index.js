const { Redis } = require('@upstash/redis');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN
});

const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));


// ===== جلسات الويب الموقّعة + صلاحيات + مساعدات =====
const SESSION_SECRET = process.env.SESSION_SECRET || process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN || 'mizan-local-secret';
const b64u = v => Buffer.from(v).toString('base64url');
const PRIV_RE = /(admin|owner|manager|مدير|صاحب|مالك)/i;
const isPrivileged = (role, title) => PRIV_RE.test(`${role || ''} ${title || ''}`);
function signSession(payload) {
    const body = b64u(JSON.stringify(payload));
    const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
    return `${body}.${sig}`;
}
function verifySession(token, agencyKey) {
    try {
        const [body, sig] = String(token || '').split('.');
        if (!body || !sig) return null;
        const good = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
        const a = Buffer.from(sig), c = Buffer.from(good);
        if (a.length !== c.length || !crypto.timingSafeEqual(a, c)) return null;
        const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
        if (!p || p.k !== agencyKey || !p.exp || p.exp < Date.now()) return null;
        return p;
    } catch { return null; }
}
// الصلاحيات الدقيقة: null = لم تُزامَن من الديسكتوب (السلوك القديم)، "" = بلا صلاحيات، "ALL" = كل شيء (صراحةً فقط)
const normPerms = v => {
    if (v == null) return null;
    if (Array.isArray(v)) return v.map(x => String(x).trim()).filter(Boolean).join(',');
    return String(v).trim();
};
const ACTION_PERM = {
    SALE_INVOICE: 'POS_SaveInvoice', EDIT_INVOICE: 'Sales_EditInvoice', DELETE_INVOICE: 'Sales_DeleteInvoice',
    COLLECTION: 'Collections_Add', DELETE_COLLECTION: 'Collections_Delete',
    EXPENSE: 'Expenses_Add', DELETE_EXPENSE: 'Expenses_Delete',
    SETTLE_VEHICLE: 'Vehicles_Settle', LOAD_SUPPLY: 'Vehicles_Add'
};
function checkGranularPermission(session, actionType) {
    const legacy = !PRIV_ACTIONS.has(actionType);            // بدون جلسة / بدون صلاحيات مزامَنة: المدير فقط للعمليات الحساسة
    if (!session) return legacy;
    if (session.p || session.r === 'admin') return true;
    if (session.perms == null) return legacy;
    if (session.perms === 'ALL') return true;
    const req = ACTION_PERM[actionType];
    if (!req) return legacy;                                  // ADD_CUSTOMER / ADD_SUPPLIER ... تبقى للمدير
    return session.perms.split(',').map(x => x.trim()).includes(req);
}
const makeToken = (agencyKey, u) => signSession({
    k: agencyKey, u: u.username, n: u.full_name, r: u.role,
    p: isPrivileged(u.role, u.job_title), perms: normPerms(u.perms), exp: Date.now() + 1000 * 60 * 60 * 24 * 30
});
const cairoToday = () => new Date().toLocaleDateString('en-CA', { timeZone: 'Africa/Cairo' });
const numOr0 = v => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const PRIV_ACTIONS = new Set(['DELETE_INVOICE', 'DELETE_COLLECTION', 'DELETE_EXPENSE', 'EDIT_INVOICE', 'SETTLE_VEHICLE', 'ADD_CUSTOMER', 'ADD_SUPPLIER']);

function saleLines(invNo, dateStr, data, items, orderId, author, extra) {
    return items.map((it, idx) => Object.assign({
        ActionType: 'SALE_INVOICE',
        OrderId: orderId,
        InvoiceNo: invNo,
        Date: dateStr,
        Customer: data.Customer || 'عميل نقدي',
        Item: it.Item,
        Supplier: it.Supplier || 'عام',
        LoadKey: it.LoadKey || data.LoadKey || '',
        Salesman: data.Salesman || 'عام',
        Grade: it.Grade || 'فرز أول ممتاز',
        CrateType: it.CrateType || 'برنيكة بلاستيك',
        Qty: numOr0(it.Qty),
        Weight: numOr0(it.Weight),
        Price: numOr0(it.Price),
        Discount: numOr0(it.Discount),
        Value: numOr0(it.Value),
        PaidAmount: idx === 0 ? numOr0(data.PaidAmount) : 0,
        RemainingAmount: idx === 0 ? numOr0(data.RemainingAmount) : 0,
        PaymentMethod: data.PaymentMethod || 'نقدي (كاش)',
        CreatedBy: author
    }, extra || {}));
}

function summarizeAction(t, d) {
    const n = v => numOr0(v).toLocaleString('en-US');
    switch (t) {
        case 'SALE_INVOICE': return `فاتورة بيع للعميل ${d.Customer || ''} بقيمة ${n((d.Items || []).reduce((a, i) => a + numOr0(i.Value), 0))} ج`;
        case 'EDIT_INVOICE': return `تعديل الفاتورة ${d.InvoiceNo || ''} (العميل ${d.Customer || ''})`;
        case 'DELETE_INVOICE': return `حذف الفاتورة ${d.InvoiceNo || ''}`;
        case 'COLLECTION': return `سند تحصيل من ${d.Customer || ''} بمبلغ ${n(d.Amount)} ج`;
        case 'DELETE_COLLECTION': return `حذف سند التحصيل ${d.ReceiptNo || ''}`;
        case 'EXPENSE': return `مصروف ${d.Category || ''} بمبلغ ${n(d.Amount)} ج`;
        case 'DELETE_EXPENSE': return `حذف مصروف رقم ${d.Id || ''}`;
        case 'PURCHASE': return `فاتورة مشتريات من ${d.Supplier || ''} بقيمة ${n(d.Value)} ج`;
        case 'LOAD_SUPPLY': return `توريد سيارة ${d.Vehicle || ''} للمورد ${d.Supplier || ''}`;
        case 'SETTLE_VEHICLE': return `تصفية سيارة ${d.Vehicle || ''} للمورد ${d.Supplier || ''} - صافي المورد ${n(d.NetDue)} ج`;
        case 'ADD_CUSTOMER': return `إضافة عميل ${d.Name || ''}`;
        case 'ADD_SUPPLIER': return `إضافة مورد ${d.Name || ''}`;
        case 'CRATE_DELIVERY': return `تسليم برانيك إلى ${d.Customer || ''} (${n(d.Qty)})`;
        case 'CRATE_RETURN': return `استرجاع برانيك من ${d.Customer || ''} (${n(d.Qty)})`;
        case 'WEIGHBRIDGE_TICKET': return `كارتة ميزان للسيارة ${d.Vehicle || ''}`;
        default: return t;
    }
}

const versionInfo = {
    latest_version: "1.0.0",
    download_url: "https://example.com/downloads/Mizan_Agency_Update.exe",
    changelog: "المنظومة السحابية الموحدة المتوافقة 100% مع أجهزة الكمبيوتر وموازين الأسواق"
};

const sendJson = (res, status, obj) => {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    return res.end(JSON.stringify(obj));
};

const sendHtml = (res, status, body) => {
    res.statusCode = status;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.end(body);
};

async function readJson(req) {
    if (req.body) {
        return typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }
    let s = '';
    for await (const chunk of req) {
        s += chunk;
        if (s.length > 25_000_000) throw new Error('حجم البيانات كبير جداً');
    }
    return JSON.parse(s || '{}');
}

const hashPassword = (password, salt) => new Promise((resolve, reject) =>
    crypto.scrypt(password, salt, 64, (e, k) => (e ? reject(e) : resolve(k.toString('hex')))));

function verifyDesktopPassword(password, storedHash) {
    if (!storedHash || !password) return false;
    if (!storedHash.includes(':')) {
        const hash = crypto.createHash('sha256').update(password, 'utf8').digest('base64');
        return hash === storedHash;
    }
    const [saltB64, hashB64] = storedHash.split(':');
    try {
        const salt = Buffer.from(saltB64, 'base64');
        const calculated = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('base64');
        return calculated === hashB64;
    } catch {
        return false;
    }
}

async function rateLimit(req, name, limit = 30, windowSec = 900) {
    const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
    const k = `rl:${name}:${ip}`;
    const n = await redis.incr(k);
    if (n === 1) await redis.expire(k, windowSec);
    return n <= limit;
}

const DEFAULT_CC = process.env.DEFAULT_COUNTRY_CODE || '20';
const OTP_TTL = 600;
const UNVERIFIED_TTL = 86400;

const emailEnabled = () => !!(process.env.RESEND_API_KEY || (process.env.SMTP_USER && process.env.SMTP_PASS));
const waEnabled = () => !!(process.env.WA_TOKEN && process.env.WA_PHONE_ID && process.env.WA_TEMPLATE);

function normalizePhone(raw) {
    let d = String(raw || '')
        .replace(/[\u0660-\u0669]/g, c => String(c.charCodeAt(0) - 0x660))
        .replace(/[^\d]/g, '');
    if (d.startsWith('00')) d = d.slice(2);
    else if (d.startsWith('0')) d = DEFAULT_CC + d.slice(1);
    return /^\d{8,15}$/.test(d) ? d : null;
}

const maskEmail = e => { const [n, d] = String(e).split('@'); return n.slice(0, 2) + '***@' + d; };
const maskPhone = p => '+' + String(p).slice(0, 2) + '*****' + String(p).slice(-3);
const maskFor = u => (u.verify_channel === 'whatsapp' ? maskPhone(u.phone) : maskEmail(u.email));
const otpHash = (salt, code) => crypto.createHmac('sha256', salt).update(String(code)).digest('hex');

async function sendEmail(to, agencyName, code) {
    const subject = 'كود التحقق من حسابك في ميزان';
    const text = `كود التحقق الخاص بك: ${code}\nصالح لمدة 10 دقائق.`;
    const html = `<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;font-size:16px">
        <p>مرحباً، لتفعيل حساب وكالة <b>${esc(agencyName)}</b> في ميزان استخدم الكود التالي:</p>
        <p style="font-size:32px;letter-spacing:6px;font-weight:bold">${code}</p>
        <p style="color:#666">صالح لمدة 10 دقائق.</p></div>`;

    if (process.env.RESEND_API_KEY) {
        const r = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ from: process.env.MAIL_FROM || 'Mizan <onboarding@resend.dev>', to: [to], subject, html, text })
        });
        if (!r.ok) throw new Error(`Resend ${r.status}: ${await r.text()}`);
        return;
    }
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
    await transporter.sendMail({
        from: process.env.MAIL_FROM || `"ميزان" <${process.env.SMTP_USER}>`,
        to, subject, text, html
    });
}

async function sendWhatsApp(phone, code) {
    const ver = process.env.WA_API_VERSION || 'v23.0';
    const r = await fetch(`https://graph.facebook.com/${ver}/${process.env.WA_PHONE_ID}/messages`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${process.env.WA_TOKEN}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
            messaging_product: 'whatsapp',
            to: phone,
            type: 'template',
            template: {
                name: process.env.WA_TEMPLATE,
                language: { code: process.env.WA_LANG || 'ar' },
                components: [
                    { type: 'body', parameters: [{ type: 'text', text: code }] },
                    { type: 'button', sub_type: 'url', index: '0', parameters: [{ type: 'text', text: code }] }
                ]
            }
        })
    });
    if (!r.ok) throw new Error(`WhatsApp ${r.status}: ${await r.text()}`);
}

async function issueCode(user) {
    const code = String(crypto.randomInt(100000, 1000000));
    if (user.verify_channel === 'whatsapp') await sendWhatsApp(user.phone, code);
    else await sendEmail(user.email, user.agency_name, code);
    await redis.set(`otp:${user.username}`, {
        hash: otpHash(user.salt, code),
        attempts: 0,
        expires: Date.now() + OTP_TTL * 1000
    }, { ex: OTP_TTL });
}

async function dropAccount(user) {
    await redis.del(`user:${user.username}`);
    await redis.del(`email:${user.email}`);
    if (user.phone) await redis.del(`phone:${user.phone}`);
    await redis.del(`otp:${user.username}`);
}

const originOf = req => `https://${req.headers['x-forwarded-host'] || req.headers.host}`;

const STYLE = `
@import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=Aref+Ruqaa:wght@700&display=swap');
body { font-family: 'Cairo', -apple-system, Tahoma, sans-serif; background: #200308; color: #FAF4F1; padding: 12px; text-align: center; margin: 0; }
.box { background: #2A040B; border: 1.5px solid #D4AF37; border-radius: 14px; max-width: 480px; margin: 25px auto; padding: 25px; text-align: right; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
h2 { color: #D4AF37; text-align: center; margin-top: 0; }
label { font-size: 13px; color: #C8B8B5; display: block; margin-top: 10px; font-weight: bold; }
input, select, textarea { width: 100%; box-sizing: border-box; padding: 10px; margin-top: 4px; border-radius: 6px; border: 1.2px solid #D4AF37; font-size: 14px; background: #FAF4F1; color: #1E1E1E; font-family: inherit; font-weight: 600; }
button, .btn { width: 100%; box-sizing: border-box; background: #5A0817; color: white; border: 1.2px solid #D4AF37; padding: 11px; border-radius: 8px; font-weight: bold; font-size: 14.5px; cursor: pointer; margin-top: 14px; text-decoration: none; display: block; text-align: center; font-family: inherit; }
button:hover, .btn:hover { background: #7A0B20; }
.small { background: #2A040B; color: #D4AF37; padding: 8px; font-size: 13px; margin-top: 6px; }
.msg { color: #ff8a8a; font-size: 13.5px; margin-top: 10px; min-height: 18px; text-align: center; font-weight: bold; }
`;

const shell = (title, body, script = '') => `<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)}</title>
<style>${STYLE}</style>
</head>
<body>${body}${script ? `<script>${script}</script>` : ''}</body>
</html>`;


// ================= الاشتراكات والمدفوعات (lib/billing.js) =================
const billing = require('../lib/billing').create({
    redis, sendJson, sendHtml, readJson, hashPassword, esc, shell, rateLimit, normalizePhone, sendWhatsApp, waEnabled
});
const { gateAgency, payRequired, redirect } = billing;

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-key, Authorization');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');

    if (req.method === 'OPTIONS') {
        res.statusCode = 200;
        return res.end();
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;
    const query = Object.fromEntries(parsedUrl.searchParams);

    try {
        if (await billing.handle(req, res, pathname, query)) return;

        if (pathname === '/' || pathname === '') {
            return sendHtml(res, 200, shell('خادم ميزان السحابي', `
                <div class="box" style="text-align:center">
                    <h2>🚀 خادم ميزان السحابي الموحد</h2>
                    <p style="color:#C8B8B5;">إدارة ومتابعة ومزامنة كافة عمليات الوكالة لحظة بلحظة مع أجهزة الكمبيوتر والموازين.</p>
                    <a class="btn" href="/login">🔑 تسجيل الدخول السحابي</a>
                    <a class="btn small" href="/register">📝 إنشاء حساب وكالة جديد</a>
                </div>`));
        }

        // مسار استعراض الفاتورة الإلكترونية عبر مسح كود الـ QR
        if (pathname === '/invoice' || pathname === '/api/invoice') {
            const invNo = String(query.id || query.inv || '').trim();
            const key = String(query.key || '').trim();

            let targetAgencyData = null;
            if (key) {
                targetAgencyData = await redis.get(`agency:${key}`);
            } else {
                // البحث في الوكالات النشطة عن رقم الفاتورة
                const keys = await redis.keys('agency:*');
                for (const k of keys.slice(0, 20)) {
                    const d = await redis.get(k);
                    if (d && Array.isArray(d.recent_sales) && d.recent_sales.some(s => String(s.InvoiceNo || s.invoiceNo) === invNo)) {
                        targetAgencyData = d;
                        break;
                    }
                }
            }

            const sales = targetAgencyData && Array.isArray(targetAgencyData.recent_sales)
                ? targetAgencyData.recent_sales.filter(s => String(s.InvoiceNo || s.invoiceNo) === invNo)
                : [];

            if (!sales || sales.length === 0) {
                return sendHtml(res, 404, shell('فاتورة غير موجودة', `
                    <div class="box" style="text-align:center;">
                        <h2>⚠️ لم يتم العثور على الفاتورة</h2>
                        <p style="color:#C8B8B5;">رقم الفاتورة المطلوبة [${esc(invNo)}] غير مسجل في السيرفر السحابي أو تم أرشفته.</p>
                    </div>`));
            }

            const first = sales[0];
            const totalVal = sales.reduce((acc, x) => acc + Number(x.Value || x.value || 0), 0);
            const paidVal = Number(first.PaidAmount || first.paidAmount || 0);
            const remVal = Math.max(0, totalVal - paidVal);

            return sendHtml(res, 200, `<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
<meta charset="UTF-8"><title>فاتورة إلكترونية معتمدة #${esc(invNo)}</title>
<style>
body { font-family: Tahoma, Cairo, sans-serif; background: #FAF4F1; padding: 20px; color: #1E1E1E; direction: rtl; }
.card { background: #FFF; max-width: 480px; margin: auto; padding: 24px; border-radius: 12px; border: 1.5px solid #5A0817; box-shadow: 0 8px 24px rgba(0,0,0,0.1); }
h2 { color: #5A0817; text-align: center; margin-top: 0; }
table { width: 100%; border-collapse: collapse; margin-top: 15px; }
th, td { padding: 8px; border-bottom: 1px solid #DDD; text-align: right; font-size: 13px; }
th { background: #5A0817; color: white; }
.tot { font-size: 17px; font-weight: bold; color: #0D7857; margin-top: 12px; text-align: left; }
</style>
</head>
<body>
<div class="card">
    <h2>🏢 ${esc(targetAgencyData.agency_name || "وكالة ميزان")}</h2>
    <div style="text-align:center;font-weight:bold;color:#5A0817;">📄 فاتورة مبيعات إلكترونية معتمدة #${esc(invNo)}</div>
    <div style="font-size:12px;color:#666;text-align:center;margin-bottom:10px;">التاريخ: ${esc(first.Date || first.date)} | العميل: <b>${esc(first.Customer || first.customer)}</b></div>
    <table>
        <thead><tr><th>الصنف</th><th>العدد</th><th>الوزن</th><th>السعر</th><th>الإجمالي</th></tr></thead>
        <tbody>
            ${sales.map(s => `<tr>
                <td><b>${esc(s.Item || s.item)}</b></td>
                <td>${Number(s.Qty || s.qty || 0).toLocaleString()} ق</td>
                <td>${Number(s.Weight || s.weight || 0).toLocaleString()} ك</td>
                <td>${Number(s.Price || s.price || 0).toLocaleString()} ج</td>
                <td>${Number(s.Value || s.value || 0).toLocaleString()} ج</td>
            </tr>`).join('')}
        </tbody>
    </table>
    <div class="tot">المجموع الكلي: ${totalVal.toLocaleString()} جنيه</div>
    <div style="margin-top:6px;font-size:13px;display:flex;justify-content:space-between;">
        <span>المدفوع: ${paidVal.toLocaleString()} ج</span>
        <span style="color:#DC2626;font-weight:bold;">المتبقي: ${remVal.toLocaleString()} ج</span>
    </div>
    <div style="margin-top:15px;text-align:center;font-size:11px;color:#888;border-top:1px dashed #CCC;padding-top:10px;">
        ⚖️ منظومة ميزان السحابية لإدارة ومحاسبة الوكالات والأسواق
    </div>
</div>
</body></html>`);
        }

        if (pathname === '/register' && req.method === 'GET') {
            const needCode = !!process.env.REGISTER_CODE;
            const em = emailEnabled(), wa = waEnabled();
            return sendHtml(res, 200, shell('إنشاء حساب وكالة جديد | ميزان', `
                <div class="box">
                    <h2>📝 إنشاء حساب وكالة جديد</h2>
                    <form id="f" autocomplete="off">
                        <label>البريد الإلكتروني</label>
                        <input type="email" name="email" required />
                        <label>اسم الوكالة</label>
                        <input type="text" name="agency_name" maxlength="60" required />
                        <label>اسم المستخدم الرئيسي</label>
                        <input type="text" name="username" pattern="[A-Za-z0-9_]{3,30}" minlength="3" maxlength="30" required />
                        <label>كلمة المرور (8 أحرف على الأقل)</label>
                        <input type="password" name="password" minlength="8" required />
                        <label>تأكيد كلمة المرور</label>
                        <input type="password" name="password2" minlength="8" required />
                        <label>استلام كود التحقق عن طريق</label>
                        <div>
                            ${em ? `<label class="radio"><input type="radio" name="channel" value="email" checked />البريد الإلكتروني</label>` : ''}
                            ${wa ? `<label class="radio"><input type="radio" name="channel" value="whatsapp" ${em ? '' : 'checked'} />واتساب</label>` : ''}
                        </div>
                        <div id="phoneBox" style="display:none">
                            <label>رقم الواتساب (مثال: 01012345678)</label>
                            <input type="tel" name="phone" />
                        </div>
                        ${needCode ? `<label>كود التسجيل</label><input type="text" name="register_code" required />` : ''}
                        <button type="submit">إنشاء الحساب وإرسال الكود</button>
                        <div class="msg" id="msg"></div>
                    </form>
                    <a class="btn small" href="/login">لديك حساب؟ سجّل الدخول</a>
                </div>`, `
                var f=document.getElementById('f'),msg=document.getElementById('msg');
                function sync(){
                  var w=f.querySelector('input[name=channel]:checked');
                  var isW=!!w&&w.value==='whatsapp';
                  document.getElementById('phoneBox').style.display=isW?'block':'none';
                  if(f.phone) f.phone.required=isW;
                }
                f.addEventListener('change',sync);sync();
                f.addEventListener('submit',function(e){
                  e.preventDefault();
                  msg.textContent='';
                  var d={};
                  new FormData(f).forEach(function(v,k){d[k]=v;});
                  if(d.password!==d.password2){msg.textContent='كلمتا المرور غير متطابقتين';return;}
                  var btn=f.querySelector('button');btn.disabled=true;
                  fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)})
                  .then(function(r){return r.json();})
                  .then(function(j){
                    btn.disabled=false;
                    if(!j.success){msg.textContent=j.message||'حدث خطأ';return;}
                    window.location.href='/verify?u='+encodeURIComponent(j.username)+'&to='+encodeURIComponent(j.sent_to||'');
                  }).catch(function(){btn.disabled=false;msg.textContent='تعذر الاتصال بالسيرفر';});
                });
                `));
        }

        if (pathname === '/api/register' && req.method === 'POST') {
            if (!(await rateLimit(req, 'register', 10))) return sendJson(res, 429, { success: false, message: 'محاولات كثيرة.' });
            let b = await readJson(req);
            const email = String(b.email || '').trim().toLowerCase();
            const agencyName = String(b.agency_name || '').trim();
            const username = String(b.username || '').trim().toLowerCase();
            const password = String(b.password || '');
            const channel = String(b.channel || 'email');

            if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return sendJson(res, 400, { success: false, message: 'البريد غير صحيح.' });
            if (!agencyName || !/^[a-z0-9_]{3,30}$/.test(username) || password.length < 8)
                return sendJson(res, 400, { success: false, message: 'البيانات غير مكتملة.' });

            let phone = channel === 'whatsapp' ? normalizePhone(b.phone) : null;
            const salt = crypto.randomBytes(16).toString('hex');
            const agencyKey = crypto.randomBytes(24).toString('hex');
            const record = {
                email, phone, agency_name: agencyName, username, salt,
                password_hash: await hashPassword(password, salt),
                agency_key: agencyKey, verified: false, verify_channel: channel,
                created_at: new Date().toISOString()
            };

            const userOk = await redis.set(`user:${username}`, record, { nx: true, ex: UNVERIFIED_TTL });
            if (!userOk) return sendJson(res, 409, { success: false, message: 'اسم المستخدم مسجل مسبقاً.' });
            await redis.set(`email:${email}`, username, { nx: true, ex: UNVERIFIED_TTL });

            try { await issueCode(record); }
            catch { await dropAccount(record); return sendJson(res, 502, { success: false, message: 'تعذر إرسال كود التحقق.' }); }

            return sendJson(res, 200, { success: true, need_verify: true, username, sent_to: maskFor(record) });
        }

        if (pathname === '/verify' && req.method === 'GET') {
            return sendHtml(res, 200, shell('تأكيد الحساب | ميزان', `
                <div class="box" id="formBox">
                    <h2>📩 تأكيد تفعيل الحساب</h2>
                    <p class="note" id="info" style="text-align:center">أدخل كود التحقق المكوّن من 6 أرقام.</p>
                    <form id="f">
                        <label>كود التحقق</label>
                        <input type="text" name="code" inputmode="numeric" maxlength="6" pattern="[0-9]{6}" required autocomplete="one-time-code" dir="ltr" style="text-align:center;letter-spacing:6px;font-size:22px" />
                        <button type="submit">تأكيد الحساب</button>
                        <div class="msg" id="msg"></div>
                    </form>
                    <button class="small" type="button" id="resend">🔁 إرسال كود جديد</button>
                </div>
                <div class="box" id="resBox" style="display:none">
                    <h2>✅ تم تفعيل حساب الوكالة بنجاح</h2>
                    <label>الرابط السحابي للوكالة</label>
                    <input type="text" id="link" readonly />
                    <button class="small" type="button" onclick="copyFrom('link')">📋 نسخ الرابط</button>
                    <label>كود ربط الوكالة</label>
                    <input type="text" id="key" readonly />
                    <button class="small" type="button" onclick="copyFrom('key')">📋 نسخ الكود</button>
                    <a class="btn" id="openPortalBtn" href="#">🚀 فتح بوابة الوكالة السحابية</a>
                </div>`, `
                var q=new URLSearchParams(location.search),u=q.get('u')||'';
                var f=document.getElementById('f'),msg=document.getElementById('msg'),info=document.getElementById('info');
                if(q.get('to')){info.textContent='أرسلنا كود التحقق إلى: '+q.get('to');}
                function show(text,ok){msg.style.color=ok?'#7fd6a8':'';msg.textContent=text;}
                f.addEventListener('submit',function(e){
                  e.preventDefault();show('',false);
                  var btn=f.querySelector('button');btn.disabled=true;
                  fetch('/api/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,code:f.code.value.trim()})})
                  .then(function(r){return r.json();})
                  .then(function(j){
                    btn.disabled=false;
                    if(!j.success){show(j.message||'حدث خطأ',false);return;}
                    document.getElementById('formBox').style.display='none';
                    document.getElementById('resBox').style.display='block';
                    document.getElementById('link').value=j.link;
                    document.getElementById('key').value=j.agency_key;
                    document.getElementById('openPortalBtn').href=j.link;
                  }).catch(function(){btn.disabled=false;show('تعذر الاتصال بالسيرفر',false);});
                });
                function copyFrom(id){var el=document.getElementById(id);el.select();if(navigator.clipboard){navigator.clipboard.writeText(el.value);}}
                `));
        }

        if (pathname === '/api/verify' && req.method === 'POST') {
            let b = await readJson(req);
            const username = String(b.username || '').trim().toLowerCase();
            const code = String(b.code || '').trim();
            const user = await redis.get(`user:${username}`);

            if (!user) return sendJson(res, 404, { success: false, message: 'الحساب غير موجود.' });
            const otp = await redis.get(`otp:${username}`);
            if (!otp || otp.expires < Date.now()) return sendJson(res, 400, { success: false, message: 'انتهت صلاحية الكود.' });

            const given = Buffer.from(otpHash(user.salt, code));
            const real = Buffer.from(otp.hash);
            if (given.length !== real.length || !crypto.timingSafeEqual(given, real))
                return sendJson(res, 400, { success: false, message: 'الكود غير صحيح.' });

            user.verified = true;
            user.verified_at = new Date().toISOString();
            await redis.set(`user:${username}`, user);
            await redis.set(`keyidx:${user.agency_key}`, username);
            await redis.del(`otp:${username}`);

            return sendJson(res, 200, {
                success: true,
                agency_key: user.agency_key,
                link: `${originOf(req)}/app?key=${user.agency_key}`
            });
        }

        if (pathname === '/login' && req.method === 'GET') {
            return sendHtml(res, 200, shell('تسجيل الدخول | ميزان', `
                <div class="box">
                    <h2>🔑 تسجيل الدخول السحابي</h2>
                    <form id="f">
                        <label>اسم المستخدم الرئيسي</label>
                        <input type="text" name="username" required autocomplete="username" />
                        <label>كلمة المرور</label>
                        <input type="password" name="password" required autocomplete="current-password" />
                        <button type="submit">دخول</button>
                        <div class="msg" id="msg"></div>
                    </form>
                    <a class="btn small" href="/register">ليس لديك حساب؟ أنشئ واحداً</a>
                    <a class="btn small" href="/forgot">نسيت كلمة المرور؟</a>
                </div>`, `
                var f=document.getElementById('f'),msg=document.getElementById('msg');
                f.addEventListener('submit',function(e){
                  e.preventDefault();
                  var d={};
                  new FormData(f).forEach(function(v,k){d[k]=v;});
                  var btn=f.querySelector('button');btn.disabled=true;
                  fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)})
                  .then(function(r){return r.json();})
                  .then(function(j){
                    btn.disabled=false;
                    if(!j.success){msg.textContent=j.message||'حدث خطأ';return;}
                    if(j.token){localStorage.setItem('mz_token',j.token);window.location.href='/account';}else{window.location.href=j.link;}
                  }).catch(function(){btn.disabled=false;msg.textContent='تعذر الاتصال بالسيرفر';});
                });
                `));
        }

        if (pathname === '/api/login' && req.method === 'POST') {
            if (!(await rateLimit(req, 'login', 20))) return sendJson(res, 429, { success: false, message: 'محاولات كثيرة، حاول لاحقاً.' });
            let b = await readJson(req);
            const username = String(b.username || '').trim().toLowerCase();
            const password = String(b.password || '');
            const user = await redis.get(`user:${username}`);

            const salt = user ? user.salt : 'x'.repeat(32);
            const hash = await hashPassword(password, salt);
            if (!user || hash !== user.password_hash) {
                return sendJson(res, 401, { success: false, message: 'بيانات الدخول غير صحيحة.' });
            }
            if (user.disabled) return sendJson(res, 403, { success: false, message: 'هذا الحساب معطّل. تواصل مع الدعم.' });

            return sendJson(res, 200, {
                success: true,
                agency_name: user.agency_name,
                token: await billing.createSession(user),
                link: `${originOf(req)}/app?key=${user.agency_key}`
            });
        }

        if (pathname === '/api/system/check-update') {
            const clientVer = query.version || "1.0.0";
            return sendJson(res, 200, {
                success: true,
                has_update: clientVer !== versionInfo.latest_version,
                client_version: clientVer,
                latest_version: versionInfo.latest_version,
                download_url: versionInfo.download_url,
                message: "أنت تعمل على أحدث إصدار معتمد.",
                changelog: versionInfo.changelog
            });
        }

        // استقبال ومزامنة كامل جداول المنظومة من أجهزة الكمبيوتر
        if ((pathname === '/api/sync/push' || pathname === '/api/sync') && req.method === 'POST') {
            let body = await readJson(req);
            const agency_key = String(body.agency_key || body.key || body.apiKey || req.headers['x-api-key'] || query.key || '').trim();
            if (!agency_key) return sendJson(res, 400, { success: false, message: "كود الوكالة مطلوب." });

            let owner = await redis.get(`keyidx:${agency_key}`);
            let user = owner ? await redis.get(`user:${owner}`) : null;
            if (!owner) await redis.set(`keyidx:${agency_key}`, "desktop_client");

            await redis.set(`agency:${agency_key}`, {
                agency_name: body.agency_name || (user ? user.agency_name : "وكالة ميزان"),
                last_sync: new Date().toISOString(),
                logical_date: body.logical_date || new Date().toISOString().slice(0, 10),
                metrics: {
                    drawer_cash: body.drawer_cash || 0,
                    today_sales: body.today_sales || 0,
                    net_profit: body.net_profit || 0,
                    open_cars_count: body.open_cars_count || 0,
                    crates_in_market: body.crates_in_market || 0
                },
                users: body.users || [],
                customers: body.customers || [],
                suppliers: body.suppliers || [],
                items: body.items || [],
                grades: body.grades || [],
                crate_types: body.crate_types || [],
                floor_stock: body.floor_stock || [],
                loads: body.loads || [],
                recent_sales: body.recent_sales || [],
                collections: body.collections || [],
                expenses: body.expenses || [],
                purchases: body.purchases || [],
                crates: body.crates || [],
                bank_accounts: body.bank_accounts || [],
                checks: body.checks || [],
                weighbridge_tickets: body.weighbridge_tickets || []
            }, { ex: 60 * 60 * 24 * 30 });

            return sendJson(res, 200, { success: true, message: "تم استقبال كامل جداول الوكالة بالسيرفر السحابي بنجاح." });
        }

        // سحب العمليات المنشأة سحابياً إلى الديسكتوب
        if (pathname === '/api/mobile/orders' && req.method === 'GET') {
            const agency_key = String(query.key || req.headers['x-api-key'] || '').trim();
            if (!agency_key) return sendJson(res, 400, { success: false, message: "كود الوكالة مطلوب." });


            const queueKey = `orders_queue:${agency_key}`;
            const queuedOrders = await redis.get(queueKey) || [];
            if (queuedOrders.length > 0) await redis.del(queueKey);

            return sendJson(res, 200, queuedOrders);
        }

        // تسجيل دخول الموظف المستورد من الديسكتوب
        if (pathname === '/api/web/user-login' && req.method === 'POST') {
            let b = await readJson(req);
            const agency_key = String(b.agency_key || '').trim();
            const username = String(b.username || '').trim();
            const password = String(b.password || '');
            if (!(await gateAgency(agency_key)).ok) return payRequired(res, agency_key);

            const data = await redis.get(`agency:${agency_key}`);
            const owner = await redis.get(`keyidx:${agency_key}`);
            const ownerUser = owner ? await redis.get(`user:${owner}`) : null;

            const cleanUser = username.toLowerCase();
            const syncedUsers = data && Array.isArray(data.users) ? data.users : [];

            const matchedUser = syncedUsers.find(u => {
                const uName = String(u.Username || u.username || '').toLowerCase();
                const fName = String(u.FullName || u.fullName || u.full_name || '').toLowerCase();
                return uName === cleanUser || fName === cleanUser;
            });

            if (matchedUser) {
                const passHash = matchedUser.PasswordHash || matchedUser.password_hash || matchedUser.passwordHash;
                if (!verifyDesktopPassword(password, passHash)) {
                    return sendJson(res, 401, { success: false, message: "كلمة المرور غير صحيحة." });
                }
                const mu = {
                    id: matchedUser.Id || matchedUser.id || 1,
                    username: matchedUser.Username || matchedUser.username,
                    full_name: matchedUser.FullName || matchedUser.fullName || matchedUser.full_name,
                    role: matchedUser.Role || matchedUser.role || 'محاسب',
                    job_title: matchedUser.JobTitle || matchedUser.job_title || 'محاسب',
                    perms: matchedUser.ServerPermissions ?? matchedUser.serverPermissions ?? matchedUser.Permissions ?? matchedUser.permissions ?? null
                };
                return sendJson(res, 200, {
                    success: true,
                    token: makeToken(agency_key, mu),
                    user: Object.assign({}, mu, { privileged: isPrivileged(mu.role, mu.job_title) })
                });
            }

            if (ownerUser && (ownerUser.username.toLowerCase() === cleanUser || cleanUser === 'admin')) {
                const hash = await hashPassword(password, ownerUser.salt);
                if (hash === ownerUser.password_hash) {
                    const ou = { id: 1, username: ownerUser.username, full_name: `${ownerUser.agency_name} (المدير العام)`, role: 'admin', job_title: 'مدير عام' };
                    return sendJson(res, 200, {
                        success: true,
                        token: makeToken(agency_key, ou),
                        user: Object.assign({}, ou, { privileged: true })
                    });
                }
            }

            return sendJson(res, 401, { success: false, message: "بيانات الدخول غير صحيحة." });
        }

        // إنشاء العمليات (إضافة، تعديل، حذف) مع تزويد كل عملية بـ OrderId فريد لمنع تكرار المزامنة
        if (pathname === '/api/web/create-action' && req.method === 'POST') {
            let b = await readJson(req);
            const { agency_key, action_type, user_name, data, source } = b;
            if (!agency_key || !action_type || !data) return sendJson(res, 400, { success: false, message: "بيانات ناقصة." });
            if (!(await gateAgency(agency_key)).ok) return payRequired(res, agency_key);

            const session = verifySession(b.token, agency_key);
            if (!checkGranularPermission(session, action_type)) {
                return sendJson(res, 403, { success: false, message: 'ليس لديك صلاحية لتنفيذ هذه العملية. سجّل الدخول بحساب مدير.' });
            }
            const actor = session ? session.n : user_name;

            const queueKey = `orders_queue:${agency_key}`;
            const queuedOrders = [];

            const dateStr = data.Date || new Date().toISOString().slice(0, 10);
            const authorFormatted = `${actor || "مستخدم"} - ${source === 'mobile' ? 'هاتف' : 'سيرفر'}`;
            const prefix = source === 'mobile' ? 'MOB' : 'SRV';
            const seq = Math.floor(1000 + Math.random() * 9000);
            const uniqueOrderId = `ORD-${Date.now()}-${seq}`;

            switch (action_type) {
                case 'SALE_INVOICE': {
                    const invNo = data.InvoiceNo || `فاتورة ${await redis.incr(`inv_seq:${agency_key}:${source === 'mobile' ? 'mob' : 'srv'}`)} (${source === 'mobile' ? 'هاتف' : 'سيرفر'})`;
                    const items = Array.isArray(data.Items) ? data.Items : [data];
                    items.forEach((it, idx) => {
                        queuedOrders.push({
                            ActionType: 'SALE_INVOICE',
                            OrderId: uniqueOrderId,
                            InvoiceNo: invNo,
                            Date: dateStr,
                            Customer: data.Customer || "عميل نقدي",
                            Item: it.Item,
                            Supplier: it.Supplier || "عام",
                            LoadKey: it.LoadKey || data.LoadKey || "",
                            Salesman: data.Salesman || "عام",
                            Grade: it.Grade || "فرز أول ممتاز",
                            CrateType: it.CrateType || "برنيكة بلاستيك",
                            Qty: Number(it.Qty || 0),
                            Weight: Number(it.Weight || 0),
                            Price: Number(it.Price || 0),
                            Discount: Number(it.Discount || 0),
                            Value: Number(it.Value || 0),
                            PaidAmount: Number(idx === 0 ? (data.PaidAmount || 0) : 0),
                            RemainingAmount: Number(idx === 0 ? (data.RemainingAmount || 0) : 0),
                            PaymentMethod: data.PaymentMethod || "نقدي (كاش)",
                            CreatedBy: authorFormatted
                        });
                    });
                    break;
                }
                case 'DELETE_INVOICE':
                    queuedOrders.push({ ActionType: 'DELETE_INVOICE', OrderId: uniqueOrderId, InvoiceNo: data.InvoiceNo, CreatedBy: authorFormatted });
                    break;
                case 'LOAD_SUPPLY': {
                    const items = Array.isArray(data.Items) ? data.Items : [{ Item: data.Item, QtyIn: Number(data.QtyIn || 0), WeightIn: Number(data.WeightIn || 0) }];
                    queuedOrders.push({
                        ActionType: 'LOAD_SUPPLY',
                        OrderId: uniqueOrderId,
                        Date: dateStr,
                        Vehicle: data.Vehicle,
                        Supplier: data.Supplier,
                        Freight: Number(data.Freight || 0),
                        FreightType: data.FreightType || "fixed",
                        Commission: Number(data.Commission || 5),
                        CommissionType: data.CommissionType || "percent",
                        CreatedBy: authorFormatted,
                        Items: items
                    });
                    break;
                }
                case 'COLLECTION':
                    queuedOrders.push({
                        ActionType: 'COLLECTION',
                        OrderId: uniqueOrderId,
                        ReceiptNo: `REC-${prefix}-${seq}`,
                        Date: dateStr,
                        Customer: data.Customer,
                        Amount: Number(data.Amount || 0),
                        PaymentMethod: data.PaymentMethod || "نقدي (كاش)",
                        CreatedBy: authorFormatted,
                        Notes: data.Notes || `سند تحصيل`
                    });
                    break;
                case 'DELETE_COLLECTION':
                    queuedOrders.push({ ActionType: 'DELETE_COLLECTION', OrderId: uniqueOrderId, ReceiptNo: data.ReceiptNo, CreatedBy: authorFormatted });
                    break;
                case 'EXPENSE':
                    queuedOrders.push({
                        ActionType: 'EXPENSE',
                        OrderId: uniqueOrderId,
                        Date: dateStr,
                        Category: data.Category || "مصاريف نثرية عامة",
                        Description: data.Description || `صرف نثري`,
                        Amount: Number(data.Amount || 0),
                        PaymentMethod: data.PaymentMethod || "نقدي (كاش)",
                        CreatedBy: authorFormatted
                    });
                    break;
                case 'DELETE_EXPENSE':
                    queuedOrders.push({ ActionType: 'DELETE_EXPENSE', OrderId: uniqueOrderId, Id: data.Id, CreatedBy: authorFormatted });
                    break;
                case 'PURCHASE':
                    queuedOrders.push({
                        ActionType: 'PURCHASE',
                        OrderId: uniqueOrderId,
                        InvoiceNo: `PUR-${prefix}-${seq}`,
                        Date: dateStr,
                        Category: data.Category || "شراء بضاعة تجارية (تضاف للأرضية)",
                        Supplier: data.Supplier,
                        Item: data.Item,
                        Qty: Number(data.Qty || 0),
                        Weight: Number(data.Weight || 0),
                        Price: Number(data.Price || 0),
                        Value: Number(data.Value || 0),
                        PaidAmount: Number(data.PaidAmount || 0),
                        RemainingAmount: Number(data.RemainingAmount || 0),
                        PaymentMethod: data.PaymentMethod || "نقدي (كاش)",
                        CreatedBy: authorFormatted
                    });
                    break;
                case 'CRATE_DELIVERY':
                case 'CRATE_RETURN':
                    queuedOrders.push({
                        ActionType: action_type,
                        OrderId: uniqueOrderId,
                        Date: dateStr,
                        Customer: data.Customer,
                        Kind: action_type === 'CRATE_RETURN' ? 'استرجاع' : 'تسليم',
                        CrateType: data.CrateType || "برنيكة بلاستيك",
                        Qty: Number(data.Qty || 0),
                        Price: Number(data.Price || 70),
                        Amount: Number(data.Amount || (data.Qty * (data.Price || 70))),
                        IsCashCollected: !!data.IsCashCollected,
                        CreatedBy: authorFormatted
                    });
                    break;
                case 'WEIGHBRIDGE_TICKET':
                    queuedOrders.push({
                        ActionType: 'WEIGHBRIDGE_TICKET',
                        OrderId: uniqueOrderId,
                        TicketNo: `WB-${prefix}-${seq}`,
                        Date: dateStr,
                        Vehicle: data.Vehicle,
                        DriverName: data.DriverName || "سائق حر",
                        Supplier: data.Supplier,
                        Item: data.Item,
                        GrossWeight: Number(data.GrossWeight || 0),
                        TareWeight: Number(data.TareWeight || 0),
                        CreatedBy: authorFormatted
                    });
                    break;
                case 'EDIT_INVOICE': {
                    const invNo = String(data.InvoiceNo || '').trim();
                    const items = Array.isArray(data.Items) ? data.Items.filter(i => i && i.Item) : [];
                    if (!invNo || !items.length) return sendJson(res, 400, { success: false, message: 'بيانات الفاتورة المعدلة ناقصة.' });
                    // حذف الفاتورة القديمة ثم إعادتها بنفس الرقم في نفس الدفعة، فلا تتكرر الأرقام
                    queuedOrders.push({ ActionType: 'DELETE_INVOICE', OrderId: `${uniqueOrderId}-D`, InvoiceNo: invNo, IsEdit: true, CreatedBy: authorFormatted });
                    saleLines(invNo, dateStr, data, items, `${uniqueOrderId}-A`, authorFormatted, { IsEdit: true, EditOf: invNo }).forEach(o => queuedOrders.push(o));
                    break;
                }
                case 'SETTLE_VEHICLE': {
                    if (!data.Supplier || !data.Vehicle) return sendJson(res, 400, { success: false, message: 'بيانات السيارة ناقصة.' });
                    queuedOrders.push({
                        ActionType: 'SETTLE_VEHICLE',
                        OrderId: uniqueOrderId,
                        Date: dateStr,
                        LoadKey: data.LoadKey || '',
                        Supplier: data.Supplier,
                        Vehicle: data.Vehicle,
                        TotalSales: numOr0(data.TotalSales),
                        CommissionRate: numOr0(data.CommissionRate),
                        CommissionType: data.CommissionType || 'percent',
                        CommissionAmount: numOr0(data.CommissionAmount),
                        Freight: numOr0(data.Freight),
                        Damage: numOr0(data.Damage),
                        NetDue: numOr0(data.NetDue),
                        Notes: data.Notes || '',
                        CreatedBy: authorFormatted
                    });
                    break;
                }
                case 'ADD_CUSTOMER':
                case 'ADD_SUPPLIER': {
                    const nm = String(data.Name || '').trim();
                    if (!nm) return sendJson(res, 400, { success: false, message: 'الاسم مطلوب.' });
                    queuedOrders.push({
                        ActionType: action_type,
                        OrderId: uniqueOrderId,
                        Name: nm,
                        Phone: String(data.Phone || '').trim(),
                        DefaultCommission: action_type === 'ADD_SUPPLIER' ? numOr0(data.DefaultCommission || 5) : undefined,
                        CreditLimit: action_type === 'ADD_CUSTOMER' ? numOr0(data.CreditLimit) : undefined,
                        CreatedBy: authorFormatted
                    });
                    break;
                }
                default:
                    return sendJson(res, 400, { success: false, message: 'نوع العملية غير معروف.' });
            }

            // منع التكرار: نفس client_id لا يُنفّذ مرتين (ضغط مزدوج / إعادة إرسال بعد انقطاع)
            if (b.client_id) {
                const fresh = await redis.set(`idem:${agency_key}:${String(b.client_id).slice(0, 64)}`, 1, { nx: true, ex: 60 * 60 * 24 });
                if (!fresh) return sendJson(res, 200, { success: true, duplicate: true, message: 'تم استلام هذه العملية من قبل ولم تتكرر.' });
            }

            const pending = (await redis.get(queueKey)) || [];
            await redis.set(queueKey, pending.concat(queuedOrders), { ex: 60 * 60 * 24 * 7 });

            try {
                const logKey = `activity:${agency_key}`;
                await redis.lpush(logKey, { ts: new Date().toISOString(), user: actor || 'مستخدم', type: action_type, summary: summarizeAction(action_type, data), order: uniqueOrderId });
                await redis.ltrim(logKey, 0, 299);
                await redis.expire(logKey, 60 * 60 * 24 * 90);
            } catch (e) { console.error('activity log failed', e); }

            return sendJson(res, 200, { success: true, message: `تم تسجيل المعاملة بنجاح وتوليد المعرف [${uniqueOrderId}] وتمريرها للمزامنة.` });
        }

        // سجل النشاط (للمدير فقط)
        if (pathname === '/api/web/activity' && req.method === 'GET') {
            const agency_key = String(query.key || '').trim();
            const session = verifySession(req.headers['x-session-token'], agency_key);
            if (!session || !session.p) return sendJson(res, 403, { success: false, message: 'غير مصرح.' });
            if (!(await gateAgency(agency_key)).ok) return payRequired(res, agency_key);
            const list = (await redis.lrange(`activity:${agency_key}`, 0, 199)) || [];
            return sendJson(res, 200, { success: true, items: list.map(x => { if (typeof x !== 'string') return x; try { return JSON.parse(x); } catch { return { ts: '', user: '', summary: x }; } }) });
        }

        // 13. بوابة الويب السحابية الشاملة لكافة الأقسام الـ 16
        if (pathname === '/app') {
            const key = String(query.key || '').trim();
            if (!(await gateAgency(key)).ok) return redirect(res, `/pay?key=${encodeURIComponent(key)}`);
            const data = key ? await redis.get(`agency:${key}`) : null;

            if (!data) {
                return sendHtml(res, 200, shell('بانتظار المزامنة | ميزان', `
                    <div class="box" style="text-align:center">
                        <h2>⏳ الحساب جاهز وبانتظار المزامنة</h2>
                        <p style="color:#C8B8B5;font-size:13px;line-height:1.8;">
                            1. افتح برنامج <b>ميزان</b> على الكمبيوتر.<br>
                            2. ادخل على <b>(الإعدادات ⚙️ ➔ الربط والمزامنة السحابية 📱)</b>.<br>
                            3. تأكد من إدخال كود الوكالة التالي:<br>
                            <b style="color:#D4AF37;font-size:16px;background:#1A0206;padding:4px 8px;border-radius:4px;display:inline-block;margin:6px 0;">${esc(key || 'يرجى تسجيل الدخول أولاً')}</b><br>
                            4. اضغط على زر <b>(🔄 مزامنة فورية الآن)</b> بالكمبيوتر.<br>
                        </p>
                        <button class="btn" onclick="location.reload()">🔄 تحديث الصفحة بعد المزامنة</button>
                    </div>`));
            }

            const m = data.metrics || {};
            const customers = Array.isArray(data.customers) ? data.customers : [];
            const suppliers = Array.isArray(data.suppliers) ? data.suppliers : [];
            const items = Array.isArray(data.items) ? data.items : [];
            const loads = Array.isArray(data.loads) ? data.loads : [];
            const users = Array.isArray(data.users) ? data.users : [];
            const floorStock = Array.isArray(data.floor_stock) ? data.floor_stock : [];
            const recentSales = Array.isArray(data.recent_sales) ? data.recent_sales : [];
            const collections = Array.isArray(data.collections) ? data.collections : [];
            const expenses = Array.isArray(data.expenses) ? data.expenses : [];
            const purchases = Array.isArray(data.purchases) ? data.purchases : [];
            const crates = Array.isArray(data.crates) ? data.crates : [];
            const bankAccounts = Array.isArray(data.bank_accounts) ? data.bank_accounts : [];
            const checks = Array.isArray(data.checks) ? data.checks : [];
            const weighbridgeTickets = Array.isArray(data.weighbridge_tickets) ? data.weighbridge_tickets : [];

            const getName = o => o.Name || o.name || o.FullName || o.fullName || '';
            const getSupplier = o => o.Supplier || o.supplier || '';
            const getPrice = o => Number(o.DefaultPrice || o.defaultPrice || o.Price || o.price || 0);
            const getBalance = o => Number(o.Balance || o.balance || 0);
            const getVehicle = o => o.Vehicle || o.vehicle || '';
            const getDate = o => o.Date || o.date || '';
            const getItem = o => o.Item || o.item || '';

            const toN = v => Number(v) || 0;
            const fm = v => toN(v).toLocaleString();
            const AR_COLS = { Id: 'م', Date: 'التاريخ', DueDate: 'الاستحقاق', Amount: 'المبلغ', Total: 'الإجمالي', Value: 'القيمة', Supplier: 'المورد', Customer: 'العميل',
                Status: 'الحالة', CheckNo: 'رقم الشيك', CheckNumber: 'رقم الشيك', Number: 'الرقم', BankName: 'البنك', Description: 'البيان', Notes: 'ملاحظات',
                InvoiceNo: 'الفاتورة', Item: 'الصنف', Weight: 'الوزن', Qty: 'الكمية', Price: 'السعر', Type: 'النوع', Kind: 'النوع', PaymentMethod: 'طريقة الدفع',
                Category: 'البند', Payee: 'المستفيد', Drawer: 'الساحب', Vehicle: 'السيارة', TicketNo: 'رقم الكارتة' };
            const colName = k => AR_COLS[k] || AR_COLS[k.charAt(0).toUpperCase() + k.slice(1)] || k;
            const genTable = (arr, emptyText) => {
                if (!arr.length) return `<div class="empty">${emptyText}</div>`;
                const cols = Object.keys(arr[0]).filter(k => typeof arr[0][k] !== 'object').slice(0, 7);
                return `<div class="tbl-wrap"><table><tr>${cols.map(c => `<th>${esc(colName(c))}</th>`).join('')}</tr>` +
                    arr.slice(0, 300).map(o => `<tr>${cols.map(c => `<td>${typeof o[c] === 'number' ? o[c].toLocaleString() : esc(o[c] == null ? '' : String(o[c]))}</td>`).join('')}</tr>`).join('') + `</table></div>`;
            };
            const bankTotal = bankAccounts.reduce((a, b) => a + toN(b.Balance || b.balance), 0);
            const drawerCash = toN(m.drawer_cash);
            const debtors = customers.map(c => ({ name: getName(c), bal: getBalance(c) })).filter(x => x.bal > 0).sort((a, b) => b.bal - a.bal);
            const creditors = customers.map(c => ({ name: getName(c), bal: getBalance(c) })).filter(x => x.bal < 0).sort((a, b) => a.bal - b.bal);
            const totalDebt = debtors.reduce((a, x) => a + x.bal, 0);
            const totalCredit = creditors.reduce((a, x) => a + x.bal, 0);
            const pendingInv = recentSales.filter(s => toN(s.RemainingAmount || s.remainingAmount) > 0);
            const pendingTotal = pendingInv.reduce((a, s) => a + toN(s.RemainingAmount || s.remainingAmount), 0);
            const syncAgeMin = Math.max(0, Math.round((Date.now() - new Date(data.last_sync).getTime()) / 60000));
            const syncAgeText = syncAgeMin < 1 ? 'الآن' : syncAgeMin < 60 ? `منذ ${syncAgeMin} دقيقة` : syncAgeMin < 1440 ? `منذ ${Math.round(syncAgeMin / 60)} ساعة` : `منذ ${Math.round(syncAgeMin / 1440)} يوم`;
            const syncStale = syncAgeMin > 1440;
            const syncLine = `<div class="sync-note${syncStale ? ' stale' : ''}">🔄 آخر بيانات مستلمة من الكمبيوتر: ${syncAgeText}${syncStale ? ' — افتح برنامج ميزان واضغط «مزامنة فورية»' : ''} <a href="javascript:location.reload()" style="color:inherit;margin-right:8px;">تحديث الصفحة</a></div>`;

            const todayC = cairoToday();
            const dayDiff = d => Math.floor((new Date(todayC + 'T00:00:00Z') - new Date(String(d).slice(0, 10) + 'T00:00:00Z')) / 86400000);
            const pick = (o, ...ks) => { for (const k of ks) { if (o[k] != null && o[k] !== '') return o[k]; } return ''; };
            const jsonS = o => JSON.stringify(o).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');

            const DONE_RE = /(محصل|مصروف|تم|مسدد|paid|cleared|collected)/i;
            const checkInfo = c => {
                const due = String(pick(c, 'DueDate', 'dueDate', 'due_date')).slice(0, 10);
                const st = String(pick(c, 'Status', 'status'));
                if (!due || DONE_RE.test(st)) return null;
                const diff = dayDiff(due);
                if (diff > 0) return { lvl: 'red', text: `متأخر ${diff} يوم` };
                if (diff >= -3) return { lvl: 'amber', text: diff === 0 ? 'يستحق اليوم' : `يستحق خلال ${-diff} يوم` };
                return null;
            };
            const checksTable = arr => {
                if (!arr.length) return '<div class="empty">لا توجد شيكات.</div>';
                const cols = Object.keys(arr[0]).filter(k => typeof arr[0][k] !== 'object').slice(0, 7);
                return `<div class="tbl-wrap"><table><thead><tr>${cols.map(c => `<th>${esc(colName(c))}</th>`).join('')}<th>التنبيه</th></tr></thead><tbody>` +
                    arr.slice(0, 300).map(o => { const ci = checkInfo(o); return `<tr>${cols.map(c => `<td>${typeof o[c] === 'number' ? o[c].toLocaleString() : esc(o[c] == null ? '' : String(o[c]))}</td>`).join('')}<td>${ci ? `<span class="bdg ${ci.lvl}">${esc(ci.text)}</span>` : ''}</td></tr>`; }).join('') + `</tbody></table></div>`;
            };
            const pendingTable = arr => arr.length ? `<div class="tbl-wrap"><table><thead><tr><th>الفاتورة</th><th>التاريخ</th><th>العميل</th><th>الإجمالي</th><th>المتبقي</th><th>إجراء</th></tr></thead><tbody>${arr.map(s => {
                const cust = s.Customer || s.customer || '';
                const rem = toN(s.RemainingAmount || s.remainingAmount);
                return `<tr><td><b>${esc(s.InvoiceNo || s.invoiceNo)}</b></td><td>${esc(s.Date || s.date)}</td><td>${esc(cust)}</td><td>${fm(s.Value || s.value)} ج</td><td style="color:#DC2626;font-weight:bold;">${fm(rem)} ج</td><td><button type="button" class="mini-btn" data-cust="${esc(cust)}" data-amt="${rem}" onclick="quickCollect(this)">💵 تحصيل</button> <button type="button" class="mini-btn" data-n="${esc(cust)}" onclick="openStatement('c', this.getAttribute('data-n'))">📄 كشف</button></td></tr>`;
            }).join('')}</tbody></table></div>` : '<div class="empty">لا توجد فواتير آجلة.</div>';

            // التنبيهات
            const alerts = [];
            checks.forEach(c => {
                const ci = checkInfo(c);
                if (ci) alerts.push({ lvl: ci.lvl, txt: `شيك ${pick(c, 'CheckNo', 'CheckNumber', 'Number')} ${pick(c, 'Payee', 'Drawer', 'Customer', 'Supplier')} بمبلغ ${fm(pick(c, 'Amount', 'amount'))} ج — ${ci.text}` });
            });
            customers.forEach(c => {
                const lim = toN(pick(c, 'CreditLimit', 'creditLimit', 'credit_limit'));
                if (lim > 0 && getBalance(c) > lim) alerts.push({ lvl: 'red', txt: `العميل ${getName(c)} تعدّى الحد الائتماني (${fm(getBalance(c))} من ${fm(lim)} ج)` });
            });
            const openCars = {};
            floorStock.forEach(f => {
                const q = toN(f.QtyRemaining || f.qtyRemaining), w = toN(f.WeightRemaining || f.weightRemaining);
                if (q <= 0 && w <= 0) return;
                const ve = f.Vehicle || f.vehicle || '', su = f.Supplier || f.supplier || '';
                const ld = loads.find(l => getVehicle(l) === ve && getSupplier(l) === su);
                const days = ld && getDate(ld) ? dayDiff(getDate(ld)) : -1;
                const k = su + '|' + ve;
                if (!openCars[k]) openCars[k] = { ve, su, days };
            });
            Object.values(openCars).forEach(o => { if (o.days >= 3) alerts.push({ lvl: o.days >= 7 ? 'red' : 'amber', txt: `سيارة ${o.ve} (المورد ${o.su}) ما زال بها بضاعة منذ ${o.days} يوم` }); });
            if (syncStale) alerts.push({ lvl: 'amber', txt: 'لم تصل مزامنة من الكمبيوتر منذ أكثر من يوم، افتح برنامج ميزان واضغط «مزامنة فورية».' });
            alerts.sort((a, b) => (a.lvl === b.lvl ? 0 : a.lvl === 'red' ? -1 : 1));
            const alertsHtml = alerts.length ? `<div class="alerts">${alerts.map(a => `<div class="al ${a.lvl}">${a.lvl === 'red' ? '🔴' : '🟠'} ${esc(a.txt)}</div>`).join('')}</div>` : '<div class="empty">✅ لا توجد تنبيهات حالياً.</div>';

            // ملخص اليوم
            const dayStr = String(data.logical_date || todayC).slice(0, 10);
            const dOf = o => String(o.Date || o.date || '').slice(0, 10);
            const salesDay = recentSales.filter(x => dOf(x) === dayStr);
            const dSales = salesDay.reduce((a, x) => a + toN(x.Value || x.value), 0);
            const dPaid = salesDay.reduce((a, x) => a + toN(x.PaidAmount || x.paidAmount), 0);
            const dRem = salesDay.reduce((a, x) => a + toN(x.RemainingAmount || x.remainingAmount), 0);
            const dInv = new Set(salesDay.map(x => x.InvoiceNo || x.invoiceNo)).size;
            const dCol = collections.filter(x => dOf(x) === dayStr).reduce((a, x) => a + toN(x.Amount || x.amount), 0);
            const dExp = expenses.filter(x => dOf(x) === dayStr).reduce((a, x) => a + toN(x.Amount || x.amount), 0);
            const dPur = purchases.filter(x => dOf(x) === dayStr).reduce((a, x) => a + toN(x.Value || x.value), 0);
            const dayText = `ملخص يوم ${dayStr} - ${data.agency_name}\nالمبيعات: ${fm(dSales)} ج (${dInv} فاتورة)\nمقبوض عند البيع: ${fm(dPaid)} ج\nآجل: ${fm(dRem)} ج\nسندات التحصيل: ${fm(dCol)} ج\nالمصروفات: ${fm(dExp)} ج\nالمشتريات: ${fm(dPur)} ج\nنقدية الدرج: ${fm(drawerCash)} ج`;

            // بيانات مضغوطة للمتصفح (الكشوف، التعديل، التصفية، الرسم البياني)
            const C_SALES = recentSales.map(x => ({ n: String(x.InvoiceNo || x.invoiceNo || ''), d: dOf(x), c: x.Customer || x.customer || '', i: x.Item || x.item || '', su: x.Supplier || x.supplier || '', lk: x.LoadKey || x.loadKey || '', ve: x.Vehicle || x.vehicle || '', v: toN(x.Value || x.value), p: toN(x.PaidAmount || x.paidAmount), r: toN(x.RemainingAmount || x.remainingAmount), q: toN(x.Qty || x.qty), w: toN(x.Weight || x.weight), pr: toN(x.Price || x.price), ds: toN(x.Discount || x.discount), pm: x.PaymentMethod || x.paymentMethod || '' }));
            const C_COLS = collections.map(x => ({ n: String(x.ReceiptNo || x.receiptNo || ''), d: dOf(x), c: x.Customer || x.customer || '', a: toN(x.Amount || x.amount), m: x.PaymentMethod || x.paymentMethod || '' }));
            const C_EXP = expenses.map(x => ({ d: dOf(x), a: toN(x.Amount || x.amount) }));
            const C_PUR = purchases.map(x => ({ d: dOf(x), s: x.Supplier || x.supplier || '', i: x.Item || x.item || '', v: toN(x.Value || x.value), p: toN(x.PaidAmount || x.paidAmount) }));
            const C_LOADS = loads.map(l => ({ k: `${getSupplier(l)} | ${getVehicle(l)} | ${getDate(l)}`, s: getSupplier(l), ve: getVehicle(l), d: String(getDate(l)).slice(0, 10), i: getItem(l), f: toN(l.Freight || l.freight), ft: l.FreightType || l.freightType || 'fixed', cm: toN(l.Commission != null ? l.Commission : (l.commission != null ? l.commission : 5)), ct: l.CommissionType || l.commissionType || 'percent' }));
            const C_CUST = customers.map(c => ({ n: getName(c), b: getBalance(c) }));
            const C_SUPP = suppliers.map(x => ({ n: getName(x), cm: toN(x.DefaultCommission || x.defaultCommission || 5) }));

            // بضاعة الأرضية مع عمر السيارة
            const stockRows = floorStock.map(f => {
                const ve = f.Vehicle || f.vehicle || '', su = f.Supplier || f.supplier || '';
                const ld = loads.find(l => getVehicle(l) === ve && getSupplier(l) === su);
                const days = ld && getDate(ld) ? dayDiff(getDate(ld)) : null;
                return { f, ve, su, days };
            });

            const NAV = [
                { icon: '🏠', name: 'الرئيسية', open: true, items: [['tab-dash', '🏠', 'الرئيسية']] },
                { icon: '📊', name: 'الملخصات المالية', open: true, items: [['tab-profit', '📈', 'الأرباح', 1], ['tab-treasury', '💰', 'الخزنة', 1], ['tab-payments', '🧾', 'المدفوعات'], ['tab-debts', '📒', 'المديونيات'], ['tab-day', '📆', 'ملخص اليوم', 1], ['tab-alerts', '🔔', 'التنبيهات' + (alerts.length ? ' (' + alerts.length + ')' : '')]] },
                { icon: '🛒', name: 'المبيعات', items: [['tab-pos', '🛒', 'نقطة البيع (POS)'], ['tab-sales-reg', '📋', 'سجل المبيعات'], ['tab-pending', '📄', 'الفواتير الآجلة']] },
                { icon: '🚚', name: 'التوريد والمخزون', items: [['tab-load', '🚚', 'ساحة توريد السيارات'], ['tab-settle', '🚛', 'تصفية سيارات الأمانة', 1], ['tab-stock', '📦', 'جرد بضاعة الأرضية'], ['tab-crate', '📦', 'حركة الصناديق والرهن'], ['tab-wb', '⚖️', 'ميزان بسكول']] },
                { icon: '💼', name: 'الحسابات والخزينة', items: [['tab-col', '🧾', 'سندات التحصيل'], ['tab-exp', '💸', 'الخزينة والمصروفات'], ['tab-pur', '📥', 'فواتير المشتريات'], ['tab-bank', '🏦', 'البنوك والشيكات', 1], ['tab-master', '👥', 'دليل الحسابات'], ['tab-statement', '📄', 'كشف حساب']] },
                { icon: '⚙️', name: 'الإعدادات', items: [['tab-key', '🔑', 'كود الوكالة والاقتران', 1], ['tab-printer', '🖨️', 'إعدادات الطابعات'], ['tab-log', '🕘', 'سجل النشاط', 1]] }
            ];

            const currentOrigin = originOf(req);
            const pairingConfigJson = JSON.stringify({
                LocalUrl: currentOrigin,
                CloudUrl: currentOrigin,
                AgencyKey: key,
                AgencyName: data.agency_name || "وكالة ميزان"
            });
            const qrImageUrl = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(pairingConfigJson)}`;

            return sendHtml(res, 200, `<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(data.agency_name)} | منظومة ميزان السحابية</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=Aref+Ruqaa:wght@700&display=swap');
body { font-family: 'Cairo', -apple-system, Tahoma, sans-serif; background: #200308; margin: 0; padding: 12px; color: #FAF4F1; }
#loginScreen { display: flex; justify-content: center; align-items: center; min-height: 90vh; }
.login-box { background: #2A040B; border: 1.8px solid #D4AF37; border-radius: 16px; max-width: 430px; width: 100%; padding: 28px; text-align: right; box-shadow: 0 15px 40px rgba(0,0,0,0.6); }
.login-header { text-align: center; margin-bottom: 20px; }
.login-header h2 { margin: 0 0 6px 0; color: #D4AF37; font-size: 24px; font-family: 'Aref Ruqaa', 'Cairo', serif; }
.login-header p { margin: 0; color: #C8B8B5; font-size: 13px; }
.badge { background: #5A0817; color: #FAF4F1; padding: 6px 10px; border-radius: 6px; font-weight: bold; font-size: 12.5px; text-align: center; margin-bottom: 15px; border: 1px solid #D4AF37; }

#mainAppScreen { display: none; background: #FAF4F1; border-radius: 12px; padding: 12px; color: #1E1E1E; box-shadow: 0 8px 30px rgba(0,0,0,0.5); }
.header { background: #2A040B; color: #FFF; padding: 16px; border-radius: 12px; text-align: center; border-bottom: 3px solid #D4AF37; margin-bottom: 10px; }
.header h2 { margin: 0; color: #D4AF37; font-size: 22px; font-family: 'Aref Ruqaa', 'Cairo', serif; }
.user-bar { background: #38050E; color: #D4AF37; padding: 8px 12px; border-radius: 8px; margin-top: 8px; font-size: 13px; display: flex; justify-content: space-between; align-items: center; }

.date-bar { background: #FFF; border: 1px solid #D4AF37; border-radius: 10px; padding: 10px 14px; margin-bottom: 12px; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; box-shadow: 0 2px 6px rgba(0,0,0,0.05); }
.date-bar label { margin: 0; font-size: 12px; font-weight: bold; color: #5A0817; }
.date-bar input[type=date] { width: 135px; padding: 6px 8px; margin: 0; font-size: 12px; border: 1px solid #C8B8B5; }
.date-bar .quick-btn { width: auto; padding: 6px 10px; margin: 0; font-size: 11.5px; background: #2A040B; border: 1px solid #D4AF37; color: #D4AF37; border-radius: 6px; cursor: pointer; }
.date-bar .quick-btn:hover { background: #5A0817; color: white; }

.nav-scroll { display: flex; gap: 6px; overflow-x: auto; margin-bottom: 12px; padding-bottom: 6px; }
.tab-btn { background: #2A040B; color: #FAF4F1; border: 1px solid #D4AF37; padding: 9px 12px; border-radius: 8px; font-weight: bold; cursor: pointer; white-space: nowrap; font-size: 12px; font-family: inherit; }
.tab-btn.active { background: #5A0817; color: #D4AF37; border-color: #D4AF37; }
.tab-content { display: none; }
.tab-content.active { display: block; }

.card { background: #FFF; border-radius: 10px; padding: 14px; margin-bottom: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); border-right: 4px solid #5A0817; color: #1E1E1E; }
.val { font-size: 20px; font-weight: bold; color: #0D7857; margin-top: 4px; }
.form-card { background: #FFF; border-radius: 10px; padding: 16px; margin-bottom: 14px; border: 1.5px solid #D4AF37; box-shadow: 0 4px 12px rgba(0,0,0,0.08); color: #1E1E1E; }
label { font-size: 12.5px; font-weight: bold; margin-top: 8px; display: block; color: #5A0817; }
input, select, textarea { width: 100%; box-sizing: border-box; padding: 10px; margin-top: 4px; border-radius: 6px; border: 1.2px solid #C8B8B5; font-size: 13.5px; background: #FFF; color: #1E1E1E; font-family: inherit; font-weight: 600; }
.submit-btn { width: 100%; background: #5A0817; color: white; border: 1px solid #D4AF37; padding: 12px; border-radius: 8px; font-weight: bold; font-size: 14.5px; cursor: pointer; margin-top: 14px; font-family: inherit; }
.submit-btn:hover { background: #7A0B20; }
.logout-btn { background: #DC2626; color: white; border: 1px solid #D4AF37; padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 11.5px; cursor: pointer; }
.logout-btn:hover { background: #B91C1C; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,0.05); color: #1E1E1E; }
th, td { padding: 8px; border-bottom: 1px solid #EEE; text-align: right; font-size: 12px; }
th { background: #5A0817; color: white; }
.grid-2 { display: flex; gap: 8px; }
.grid-2 > div { flex: 1; }
.msg { color: #ff8a8a; font-size: 13.5px; margin-top: 10px; min-height: 18px; text-align: center; font-weight: bold; }
.topbar { position: sticky; top: 0; z-index: 30; background: #2A040B; color: #D4AF37; border: 1px solid #D4AF37; border-radius: 10px; padding: 8px 12px; margin-bottom: 10px; display: flex; align-items: center; gap: 12px; font-weight: 800; }
.hamb { width: auto; background: #D4AF37; color: #200308; border: none; border-radius: 8px; font-size: 22px; line-height: 1; padding: 6px 13px; cursor: pointer; }
.drawer-overlay { position: fixed; top: 0; right: 0; bottom: 0; left: 0; background: rgba(0,0,0,0.55); opacity: 0; pointer-events: none; transition: opacity .2s; z-index: 80; }
.drawer-overlay.show { opacity: 1; pointer-events: auto; }
.drawer { position: fixed; top: 0; right: 0; height: 100%; width: 300px; max-width: 86vw; background: #2A040B; border-left: 2px solid #D4AF37; transform: translateX(105%); transition: transform .25s; z-index: 90; display: flex; flex-direction: column; overflow-y: auto; color: #FAF4F1; }
.drawer.open { transform: translateX(0); }
.drawer-head { display: flex; justify-content: space-between; align-items: center; padding: 14px; border-bottom: 1px solid #5A0817; color: #D4AF37; font-size: 15px; }
.drawer-x { width: auto; background: transparent; color: #FAF4F1; border: none; font-size: 18px; cursor: pointer; }
.drawer-user { padding: 8px 14px; font-size: 12.5px; color: #C8B8B5; border-bottom: 1px solid #5A0817; }
.nav-group { border-bottom: 1px solid #38050E; }
.nav-gh { width: 100%; display: flex; justify-content: space-between; align-items: center; background: transparent; color: #D4AF37; border: none; padding: 12px 14px; font-weight: 800; font-size: 13.5px; cursor: pointer; font-family: inherit; }
.nav-gh i { font-style: normal; transition: transform .2s; }
.nav-group.open .nav-gh i { transform: rotate(180deg); }
.nav-gb { display: none; padding: 0 8px 8px; }
.nav-group.open .nav-gb { display: block; }
.nav-item { width: 100%; display: flex; align-items: center; gap: 8px; background: transparent; color: #FAF4F1; border: none; border-radius: 8px; padding: 10px 12px; font-size: 13.5px; cursor: pointer; text-align: right; font-family: inherit; }
.nav-item span { width: 24px; text-align: center; }
.nav-item:hover { background: #38050E; }
.nav-item.active { background: #5A0817; color: #D4AF37; font-weight: 800; }
.drawer-foot { margin-top: auto; padding: 12px 14px; display: flex; gap: 8px; border-top: 1px solid #5A0817; }
.drawer-foot a, .drawer-foot button { flex: 1; text-align: center; text-decoration: none; background: #38050E; color: #D4AF37; border: 1px solid #D4AF37; border-radius: 8px; padding: 9px; font-size: 12.5px; cursor: pointer; font-family: inherit; }
.sync-note { background: #FFF; border: 1px solid #D4AF37; border-radius: 10px; padding: 8px 12px; margin-bottom: 12px; font-size: 12.5px; color: #5A0817; font-weight: bold; }
.sync-note.stale { background: #FEF3C7; border-color: #B45309; color: #92400E; }
.home-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 12px; margin-bottom: 12px; }
.big-card { background: linear-gradient(135deg, #2A040B, #4A0A14); color: #FAF4F1; border-radius: 14px; padding: 16px; cursor: pointer; border: 1.5px solid #D4AF37; border-top-width: 5px; box-shadow: 0 6px 18px rgba(0,0,0,0.25); transition: transform .12s; }
.big-card:hover { transform: translateY(-2px); }
.big-card.c-profit { border-top-color: #22c55e; } .big-card.c-treasury { border-top-color: #D4AF37; } .big-card.c-pay { border-top-color: #38bdf8; } .big-card.c-debt { border-top-color: #ef4444; }
.bc-top { display: flex; align-items: center; gap: 8px; font-weight: 800; font-size: 15px; color: #D4AF37; }
.bc-ico { font-size: 24px; }
.bc-val { font-size: 28px; font-weight: 800; margin: 10px 0 4px; }
.bc-sub { font-size: 12.5px; color: #C8B8B5; min-height: 18px; }
.bc-go { margin-top: 10px; font-size: 12px; color: #D4AF37; font-weight: bold; }
.mini-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; }
.mini { background: #FFF; border-radius: 10px; padding: 10px; border-right: 4px solid #5A0817; font-size: 12.5px; }
.mini b { display: block; font-size: 17px; color: #0D7857; margin-top: 3px; }
.pg-head { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.pg-head h3 { margin: 0; color: #5A0817; }
.back-btn { width: auto; background: #5A0817; color: #D4AF37; border: 1px solid #D4AF37; border-radius: 8px; padding: 6px 12px; font-weight: bold; cursor: pointer; font-family: inherit; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; margin: 10px 0; }
.tile { background: #FFF; border-radius: 10px; padding: 10px; border: 1px solid #D4AF37; text-align: center; font-size: 12.5px; color: #5A0817; font-weight: bold; }
.tile b { display: block; font-size: 19px; color: #0D7857; margin-top: 4px; }
.tile.red b { color: #DC2626; }
.tbl-wrap { overflow-x: auto; }
.empty { color: #888; font-size: 13px; padding: 8px; }
.note { color: #666; font-size: 12px; line-height: 1.7; }
h4.sec { margin: 16px 0 4px; color: #5A0817; }
body.nonpriv .priv-only { display: none !important; }
body.busy .submit-btn { opacity: .6; pointer-events: none; }
.toast { position: fixed; bottom: 18px; left: 50%; transform: translateX(-50%); background: #2A040B; color: #FAF4F1; border: 1px solid #D4AF37; border-radius: 10px; padding: 10px 16px; z-index: 200; font-size: 13px; max-width: 90vw; box-shadow: 0 6px 20px rgba(0,0,0,.4); }
.toast.err { background: #7f1d1d; }
.mini-btn { width: auto; background: #5A0817; color: #D4AF37; border: 1px solid #D4AF37; border-radius: 6px; padding: 3px 8px; cursor: pointer; font-size: 11.5px; font-family: inherit; margin: 1px; }
.mini-btn.red { background: #DC2626; color: #fff; }
.tb-tools { display: flex; gap: 6px; align-items: center; margin: 8px 0 0; flex-wrap: wrap; }
.tb-tools input { flex: 1; min-width: 140px; margin: 0; padding: 7px 9px; }
.bdg { display: inline-block; border-radius: 10px; padding: 2px 8px; font-size: 11px; font-weight: bold; }
.bdg.red { background: #FEE2E2; color: #B91C1C; }
.bdg.amber { background: #FEF3C7; color: #92400E; }
.alerts .al { border-radius: 8px; padding: 8px 10px; margin: 6px 0; font-size: 12.5px; font-weight: bold; }
.al.red { background: #FEE2E2; color: #991B1B; border: 1px solid #F87171; }
.al.amber { background: #FEF3C7; color: #92400E; border: 1px solid #F59E0B; }
.modal-bg { position: fixed; top: 0; right: 0; bottom: 0; left: 0; background: rgba(0,0,0,.6); z-index: 150; display: flex; align-items: flex-start; justify-content: center; overflow: auto; padding: 16px; }
.modal { background: #FAF4F1; color: #1E1E1E; border: 2px solid #D4AF37; border-radius: 14px; padding: 16px; max-width: 560px; width: 100%; }
.line-box { background: #FFF; border: 1px solid #D4AF37; border-radius: 10px; padding: 8px; margin: 8px 0; }
#offlineBadge { display: none; background: #B45309; color: #fff; border-radius: 8px; padding: 3px 10px; font-size: 11.5px; font-weight: bold; }
.chart-card { background: #FFF; border: 1px solid #D4AF37; border-radius: 12px; padding: 10px; margin: 10px 0; }
.act-row { display: flex; gap: 8px; flex-wrap: wrap; margin: 10px 0; }
.act-row .submit-btn { width: auto; margin-top: 0; padding: 9px 14px; font-size: 13px; }
</style>
</head>
<body>

    <!-- 1. شاشة تسجيل الدخول المسبقة للموظفين -->
    <div id="loginScreen">
        <div class="login-box">
            <div class="login-header">
                <h2>🏢 ${esc(data.agency_name)}</h2>
                <p>منظومة ميزان | تسجيل دخول الموظفين</p>
            </div>
            
            <div class="badge">🔐 بوابة تسجيل الدخول الآمنة</div>

            <form onsubmit="handleUserLogin(event)">
                <label style="color:#D4AF37;">اختر المستخدم / الموظف</label>
                ${users && users.length > 0 ? `
                <select id="loginUserSelect" onchange="syncSelectedUserText()" required style="background:#FAF4F1;">
                    ${users.map(u => `<option value="${esc(u.Username || u.username)}">${esc(u.FullName || u.fullName || u.Username)} (${esc(u.JobTitle || u.job_title || u.Role || 'محاسب')})</option>`).join('')}
                </select>
                <input type="hidden" id="loginUserInput" value="${esc(users[0].Username || users[0].username)}" />
                ` : `
                <input type="text" id="loginUserInput" placeholder="اسم المستخدم أو admin" required style="background:#FAF4F1;" />
                `}

                <label style="color:#D4AF37;">كلمة المرور</label>
                <input type="password" id="loginPassInput" placeholder="أدخل كلمة المرور الخاصة بك" required style="background:#FAF4F1;" />

                <button type="submit" class="submit-btn" style="background:#5A0817;margin-top:20px;">🚀 دخول للمنظومة</button>
                <div class="msg" id="loginErrorMsg"></div>
            </form>
        </div>
    </div>

    <!-- 2. الشاشة الرئيسية لجميع الأقسام والخدمات -->
    <div id="mainAppScreen">
        <div class="header">
            <h2>🏢 ${esc(data.agency_name)}</h2>
            <div style="font-size:11px; color:#C8B8B5; margin-top:4px;">اليومية: ${esc(data.logical_date)} | آخر مزامنة: ${new Date(data.last_sync).toLocaleTimeString('ar-EG', { timeZone: 'Africa/Cairo' })}</div>
            <div class="user-bar">
                <span id="activeUserLabel">👤 الموظف: --</span>
                <span id="offlineBadge" onclick="flushOffline()" style="cursor:pointer"></span>
            </div>
        </div>

        <!-- شريط الفلترة التاريخية -->
        <div class="date-bar">
            <label>📅 من:</label>
            <input type="date" id="filterFromDate" onchange="applyGlobalDateFilter()" />
            <label>إلى:</label>
            <input type="date" id="filterToDate" onchange="applyGlobalDateFilter()" />
            <button type="button" class="quick-btn" onclick="setDateRange('today')">اليوم</button>
            <button type="button" class="quick-btn" onclick="setDateRange('month')">الشهر الحالي</button>
            <button type="button" class="quick-btn" onclick="setDateRange('all')">عرض الكل</button>
            <span id="rangeLabel" class="note" style="margin-right:auto;"></span>
        </div>

        <!-- شريط علوي + قائمة جانبية منسدلة -->
        <div class="topbar">
            <button type="button" class="hamb" onclick="openDrawer()" aria-label="القائمة">☰</button>
            <span id="topTitle">🏠 الرئيسية</span>
        </div>
        <div id="drawerOverlay" class="drawer-overlay" onclick="closeDrawer()"></div>
        <aside id="drawer" class="drawer">
            <div class="drawer-head"><b>🏢 ${esc(data.agency_name)}</b><button type="button" class="drawer-x" onclick="closeDrawer()">✖</button></div>
            <div class="drawer-user" id="drawerUser">👤 --</div>
            <nav>
                ${NAV.map(g => `<div class="nav-group${g.open ? ' open' : ''}">
                    <button type="button" class="nav-gh" onclick="toggleGroup(this)"><span>${g.icon} ${g.name}</span><i>▾</i></button>
                    <div class="nav-gb">${g.items.map(it => `<button type="button" class="nav-item${it[0] === 'tab-dash' ? ' active' : ''}${it[3] ? ' priv-only' : ''}" data-tab="${it[0]}" data-title="${it[1]} ${it[2]}" onclick="switchTab('${it[0]}')"><span>${it[1]}</span>${it[2]}</button>`).join('')}</div>
                </div>`).join('')}
            </nav>
            <div class="drawer-foot"><a href="/account">👤 حسابي والاشتراك</a><button type="button" onclick="handleLogout()">🚪 خروج</button></div>
        </aside>

        <!-- 1. الرئيسية: كروت الأرباح والخزنة والمدفوعات والمديونيات -->
        <div id="tab-dash" class="tab-content active">
            ${syncLine}
            <div class="home-grid">
                <div class="big-card c-profit priv-only" onclick="switchTab('tab-profit')">
                    <div class="bc-top"><span class="bc-ico">📈</span>الأرباح</div>
                    <div class="bc-val">${fm(m.net_profit)} ج</div>
                    <div class="bc-sub">مبيعات اليوم: ${fm(m.today_sales)} ج</div>
                    <div class="bc-go">عرض التفاصيل ◂</div>
                </div>
                <div class="big-card c-treasury priv-only" onclick="switchTab('tab-treasury')">
                    <div class="bc-top"><span class="bc-ico">💰</span>الخزنة</div>
                    <div class="bc-val">${fm(drawerCash + bankTotal)} ج</div>
                    <div class="bc-sub">نقدية الدرج: ${fm(drawerCash)} • البنوك: ${fm(bankTotal)}</div>
                    <div class="bc-go">عرض التفاصيل ◂</div>
                </div>
                <div class="big-card c-pay" onclick="switchTab('tab-payments')">
                    <div class="bc-top"><span class="bc-ico">🧾</span>المدفوعات</div>
                    <div class="bc-val"><span data-sum="in+salepaid" data-unit=" ج">0 ج</span></div>
                    <div class="bc-sub">مقبوضات الفترة • مصروفات: <span data-sum="exp" data-unit=" ج">0 ج</span></div>
                    <div class="bc-go">عرض التفاصيل ◂</div>
                </div>
                <div class="big-card c-debt" onclick="switchTab('tab-debts')">
                    <div class="bc-top"><span class="bc-ico">📒</span>المديونيات</div>
                    <div class="bc-val">${fm(totalDebt)} ج</div>
                    <div class="bc-sub">${debtors.length} عميل مدين • آجل غير مسدد: ${fm(pendingTotal)} ج</div>
                    <div class="bc-go">عرض التفاصيل ◂</div>
                </div>
            </div>
            ${alerts.length ? `<div onclick="switchTab('tab-alerts')" style="cursor:pointer">${alertsHtml}</div>` : ''}
            <div class="chart-card"><b style="color:#5A0817">📊 آخر 7 أيام (من بيانات المزامنة)</b><div id="chart7"></div></div>
            <div class="mini-row">
                <div class="mini">💵 مبيعات اليوم<b>${fm(m.today_sales)} ج</b></div>
                <div class="mini">🚚 سيارات مفتوحة<b>${fm(m.open_cars_count)}</b></div>
                <div class="mini">📦 برانيك بالسوق<b>${fm(m.crates_in_market)}</b></div>
            </div>
            <p class="note">المدفوعات تتغير حسب الفترة المختارة بالأعلى، وباقي الأرقام كما أرسلها برنامج الكمبيوتر.</p>
        </div>

        <!-- تفاصيل: الأرباح -->
        <div id="tab-profit" class="tab-content" data-priv="1">
            <div class="pg-head"><button type="button" class="back-btn" onclick="switchTab('tab-dash')">▸ الرئيسية</button><h3>📈 الأرباح</h3></div>
            ${syncLine}
            <div class="tiles">
                <div class="tile">صافي الربح (من الكمبيوتر)<b>${fm(m.net_profit)} ج</b></div>
                <div class="tile">مبيعات اليوم<b>${fm(m.today_sales)} ج</b></div>
                <div class="tile">مبيعات الفترة<b data-sum="sale" data-unit=" ج">0 ج</b></div>
                <div class="tile">عدد الفواتير<b data-cnt="sale">0</b></div>
                <div class="tile red">مصروفات الفترة<b data-sum="exp" data-unit=" ج">0 ج</b></div>
                <div class="tile">تحصيلات الفترة<b data-sum="in" data-unit=" ج">0 ج</b></div>
            </div>
            <p class="note">صافي الربح يحسبه برنامج الكمبيوتر وقت المزامنة. بقية الأرقام تتغير حسب الفترة المختارة.</p>
            <h4 class="sec">فواتير المبيعات</h4>
            <div class="tbl-wrap"><table>
                <thead><tr><th>الفاتورة</th><th>التاريخ</th><th>العميل</th><th>الصنف</th><th>الإجمالي</th></tr></thead>
                <tbody id="profSalesBody">${recentSales.map(s => `<tr data-date="${esc((s.Date || s.date || '').slice(0, 10))}" data-k="sale" data-amt="${toN(s.Value || s.value)}"><td><b>${esc(s.InvoiceNo || s.invoiceNo)}</b></td><td>${esc(s.Date || s.date)}</td><td>${esc(s.Customer || s.customer)}</td><td>${esc(s.Item || s.item)}</td><td>${fm(s.Value || s.value)} ج</td></tr>`).join('')}</tbody>
            </table></div>
            <h4 class="sec">💸 مصروفات الفترة</h4>
            <div class="tbl-wrap"><table>
                <thead><tr><th>التاريخ</th><th>البند</th><th>البيان</th><th>المبلغ</th></tr></thead>
                <tbody id="profExpBody">${expenses.map(e => `<tr data-date="${esc((e.Date || e.date || '').slice(0, 10))}"><td>${esc(e.Date || e.date)}</td><td>${esc(e.Category || e.category)}</td><td>${esc(e.Description || e.description)}</td><td>${fm(e.Amount || e.amount)} ج</td></tr>`).join('')}</tbody>
            </table></div>
            <h4 class="sec">📥 تحصيلات الفترة</h4>
            <div class="tbl-wrap"><table>
                <thead><tr><th>السند</th><th>التاريخ</th><th>العميل</th><th>المبلغ</th><th>الطريقة</th></tr></thead>
                <tbody id="profColBody">${collections.map(c => `<tr data-date="${esc((c.Date || c.date || '').slice(0, 10))}"><td><b>${esc(c.ReceiptNo || c.receiptNo)}</b></td><td>${esc(c.Date || c.date)}</td><td>${esc(c.Customer || c.customer)}</td><td>${fm(c.Amount || c.amount)} ج</td><td>${esc(c.PaymentMethod || c.paymentMethod)}</td></tr>`).join('')}</tbody>
            </table></div>
        </div>

        <!-- تفاصيل: الخزنة -->
        <div id="tab-treasury" class="tab-content" data-priv="1">
            <div class="pg-head"><button type="button" class="back-btn" onclick="switchTab('tab-dash')">▸ الرئيسية</button><h3>💰 الخزنة</h3></div>
            ${syncLine}
            <div class="tiles">
                <div class="tile">نقدية الدرج<b>${fm(drawerCash)} ج</b></div>
                <div class="tile">أرصدة البنوك<b>${fm(bankTotal)} ج</b></div>
                <div class="tile">إجمالي الخزنة<b>${fm(drawerCash + bankTotal)} ج</b></div>
                <div class="tile red">مصروفات الفترة<b data-sum="exp" data-unit=" ج">0 ج</b></div>
            </div>
            <h4 class="sec">🏦 الحسابات البنكية</h4>
            ${bankAccounts.length ? `<div class="tbl-wrap"><table><tr><th>البنك / الحساب</th><th>رقم الحساب</th><th>الرصيد</th></tr>${bankAccounts.map(b => `<tr><td><b>${esc(b.BankName || b.bankName)}</b> (${esc(b.AccountName || b.accountName)})</td><td>${esc(b.AccountNumber || b.accountNumber)}</td><td>${fm(b.Balance || b.balance)} ج</td></tr>`).join('')}</table></div>` : '<div class="empty">لا توجد حسابات بنكية مسجلة.</div>'}
            <h4 class="sec">🧾 الشيكات</h4>
            ${checksTable(checks)}
            <button type="button" class="back-btn" style="margin-top:12px" onclick="switchTab('tab-exp')">عرض المصروفات وتسجيل مصروف ◂</button>
        </div>

        <!-- تفاصيل: المدفوعات -->
        <div id="tab-payments" class="tab-content">
            <div class="pg-head"><button type="button" class="back-btn" onclick="switchTab('tab-dash')">▸ الرئيسية</button><h3>🧾 المدفوعات</h3></div>
            ${syncLine}
            <div class="tiles">
                <div class="tile">مقبوض عند البيع<b data-sum="salepaid" data-unit=" ج">0 ج</b></div>
                <div class="tile">سندات التحصيل<b data-sum="in" data-unit=" ج">0 ج</b></div>
                <div class="tile">إجمالي المقبوضات<b data-sum="in+salepaid" data-unit=" ج">0 ج</b></div>
                <div class="tile red">المصروفات<b data-sum="exp" data-unit=" ج">0 ج</b></div>
            </div>
            <h4 class="sec">📥 سندات التحصيل</h4>
            <div class="tbl-wrap"><table>
                <thead><tr><th>السند</th><th>التاريخ</th><th>العميل</th><th>المبلغ</th><th>الطريقة</th></tr></thead>
                <tbody id="payInBody">${collections.map(c => `<tr data-date="${esc((c.Date || c.date || '').slice(0, 10))}" data-k="in" data-amt="${toN(c.Amount || c.amount)}"><td><b>${esc(c.ReceiptNo || c.receiptNo)}</b></td><td>${esc(c.Date || c.date)}</td><td>${esc(c.Customer || c.customer)}</td><td>${fm(c.Amount || c.amount)} ج</td><td>${esc(c.PaymentMethod || c.paymentMethod)}</td></tr>`).join('')}</tbody>
            </table></div>
            <h4 class="sec">💵 مبالغ مدفوعة عند البيع</h4>
            <div class="tbl-wrap"><table>
                <thead><tr><th>الفاتورة</th><th>التاريخ</th><th>العميل</th><th>المدفوع</th></tr></thead>
                <tbody id="salePaidBody">${recentSales.filter(s => toN(s.PaidAmount || s.paidAmount) > 0).map(s => `<tr data-date="${esc((s.Date || s.date || '').slice(0, 10))}" data-k="salepaid" data-amt="${toN(s.PaidAmount || s.paidAmount)}"><td><b>${esc(s.InvoiceNo || s.invoiceNo)}</b></td><td>${esc(s.Date || s.date)}</td><td>${esc(s.Customer || s.customer)}</td><td>${fm(s.PaidAmount || s.paidAmount)} ج</td></tr>`).join('')}</tbody>
            </table></div>
            <h4 class="sec">💸 المصروفات</h4>
            <div class="tbl-wrap"><table>
                <thead><tr><th>التاريخ</th><th>البند</th><th>البيان</th><th>المبلغ</th></tr></thead>
                <tbody id="payOutBody">${expenses.map(e => `<tr data-date="${esc((e.Date || e.date || '').slice(0, 10))}" data-k="exp" data-amt="${toN(e.Amount || e.amount)}"><td>${esc(e.Date || e.date)}</td><td>${esc(e.Category || e.category)}</td><td>${esc(e.Description || e.description)}</td><td>${fm(e.Amount || e.amount)} ج</td></tr>`).join('')}</tbody>
            </table></div>
            <h4 class="sec">📥 فواتير المشتريات</h4>
            ${genTable(purchases, 'لا توجد فواتير مشتريات.')}
        </div>

        <!-- تفاصيل: المديونيات -->
        <div id="tab-debts" class="tab-content">
            <div class="pg-head"><button type="button" class="back-btn" onclick="switchTab('tab-dash')">▸ الرئيسية</button><h3>📒 المديونيات</h3></div>
            ${syncLine}
            <div class="tiles">
                <div class="tile red">إجمالي المديونيات<b>${fm(totalDebt)} ج</b></div>
                <div class="tile">عدد العملاء المدينين<b>${debtors.length}</b></div>
                <div class="tile red">فواتير آجلة غير مسددة<b>${fm(pendingTotal)} ج</b></div>
                <div class="tile">أرصدة دائنة للعملاء<b>${fm(Math.abs(totalCredit))} ج</b></div>
            </div>
            <input type="text" id="debtSearch" placeholder="🔎 ابحث باسم العميل..." oninput="filterDebts()" />
            <h4 class="sec">العملاء المدينون (الأعلى مديونية أولاً)</h4>
            ${debtors.length ? `<div class="tbl-wrap"><table><thead><tr><th>العميل</th><th>المديونية</th><th>إجراء</th></tr></thead><tbody id="debtBody">${debtors.map(x => `<tr data-name="${esc(x.name)}"><td><b>${esc(x.name)}</b></td><td style="color:#DC2626;font-weight:bold;">${fm(x.bal)} ج</td><td><button type="button" class="mini-btn" data-cust="${esc(x.name)}" data-amt="${x.bal}" onclick="quickCollect(this)">💵 تحصيل</button> <button type="button" class="mini-btn" data-n="${esc(x.name)}" onclick="openStatement('c', this.getAttribute('data-n'))">📄 كشف</button></td></tr>`).join('')}</tbody></table></div>` : '<div class="empty">لا توجد مديونيات.</div>'}
            ${creditors.length ? `<h4 class="sec">أرصدة دائنة (للعميل عند الوكالة)</h4><div class="tbl-wrap"><table><thead><tr><th>العميل</th><th>الرصيد</th></tr></thead><tbody id="creditBody">${creditors.map(x => `<tr data-name="${esc(x.name)}"><td>${esc(x.name)}</td><td>${fm(Math.abs(x.bal))} ج</td></tr>`).join('')}</tbody></table></div>` : ''}
            <h4 class="sec">📄 الفواتير الآجلة غير المسددة</h4>
            ${pendingTable(pendingInv)}
        </div>

        <!-- شاشة عرض كود الوكالة والاقتران الفوري بالـ QR -->
        <div id="tab-key" class="tab-content" data-priv="1">
            <div class="form-card" style="text-align:center;">
                <h3 style="margin-top:0;color:#5A0817;">🔑 كود ربط الوكالة السحابي واقتران الهواتف</h3>
                <p style="color:#666;font-size:12.5px;">استخدم هذا الكود أو امسح الباركود بالكاميرا لربط أجهزة الكمبيوتر والهواتف بهذه الوكالة فوراً.</p>

                <div style="background:#FFF;border:2px dashed #D4AF37;border-radius:12px;padding:15px;display:inline-block;margin:10px auto;">
                    <img src="${esc(qrImageUrl)}" alt="QR Code" style="width:200px;height:200px;display:block;margin:auto;" />
                    <div style="font-size:11px;color:#888;margin-top:6px;">امسح من كاميرا الهاتف أو برنامج الكمبيوتر</div>
                </div>

                <div style="max-width:380px;margin:auto;text-align:right;">
                    <label>كود ربط الوكالة السري (Agency Sync Key):</label>
                    <div style="display:flex;gap:6px;">
                        <input type="text" id="dispKey" value="${esc(key)}" readonly style="text-align:center;font-weight:bold;font-family:Consolas;letter-spacing:1px;" />
                        <button type="button" class="btn" style="width:auto;margin:4px 0 0 0;padding:8px 14px;" onclick="copyText('dispKey')">📋 نسخ</button>
                    </div>

                    <label style="margin-top:12px;">رابط السيرفر السحابي (Cloud Server URL):</label>
                    <div style="display:flex;gap:6px;">
                        <input type="text" id="dispUrl" value="${esc(currentOrigin)}" readonly style="text-align:center;font-family:Consolas;" />
                        <button type="button" class="btn" style="width:auto;margin:4px 0 0 0;padding:8px 14px;" onclick="copyText('dispUrl')">📋 نسخ</button>
                    </div>
                </div>

                <div style="background:#FDF4DF;border:1px solid #D4AF37;border-radius:8px;padding:10px;margin-top:16px;text-align:right;font-size:12px;line-height:1.8;">
                    <b>💡 خطوات ربط برنامج الكمبيوتر:</b><br>
                    1. افتح برنامج <b>ميزان</b> على الكمبيوتر ➔ <b>الإعدادات</b> ➔ <b>الربط والمزامنة السحابية</b>.<br>
                    2. الصق <b>رابط السيرفر</b> في خانة (عنوان السيرفر السحابي).<br>
                    3. الصق <b>كود الوكالة</b> في خانة (كود ربط الوكالة السري) واضغط حفظ ثم <b>(مزامنة فورية الآن)</b>.
                </div>
            </div>
        </div>

        <!-- 2. نقطة البيع وسلة الفواتير (POS) -->
        <div id="tab-pos" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">🛒 إصدار فاتورة مبيعات سحابية</h3>
                <form id="f-pos" onsubmit="handlePosSubmit(event)">
                    <label>العميل / المشتري</label>
                    <select name="Customer" id="posCustSelect" required>
                        <option value="عميل نقدي">عميل نقدي</option>
                        ${customers.map(c => `<option value="${esc(getName(c))}">${esc(getName(c))} (مديونية: ${getBalance(c).toLocaleString()} ج)</option>`).join('')}
                    </select>

                    <label>سيارة المورد / الحمولة</label>
                    <select name="LoadKey" id="posLoadSelect">
                        <option value="" data-supplier="">مبيعات مباشرة (بدون سيارة)</option>
                        ${loads.map(l => `<option value="${esc(getSupplier(l))} | ${esc(getVehicle(l))} | ${esc(getDate(l))}" data-supplier="${esc(getSupplier(l))}">${esc(getSupplier(l))} | ${esc(getVehicle(l))} (${esc(getItem(l))})</option>`).join('')}
                    </select>

                    <label>الصنف</label>
                    <select name="Item" id="posItemSelect" required>
                        ${items.map(i => `<option value="${esc(getName(i))}" data-supplier="${esc(getSupplier(i))}" data-price="${getPrice(i)}">${esc(getName(i))} - [${esc(getSupplier(i))}]</option>`).join('')}
                    </select>

                    <div class="grid-2">
                        <div>
                            <label>العدد (صناديق)</label>
                            <input type="number" name="Qty" id="posQty" value="0" step="1" oninput="calcPosTotal()" />
                        </div>
                        <div>
                            <label>الوزن (كجم)</label>
                            <input type="number" name="Weight" id="posWeight" value="0" step="0.1" oninput="calcPosTotal()" />
                        </div>
                    </div>

                    <div class="grid-2">
                        <div>
                            <label>السعر (جنيه)</label>
                            <input type="number" name="Price" id="posPrice" value="0" step="0.5" required oninput="calcPosTotal()" />
                        </div>
                        <div>
                            <label>الخصم</label>
                            <input type="number" name="Discount" id="posDisc" value="0" step="1" oninput="calcPosTotal()" />
                        </div>
                    </div>

                    <label>طريقة السداد</label>
                    <select name="PaymentMethod" id="posPayMethod" onchange="calcPosTotal()">
                        <option value="نقدي (كاش)">نقدي (كاش)</option>
                        <option value="آجل على الحساب">آجل على الحساب</option>
                        <option value="إنستاباي (InstaPay)">إنستاباي (InstaPay)</option>
                        <option value="فودافون كاش / محفظة">فودافون كاش / محفظة</option>
                    </select>

                    <div class="card" style="margin-top:12px;background:#FDF4DF;border-right-color:#D4AF37;">
                        <div>الإجمالي المطلوب: <b id="posTotalTxt" style="font-size:18px;color:#5A0817;">0 ج</b></div>
                    </div>

                    <button type="submit" class="submit-btn">💾 حفظ الفاتورة وتمريرها للمزامنة</button>
                </form>
            </div>
        </div>

        <!-- 3. سجل المبيعات واليومية المفصلة -->
        <div id="tab-sales-reg" class="tab-content">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <h3 style="margin:0;">📋 سجل فواتير المبيعات</h3>
                <span id="salesSummaryBadge" style="font-weight:bold;color:#5A0817;"></span>
            </div>
            <table>
                <thead>
                    <tr><th>الفاتورة</th><th>التاريخ</th><th>العميل</th><th>الصنف</th><th>الوزن</th><th>الإجمالي</th><th>المدفوع</th><th>إجراء</th></tr>
                </thead>
                <tbody id="salesTableBody">
                    ${recentSales.map(s => `
                        <tr data-date="${esc((s.Date || s.date || '').slice(0, 10))}">
                            <td><b>${esc(s.InvoiceNo || s.invoiceNo)}</b></td>
                            <td>${esc(s.Date || s.date)}</td>
                            <td>${esc(s.Customer || s.customer)}</td>
                            <td>${esc(s.Item || s.item)}</td>
                            <td>${Number(s.Weight || s.weight || 0).toLocaleString()} ك</td>
                            <td>${Number(s.Value || s.value || 0).toLocaleString()} ج</td>
                            <td>${Number(s.PaidAmount || s.paidAmount || 0).toLocaleString()} ج</td>
                            <td><button type="button" class="priv-only" style="background:#5A0817;color:#D4AF37;border:1px solid #D4AF37;border-radius:4px;padding:3px 8px;cursor:pointer;" onclick="editInvoice('${esc(s.InvoiceNo || s.invoiceNo)}')">✏️ تعديل</button> <button type="button" class="priv-only" style="background:#DC2626;color:white;border:none;border-radius:4px;padding:3px 8px;cursor:pointer;" onclick="deleteInvoiceAction('${esc(s.InvoiceNo || s.invoiceNo)}')">🗑️ حذف</button></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <!-- 4. ساحة توريد السيارات -->
        <div id="tab-load" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">🚚 توريد وتنزيل سيارة بالأرضية</h3>
                <div class="grid-2">
                    <div>
                        <label>المورد / التاجر</label>
                        <select id="loadSuppSelect" required>
                            ${suppliers.map(s => `<option value="${esc(getName(s))}">${esc(getName(s))}</option>`).join('')}
                        </select>
                    </div>
                    <div>
                        <label>رقم / بيان السيارة</label>
                        <input type="text" id="loadVehInput" placeholder="مثال: 5412 نقل" required />
                    </div>
                </div>

                <div class="grid-2">
                    <div>
                        <label>نولون النقل الإجمالي (ج)</label>
                        <input type="number" id="loadFreightInput" value="0" />
                    </div>
                    <div>
                        <label>نسبة العمولة (%)</label>
                        <input type="number" id="loadCommInput" value="5" step="0.5" />
                    </div>
                </div>

                <div style="background:#F9FAFB;border:1px solid #D4AF37;border-radius:8px;padding:10px;margin-top:12px;">
                    <h4 style="margin:0 0 8px 0;color:#5A0817;">📦 إضافة صنف لحمولة السيارة:</h4>
                    <div class="grid-2">
                        <div>
                            <label>الصنف</label>
                            <select id="loadItemSelect">
                                ${items.map(i => `<option value="${esc(getName(i))}">${esc(getName(i))}</option>`).join('')}
                            </select>
                        </div>
                        <div>
                            <label>العدد الوارد (صناديق)</label>
                            <input type="number" id="loadItemQty" value="50" step="1" />
                        </div>
                    </div>
                    <div>
                        <label>الوزن الوارد (كجم)</label>
                        <input type="number" id="loadItemWt" value="1250" step="0.5" />
                    </div>
                    <button type="button" class="btn" style="background:#0D7857;margin-top:10px;" onclick="addItemToLoadCart()">➕ إضافة الصنف للسيارة</button>
                </div>

                <h4 style="margin:12px 0 4px 0;">الأصناف المحملة:</h4>
                <table id="loadItemsTable">
                    <thead><tr><th>الصنف</th><th>العدد</th><th>الوزن</th><th>حذف</th></tr></thead>
                    <tbody id="loadItemsTbody">
                        <tr><td colspan="4" style="text-align:center;color:#666;">لم يتم إضافة أصناف للسيارة بعد</td></tr>
                    </tbody>
                </table>

                <button type="button" class="submit-btn" style="margin-top:16px;" onclick="submitFullVehicleLoad()">🚚 تثبيت وحفظ السيارة بالأرضية</button>
            </div>
        </div>

        <!-- 5. تصفية سيارات الأمانة -->
        <div id="tab-settle" class="tab-content" data-priv="1">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">🚛 تصفية وإقفال سيارة أمانة</h3>
                <label>اختر السيارة للتصفية</label>
                <select id="settleLoadSelect" onchange="updateSettlePreview()">
                    <option value="">-- اختر السيارة --</option>
                    ${loads.map(l => `<option value="${esc(getSupplier(l))} | ${esc(getVehicle(l))} | ${esc(getDate(l))}" data-supplier="${esc(getSupplier(l))}" data-vehicle="${esc(getVehicle(l))}" data-freight="${toN(l.Freight || l.freight)}" data-freighttype="${esc(l.FreightType || l.freightType || 'fixed')}" data-comm="${toN(l.Commission != null ? l.Commission : (l.commission != null ? l.commission : 5))}" data-commtype="${esc(l.CommissionType || l.commissionType || 'percent')}">${esc(getSupplier(l))} | ${esc(getVehicle(l))} (${esc(getItem(l))})</option>`).join('')}
                </select>
                <label>خصم الهالك / التالف (جنيه)</label>
                <input type="number" id="settleDamage" value="0" step="1" min="0" oninput="updateSettlePreview()" />
                <label>ملاحظات</label>
                <input type="text" id="settleNotes" placeholder="اختياري" />
                <div id="settlePreviewBox" class="card" style="margin-top:12px;display:none;"></div>
                <div class="act-row">
                    <button type="button" class="submit-btn" onclick="submitSettle()">✅ تأكيد التصفية</button>
                    <button type="button" class="submit-btn" style="background:#2A040B" onclick="printSettle()">🖨️ طباعة كشف المورد</button>
                </div>
                <p class="note">الحساب من مبيعات هذه السيارة المزامنة من الكمبيوتر. بعد التأكيد تُرسل التصفية للكمبيوتر وتُنفّذ عند المزامنة القادمة.</p>
            </div>
        </div>

        <!-- 6. جرد بضاعة الأرضية -->
        <div id="tab-stock" class="tab-content">
            <h3>🚚 بضاعة الأرضية والسيارات المفتوحة (${esc(floorStock.length)})</h3>
            <div class="tbl-wrap"><table>
                <thead><tr><th>الصنف</th><th>السيارة</th><th>المورد</th><th>باقي عدد</th><th>باقي وزن</th><th>عمر السيارة</th></tr></thead>
                <tbody>
                ${stockRows.map(r => `<tr>
                        <td><b>${esc(r.f.Item || r.f.item)}</b></td>
                        <td>${esc(r.ve)}</td>
                        <td>${esc(r.su)}</td>
                        <td>${Number(r.f.QtyRemaining || r.f.qtyRemaining || 0).toLocaleString()} ق</td>
                        <td>${Number(r.f.WeightRemaining || r.f.weightRemaining || 0).toLocaleString()} ك</td>
                        <td>${r.days == null ? '-' : `<span class="bdg ${r.days >= 7 ? 'red' : r.days >= 3 ? 'amber' : ''}">${r.days} يوم</span>`}</td>
                    </tr>`).join('')}
                </tbody>
            </table></div>
        </div>

        <!-- 7. سندات التحصيل والمقبوضات -->
        <div id="tab-col" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">🧾 تسجيل سند قبض وتحصيل</h3>
                <form onsubmit="handleColSubmit(event)">
                    <label>العميل</label>
                    <select name="Customer" id="colCust" required>
                        ${customers.map(c => `<option value="${esc(getName(c))}">${esc(getName(c))} (مديونية: ${getBalance(c).toLocaleString()} ج)</option>`).join('')}
                    </select>
                    <label>المبلغ المحصل (جنيه)</label>
                    <input type="number" name="Amount" id="colAmount" step="1" required />
                    <label>طريقة الدفع</label>
                    <select name="PaymentMethod">
                        <option value="نقدي (كاش)">نقدي (كاش)</option>
                        <option value="إنستاباي (InstaPay)">إنستاباي (InstaPay)</option>
                        <option value="فودافون كاش / محفظة">فودافون كاش / محفظة</option>
                    </select>
                    <label>البيان / ملاحظات</label>
                    <input type="text" name="Notes" value="سداد دفعة بالحساب" />
                    <button type="submit" class="submit-btn">🧾 حفظ وتأكيد سند القبض</button>
                </form>
            </div>

            <h3>سندات التحصيل المسجلة</h3>
            <table>
                <thead>
                    <tr><th>رقم السند</th><th>التاريخ</th><th>العميل</th><th>المبلغ</th><th>طريقة الدفع</th><th>إجراء</th></tr>
                </thead>
                <tbody id="colTableBody">
                    ${collections.map(c => `
                        <tr data-date="${esc((c.Date || c.date || '').slice(0, 10))}">
                            <td><b>${esc(c.ReceiptNo || c.receiptNo)}</b></td>
                            <td>${esc(c.Date || c.date)}</td>
                            <td>${esc(c.Customer || c.customer)}</td>
                            <td>${Number(c.Amount || c.amount || 0).toLocaleString()} ج</td>
                            <td>${esc(c.PaymentMethod || c.paymentMethod)}</td>
                            <td><button type="button" class="priv-only" style="background:#DC2626;color:white;border:none;border-radius:4px;padding:3px 8px;cursor:pointer;" onclick="deleteColAction('${esc(c.ReceiptNo || c.receiptNo)}')">🗑️ حذف</button></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <!-- 8. الفواتير الآجلة والذمم -->
        <div id="tab-pending" class="tab-content">
            <h3>📄 كشف الفواتير الآجلة غير المسددة بالكامل</h3>
            ${pendingTable(pendingInv)}
        </div>

        <!-- 9. الخزينة والمصروفات والرواتب -->
        <div id="tab-exp" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">💸 صرف وتسجيل مصروف</h3>
                <form onsubmit="handleExpSubmit(event)">
                    <label>بند المصروف</label>
                    <select name="Category">
                        <option value="إكراميات وعتالة الأرضية">إكراميات وعتالة الأرضية</option>
                        <option value="بوفيه وضيافة">بوفيه وضيافة</option>
                        <option value="نولون ونقل">نولون ونقل</option>
                        <option value="صيانة ومستلزمات">صيانة ومستلزمات</option>
                        <option value="رواتب موظفين وعمال">رواتب موظفين وعمال</option>
                        <option value="مصاريف نثرية عامة">مصاريف نثرية عامة</option>
                    </select>
                    <label>البيان / تفاصيل الصرف</label>
                    <input type="text" name="Description" required />
                    <label>المبلغ المنصرف (جنيه)</label>
                    <input type="number" name="Amount" step="1" required />
                    <button type="submit" class="submit-btn">💸 خصم وصرف المصروف</button>
                </form>
            </div>

            <h3>المصروفات المسجلة</h3>
            <table>
                <thead>
                    <tr><th>التاريخ</th><th>البند</th><th>البيان</th><th>المبلغ</th><th>إجراء</th></tr>
                </thead>
                <tbody id="expTableBody">
                    ${expenses.map(e => `
                        <tr data-date="${esc((e.Date || e.date || '').slice(0, 10))}">
                            <td>${esc(e.Date || e.date)}</td>
                            <td>${esc(e.Category || e.category)}</td>
                            <td>${esc(e.Description || e.description)}</td>
                            <td>${Number(e.Amount || e.amount || 0).toLocaleString()} ج</td>
                            <td><button type="button" class="priv-only" style="background:#DC2626;color:white;border:none;border-radius:4px;padding:3px 8px;cursor:pointer;" onclick="deleteExpAction(${e.Id || e.id || 0})">🗑️ حذف</button></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <!-- 10. فواتير المشتريات -->
        <div id="tab-pur" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">📥 تسجيل فاتورة شراء بضاعة وأصول</h3>
                <form onsubmit="handlePurSubmit(event)">
                    <label>بند الشراء</label>
                    <select name="Category">
                        <option value="شراء بضاعة تجارية (تضاف للأرضية)">شراء بضاعة تجارية (تضاف للأرضية)</option>
                        <option value="شراء أثاث وديكور">شراء أثاث وديكور</option>
                        <option value="شراء أجهزة وموازين">شراء أجهزة وموازين</option>
                    </select>
                    <label>المورد / الجهة</label>
                    <select name="Supplier" required>
                        ${suppliers.map(s => `<option value="${esc(getName(s))}">${esc(getName(s))}</option>`).join('')}
                    </select>
                    <label>الصنف / البيان</label>
                    <input type="text" name="Item" required />
                    <div class="grid-2">
                        <div>
                            <label>الكمية</label>
                            <input type="number" name="Qty" value="1" />
                        </div>
                        <div>
                            <label>الوزن (كجم)</label>
                            <input type="number" name="Weight" value="0" />
                        </div>
                    </div>
                    <div class="grid-2">
                        <div>
                            <label>إجمالي القيمة (ج)</label>
                            <input type="number" name="Value" step="1" required />
                        </div>
                        <div>
                            <label>المدفوع نقداً</label>
                            <input type="number" name="PaidAmount" value="0" />
                        </div>
                    </div>
                    <button type="submit" class="submit-btn">📥 حفظ فاتورة الشراء</button>
                </form>
            </div>
        </div>

        <!-- 11. حركة الصناديق والبرانيك -->
        <div id="tab-crate" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">📦 حركة وتأمين الصناديق والبرانيك</h3>
                <form onsubmit="handleCrateSubmit(event)">
                    <label>العميل</label>
                    <select name="Customer" required>
                        ${customers.map(c => `<option value="${esc(getName(c))}">${esc(getName(c))}</option>`).join('')}
                    </select>
                    <label>نوع الحركة</label>
                    <select name="Kind">
                        <option value="تسليم">تسليم للعميل (+)</option>
                        <option value="استرجاع">استرجاع من العميل (-)</option>
                    </select>
                    <div class="grid-2">
                        <div>
                            <label>عدد الصناديق</label>
                            <input type="number" name="Qty" value="0" step="1" required />
                        </div>
                        <div>
                            <label>سعر التأمين (ج)</label>
                            <input type="number" name="Price" value="70" />
                        </div>
                    </div>
                    <label>
                        <input type="checkbox" name="IsCashCollected" style="width:auto;margin-left:6px;" checked />
                        تسوية رهن التأمين نقداً بالدرج
                    </label>
                    <button type="submit" class="submit-btn">📦 تثبيت حركة الصناديق</button>
                </form>
            </div>
        </div>

        <!-- 12. البنوك والشيكات -->
        <div id="tab-bank" class="tab-content" data-priv="1">
            <h3>🏦 الحسابات البنكية الجارية</h3>
            ${bankAccounts.length ? `<div class="tbl-wrap"><table>
                <thead><tr><th>البنك / الحساب</th><th>رقم الحساب</th><th>الرصيد</th></tr></thead>
                <tbody>${bankAccounts.map(b => `<tr>
                        <td><b>${esc(b.BankName || b.bankName)}</b> (${esc(b.AccountName || b.accountName)})</td>
                        <td>${esc(b.AccountNumber || b.accountNumber)}</td>
                        <td>${Number(b.Balance || b.balance || 0).toLocaleString()} ج</td>
                    </tr>`).join('')}</tbody>
            </table></div>` : '<div class="empty">لا توجد حسابات بنكية مسجلة.</div>'}
            <h3>🧾 الشيكات (المتأخرة والقريبة تظهر بتنبيه)</h3>
            ${checksTable(checks)}
        </div>

        <!-- 13. ميزان بسكول السيارات -->
        <div id="tab-wb" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">⚖️ تسجيل كارتة ميزان بسكول</h3>
                <form onsubmit="handleWbSubmit(event)">
                    <label>رقم السيارة</label>
                    <input type="text" name="Vehicle" required />
                    <label>اسم السائق</label>
                    <input type="text" name="DriverName" value="سائق حر" />
                    <label>المورد</label>
                    <select name="Supplier" required>
                        ${suppliers.map(s => `<option value="${esc(getName(s))}">${esc(getName(s))}</option>`).join('')}
                    </select>
                    <label>الصنف</label>
                    <select name="Item" required>
                        ${items.map(i => `<option value="${esc(getName(i))}">${esc(getName(i))}</option>`).join('')}
                    </select>
                    <div class="grid-2">
                        <div>
                            <label>الوزن القائم (كجم)</label>
                            <input type="number" name="GrossWeight" step="10" required />
                        </div>
                        <div>
                            <label>وزن الفارغ (كجم)</label>
                            <input type="number" name="TareWeight" step="10" required />
                        </div>
                    </div>
                    <button type="submit" class="submit-btn">⚖️ إصدار وحفظ كارتة البسكول</button>
                </form>
            </div>
        </div>

        <!-- 14. دليل الحسابات -->
        <div id="tab-master" class="tab-content">
            <div class="form-card priv-only">
                <h3 style="margin-top:0;color:#5A0817;">➕ إضافة عميل أو مورد</h3>
                <form onsubmit="handlePartySubmit(event)">
                    <div class="grid-2">
                        <div><label>النوع</label><select name="Kind" onchange="this.form.Extra.placeholder = this.value === 'c' ? 'الحد الائتماني (اختياري)' : 'نسبة العمولة %'"><option value="c">عميل</option><option value="s">مورد</option></select></div>
                        <div><label>الاسم</label><input type="text" name="Name" required /></div>
                    </div>
                    <div class="grid-2">
                        <div><label>الهاتف</label><input type="text" name="Phone" /></div>
                        <div><label>حد ائتماني / عمولة</label><input type="number" name="Extra" step="0.5" placeholder="الحد الائتماني (اختياري)" /></div>
                    </div>
                    <button type="submit" class="submit-btn">💾 حفظ وتمرير للمزامنة</button>
                </form>
            </div>
            <h3>👥 العملاء والموردين (${customers.length} عميل / ${suppliers.length} مورد)</h3>
            <div class="tbl-wrap"><table>
                <thead><tr><th>الاسم</th><th>الصفة</th><th>المديونية / الرصيد</th><th>إجراء</th></tr></thead>
                <tbody>
                ${customers.map(c => `<tr><td>${esc(getName(c))}</td><td>عميل</td><td>${getBalance(c).toLocaleString()} ج</td><td><button type="button" class="mini-btn" data-n="${esc(getName(c))}" onclick="openStatement('c', this.getAttribute('data-n'))">📄 كشف</button></td></tr>`).join('')}
                ${suppliers.map(s => `<tr><td>${esc(getName(s))}</td><td>مورد</td><td>عمولة: ${esc(s.DefaultCommission || s.defaultCommission || 0)}%</td><td><button type="button" class="mini-btn" data-n="${esc(getName(s))}" onclick="openStatement('s', this.getAttribute('data-n'))">📄 كشف</button></td></tr>`).join('')}
                </tbody>
            </table></div>
        </div>

        <!-- كشف حساب عميل / مورد -->
        <div id="tab-statement" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">📄 كشف حساب</h3>
                <div class="grid-2">
                    <div><label>النوع</label><select id="stType" onchange="fillStParties()"><option value="c">عميل</option><option value="s">مورد</option></select></div>
                    <div><label>الاسم</label><select id="stName"></select></div>
                </div>
                <button type="button" class="submit-btn" onclick="renderStatement()">عرض الكشف</button>
            </div>
            <div id="stOut"></div>
        </div>

        <!-- ملخص اليوم -->
        <div id="tab-day" class="tab-content" data-priv="1">
            <div class="pg-head"><h3>📆 ملخص يوم ${esc(dayStr)}</h3></div>
            ${syncLine}
            <div id="dayOut">
            <div class="tiles">
                <div class="tile">المبيعات<b>${fm(dSales)} ج</b></div>
                <div class="tile">عدد الفواتير<b>${dInv}</b></div>
                <div class="tile">مقبوض عند البيع<b>${fm(dPaid)} ج</b></div>
                <div class="tile red">آجل<b>${fm(dRem)} ج</b></div>
                <div class="tile">سندات التحصيل<b>${fm(dCol)} ج</b></div>
                <div class="tile red">المصروفات<b>${fm(dExp)} ج</b></div>
                <div class="tile">المشتريات<b>${fm(dPur)} ج</b></div>
                <div class="tile">نقدية الدرج<b>${fm(drawerCash)} ج</b></div>
            </div>
            </div>
            <div class="act-row">
                <button type="button" class="submit-btn" onclick="printOut('dayOut', 'ملخص اليوم')">🖨️ طباعة / PDF</button>
                <button type="button" class="submit-btn" style="background:#128C7E" data-text="${esc(dayText)}" onclick="shareWa(this.getAttribute('data-text'))">📲 مشاركة واتساب</button>
            </div>
            <p class="note">الأرقام من آخر مزامنة. إقفال اليومية نفسه يتم من برنامج الكمبيوتر.</p>
        </div>

        <!-- التنبيهات -->
        <div id="tab-alerts" class="tab-content">
            <div class="pg-head"><h3>🔔 التنبيهات</h3></div>
            ${alertsHtml}
        </div>

        <!-- سجل النشاط -->
        <div id="tab-log" class="tab-content" data-priv="1">
            <div class="pg-head"><h3>🕘 سجل النشاط</h3><button type="button" class="back-btn" onclick="loadActivity()">🔄 تحديث</button></div>
            <div class="tbl-wrap"><table><thead><tr><th>الوقت</th><th>المستخدم</th><th>العملية</th></tr></thead><tbody id="logBody"><tr><td colspan="3" class="empty">افتح الشاشة لتحميل السجل.</td></tr></tbody></table></div>
            <p class="note">آخر 200 عملية تمت من هذه البوابة (إضافة، تعديل، حذف، تصفية).</p>
        </div>

        <!-- 15. إعدادات الطابعات والشبكة -->
        <div id="tab-printer" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">🖨️ إعدادات الطابعات والشبكة (Mobile &amp; Thermal Printing)</h3>
                <label>مقاس الطباعة الافتراضي على الهاتف والمتصفح</label>
                <select id="webPrinterSize" onchange="savePrinterPrefs()">
                    <option value="80mm">حراري 80mm رول كاشير (بلوتوث / شبكة)</option>
                    <option value="58mm">حراري 58mm رول صغير</option>
                    <option value="A5">ورق عادي A5 (نصف ورقة)</option>
                    <option value="A4">ورق عادي A4 (ورقة كاملة)</option>
                </select>

                <label>عنوان IP طابعة الشبكة الحرارية (Network Thermal IP / اختياري)</label>
                <input type="text" id="netPrinterIp" placeholder="مثال: 192.168.1.200:9100" onchange="savePrinterPrefs()" />

                <label style="margin-top:12px;">
                    <input type="checkbox" id="chkAutoPrintWeb" onchange="savePrinterPrefs()" style="width:auto;margin-left:6px;" checked />
                    تشغيل نافذة الطباعة تلقائياً فور حفظ الفاتورة على الهاتف
                </label>

                <button type="button" class="submit-btn" style="background:#0D7857;" onclick="testWebPrint()">🖨️ تجربة طباعة إيصال اختباري الآن</button>
            </div>
        </div>
    </div>

    <!-- مساحة الطباعة المخفية -->
    <div id="printArea" style="display:none;"></div>

    <script>
    const AGENCY_KEY = "${esc(key)}";
    const AGENCY_NAME = ${jsonS(String(data.agency_name || ''))};
    const TODAY_C = ${jsonS(todayC)};
    const SALES = ${jsonS(C_SALES)};
    const COLS = ${jsonS(C_COLS)};
    const EXPS = ${jsonS(C_EXP)};
    const PURS = ${jsonS(C_PUR)};
    const LOADS = ${jsonS(C_LOADS)};
    const CUSTS = ${jsonS(C_CUST)};
    const SUPPS = ${jsonS(C_SUPP)};
    let currentUser = JSON.parse(localStorage.getItem('mizan_staff_' + AGENCY_KEY) || 'null');
    let vehicleCargoItems = [];
    const esc = s => String(s == null ? '' : s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;').split('"').join('&quot;');

    function syncScreenState() {
        applyRole();
        if (currentUser && currentUser.full_name && currentUser.token) {
            document.getElementById('loginScreen').style.display = 'none';
            document.getElementById('mainAppScreen').style.display = 'block';
            document.getElementById('activeUserLabel').innerHTML = '👤 الموظف: <b>' + currentUser.full_name + '</b> (' + (currentUser.job_title || currentUser.role) + ')';
            document.getElementById('drawerUser').innerHTML = document.getElementById('activeUserLabel').innerHTML;
        } else {
            document.getElementById('loginScreen').style.display = 'flex';
            document.getElementById('mainAppScreen').style.display = 'none';
        }
    }
    syncScreenState();

    function copyText(elemId) {
        const el = document.getElementById(elemId);
        if (!el) return;
        el.select();
        if (navigator.clipboard) {
            navigator.clipboard.writeText(el.value).then(() => alert('تم النسخ للحافظة بنجاح!'));
        }
    }

    function syncSelectedUserText() {
        const sel = document.getElementById('loginUserSelect');
        if (sel) {
            document.getElementById('loginUserInput').value = sel.value;
        }
    }

    async function handleUserLogin(e) {
        e.preventDefault();
        const msg = document.getElementById('loginErrorMsg');
        msg.textContent = 'جاري التحقق من الحساب...';
        try {
            const r = await fetch('/api/web/user-login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    agency_key: AGENCY_KEY,
                    username: document.getElementById('loginUserInput').value.trim(),
                    password: document.getElementById('loginPassInput').value
                })
            });
            const j = await r.json();
            if (!j.success) { msg.textContent = j.message || 'بيانات الدخول غير صحيحة'; return; }
            currentUser = j.user;
            currentUser.token = j.token;
            localStorage.setItem('mizan_staff_' + AGENCY_KEY, JSON.stringify(currentUser));
            document.getElementById('loginPassInput').value = '';
            msg.textContent = '';
            syncScreenState();
        } catch {
            msg.textContent = 'تعذر الاتصال بالسيرفر.';
        }
    }

    function handleLogout() {
        if (confirm('هل تريد بالتأكيد تسجيل الخروج وقفل الشاشة؟')) {
            currentUser = null;
            localStorage.removeItem('mizan_staff_' + AGENCY_KEY);
            syncScreenState();
        }
    }

    function openDrawer() {
        document.getElementById('drawer').classList.add('open');
        document.getElementById('drawerOverlay').classList.add('show');
        document.body.style.overflow = 'hidden';
    }
    function closeDrawer() {
        document.getElementById('drawer').classList.remove('open');
        document.getElementById('drawerOverlay').classList.remove('show');
        document.body.style.overflow = '';
    }
    function toggleGroup(btn) { btn.parentNode.classList.toggle('open'); }

    function switchTab(tabId) {
        const target = document.getElementById(tabId);
        if (target && target.getAttribute('data-priv') === '1' && !isPriv()) { toast('هذه الشاشة متاحة للمدير فقط', false); closeDrawer(); return; }
        document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
        if (target) target.classList.add('active');
        document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.getAttribute('data-tab') === tabId));
        const it = document.querySelector('.nav-item[data-tab="' + tabId + '"]');
        if (it) {
            const g = it.parentNode.parentNode;
            if (g) g.classList.add('open');
            document.getElementById('topTitle').textContent = it.getAttribute('data-title');
        }
        closeDrawer();
        window.scrollTo(0, 0);
        try { history.replaceState(null, '', '#' + tabId); } catch (e) {}
        if (tabId === 'tab-log') loadActivity();
    }

    function updateSummaries() {
        const sums = {};
        document.querySelectorAll('tr[data-k]').forEach(tr => {
            if (tr.getAttribute('data-dh') === '1') return;
            const k = tr.getAttribute('data-k');
            sums[k] = (sums[k] || 0) + (Number(tr.getAttribute('data-amt')) || 0);
            sums[k + '#n'] = (sums[k + '#n'] || 0) + 1;
        });
        document.querySelectorAll('[data-sum]').forEach(el => {
            let v = 0;
            el.getAttribute('data-sum').split('+').forEach(k => { v += sums[k] || 0; });
            el.textContent = v.toLocaleString() + (el.getAttribute('data-unit') || '');
        });
        document.querySelectorAll('[data-cnt]').forEach(el => { el.textContent = String(sums[el.getAttribute('data-cnt') + '#n'] || 0); });
    }

    function filterDebts() {
        const q = document.getElementById('debtSearch').value.trim().toLowerCase();
        document.querySelectorAll('#debtBody tr, #creditBody tr').forEach(tr => {
            tr.style.display = (tr.getAttribute('data-name') || '').toLowerCase().indexOf(q) > -1 ? '' : 'none';
        });
    }

    function setDateRange(type) {
        const today = new Date().toLocaleDateString('en-CA', { timeZone: 'Africa/Cairo' });
        const fromInput = document.getElementById('filterFromDate');
        const toInput = document.getElementById('filterToDate');

        if (type === 'today') {
            fromInput.value = today;
            toInput.value = today;
        } else if (type === 'month') {
            fromInput.value = today.slice(0, 7) + '-01';
            toInput.value = today;
        } else if (type === 'all') {
            fromInput.value = '';
            toInput.value = '';
        }
        applyGlobalDateFilter();
    }

    function applyGlobalDateFilter() {
        const from = document.getElementById('filterFromDate').value;
        const to = document.getElementById('filterToDate').value;
        const rl = document.getElementById('rangeLabel');
        if (rl) rl.textContent = (from || to) ? ('الفترة: ' + (from || 'البداية') + ' ← ' + (to || 'اليوم')) : 'الفترة: عرض الكل';

        ['salesTableBody', 'colTableBody', 'expTableBody', 'profSalesBody', 'profExpBody', 'profColBody', 'payInBody', 'salePaidBody', 'payOutBody'].forEach(bodyId => {
            const tbody = document.getElementById(bodyId);
            if (!tbody) return;
            const rows = tbody.querySelectorAll('tr');
            rows.forEach(tr => {
                const rowDate = tr.getAttribute('data-date');
                if (!rowDate) { tr.style.display = ''; tr.setAttribute('data-dh', '0'); return; }
                let show = true;
                if (from && rowDate < from) show = false;
                if (to && rowDate > to) show = false;
                tr.setAttribute('data-dh', show ? '0' : '1');
                tr.style.display = (show && tr.getAttribute('data-sh') !== '1') ? '' : 'none';
            });
        });
        updateSummaries();
    }

    function calcPosTotal() {
        const w = parseFloat(document.getElementById('posWeight').value) || 0;
        const q = parseFloat(document.getElementById('posQty').value) || 0;
        const p = parseFloat(document.getElementById('posPrice').value) || 0;
        const d = parseFloat(document.getElementById('posDisc').value) || 0;
        const base = w > 0 ? w : q;
        const tot = Math.max(0, (base * p) - d);
        document.getElementById('posTotalTxt').textContent = Math.round(tot).toLocaleString() + ' ج';
    }

    function addItemToLoadCart() {
        const item = document.getElementById('loadItemSelect').value;
        const q = parseFloat(document.getElementById('loadItemQty').value) || 0;
        const w = parseFloat(document.getElementById('loadItemWt').value) || 0;
        if (q <= 0 && w <= 0) { alert('أدخل كمية أو وزن صحيح'); return; }
        
        vehicleCargoItems.push({ Item: item, QtyIn: q, WeightIn: w });
        renderVehicleCargoTable();
    }

    function removeLoadItem(idx) {
        vehicleCargoItems.splice(idx, 1);
        renderVehicleCargoTable();
    }

    function renderVehicleCargoTable() {
        const tbody = document.getElementById('loadItemsTbody');
        if (vehicleCargoItems.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#666;">لم يتم إضافة أصناف للسيارة بعد</td></tr>';
            return;
        }
        tbody.innerHTML = vehicleCargoItems.map((it, idx) => \`
            <tr>
                <td><b>\${esc(it.Item)}</b></td>
                <td>\${it.QtyIn} ق</td>
                <td>\${it.WeightIn} ك</td>
                <td><button type="button" style="background:#DC2626;color:white;border:none;border-radius:4px;padding:2px 8px;cursor:pointer;" onclick="removeLoadItem(\${idx})">✕</button></td>
            </tr>
        \`).join('');
    }

    async function submitFullVehicleLoad() {
        const supp = document.getElementById('loadSuppSelect').value;
        const veh = document.getElementById('loadVehInput').value.trim();
        const fr = parseFloat(document.getElementById('loadFreightInput').value) || 0;
        const comm = parseFloat(document.getElementById('loadCommInput').value) || 5;

        if (!veh) { alert('يرجى إدخال رقم أو بيان السيارة'); return; }
        if (vehicleCargoItems.length === 0) { alert('يرجى إضافة صنف واحد على الأقل للسيارة'); return; }

        const data = {
            Supplier: supp,
            Vehicle: veh,
            Freight: fr,
            Commission: comm,
            FreightType: 'fixed',
            Items: vehicleCargoItems
        };

        const ok = await sendAction('LOAD_SUPPLY', data);
        if (ok) {
            vehicleCargoItems = [];
            document.getElementById('loadVehInput').value = '';
            document.getElementById('loadFreightInput').value = '0';
            renderVehicleCargoTable();
        }
    }

    function savePrinterPrefs() {
        const pSize = document.getElementById('webPrinterSize').value;
        const pIp = document.getElementById('netPrinterIp').value;
        const pAuto = document.getElementById('chkAutoPrintWeb').checked;
        localStorage.setItem('mizan_print_size', pSize);
        localStorage.setItem('mizan_print_ip', pIp);
        localStorage.setItem('mizan_print_auto', pAuto ? '1' : '0');
    }

    function loadPrinterPrefs() {
        const pSize = localStorage.getItem('mizan_print_size') || '80mm';
        const pIp = localStorage.getItem('mizan_print_ip') || '';
        const pAuto = localStorage.getItem('mizan_print_auto') !== '0';
        if (document.getElementById('webPrinterSize')) document.getElementById('webPrinterSize').value = pSize;
        if (document.getElementById('netPrinterIp')) document.getElementById('netPrinterIp').value = pIp;
        if (document.getElementById('chkAutoPrintWeb')) document.getElementById('chkAutoPrintWeb').checked = pAuto;
    }
    setTimeout(loadPrinterPrefs, 100);

    function testWebPrint() {
        printInvoiceReceipt({
            agencyName: "${esc(data.agency_name)}",
            invoiceNo: "SRV-TEST-001",
            customer: "عميل تجريبي",
            item: "طماطم فاخرة",
            qty: 50,
            weight: 125.0,
            price: 15.0,
            total: 1875.0,
            paid: 1875.0,
            remaining: 0
        });
    }

    function printInvoiceReceipt(inv) {
        const area = document.getElementById('printArea');
        area.style.display = 'block';
        area.innerHTML = \`
            <div style="font-family:Tahoma,sans-serif;width:280px;margin:auto;text-align:right;font-size:12px;padding:10px;">
                <h3 style="text-align:center;margin:0 0 5px 0;">\${esc(inv.agencyName)}</h3>
                <div style="text-align:center;font-size:11px;border-bottom:1px dashed #000;padding-bottom:5px;">فاتورة مبيعات #\${esc(inv.invoiceNo)}</div>
                <div style="margin:6px 0;">العميل: \${esc(inv.customer)}</div>
                <div style="margin:6px 0;">الصنف: \${esc(inv.item)} (\${inv.qty}ق / \${inv.weight}ك @ \${inv.price}ج)</div>
                <div style="font-weight:bold;font-size:14px;border-top:1px dashed #000;border-bottom:1px dashed #000;padding:5px 0;">الإجمالي: \${inv.total.toLocaleString()} جنيه</div>
                <div style="text-align:center;margin-top:10px;font-size:10px;">منظومة ميزان السحابية</div>
            </div>
        \`;
        window.print();
        setTimeout(() => { area.style.display = 'none'; }, 1000);
    }

    // ===== أدوات عامة =====
    function isPriv() { return !!(currentUser && currentUser.privileged); }
    function applyRole() { document.body.classList.toggle('nonpriv', !isPriv()); }
    var toastTimer = null;
    function toast(msg, ok) {
        var t = document.getElementById('toastBox');
        if (!t) { t = document.createElement('div'); t.id = 'toastBox'; document.body.appendChild(t); }
        t.className = 'toast' + (ok === false ? ' err' : '');
        t.textContent = msg; t.style.display = 'block';
        clearTimeout(toastTimer);
        toastTimer = setTimeout(function () { t.style.display = 'none'; }, 4500);
    }
    function uid() { return Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10); }
    function fmt(n) { return (Number(n) || 0).toLocaleString('en-US'); }
    function forceLogout() { currentUser = null; localStorage.removeItem('mizan_staff_' + AGENCY_KEY); syncScreenState(); }

    // ===== الإرسال: حماية من الضغط المزدوج + طابور عدم الاتصال =====
    var QK = 'mizan_offq_' + AGENCY_KEY;
    var sending = false, flushing = false;
    function getQ() { try { return JSON.parse(localStorage.getItem(QK) || '[]'); } catch (e) { return []; } }
    function setQ(q) { try { localStorage.setItem(QK, JSON.stringify(q)); } catch (e) {} updateOfflineBadge(); }
    function updateOfflineBadge() {
        var b = document.getElementById('offlineBadge'); if (!b) return;
        var n = getQ().length;
        b.style.display = n ? 'inline-block' : 'none';
        b.textContent = '⏳ ' + n + ' عملية بانتظار الإرسال (اضغط للمحاولة)';
    }
    async function postAction(item) {
        try {
            var r = await fetch('/api/web/create-action', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(item) });
            var j = null; try { j = await r.json(); } catch (e) {}
            return { status: r.status, json: j };
        } catch (e) { return { netErr: true }; }
    }
    async function flushOffline() {
        if (flushing) return;
        var q = getQ(); if (!q.length) return;
        flushing = true; var rest = [], sent = 0;
        for (var i = 0; i < q.length; i++) {
            var res = await postAction(q[i]);
            if (res.netErr || res.status >= 500) { rest = q.slice(i); break; }
            if (res.json && res.json.success) sent++;
            else toast('تعذر إرسال عملية محفوظة: ' + ((res.json && res.json.message) || res.status), false);
        }
        setQ(rest); flushing = false;
        if (sent) toast('تم إرسال ' + sent + ' عملية كانت معلّقة ✅');
    }
    async function sendAction(action_type, data) {
        if (!currentUser || !currentUser.full_name || !currentUser.token) { toast('انتهت الجلسة، سجّل الدخول من جديد', false); forceLogout(); return false; }
        if (sending) { toast('جاري إرسال عملية أخرى، انتظر لحظة...', false); return false; }
        sending = true; document.body.classList.add('busy');
        try {
            var item = { agency_key: AGENCY_KEY, action_type: action_type, user_name: currentUser.full_name, source: 'server', data: data, client_id: uid(), token: currentUser.token };
            var res = await postAction(item);
            if (res.netErr) {
                var q = getQ(); q.push(item); setQ(q);
                toast('لا يوجد اتصال: تم حفظ العملية على جهازك وستُرسل تلقائياً عند عودة الإنترنت');
                return true;
            }
            if (res.status === 402) { location.href = '/pay?key=' + encodeURIComponent(AGENCY_KEY); return false; }
            if (res.json && res.json.success) { toast(res.json.duplicate ? res.json.message : 'تم الحفظ وتمريره للمزامنة ✅'); return true; }
            toast('خطأ: ' + ((res.json && res.json.message) || 'فشلت العملية'), false);
            return false;
        } finally { sending = false; document.body.classList.remove('busy'); }
    }

    async function handlePosSubmit(e) {
        e.preventDefault();
        const f = e.target;
        const w = parseFloat(f.Weight.value) || 0;
        const q = parseFloat(f.Qty.value) || 0;
        const p = parseFloat(f.Price.value) || 0;
        const d = parseFloat(f.Discount.value) || 0;
        const base = w > 0 ? w : q;
        const val = Math.max(0, (base * p) - d);
        const isCash = f.PaymentMethod.value.includes('نقدي') || f.Customer.value === 'عميل نقدي';

        const itemSelect = document.getElementById('posItemSelect');
        const selectedItemOpt = itemSelect.options[itemSelect.selectedIndex];
        const supplierName = selectedItemOpt.getAttribute('data-supplier') || 'عام';

        const data = {
            Customer: f.Customer.value,
            LoadKey: f.LoadKey.value,
            PaymentMethod: f.PaymentMethod.value,
            PaidAmount: isCash ? val : 0,
            RemainingAmount: isCash ? 0 : val,
            Items: [{
                Item: f.Item.value,
                Supplier: supplierName,
                LoadKey: f.LoadKey.value,
                Qty: q,
                Weight: w,
                Price: p,
                Discount: d,
                Value: val
            }]
        };

        const ok = await sendAction('SALE_INVOICE', data);
        if (ok) {
            if (document.getElementById('chkAutoPrintWeb')?.checked) {
                printInvoiceReceipt({
                    agencyName: "${esc(data.agency_name)}",
                    invoiceNo: "SRV-AUTO",
                    customer: f.Customer.value,
                    item: f.Item.value,
                    qty: q,
                    weight: w,
                    price: p,
                    total: val,
                    paid: isCash ? val : 0,
                    remaining: isCash ? 0 : val
                });
            }
            f.reset();
            calcPosTotal();
        }
    }

    async function handleColSubmit(e) {
        e.preventDefault();
        const f = e.target;
        const data = {
            Customer: f.Customer.value,
            Amount: parseFloat(f.Amount.value) || 0,
            PaymentMethod: f.PaymentMethod.value,
            Notes: f.Notes.value
        };
        const ok = await sendAction('COLLECTION', data);
        if (ok) f.reset();
    }

    async function handleExpSubmit(e) {
        e.preventDefault();
        const f = e.target;
        const data = {
            Category: f.Category.value,
            Description: f.Description.value,
            Amount: parseFloat(f.Amount.value) || 0,
            PaymentMethod: 'نقدي (كاش)'
        };
        const ok = await sendAction('EXPENSE', data);
        if (ok) f.reset();
    }

    async function handlePurSubmit(e) {
        e.preventDefault();
        const f = e.target;
        const val = parseFloat(f.Value.value) || 0;
        const paid = parseFloat(f.PaidAmount.value) || 0;
        const data = {
            Category: f.Category.value,
            Supplier: f.Supplier.value,
            Item: f.Item.value,
            Qty: parseFloat(f.Qty.value) || 1,
            Weight: parseFloat(f.Weight.value) || 0,
            Value: val,
            PaidAmount: paid,
            RemainingAmount: Math.max(0, val - paid),
            PaymentMethod: 'نقدي (كاش)'
        };
        const ok = await sendAction('PURCHASE', data);
        if (ok) f.reset();
    }

    async function handleCrateSubmit(e) {
        e.preventDefault();
        const f = e.target;
        const data = {
            Customer: f.Customer.value,
            Qty: parseFloat(f.Qty.value) || 0,
            Price: parseFloat(f.Price.value) || 70,
            IsCashCollected: !!f.IsCashCollected?.checked
        };
        const ok = await sendAction(f.Kind.value === 'استرجاع' ? 'CRATE_RETURN' : 'CRATE_DELIVERY', data);
        if (ok) f.reset();
    }

    async function handleWbSubmit(e) {
        e.preventDefault();
        const f = e.target;
        const data = {
            Vehicle: f.Vehicle.value,
            DriverName: f.DriverName.value,
            Supplier: f.Supplier.value,
            Item: f.Item.value,
            GrossWeight: parseFloat(f.GrossWeight.value) || 0,
            TareWeight: parseFloat(f.TareWeight.value) || 0
        };
        const ok = await sendAction('WEIGHBRIDGE_TICKET', data);
        if (ok) f.reset();
    }

    async function deleteInvoiceAction(invNo) {
        if (confirm('هل تريد حذف الفاتورة #' + invNo + ' من السيرفر والديسكتوب؟')) {
            await sendAction('DELETE_INVOICE', { InvoiceNo: invNo });
        }
    }

    async function deleteColAction(recNo) {
        if (confirm('هل تريد حذف سند التحصيل #' + recNo + '؟')) {
            await sendAction('DELETE_COLLECTION', { ReceiptNo: recNo });
        }
    }

    async function deleteExpAction(expId) {
        if (confirm('هل تريد حذف هذا المصروف؟')) {
            await sendAction('DELETE_EXPENSE', { Id: expId });
        }
    }

    // ===== جداول: بحث + تصدير Excel + طباعة =====
    function bodyRows(t) { return Array.prototype.filter.call(t.querySelectorAll('tr'), function (tr) { return !tr.querySelector('th'); }); }
    function actionCols(t) {
        var idx = {};
        t.querySelectorAll('tr').forEach(function (tr) {
            Array.prototype.forEach.call(tr.children, function (c, i) {
                if (c.querySelector('button') || (c.tagName === 'TH' && c.textContent.trim() === 'إجراء')) idx[i] = 1;
            });
        });
        return idx;
    }
    function tableRowsText(t) {
        var idx = actionCols(t), out = [];
        t.querySelectorAll('tr').forEach(function (tr) {
            if (tr.style.display === 'none') return;
            var cells = [];
            Array.prototype.forEach.call(tr.children, function (c, i) {
                if (!idx[i]) cells.push(c.textContent.split(String.fromCharCode(10)).join(' ').trim());
            });
            if (cells.length) out.push(cells);
        });
        return out;
    }
    function csvCell(v) { return '"' + String(v).split('"').join('""') + '"'; }
    function exportCsv(tbls, name) {
        var NL = String.fromCharCode(10), lines = [];
        tbls.forEach(function (t, i) {
            if (i) lines.push('');
            tableRowsText(t).forEach(function (r) { lines.push(r.map(csvCell).join(',')); });
        });
        var blob = new Blob([String.fromCharCode(65279) + lines.join(NL)], { type: 'text/csv;charset=utf-8' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob); a.download = name + '-' + TODAY_C + '.csv';
        document.body.appendChild(a); a.click();
        setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
    }
    function tableHtml(t) {
        var c = t.cloneNode(true), idx = actionCols(c);
        c.querySelectorAll('tr').forEach(function (tr) {
            if (tr.style.display === 'none') { tr.parentNode.removeChild(tr); return; }
            var cells = Array.prototype.slice.call(tr.children);
            for (var i = cells.length - 1; i >= 0; i--) { if (idx[i]) tr.removeChild(cells[i]); }
        });
        return '<table>' + c.innerHTML + '</table>';
    }
    function openPrint(title, html) {
        var w = window.open('', '_blank');
        if (!w) { toast('اسمح بالنوافذ المنبثقة لإتمام الطباعة', false); return; }
        w.document.write('<!DOCTYPE html><html dir="rtl" lang="ar"><head><meta charset="UTF-8"><title>' + esc(title) + '</title><style>body{font-family:Tahoma,Arial,sans-serif;padding:16px;color:#000}table{width:100%;border-collapse:collapse;margin:8px 0}th,td{border:1px solid #444;padding:5px 7px;font-size:12px;text-align:right}th{background:#eee}.tile{display:inline-block;border:1px solid #444;padding:6px 10px;margin:3px;font-size:12px}.tile b{display:block;font-size:15px}button,.tb-tools,.act-row{display:none}</style></head><body><h2>' + esc(AGENCY_NAME) + '</h2><h3>' + esc(title) + '</h3><div style="font-size:11px;color:#555">التاريخ: ' + TODAY_C + '</div>' + html + '<p style="font-size:11px;color:#555;margin-top:20px">تم الإنشاء بواسطة منظومة ميزان</p></body></html>');
        w.document.close(); w.focus();
        setTimeout(function () { w.print(); }, 300);
    }
    function printOut(id, title) { openPrint(title, document.getElementById(id).innerHTML); }
    function shareWa(text) { window.open('https://wa.me/?text=' + encodeURIComponent(text), '_blank'); }
    function exportOut(id, name) { var ts = document.getElementById(id).querySelectorAll('table'); if (!ts.length) { toast('لا توجد جداول للتصدير', false); return; } exportCsv(Array.prototype.slice.call(ts), name); }

    function initTableTools() {
        document.querySelectorAll('.tab-content table').forEach(function (t) {
            if (t.closest('#tab-key') || t.closest('#tab-printer') || t.closest('#tab-day') || t.closest('#stOut') || t.querySelector('#debtBody') || t.querySelector('#creditBody') || t.querySelector('#logBody')) return;
            if (bodyRows(t).length < 6) return;
            var host = t.parentNode.classList.contains('tbl-wrap') ? t.parentNode : t;
            var bar = document.createElement('div'); bar.className = 'tb-tools';
            var inp = document.createElement('input'); inp.type = 'text'; inp.placeholder = '🔎 بحث في الجدول...';
            var bx = document.createElement('button'); bx.type = 'button'; bx.className = 'mini-btn'; bx.textContent = '⬇ Excel';
            var bp = document.createElement('button'); bp.type = 'button'; bp.className = 'mini-btn'; bp.textContent = '🖨️ PDF / طباعة';
            bar.appendChild(inp); bar.appendChild(bx); bar.appendChild(bp);
            host.parentNode.insertBefore(bar, host);
            inp.addEventListener('input', function () {
                var q = inp.value.trim().toLowerCase();
                bodyRows(t).forEach(function (tr) {
                    var ok = !q || tr.textContent.toLowerCase().indexOf(q) > -1;
                    tr.setAttribute('data-sh', ok ? '0' : '1');
                    tr.style.display = (!ok || tr.getAttribute('data-dh') === '1') ? 'none' : '';
                });
            });
            bx.addEventListener('click', function () { exportCsv([t], 'mizan'); });
            bp.addEventListener('click', function () { openPrint(document.getElementById('topTitle').textContent, tableHtml(t)); });
        });
    }

    // ===== تحصيل سريع =====
    function quickCollect(btn) {
        switchTab('tab-col');
        var sel = document.getElementById('colCust'), amt = document.getElementById('colAmount'), c = btn.getAttribute('data-cust');
        if (sel) { for (var i = 0; i < sel.options.length; i++) { if (sel.options[i].value === c) { sel.selectedIndex = i; break; } } }
        if (amt) { amt.value = btn.getAttribute('data-amt'); amt.focus(); }
    }

    // ===== نافذة + تعديل فاتورة =====
    var editState = null;
    function openModal(html) {
        closeModal();
        var bg = document.createElement('div'); bg.className = 'modal-bg'; bg.id = 'modalBg';
        bg.innerHTML = '<div class="modal">' + html + '</div>';
        document.body.appendChild(bg); document.body.style.overflow = 'hidden';
    }
    function closeModal() { var bg = document.getElementById('modalBg'); if (bg) bg.remove(); document.body.style.overflow = ''; }
    function editInvoice(no) {
        if (!isPriv()) { toast('التعديل للمدير فقط', false); return; }
        var rows = SALES.filter(function (x) { return x.n === no; });
        if (!rows.length) { toast('الفاتورة غير موجودة في البيانات المزامنة', false); return; }
        var paid = 0, rem = 0;
        rows.forEach(function (r) { paid += r.p; rem += r.r; });
        editState = { no: no, date: rows[0].d, auto: rem <= 0, rows: rows, total: 0 };
        var h = '<h3 style="margin-top:0;color:#5A0817">✏️ تعديل الفاتورة #' + esc(no) + '</h3><label>العميل</label><select id="edCust">';
        var names = ['عميل نقدي'];
        CUSTS.forEach(function (c) { if (names.indexOf(c.n) < 0) names.push(c.n); });
        if (names.indexOf(rows[0].c) < 0) names.push(rows[0].c);
        names.forEach(function (n) { h += '<option value="' + esc(n) + '"' + (n === rows[0].c ? ' selected' : '') + '>' + esc(n) + '</option>'; });
        h += '</select>';
        rows.forEach(function (r, i) {
            h += '<div class="line-box"><b>' + esc(r.i) + '</b><div class="grid-2"><div><label>العدد</label><input type="number" id="edQ' + i + '" value="' + r.q + '" oninput="calcEdit()"></div><div><label>الوزن</label><input type="number" id="edW' + i + '" value="' + r.w + '" step="0.1" oninput="calcEdit()"></div></div><div class="grid-2"><div><label>السعر</label><input type="number" id="edP' + i + '" value="' + r.pr + '" step="0.5" oninput="calcEdit()"></div><div><label>الخصم</label><input type="number" id="edD' + i + '" value="' + r.ds + '" oninput="calcEdit()"></div></div><div>قيمة البند: <b id="edV' + i + '"></b></div></div>';
        });
        var pays = ['نقدي (كاش)', 'آجل على الحساب', 'إنستاباي (InstaPay)', 'فودافون كاش / محفظة'];
        if (rows[0].pm && pays.indexOf(rows[0].pm) < 0) pays.push(rows[0].pm);
        h += '<label>طريقة السداد</label><select id="edPay">';
        pays.forEach(function (m) { h += '<option value="' + esc(m) + '"' + (m === rows[0].pm ? ' selected' : '') + '>' + esc(m) + '</option>'; });
        h += '</select><label>المدفوع (جنيه)</label><input type="number" id="edPaid" value="' + paid + '" oninput="editState.auto=false;calcEdit()">';
        h += '<div class="card" style="margin-top:10px">الإجمالي: <b id="edTotal"></b> — المتبقي: <b id="edRem"></b></div>';
        h += '<div class="act-row"><button type="button" class="submit-btn" onclick="saveEdit()">💾 حفظ التعديل</button><button type="button" class="submit-btn" style="background:#666" onclick="closeModal()">إلغاء</button></div>';
        h += '<p class="note">التعديل يستبدل الفاتورة القديمة بنفس رقمها ولا يضيف فاتورة جديدة.</p>';
        openModal(h); calcEdit();
    }
    function edNum(id) { return parseFloat(document.getElementById(id).value) || 0; }
    function calcEdit() {
        var total = 0;
        editState.rows.forEach(function (r, i) {
            var q = edNum('edQ' + i), w = edNum('edW' + i), p = edNum('edP' + i), d = edNum('edD' + i);
            var v = Math.max(0, (w > 0 ? w : q) * p - d);
            r._v = v; total += v;
            document.getElementById('edV' + i).textContent = fmt(Math.round(v)) + ' ج';
        });
        var pe = document.getElementById('edPaid');
        if (editState.auto) pe.value = Math.round(total);
        var paid = parseFloat(pe.value) || 0;
        editState.total = total;
        document.getElementById('edTotal').textContent = fmt(Math.round(total)) + ' ج';
        document.getElementById('edRem').textContent = fmt(Math.round(Math.max(0, total - paid))) + ' ج';
    }
    async function saveEdit() {
        calcEdit();
        var paid = edNum('edPaid'), total = editState.total;
        if (paid > total + 0.001) { toast('المدفوع أكبر من إجمالي الفاتورة', false); return; }
        var items = editState.rows.map(function (r, i) {
            return { Item: r.i, Supplier: r.su || 'عام', LoadKey: r.lk || '', Qty: edNum('edQ' + i), Weight: edNum('edW' + i), Price: edNum('edP' + i), Discount: edNum('edD' + i), Value: r._v };
        });
        var data = { InvoiceNo: editState.no, Date: editState.date, Customer: document.getElementById('edCust').value, PaymentMethod: document.getElementById('edPay').value, PaidAmount: paid, RemainingAmount: Math.max(0, total - paid), Items: items };
        if (!confirm('تأكيد تعديل الفاتورة #' + editState.no + '؟')) return;
        var ok = await sendAction('EDIT_INVOICE', data);
        if (ok) closeModal();
    }

    // ===== تصفية سيارات الأمانة =====
    function loadSales(l) {
        var t = 0, seen = {}, cnt = 0;
        SALES.forEach(function (s) {
            var m = s.lk ? s.lk === l.k : (s.su === l.s && s.ve === l.ve);
            if (m) { t += s.v; if (!seen[s.n]) { seen[s.n] = 1; cnt++; } }
        });
        return { total: t, count: cnt };
    }
    function loadFigures(l, damage) {
        var ls = loadSales(l);
        var comm = l.ct === 'percent' ? ls.total * l.cm / 100 : l.cm;
        var fr = l.ft === 'percent' ? ls.total * l.f / 100 : l.f;
        return { total: ls.total, count: ls.count, comm: comm, freight: fr, damage: damage || 0, net: ls.total - comm - fr - (damage || 0) };
    }
    function currentLoad() {
        var sel = document.getElementById('settleLoadSelect');
        if (!sel || sel.selectedIndex < 1) return null;
        return LOADS[sel.selectedIndex - 1] || null;
    }
    function settleHtml(l, f) {
        var rate = l.ct === 'percent' ? (l.cm + '%') : 'مبلغ ثابت';
        return '<div>المورد: <b>' + esc(l.s) + '</b> — السيارة: <b>' + esc(l.ve) + '</b> — ' + esc(l.i) + '</div>' +
            '<div>عدد الفواتير: <b>' + f.count + '</b></div>' +
            '<div>إجمالي المبيعات: <b>' + fmt(Math.round(f.total)) + ' ج</b></div>' +
            '<div>العمولة (' + rate + '): <b>' + fmt(Math.round(f.comm)) + ' ج</b></div>' +
            '<div>النولون: <b>' + fmt(Math.round(f.freight)) + ' ج</b></div>' +
            '<div>الهالك / التالف: <b>' + fmt(Math.round(f.damage)) + ' ج</b></div>' +
            '<div style="margin-top:6px;font-size:16px">صافي المورد: <b style="color:' + (f.net < 0 ? '#DC2626' : '#0D7857') + '">' + fmt(Math.round(f.net)) + ' ج</b></div>' +
            (f.total <= 0 ? '<div style="color:#B45309;margin-top:6px">⚠️ لا توجد مبيعات مسجلة لهذه السيارة في البيانات المزامنة.</div>' : '');
    }
    function updateSettlePreview() {
        var box = document.getElementById('settlePreviewBox'), l = currentLoad();
        if (!l) { box.style.display = 'none'; return; }
        box.style.display = 'block';
        box.innerHTML = settleHtml(l, loadFigures(l, edNumSafe('settleDamage')));
    }
    function edNumSafe(id) { var e = document.getElementById(id); return e ? (parseFloat(e.value) || 0) : 0; }
    async function submitSettle() {
        var l = currentLoad();
        if (!l) { toast('اختر السيارة أولاً', false); return; }
        var dmg = edNumSafe('settleDamage'), f = loadFigures(l, dmg);
        if (f.total <= 0 && !confirm('لا توجد مبيعات لهذه السيارة. هل تريد المتابعة؟')) return;
        if (f.net < 0 && !confirm('صافي المورد بالسالب. هل تريد المتابعة؟')) return;
        if (!confirm('تأكيد تصفية سيارة ' + l.ve + ' للمورد ' + l.s + ' بصافي ' + fmt(Math.round(f.net)) + ' ج؟')) return;
        await sendAction('SETTLE_VEHICLE', { LoadKey: l.k, Supplier: l.s, Vehicle: l.ve, TotalSales: f.total, CommissionRate: l.cm, CommissionType: l.ct, CommissionAmount: f.comm, Freight: f.freight, Damage: dmg, NetDue: f.net, Notes: document.getElementById('settleNotes').value });
    }
    function printSettle() {
        var l = currentLoad();
        if (!l) { toast('اختر السيارة أولاً', false); return; }
        openPrint('كشف تصفية سيارة أمانة', '<div style="line-height:2">' + settleHtml(l, loadFigures(l, edNumSafe('settleDamage'))) + '</div>');
    }

    // ===== كشوف الحساب =====
    var stText = '';
    function htmlTable(headers, rows) {
        var h = '<div class="tbl-wrap"><table><thead><tr>' + headers.map(function (x) { return '<th>' + x + '</th>'; }).join('') + '</tr></thead><tbody>';
        rows.forEach(function (r) { h += '<tr>' + r.map(function (c) { return '<td>' + c + '</td>'; }).join('') + '</tr>'; });
        return h + '</tbody></table></div>';
    }
    function fillStParties() {
        var sel = document.getElementById('stName'), t = document.getElementById('stType');
        if (!sel || !t) return;
        var arr = t.value === 'c' ? CUSTS : SUPPS;
        sel.innerHTML = arr.map(function (x) { return '<option value="' + esc(x.n) + '">' + esc(x.n) + '</option>'; }).join('');
    }
    function openStatement(type, name) {
        switchTab('tab-statement');
        document.getElementById('stType').value = type; fillStParties();
        document.getElementById('stName').value = name; renderStatement();
    }
    function tile(label, val, red) { return '<div class="tile' + (red ? ' red' : '') + '"><span>' + label + '</span><b>' + val + '</b></div>'; }
    function renderStatement() {
        var type = document.getElementById('stType').value, name = document.getElementById('stName').value, out = document.getElementById('stOut');
        if (!name) { out.innerHTML = '<div class="empty">اختر الاسم أولاً.</div>'; return; }
        var html = '', NL = String.fromCharCode(10);
        if (type === 'c') {
            var inv = {}, order = [];
            SALES.forEach(function (s) {
                if (s.c !== name) return;
                if (!inv[s.n]) { inv[s.n] = { n: s.n, d: s.d, v: 0, p: 0, r: 0 }; order.push(s.n); }
                inv[s.n].v += s.v; inv[s.n].p += s.p; inv[s.n].r += s.r;
            });
            var list = order.map(function (k) { return inv[k]; }).sort(function (a, b) { return a.d < b.d ? 1 : -1; });
            var cols = COLS.filter(function (c) { return c.c === name; }).sort(function (a, b) { return a.d < b.d ? 1 : -1; });
            var tv = 0, tp = 0, tr = 0, tc = 0, bal = 0;
            list.forEach(function (x) { tv += x.v; tp += x.p; tr += x.r; });
            cols.forEach(function (c) { tc += c.a; });
            CUSTS.forEach(function (c) { if (c.n === name) bal = c.b; });
            html = '<div class="form-card" id="stCard"><h3 style="margin-top:0;color:#5A0817">كشف حساب العميل: ' + esc(name) + '</h3><div class="note">' + esc(AGENCY_NAME) + ' — بتاريخ ' + TODAY_C + '</div><div class="tiles">' +
                tile('إجمالي المبيعات', fmt(tv) + ' ج') + tile('مدفوع عند البيع', fmt(tp) + ' ج') + tile('آجل', fmt(tr) + ' ج', 1) + tile('سندات التحصيل', fmt(tc) + ' ج') + tile('الرصيد الحالي', fmt(bal) + ' ج', bal > 0) + '</div>' +
                '<h4 class="sec">الفواتير</h4>' + (list.length ? htmlTable(['الفاتورة', 'التاريخ', 'الإجمالي', 'المدفوع', 'المتبقي'], list.map(function (x) { return [esc(x.n), esc(x.d), fmt(x.v), fmt(x.p), fmt(x.r)]; })) : '<div class="empty">لا توجد فواتير في البيانات المزامنة.</div>') +
                '<h4 class="sec">سندات التحصيل</h4>' + (cols.length ? htmlTable(['السند', 'التاريخ', 'المبلغ', 'الطريقة'], cols.map(function (c) { return [esc(c.n), esc(c.d), fmt(c.a), esc(c.m)]; })) : '<div class="empty">لا توجد سندات.</div>') +
                '<p class="note">الرصيد الحالي كما وصل من برنامج الكمبيوتر، والفواتير والسندات هي آخر ما تمت مزامنته.</p></div>';
            stText = 'كشف حساب العميل ' + name + ' - ' + AGENCY_NAME + NL + 'إجمالي المبيعات: ' + fmt(tv) + ' ج' + NL + 'سندات التحصيل: ' + fmt(tc) + ' ج' + NL + 'الرصيد الحالي: ' + fmt(bal) + ' ج';
        } else {
            var mine = LOADS.filter(function (l) { return l.s === name; }), gt = 0, gc = 0, gf = 0, rows = [];
            mine.forEach(function (l) {
                var f = loadFigures(l, 0);
                gt += f.total; gc += f.comm; gf += f.freight;
                rows.push([esc(l.d), esc(l.ve), esc(l.i), fmt(Math.round(f.total)), fmt(Math.round(f.comm)), fmt(Math.round(f.freight)), fmt(Math.round(f.net))]);
            });
            var pv = 0, pp = 0, prow = [];
            PURS.forEach(function (p) { if (p.s === name) { pv += p.v; pp += p.p; prow.push([esc(p.d), esc(p.i), fmt(p.v), fmt(p.p), fmt(Math.max(0, p.v - p.p))]); } });
            var net = gt - gc - gf;
            html = '<div class="form-card" id="stCard"><h3 style="margin-top:0;color:#5A0817">كشف حساب المورد: ' + esc(name) + '</h3><div class="note">' + esc(AGENCY_NAME) + ' — بتاريخ ' + TODAY_C + '</div><div class="tiles">' +
                tile('عدد السيارات', mine.length) + tile('إجمالي المبيعات', fmt(Math.round(gt)) + ' ج') + tile('العمولة', fmt(Math.round(gc)) + ' ج') + tile('النولون', fmt(Math.round(gf)) + ' ج') + tile('الصافي التقديري', fmt(Math.round(net)) + ' ج') + tile('مشتريات من المورد', fmt(pv) + ' ج') + '</div>' +
                '<h4 class="sec">السيارات</h4>' + (rows.length ? htmlTable(['التاريخ', 'السيارة', 'الصنف', 'المبيعات', 'العمولة', 'النولون', 'الصافي'], rows) : '<div class="empty">لا توجد سيارات لهذا المورد.</div>') +
                (prow.length ? '<h4 class="sec">فواتير المشتريات</h4>' + htmlTable(['التاريخ', 'الصنف', 'القيمة', 'المدفوع', 'المتبقي'], prow) : '') +
                '<p class="note">الصافي تقديري قبل الهالك وأي تصفيات سابقة. استخدم شاشة التصفية للإقفال.</p></div>';
            stText = 'كشف حساب المورد ' + name + ' - ' + AGENCY_NAME + NL + 'عدد السيارات: ' + mine.length + NL + 'إجمالي المبيعات: ' + fmt(Math.round(gt)) + ' ج' + NL + 'العمولة: ' + fmt(Math.round(gc)) + ' ج' + NL + 'النولون: ' + fmt(Math.round(gf)) + ' ج' + NL + 'الصافي التقديري: ' + fmt(Math.round(net)) + ' ج';
        }
        html += '<div class="act-row"><button type="button" class="submit-btn" onclick="printOut(\\'stCard\\', \\'كشف حساب\\')">🖨️ طباعة / PDF</button><button type="button" class="submit-btn" style="background:#128C7E" onclick="shareWa(stText)">📲 مشاركة واتساب</button><button type="button" class="submit-btn" style="background:#2A040B" onclick="exportOut(\\'stCard\\', \\'kashf\\')">⬇ Excel</button></div>';
        out.innerHTML = html;
    }

    // ===== إضافة عميل / مورد =====
    async function handlePartySubmit(e) {
        e.preventDefault();
        var f = e.target, isC = f.Kind.value === 'c', x = parseFloat(f.Extra.value) || 0;
        var data = { Name: f.Name.value.trim(), Phone: f.Phone.value.trim() };
        if (isC) data.CreditLimit = x; else data.DefaultCommission = x || 5;
        var ok = await sendAction(isC ? 'ADD_CUSTOMER' : 'ADD_SUPPLIER', data);
        if (ok) f.reset();
    }

    // ===== رسم آخر 7 أيام =====
    function chart7() {
        var box = document.getElementById('chart7'); if (!box) return;
        var days = [], i;
        for (i = 6; i >= 0; i--) { var d = new Date(TODAY_C + 'T12:00:00Z'); d.setUTCDate(d.getUTCDate() - i); days.push(d.toISOString().slice(0, 10)); }
        function sum(arr, key) { var m = {}; arr.forEach(function (x) { m[x.d] = (m[x.d] || 0) + x[key]; }); return days.map(function (dd) { return m[dd] || 0; }); }
        var series = [{ n: 'مبيعات', c: '#0D7857', v: sum(SALES, 'v') }, { n: 'تحصيلات', c: '#2563EB', v: sum(COLS, 'a') }, { n: 'مصروفات', c: '#DC2626', v: sum(EXPS, 'a') }];
        var max = 1; series.forEach(function (s) { s.v.forEach(function (x) { if (x > max) max = x; }); });
        var W = 700, H = 210, padB = 30, padT = 12, gw = W / 7, bw = 16;
        var svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" style="width:100%;height:auto">';
        days.forEach(function (dd, di) {
            series.forEach(function (s, si) {
                var h = Math.round((s.v[di] / max) * (H - padB - padT)), x = di * gw + gw / 2 - 26 + si * (bw + 2), y = H - padB - h;
                svg += '<rect x="' + x + '" y="' + y + '" width="' + bw + '" height="' + h + '" rx="3" fill="' + s.c + '"><title>' + s.n + ': ' + fmt(s.v[di]) + '</title></rect>';
            });
            svg += '<text x="' + (di * gw + gw / 2) + '" y="' + (H - 10) + '" font-size="12" text-anchor="middle" fill="#5A0817">' + dd.slice(8) + '/' + dd.slice(5, 7) + '</text>';
        });
        svg += '</svg>';
        var legend = '<div style="display:flex;gap:12px;flex-wrap:wrap;font-size:12px;margin-top:4px">' + series.map(function (s) { return '<span><i style="display:inline-block;width:10px;height:10px;background:' + s.c + ';border-radius:2px;margin-left:4px"></i>' + s.n + ' (' + fmt(s.v.reduce(function (a, b) { return a + b; }, 0)) + ')</span>'; }).join('') + '</div>';
        box.innerHTML = svg + legend;
    }

    // ===== سجل النشاط =====
    async function loadActivity() {
        var body = document.getElementById('logBody');
        body.innerHTML = '<tr><td colspan="3">جاري التحميل...</td></tr>';
        try {
            var r = await fetch('/api/web/activity?key=' + encodeURIComponent(AGENCY_KEY), { headers: { 'x-session-token': currentUser.token } });
            var j = await r.json();
            if (!j.success) { body.innerHTML = '<tr><td colspan="3">' + esc(j.message || 'تعذر التحميل') + '</td></tr>'; return; }
            body.innerHTML = j.items.length ? j.items.map(function (x) { return '<tr><td>' + esc(x.ts ? new Date(x.ts).toLocaleString('ar-EG', { timeZone: 'Africa/Cairo' }) : '') + '</td><td>' + esc(x.user) + '</td><td>' + esc(x.summary) + '</td></tr>'; }).join('') : '<tr><td colspan="3">لا توجد عمليات مسجلة بعد.</td></tr>';
        } catch (e) { body.innerHTML = '<tr><td colspan="3">تعذر الاتصال بالسيرفر.</td></tr>'; }
    }

    initTableTools(); chart7(); fillStParties(); updateOfflineBadge(); flushOffline();
    window.addEventListener('online', flushOffline);
    setInterval(flushOffline, 30000);

    setDateRange('today');
    updateSummaries();
    (function () {
        const h = (location.hash || '').replace('#', '');
        if (h.indexOf('tab-') === 0 && document.getElementById(h)) switchTab(h);
    })();
    </script>
</body>
</html>
`);
        }

        res.statusCode = 404;
        return res.end("Not Found");
    } catch (err) {
        console.error(err);
        return sendJson(res, 500, { success: false, message: 'خطأ في السيرفر السحابي.' });
    }
};
