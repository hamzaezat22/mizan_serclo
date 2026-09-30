const { Redis } = require('@upstash/redis');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN
});

const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const versionInfo = {
    latest_version: "2.1.0",
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
                return sendJson(res, 200, {
                    success: true,
                    user: {
                        id: matchedUser.Id || matchedUser.id || 1,
                        username: matchedUser.Username || matchedUser.username,
                        full_name: matchedUser.FullName || matchedUser.fullName || matchedUser.full_name,
                        role: matchedUser.Role || matchedUser.role || 'محاسب',
                        job_title: matchedUser.JobTitle || matchedUser.job_title || 'محاسب'
                    }
                });
            }

            if (ownerUser && (ownerUser.username.toLowerCase() === cleanUser || cleanUser === 'admin')) {
                const hash = await hashPassword(password, ownerUser.salt);
                if (hash === ownerUser.password_hash) {
                    return sendJson(res, 200, {
                        success: true,
                        user: { id: 1, username: ownerUser.username, full_name: `${ownerUser.agency_name} (المدير العام)`, role: 'admin', job_title: 'مدير عام' }
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

            const queueKey = `orders_queue:${agency_key}`;
            const queuedOrders = await redis.get(queueKey) || [];

            const dateStr = data.Date || new Date().toISOString().slice(0, 10);
            const authorFormatted = `${user_name || "مستخدم"} (${source === 'mobile' ? 'مستخدم الهاتف' : 'مستخدم السيرفر'})`;
            const prefix = source === 'mobile' ? 'MOB' : 'SRV';
            const seq = Math.floor(1000 + Math.random() * 9000);
            const uniqueOrderId = `ORD-${Date.now()}-${seq}`;

            switch (action_type) {
                case 'SALE_INVOICE': {
                    const invNo = data.InvoiceNo || `${prefix}-${dateStr.replace(/-/g, '')}-${seq}`;
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
            }

            await redis.set(queueKey, queuedOrders, { ex: 60 * 60 * 24 * 7 });
            return sendJson(res, 200, { success: true, message: `تم تسجيل المعاملة بنجاح وتوليد المعرف [${uniqueOrderId}] وتمريرها للمزامنة.` });
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
                <div>
                    <button type="button" class="tab-btn" style="background:#D4AF37;color:#200308;padding:4px 10px;font-size:11px;margin-left:6px;" onclick="switchTab('tab-key', this)">🔑 كود الوكالة والاقتران</button>
                    <button class="logout-btn" onclick="handleLogout()">🚪 خروج</button>
                </div>
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
        </div>

        <!-- شريط التنقل للأقسام -->
        <div class="nav-scroll">
            <button class="tab-btn active" onclick="switchTab('tab-dash', this)">📊 المؤشرات الحية</button>
            <button class="tab-btn" onclick="switchTab('tab-pos', this)">🛒 نقطة البيع (POS)</button>
            <button class="tab-btn" onclick="switchTab('tab-sales-reg', this)">📋 سجل المبيعات</button>
            <button class="tab-btn" onclick="switchTab('tab-load', this)">🚚 ساحة توريد السيارات</button>
            <button class="tab-btn" onclick="switchTab('tab-settle', this)">🚛 تصفية سيارات الأمانة</button>
            <button class="tab-btn" onclick="switchTab('tab-stock', this)">📦 جرد بضاعة الأرضية</button>
            <button class="tab-btn" onclick="switchTab('tab-col', this)">🧾 سندات التحصيل</button>
            <button class="tab-btn" onclick="switchTab('tab-pending', this)">📄 الفواتير الآجلة</button>
            <button class="tab-btn" onclick="switchTab('tab-exp', this)">💸 الخزينة والمصروفات</button>
            <button class="tab-btn" onclick="switchTab('tab-pur', this)">📥 فواتير المشتريات</button>
            <button class="tab-btn" onclick="switchTab('tab-crate', this)">📦 حركة الصناديق والرهن</button>
            <button class="tab-btn" onclick="switchTab('tab-bank', this)">🏦 البنوك والشيكات</button>
            <button class="tab-btn" onclick="switchTab('tab-wb', this)">⚖️ ميزان بسكول</button>
            <button class="tab-btn" onclick="switchTab('tab-master', this)">👥 دليل الحسابات</button>
            <button class="tab-btn" onclick="switchTab('tab-key', this)">🔑 كود الوكالة والاقتران</button>
            <button class="tab-btn" onclick="switchTab('tab-printer', this)">🖨️ إعدادات الطابعات</button>
        </div>

        <!-- 1. المؤشرات الحية -->
        <div id="tab-dash" class="tab-content active">
            <div class="card">
                <div>💰 نقدية الدرج الحالية:</div>
                <div class="val">${Number(m.drawer_cash || 0).toLocaleString()} ج</div>
            </div>
            <div class="card">
                <div>💵 مبيعات اليوم:</div>
                <div class="val" style="color:#5A0817;">${Number(m.today_sales || 0).toLocaleString()} ج</div>
            </div>
            <div class="card">
                <div>📈 أرباح الوكالة اليومية:</div>
                <div class="val">${Number(m.net_profit || 0).toLocaleString()} ج</div>
            </div>
            <div class="card">
                <div>📦 برانيك متداولة بالسوق:</div>
                <div class="val" style="color:#B45309;">${Number(m.crates_in_market || 0).toLocaleString()} برنيكة</div>
            </div>
        </div>

        <!-- شاشة عرض كود الوكالة والاقتران الفوري بالـ QR -->
        <div id="tab-key" class="tab-content">
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
                            <td><button type="button" style="background:#DC2626;color:white;border:none;border-radius:4px;padding:3px 8px;cursor:pointer;" onclick="deleteInvoiceAction('${esc(s.InvoiceNo || s.invoiceNo)}')">🗑️ حذف</button></td>
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
        <div id="tab-settle" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">🚛 تصفية وإقفال سيارة أمانة</h3>
                <label>اختر السيارة للتصفية</label>
                <select id="settleLoadSelect" onchange="updateSettlePreview()">
                    <option value="">-- اختر السيارة --</option>
                    ${loads.map(l => `<option value="${esc(getSupplier(l))} | ${esc(getVehicle(l))} | ${esc(getDate(l))}" data-supplier="${esc(getSupplier(l))}" data-vehicle="${esc(getVehicle(l))}" data-freight="${l.Freight || l.freight || 0}" data-comm="${l.Commission || l.commission || 5}">${esc(getSupplier(l))} | ${esc(getVehicle(l))} (${esc(getItem(l))})</option>`).join('')}
                </select>
                <div id="settlePreviewBox" style="margin-top:12px;display:none;" class="card">
                    <div>المورد: <b id="settleSuppTxt"></b></div>
                    <div>نولون النقل: <b id="settleFreightTxt">0 ج</b></div>
                    <div>نسبة العمولة: <b id="settleCommTxt">5%</b></div>
                </div>
            </div>
        </div>

        <!-- 6. جرد بضاعة الأرضية -->
        <div id="tab-stock" class="tab-content">
            <h3>🚚 بضاعة الأرضية والسيارات المفتوحة (${esc(floorStock.length)})</h3>
            <table>
                <tr><th>الصنف</th><th>السيارة</th><th>المورد</th><th>باقي عدد</th><th>باقي وزن</th></tr>
                ${floorStock.map(f => `
                    <tr>
                        <td><b>${esc(f.Item || f.item)}</b></td>
                        <td>${esc(f.Vehicle || f.vehicle)}</td>
                        <td>${esc(f.Supplier || f.supplier)}</td>
                        <td>${Number(f.QtyRemaining || f.qtyRemaining || 0).toLocaleString()} ق</td>
                        <td>${Number(f.WeightRemaining || f.weightRemaining || 0).toLocaleString()} ك</td>
                    </tr>
                `).join('')}
            </table>
        </div>

        <!-- 7. سندات التحصيل والمقبوضات -->
        <div id="tab-col" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">🧾 تسجيل سند قبض وتحصيل</h3>
                <form onsubmit="handleColSubmit(event)">
                    <label>العميل</label>
                    <select name="Customer" required>
                        ${customers.map(c => `<option value="${esc(getName(c))}">${esc(getName(c))} (مديونية: ${getBalance(c).toLocaleString()} ج)</option>`).join('')}
                    </select>
                    <label>المبلغ المحصل (جنيه)</label>
                    <input type="number" name="Amount" step="1" required />
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
                            <td><button type="button" style="background:#DC2626;color:white;border:none;border-radius:4px;padding:3px 8px;cursor:pointer;" onclick="deleteColAction('${esc(c.ReceiptNo || c.receiptNo)}')">🗑️ حذف</button></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <!-- 8. الفواتير الآجلة والذمم -->
        <div id="tab-pending" class="tab-content">
            <h3>📄 كشف الفواتير الآجلة غير المسددة بالكامل</h3>
            <table>
                <tr><th>الفاتورة</th><th>التاريخ</th><th>العميل</th><th>الإجمالي</th><th>المتبقي الآجل</th></tr>
                ${recentSales.filter(s => (s.RemainingAmount || s.remainingAmount) > 0).map(s => `
                    <tr>
                        <td><b>${esc(s.InvoiceNo || s.invoiceNo)}</b></td>
                        <td>${esc(s.Date || s.date)}</td>
                        <td>${esc(s.Customer || s.customer)}</td>
                        <td>${Number(s.Value || s.value || 0).toLocaleString()} ج</td>
                        <td style="color:#DC2626;font-weight:bold;">${Number(s.RemainingAmount || s.remainingAmount || 0).toLocaleString()} ج</td>
                    </tr>
                `).join('')}
            </table>
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
                            <td><button type="button" style="background:#DC2626;color:white;border:none;border-radius:4px;padding:3px 8px;cursor:pointer;" onclick="deleteExpAction(${e.Id || e.id || 0})">🗑️ حذف</button></td>
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
        <div id="tab-bank" class="tab-content">
            <h3>🏦 الحسابات البنكية الجارية</h3>
            <table>
                <tr><th>البنك / الحساب</th><th>رقم الحساب</th><th>الرصيد</th></tr>
                ${bankAccounts.map(b => `
                    <tr>
                        <td><b>${esc(b.BankName || b.bankName)}</b> (${esc(b.AccountName || b.accountName)})</td>
                        <td>${esc(b.AccountNumber || b.accountNumber)}</td>
                        <td>${Number(b.Balance || b.balance || 0).toLocaleString()} ج</td>
                    </tr>
                `).join('')}
            </table>
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
            <h3>👥 العملاء والموردين (${customers.length} عميل / ${suppliers.length} مورد)</h3>
            <table>
                <tr><th>الاسم</th><th>الصفة</th><th>المديونية / الرصيد</th></tr>
                ${customers.map(c => `<tr><td>${esc(getName(c))}</td><td>عميل</td><td>${getBalance(c).toLocaleString()} ج</td></tr>`).join('')}
                ${suppliers.map(s => `<tr><td>${esc(getName(s))}</td><td>مورد</td><td>عمولة: ${esc(s.DefaultCommission || s.defaultCommission || 0)}%</td></tr>`).join('')}
            </table>
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
    let currentUser = JSON.parse(localStorage.getItem('mizan_staff_' + AGENCY_KEY) || 'null');
    let vehicleCargoItems = [];
    const esc = s => String(s == null ? '' : s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;').split('"').join('&quot;');

    function syncScreenState() {
        if (currentUser && currentUser.full_name) {
            document.getElementById('loginScreen').style.display = 'none';
            document.getElementById('mainAppScreen').style.display = 'block';
            document.getElementById('activeUserLabel').innerHTML = '👤 الموظف: <b>' + currentUser.full_name + '</b> (' + (currentUser.job_title || currentUser.role) + ')';
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

    function switchTab(tabId, btn) {
        document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
        const target = document.getElementById(tabId);
        if (target) target.classList.add('active');
        if (btn) btn.classList.add('active');
    }

    function setDateRange(type) {
        const today = new Date().toISOString().slice(0, 10);
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

        ['salesTableBody', 'colTableBody', 'expTableBody'].forEach(bodyId => {
            const tbody = document.getElementById(bodyId);
            if (!tbody) return;
            const rows = tbody.querySelectorAll('tr');
            rows.forEach(tr => {
                const rowDate = tr.getAttribute('data-date');
                if (!rowDate) { tr.style.display = ''; return; }
                let show = true;
                if (from && rowDate < from) show = false;
                if (to && rowDate > to) show = false;
                tr.style.display = show ? '' : 'none';
            });
        });
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

    async function sendAction(action_type, data) {
        if (!currentUser || !currentUser.full_name) {
            alert('انتهت الجلسة، يرجى تسجيل الدخول مجدداً.');
            handleLogout();
            return false;
        }
        try {
            const r = await fetch('/api/web/create-action', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    agency_key: AGENCY_KEY,
                    action_type,
                    user_name: currentUser.full_name,
                    source: 'server',
                    data
                })
            });
            if (r.status === 402) { location.href = '/pay?key=' + encodeURIComponent(AGENCY_KEY); return false; }
            const j = await r.json();
            if (j.success) {
                alert(j.message);
                return true;
            } else {
                alert('خطأ: ' + (j.message || 'فشلت العملية'));
                return false;
            }
        } catch (e) {
            alert('تعذر الاتصال بالسيرفر السحابي: ' + e.message);
            return false;
        }
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

    setDateRange('today');
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
