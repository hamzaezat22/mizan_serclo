const { Redis } = require('@upstash/redis');
const crypto = require('crypto');

// تخزين دائم على Upstash Redis
const redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN
});

// ---------- أدوات مساعدة ----------
const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const versionInfo = {
    latest_version: "2.1.0",
    download_url: "https://example.com/downloads/Mizan_Agency_Update.exe",
    changelog: "تحسينات فائقة في محرك الطباعة والربط السحابي ومزامنة الدفاتر"
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
    let s = '';
    for await (const chunk of req) {
        s += chunk;
        if (s.length > 2_000_000) throw new Error('الطلب كبير جداً');
    }
    return JSON.parse(s || '{}');
}

const hashPassword = (password, salt) => new Promise((resolve, reject) =>
    crypto.scrypt(password, salt, 64, (e, k) => (e ? reject(e) : resolve(k.toString('hex')))));

// حد للمحاولات لمنع التخمين (لكل IP)
async function rateLimit(req, name, limit = 10, windowSec = 900) {
    const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
    const k = `rl:${name}:${ip}`;
    const n = await redis.incr(k);
    if (n === 1) await redis.expire(k, windowSec);
    return n <= limit;
}


// ---------- إعدادات التحقق (كود من 6 أرقام) ----------
const DEFAULT_CC = process.env.DEFAULT_COUNTRY_CODE || '20'; // مصر
const OTP_TTL = 600;            // صلاحية الكود 10 دقائق
const UNVERIFIED_TTL = 86400;   // الحساب غير المفعّل يُحذف بعد 24 ساعة

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
    const text = `كود التحقق الخاص بك: ${code}\nصالح لمدة 10 دقائق. لا تشاركه مع أحد.`;
    const html = `<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;font-size:16px">
        <p>مرحباً، لتفعيل حساب وكالة <b>${esc(agencyName)}</b> في ميزان استخدم الكود التالي:</p>
        <p style="font-size:32px;letter-spacing:6px;font-weight:bold">${code}</p>
        <p style="color:#666">صالح لمدة 10 دقائق. لا تشاركه مع أحد.</p></div>`;

    if (process.env.RESEND_API_KEY) {
        const r = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ from: process.env.MAIL_FROM || 'Mizan <onboarding@resend.dev>', to: [to], subject, html, text })
        });
        if (!r.ok) throw new Error(`Resend ${r.status}: ${await r.text()}`);
        return;
    }
    const nodemailer = require('nodemailer');
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

// يولّد كود، يرسله، ثم يخزّن هاشه (لو الإرسال فشل لا يُخزَّن شيء)
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

// ---------- التصميم ----------
const STYLE = `
body { font-family: -apple-system, Tahoma, sans-serif; background: #200308; color: #FAF4F1; padding: 25px; text-align: center; margin: 0; }
.box { background: #2A040B; border: 1.5px solid #D4AF37; border-radius: 12px; max-width: 420px; margin: 40px auto; padding: 25px; text-align: right; }
h2 { color: #D4AF37; text-align: center; margin-top: 0; }
label { font-size: 13px; color: #C8B8B5; display: block; margin-top: 12px; }
input { width: 100%; box-sizing: border-box; padding: 12px; margin-top: 5px; border-radius: 8px; border: 1px solid #D4AF37; font-size: 16px; background: #FAF4F1; color: #1E1E1E; }
button, .btn { width: 100%; box-sizing: border-box; background: #5A0817; color: white; border: 1px solid #D4AF37; padding: 12px; border-radius: 8px; font-weight: bold; font-size: 16px; cursor: pointer; margin-top: 18px; text-decoration: none; display: block; text-align: center; }
.small { background: #2A040B; color: #D4AF37; padding: 8px; font-size: 14px; margin-top: 6px; }
.msg { color: #ff8a8a; font-size: 14px; margin-top: 12px; min-height: 18px; text-align: center; }
input[type=radio] { width: auto; margin: 0 0 0 6px; }
.radio { display: inline-block; margin: 8px 0 0 14px; color: #FAF4F1; font-size: 15px; }
.note { font-size: 12px; color: #C8B8B5; margin-top: 12px; line-height: 1.7; }
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

// ---------- سكريبتات الصفحات ----------
const REGISTER_SCRIPT = `
var f=document.getElementById('f'),msg=document.getElementById('msg');
function sync(){
  var w=f.querySelector('input[name=channel]:checked');
  var isW=!!w&&w.value==='whatsapp';
  document.getElementById('phoneBox').style.display=isW?'block':'none';
  f.phone.required=isW;
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
`;

const VERIFY_SCRIPT = `
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
  }).catch(function(){btn.disabled=false;show('تعذر الاتصال بالسيرفر',false);});
});
document.getElementById('resend').addEventListener('click',function(){
  var b=this;b.disabled=true;show('',false);
  fetch('/api/resend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u})})
  .then(function(r){return r.json();})
  .then(function(j){
    b.disabled=false;
    show(j.success?('تم إرسال كود جديد إلى '+j.sent_to):(j.message||'حدث خطأ'),!!j.success);
  }).catch(function(){b.disabled=false;show('تعذر الاتصال بالسيرفر',false);});
});
function copyFrom(id){var el=document.getElementById(id);el.select();if(navigator.clipboard){navigator.clipboard.writeText(el.value);}}
`;

const LOGIN_SCRIPT = `
var f=document.getElementById('f'),msg=document.getElementById('msg');
f.addEventListener('submit',function(e){
  e.preventDefault();
  msg.textContent='';
  var d={};
  new FormData(f).forEach(function(v,k){d[k]=v;});
  var btn=f.querySelector('button');btn.disabled=true;
  fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)})
  .then(function(r){return r.json();})
  .then(function(j){
    btn.disabled=false;
    if(j.need_verify){window.location.href='/verify?u='+encodeURIComponent(j.username);return;}
    if(!j.success){msg.textContent=j.message||'حدث خطأ';return;}
    window.location.href=j.link;
  }).catch(function(){btn.disabled=false;msg.textContent='تعذر الاتصال بالسيرفر';});
});
`;

// ---------- الدالة الرئيسية ----------
module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.statusCode = 200;
        return res.end();
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;
    const query = Object.fromEntries(parsedUrl.searchParams);

    try {
        // 1. الصفحة الرئيسية
        if (pathname === '/' || pathname === '') {
            return sendHtml(res, 200, shell('خادم ميزان السحابي', `
                <div class="box" style="text-align:center">
                    <h2>🚀 خادم ميزان السحابي</h2>
                    <p style="color:#C8B8B5;">متابعة وكالتك من الموبايل لحظة بلحظة.</p>
                    <a class="btn" href="/login">🔑 تسجيل الدخول</a>
                    <a class="btn small" href="/register">📝 إنشاء حساب وكالة جديد</a>
                </div>`));
        }

        // 2. صفحة التسجيل
        if (pathname === '/register' && req.method === 'GET') {
            const needCode = !!process.env.REGISTER_CODE;
            const em = emailEnabled(), wa = waEnabled();
            if (!em && !wa) {
                return sendHtml(res, 200, shell('التسجيل غير متاح | ميزان', `
                    <div class="box" style="text-align:center">
                        <h2>⚙️ التسجيل غير متاح حالياً</h2>
                        <p style="color:#C8B8B5;">لم يتم إعداد وسيلة إرسال كود التحقق (بريد أو واتساب) في السيرفر بعد.</p>
                    </div>`));
            }
            return sendHtml(res, 200, shell('إنشاء حساب وكالة | ميزان', `
                <div class="box">
                    <h2>📝 إنشاء حساب وكالة</h2>
                    <form id="f" autocomplete="off">
                        <label>البريد الإلكتروني</label>
                        <input type="email" name="email" required />
                        <label>اسم الوكالة</label>
                        <input type="text" name="agency_name" maxlength="60" required />
                        <label>اسم المستخدم (حروف إنجليزية وأرقام)</label>
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
                        ${needCode ? `<label>كود التسجيل (من مزوّد الخدمة)</label><input type="text" name="register_code" required />` : ''}
                        <button type="submit">إنشاء الحساب وإرسال الكود</button>
                        <div class="msg" id="msg"></div>
                    </form>
                    <a class="btn small" href="/login">لديك حساب؟ سجّل الدخول</a>
                </div>`, REGISTER_SCRIPT));
        }

        // 3. تنفيذ التسجيل (يرسل كود تحقق ولا يُصدر الرابط قبل التأكيد)
        if (pathname === '/api/register' && req.method === 'POST') {
            if (!(await rateLimit(req, 'register', 10))) {
                return sendJson(res, 429, { success: false, message: 'محاولات كثيرة، حاول بعد قليل.' });
            }
            let b;
            try { b = await readJson(req); } catch (e) {
                return sendJson(res, 400, { success: false, message: 'بيانات غير صالحة.' });
            }

            if (process.env.REGISTER_CODE && String(b.register_code || '') !== process.env.REGISTER_CODE) {
                return sendJson(res, 403, { success: false, message: 'كود التسجيل غير صحيح.' });
            }

            const email = String(b.email || '').trim().toLowerCase();
            const agencyName = String(b.agency_name || '').trim();
            const username = String(b.username || '').trim().toLowerCase();
            const password = String(b.password || '');
            const channel = String(b.channel || 'email');

            if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || email.length > 120)
                return sendJson(res, 400, { success: false, message: 'البريد الإلكتروني غير صحيح.' });
            if (!agencyName || agencyName.length > 60)
                return sendJson(res, 400, { success: false, message: 'اسم الوكالة مطلوب (حتى 60 حرفاً).' });
            if (!/^[a-z0-9_]{3,30}$/.test(username))
                return sendJson(res, 400, { success: false, message: 'اسم المستخدم: 3 إلى 30 حرفاً إنجليزياً أو أرقاماً أو _' });
            if (password.length < 8 || password.length > 100)
                return sendJson(res, 400, { success: false, message: 'كلمة المرور لا تقل عن 8 أحرف.' });
            if (!((channel === 'email' && emailEnabled()) || (channel === 'whatsapp' && waEnabled())))
                return sendJson(res, 400, { success: false, message: 'وسيلة التحقق المختارة غير متاحة.' });

            let phone = null;
            if (channel === 'whatsapp') {
                phone = normalizePhone(b.phone);
                if (!phone) return sendJson(res, 400, { success: false, message: 'رقم الواتساب غير صحيح.' });
            }

            const salt = crypto.randomBytes(16).toString('hex');
            const agencyKey = crypto.randomBytes(24).toString('hex'); // 48 حرف عشوائي
            const record = {
                email,
                phone,
                agency_name: agencyName,
                username,
                salt,
                password_hash: await hashPassword(password, salt),
                agency_key: agencyKey,
                verified: false,
                verify_channel: channel,
                created_at: new Date().toISOString()
            };

            const userOk = await redis.set(`user:${username}`, record, { nx: true, ex: UNVERIFIED_TTL });
            if (!userOk) return sendJson(res, 409, { success: false, message: 'اسم المستخدم مستخدم بالفعل.' });

            const emailOk = await redis.set(`email:${email}`, username, { nx: true, ex: UNVERIFIED_TTL });
            if (!emailOk) {
                await redis.del(`user:${username}`);
                return sendJson(res, 409, { success: false, message: 'هذا البريد مسجّل بالفعل.' });
            }
            if (phone) {
                const phoneOk = await redis.set(`phone:${phone}`, username, { nx: true, ex: UNVERIFIED_TTL });
                if (!phoneOk) {
                    await redis.del(`user:${username}`);
                    await redis.del(`email:${email}`);
                    return sendJson(res, 409, { success: false, message: 'رقم الواتساب مسجّل بالفعل.' });
                }
            }

            try {
                await issueCode(record);
            } catch (err) {
                console.error('send code failed:', err.message);
                await dropAccount(record);
                return sendJson(res, 502, { success: false, message: 'تعذر إرسال كود التحقق. تأكد من صحة البيانات وحاول مرة أخرى.' });
            }

            await redis.set(`cool:${username}`, 1, { ex: 60 }); // أول إعادة إرسال بعد دقيقة
            return sendJson(res, 200, { success: true, need_verify: true, username, sent_to: maskFor(record) });
        }

        // 3.1 صفحة إدخال كود التحقق
        if (pathname === '/verify' && req.method === 'GET') {
            return sendHtml(res, 200, shell('تأكيد الحساب | ميزان', `
                <div class="box" id="formBox">
                    <h2>📩 تأكيد الحساب</h2>
                    <p class="note" id="info" style="text-align:center">أدخل كود التحقق المكوّن من 6 أرقام.</p>
                    <form id="f">
                        <label>كود التحقق</label>
                        <input type="text" name="code" inputmode="numeric" maxlength="6" pattern="[0-9]{6}" required autocomplete="one-time-code" dir="ltr" style="text-align:center;letter-spacing:6px;font-size:22px" />
                        <button type="submit">تأكيد</button>
                        <div class="msg" id="msg"></div>
                    </form>
                    <button class="small" type="button" id="resend">🔁 إرسال كود جديد</button>
                </div>
                <div class="box" id="resBox" style="display:none">
                    <h2>✅ تم تفعيل الحساب</h2>
                    <label>الرابط الخاص بوكالتك (للموبايل وللكمبيوتر)</label>
                    <input type="text" id="link" readonly />
                    <button class="small" type="button" onclick="copyFrom('link')">📋 نسخ الرابط</button>
                    <label>كود الوكالة (يُستخدم في برنامج الكمبيوتر)</label>
                    <input type="text" id="key" readonly />
                    <button class="small" type="button" onclick="copyFrom('key')">📋 نسخ الكود</button>
                    <div class="note">
                        ⚠️ الرابط والكود سريان: كل من يملكهما يستطيع رؤية بيانات وكالتك، فلا تشاركهما مع أحد.<br>
                        لو ضاع منك الرابط، ادخل بصفحة تسجيل الدخول باسم المستخدم وكلمة المرور وسيظهر لك من جديد.
                    </div>
                </div>`, VERIFY_SCRIPT));
        }

        // 3.2 تأكيد الكود وتفعيل الحساب (هنا فقط يُصدر الرابط)
        if (pathname === '/api/verify' && req.method === 'POST') {
            if (!(await rateLimit(req, 'verify', 20))) {
                return sendJson(res, 429, { success: false, message: 'محاولات كثيرة، حاول بعد قليل.' });
            }
            let b;
            try { b = await readJson(req); } catch (e) {
                return sendJson(res, 400, { success: false, message: 'بيانات غير صالحة.' });
            }
            const username = String(b.username || '').trim().toLowerCase();
            const code = String(b.code || '').trim();
            const user = /^[a-z0-9_]{3,30}$/.test(username) ? await redis.get(`user:${username}`) : null;

            if (!user) return sendJson(res, 404, { success: false, message: 'الحساب غير موجود أو انتهت مهلة التفعيل، سجّل من جديد.' });
            if (user.verified !== false) return sendJson(res, 400, { success: false, message: 'الحساب مفعّل بالفعل، سجّل الدخول.' });

            const otp = await redis.get(`otp:${username}`);
            if (!otp || otp.expires < Date.now())
                return sendJson(res, 400, { success: false, message: 'انتهت صلاحية الكود، اطلب كوداً جديداً.' });
            if (otp.attempts >= 5) {
                await redis.del(`otp:${username}`);
                return sendJson(res, 429, { success: false, message: 'تجاوزت عدد المحاولات، اطلب كوداً جديداً.' });
            }

            const given = Buffer.from(otpHash(user.salt, code));
            const real = Buffer.from(otp.hash);
            const ok = given.length === real.length && crypto.timingSafeEqual(given, real);
            if (!ok) {
                otp.attempts += 1;
                await redis.set(`otp:${username}`, otp, { ex: Math.max(1, Math.ceil((otp.expires - Date.now()) / 1000)) });
                return sendJson(res, 400, { success: false, message: 'الكود غير صحيح.' });
            }

            user.verified = true;
            user.verified_at = new Date().toISOString();
            await redis.set(`user:${username}`, user);              // بدون انتهاء صلاحية
            await redis.persist(`email:${user.email}`);
            if (user.phone) await redis.persist(`phone:${user.phone}`);
            await redis.set(`keyidx:${user.agency_key}`, username); // تفعيل المزامنة
            await redis.del(`otp:${username}`);

            return sendJson(res, 200, {
                success: true,
                agency_key: user.agency_key,
                link: `${originOf(req)}/app?key=${user.agency_key}`
            });
        }

        // 3.3 إعادة إرسال الكود
        if (pathname === '/api/resend' && req.method === 'POST') {
            if (!(await rateLimit(req, 'resend', 10))) {
                return sendJson(res, 429, { success: false, message: 'محاولات كثيرة، حاول بعد قليل.' });
            }
            let b;
            try { b = await readJson(req); } catch (e) {
                return sendJson(res, 400, { success: false, message: 'بيانات غير صالحة.' });
            }
            const username = String(b.username || '').trim().toLowerCase();
            const user = /^[a-z0-9_]{3,30}$/.test(username) ? await redis.get(`user:${username}`) : null;
            if (!user || user.verified !== false)
                return sendJson(res, 400, { success: false, message: 'لا يمكن إرسال كود لهذا الحساب.' });

            const cool = await redis.set(`cool:${username}`, 1, { nx: true, ex: 60 });
            if (!cool) return sendJson(res, 429, { success: false, message: 'انتظر دقيقة قبل طلب كود جديد.' });
            const n = await redis.incr(`sends:${username}`);
            if (n === 1) await redis.expire(`sends:${username}`, 3600);
            if (n > 5) return sendJson(res, 429, { success: false, message: 'تجاوزت الحد، حاول بعد ساعة.' });

            try {
                await issueCode(user);
            } catch (err) {
                console.error('resend failed:', err.message);
                return sendJson(res, 502, { success: false, message: 'تعذر إرسال الكود، حاول لاحقاً.' });
            }
            return sendJson(res, 200, { success: true, sent_to: maskFor(user) });
        }

        // 4. صفحة تسجيل الدخول
        if (pathname === '/login' && req.method === 'GET') {
            return sendHtml(res, 200, shell('تسجيل الدخول | ميزان', `
                <div class="box">
                    <h2>🔑 تسجيل الدخول</h2>
                    <form id="f">
                        <label>اسم المستخدم</label>
                        <input type="text" name="username" required autocomplete="username" />
                        <label>كلمة المرور</label>
                        <input type="password" name="password" required autocomplete="current-password" />
                        <button type="submit">دخول</button>
                        <div class="msg" id="msg"></div>
                    </form>
                    <a class="btn small" href="/register">ليس لديك حساب؟ أنشئ واحداً</a>
                </div>`, LOGIN_SCRIPT));
        }

        // 5. تنفيذ الدخول (يرجّع الرابط الخاص بالوكالة)
        if (pathname === '/api/login' && req.method === 'POST') {
            if (!(await rateLimit(req, 'login', 10))) {
                return sendJson(res, 429, { success: false, message: 'محاولات كثيرة، حاول بعد 15 دقيقة.' });
            }
            let b;
            try { b = await readJson(req); } catch (e) {
                return sendJson(res, 400, { success: false, message: 'بيانات غير صالحة.' });
            }
            const username = String(b.username || '').trim().toLowerCase();
            const password = String(b.password || '');
            const user = /^[a-z0-9_]{3,30}$/.test(username) ? await redis.get(`user:${username}`) : null;

            // نحسب الهاش حتى لو المستخدم غير موجود (تقليل فروق التوقيت)
            const salt = user ? user.salt : 'x'.repeat(32);
            const hash = await hashPassword(password.slice(0, 100), salt);
            const ok = user &&
                hash.length === user.password_hash.length &&
                crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(user.password_hash));

            if (!ok) return sendJson(res, 401, { success: false, message: 'اسم المستخدم أو كلمة المرور غير صحيحة.' });

            if (user.verified === false)
                return sendJson(res, 200, { success: false, need_verify: true, username, message: 'الحساب غير مفعّل بعد.' });

            return sendJson(res, 200, {
                success: true,
                agency_name: user.agency_name,
                link: `${originOf(req)}/app?key=${user.agency_key}`
            });
        }

        // 6. فحص التحديثات
        if (pathname === '/api/system/check-update') {
            const clientVer = query.version || "1.0.0";
            const hasUpdate = clientVer !== versionInfo.latest_version;
            return sendJson(res, 200, {
                success: true,
                has_update: hasUpdate,
                client_version: clientVer,
                latest_version: versionInfo.latest_version,
                download_url: versionInfo.download_url,
                message: hasUpdate ? "الرجاء تنزيل التحديث الجديد للعمل بكفاءة أعلى ومزامنة سحابية فائقة السرعة." : "أنت تعمل على أحدث إصدار معتمد.",
                changelog: versionInfo.changelog
            });
        }

        // 7. مزامنة ورفع البيانات من كمبيوتر الوكالة (لازم كود وكالة مسجّل)
        if (pathname === '/api/sync/push' && req.method === 'POST') {
            let body;
            try { body = await readJson(req); } catch (e) {
                return sendJson(res, 400, { success: false, message: 'بيانات غير صالحة.' });
            }
            const { agency_key, drawer_cash, today_sales, net_profit, open_cars_count, floor_stock, recent_sales } = body;

            if (!agency_key) return sendJson(res, 400, { success: false, message: "كود الوكالة مطلوب." });

            const owner = await redis.get(`keyidx:${agency_key}`);
            if (!owner) return sendJson(res, 401, { success: false, message: "كود الوكالة غير صحيح." });
            const user = await redis.get(`user:${owner}`);

            await redis.set(`agency:${agency_key}`, {
                agency_name: user ? user.agency_name : "وكالة ميزان",
                last_sync: new Date().toISOString(),
                metrics: {
                    drawer_cash: drawer_cash || 0,
                    today_sales: today_sales || 0,
                    net_profit: net_profit || 0,
                    open_cars_count: open_cars_count || 0
                },
                floor_stock: floor_stock || [],
                recent_sales: recent_sales || []
            }, { ex: 60 * 60 * 24 * 30 });

            return sendJson(res, 200, { success: true, message: "تمت المزامنة بنجاح في السيرفر السحابي." });
        }

        // 8. بوابة الموبايل
        if (pathname === '/app') {
            const key = String(query.key || '');
            const data = key ? await redis.get(`agency:${key}`) : null;

            if (!data) {
                const owner = key ? await redis.get(`keyidx:${key}`) : null;
                if (owner) {
                    return sendHtml(res, 200, shell('بانتظار المزامنة | ميزان', `
                        <meta http-equiv="refresh" content="20">
                        <div class="box" style="text-align:center">
                            <h2>⏳ الحساب جاهز</h2>
                            <p style="color:#C8B8B5;">لم تصل أي بيانات من الكمبيوتر بعد. شغّل المزامنة من برنامج الكمبيوتر وستتحدث هذه الصفحة تلقائياً.</p>
                        </div>`));
                }
                return sendHtml(res, 200, shell('بوابة الوكالة | ميزان', `
                    <div class="box" style="text-align:center">
                        <h2>🏢 بوابة الوكالة السحابية</h2>
                        <p style="color:#C8B8B5;">${key ? 'الرابط غير صحيح.' : ''} سجّل الدخول للوصول إلى وكالتك.</p>
                        <a class="btn" href="/login">🔑 تسجيل الدخول</a>
                        <a class="btn small" href="/register">📝 إنشاء حساب جديد</a>
                    </div>`));
            }

            const m = data.metrics || {};
            return sendHtml(res, 200, `
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${esc(data.agency_name)} | المتابعة الحية</title>
            <style>
                body { font-family: -apple-system, Tahoma, sans-serif; background: #FAF4F1; margin: 0; padding: 15px; color: #1E1E1E; }
                .header { background: #2A040B; color: #FFF; padding: 16px; border-radius: 12px; text-align: center; border-bottom: 3px solid #D4AF37; margin-bottom: 12px; }
                .header h2 { margin: 0; color: #D4AF37; font-size: 20px; }
                .card { background: #FFF; border-radius: 10px; padding: 14px; margin-bottom: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); border-right: 4px solid #5A0817; }
                .val { font-size: 22px; font-weight: bold; color: #0D7857; margin-top: 4px; }
                table { width: 100%; border-collapse: collapse; margin-top: 10px; background: white; border-radius: 8px; overflow: hidden; }
                th, td { padding: 8px; border-bottom: 1px solid #EEE; text-align: right; font-size: 12px; }
                th { background: #5A0817; color: white; }
                .reload-btn { width: 100%; background: #2A040B; color: #D4AF37; border: 1px solid #D4AF37; padding: 10px; border-radius: 8px; font-weight: bold; cursor: pointer; margin-bottom: 15px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🏢 ${esc(data.agency_name)}</h2>
                <div style="font-size:11px; color:#C8B8B5; margin-top:4px;">آخر تحديث من الكمبيوتر: ${new Date(data.last_sync).toLocaleTimeString('ar-EG', { timeZone: 'Africa/Cairo' })}</div>
            </div>

            <button class="reload-btn" onclick="location.reload()">🔄 تحديث الأرقام الحية الآن</button>

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

            <h3>🚚 بضاعة الأرضية والسيارات (${esc(m.open_cars_count || 0)})</h3>
            <table>
                <tr><th>الصنف</th><th>السيارة</th><th>باقي عدد</th><th>باقي وزن</th></tr>
                ${(data.floor_stock || []).slice(0, 20).map(f => `
                    <tr>
                        <td><b>${esc(f.Item)}</b></td>
                        <td>${esc(f.Vehicle)}</td>
                        <td>${esc(f.QtyRemaining)} ق</td>
                        <td>${esc(f.WeightRemaining)} ك</td>
                    </tr>
                `).join('')}
            </table>
        </body>
        </html>
        `);
        }

        res.statusCode = 404;
        return res.end("Not Found");
    } catch (err) {
        console.error(err);
        return sendJson(res, 500, { success: false, message: 'خطأ في السيرفر.' });
    }
};
