const { Redis } = require('@upstash/redis');
const crypto = require('crypto');

const redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN
});

const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const versionInfo = {
    latest_version: "2.1.0",
    download_url: "https://example.com/downloads/Mizan_Agency_Update.exe",
    changelog: "معالجة احتساب الأرباح اللحظية وتمييز مستخدمي السيرفر"
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
        if (s.length > 15_000_000) throw new Error('حجم البيانات كبير جداً');
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

async function rateLimit(req, name, limit = 25, windowSec = 900) {
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
body { font-family: -apple-system, Tahoma, 'Cairo', sans-serif; background: #200308; color: #FAF4F1; padding: 15px; text-align: center; margin: 0; }
.box { background: #2A040B; border: 1.5px solid #D4AF37; border-radius: 12px; max-width: 440px; margin: 25px auto; padding: 25px; text-align: right; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
h2 { color: #D4AF37; text-align: center; margin-top: 0; }
label { font-size: 13px; color: #C8B8B5; display: block; margin-top: 10px; font-weight: bold; }
input, select, textarea { width: 100%; box-sizing: border-box; padding: 10px; margin-top: 4px; border-radius: 6px; border: 1px solid #D4AF37; font-size: 14px; background: #FAF4F1; color: #1E1E1E; font-family: inherit; }
button, .btn { width: 100%; box-sizing: border-box; background: #5A0817; color: white; border: 1px solid #D4AF37; padding: 11px; border-radius: 8px; font-weight: bold; font-size: 14.5px; cursor: pointer; margin-top: 14px; text-decoration: none; display: block; text-align: center; font-family: inherit; }
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

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-key, Authorization');

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
                    <h2>🚀 خادم ميزان السحابي المتكامل</h2>
                    <p style="color:#C8B8B5;">إدارة ومتابعة ومزامنة كافة عمليات الوكالة لحظة بلحظة.</p>
                    <a class="btn" href="/login">🔑 تسجيل الدخول السحابي</a>
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
                        <p style="color:#C8B8B5;">لم يتم إعداد وسيلة إرسال كود التحقق في السيرفر بعد.</p>
                    </div>`));
            }
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

        // 3. API تسجيل الحساب
        if (pathname === '/api/register' && req.method === 'POST') {
            if (!(await rateLimit(req, 'register', 10))) {
                return sendJson(res, 429, { success: false, message: 'محاولات كثيرة، حاول بعد قليل.' });
            }
            let b = await readJson(req);
            if (process.env.REGISTER_CODE && String(b.register_code || '') !== process.env.REGISTER_CODE) {
                return sendJson(res, 403, { success: false, message: 'كود التسجيل غير صحيح.' });
            }

            const email = String(b.email || '').trim().toLowerCase();
            const agencyName = String(b.agency_name || '').trim();
            const username = String(b.username || '').trim().toLowerCase();
            const password = String(b.password || '');
            const channel = String(b.channel || 'email');

            if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return sendJson(res, 400, { success: false, message: 'البريد غير صحيح.' });
            if (!agencyName) return sendJson(res, 400, { success: false, message: 'اسم الوكالة مطلوب.' });
            if (!/^[a-z0-9_]{3,30}$/.test(username)) return sendJson(res, 400, { success: false, message: 'اسم المستخدم غير صالح.' });
            if (password.length < 8) return sendJson(res, 400, { success: false, message: 'كلمة المرور قصيرة.' });

            let phone = channel === 'whatsapp' ? normalizePhone(b.phone) : null;
            if (channel === 'whatsapp' && !phone) return sendJson(res, 400, { success: false, message: 'رقم الواتساب غير صحيح.' });

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

            try {
                await issueCode(record);
            } catch (err) {
                await dropAccount(record);
                return sendJson(res, 502, { success: false, message: 'تعذر إرسال كود التحقق.' });
            }

            return sendJson(res, 200, { success: true, need_verify: true, username, sent_to: maskFor(record) });
        }

        // 4. صفحة التحقق
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
                    <label>الرابط السحابي للوكالة (للموبايل والكمبيوتر)</label>
                    <input type="text" id="link" readonly />
                    <button class="small" type="button" onclick="copyFrom('link')">📋 نسخ الرابط</button>
                    <label>كود ربط الوكالة (لبرنامج الكمبيوتر)</label>
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
                `));
        }

        // 5. API التحقق من الكود
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
            if (given.length !== real.length || !crypto.timingSafeEqual(given, real)) {
                return sendJson(res, 400, { success: false, message: 'الكود غير صحيح.' });
            }

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

        // 6. صفحة تسجيل الدخول الرئيسية
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
                </div>`, `
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
                    if(!j.success){msg.textContent=j.message||'حدث خطأ';return;}
                    window.location.href=j.link;
                  }).catch(function(){btn.disabled=false;msg.textContent='تعذر الاتصال بالسيرفر';});
                });
                `));
        }

        // 7. API تسجيل الدخول
        if (pathname === '/api/login' && req.method === 'POST') {
            let b = await readJson(req);
            const username = String(b.username || '').trim().toLowerCase();
            const password = String(b.password || '');
            const user = await redis.get(`user:${username}`);

            const salt = user ? user.salt : 'x'.repeat(32);
            const hash = await hashPassword(password, salt);
            if (!user || hash !== user.password_hash) {
                return sendJson(res, 401, { success: false, message: 'بيانات الدخول غير صحيحة.' });
            }

            return sendJson(res, 200, {
                success: true,
                agency_name: user.agency_name,
                link: `${originOf(req)}/app?key=${user.agency_key}`
            });
        }

        // 8. فحص التحديثات
        if (pathname === '/api/system/check-update') {
            const clientVer = query.version || "1.0.0";
            const hasUpdate = clientVer !== versionInfo.latest_version;
            return sendJson(res, 200, {
                success: true,
                has_update: hasUpdate,
                client_version: clientVer,
                latest_version: versionInfo.latest_version,
                download_url: versionInfo.download_url,
                message: hasUpdate ? "تحديث جديد متاح لمنظومة ميزان." : "أنت تعمل على أحدث إصدار.",
                changelog: versionInfo.changelog
            });
        }

        // 9. مزامنة البيانات الكاملة من كمبيوتر الوكالة (Push from Desktop)
        if ((pathname === '/api/sync/push' || pathname === '/api/sync') && req.method === 'POST') {
            let body = await readJson(req);
            const agency_key = String(body.agency_key || body.key || body.apiKey || req.headers['x-api-key'] || query.key || '').trim();

            if (!agency_key) return sendJson(res, 400, { success: false, message: "كود الوكالة مطلوب." });

            let owner = await redis.get(`keyidx:${agency_key}`);
            let user = owner ? await redis.get(`user:${owner}`) : null;

            if (!owner) {
                await redis.set(`keyidx:${agency_key}`, "desktop_client");
            }

            const payloadUsers = body.users || [];

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
                users: payloadUsers,
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
                crates: body.crates || [],
                purchases: body.purchases || [],
                bank_accounts: body.bank_accounts || [],
                checks: body.checks || [],
                cost_centers: body.cost_centers || [],
                settlements: body.settlements || [],
                weighbridge_tickets: body.weighbridge_tickets || [],
                custom_screens: body.custom_screens || [],
                chart_of_accounts: body.chart_of_accounts || [],
                overdue_customers: body.overdue_customers || []
            }, { ex: 60 * 60 * 24 * 30 });

            return sendJson(res, 200, { success: true, message: `تم استقبال مزامنة الوكالة بنجاح (${(body.items || []).length} صنف و ${(body.customers || []).length} عميل).` });
        }

        // 10. سحب العمليات المنشأة سحابياً إلى كمبيوتر الوكالة (Pull to Desktop)
        if (pathname === '/api/mobile/orders' && req.method === 'GET') {
            const agency_key = String(query.key || req.headers['x-api-key'] || '').trim();
            if (!agency_key) return sendJson(res, 400, { success: false, message: "كود الوكالة مطلوب." });

            const queueKey = `orders_queue:${agency_key}`;
            const queuedOrders = await redis.get(queueKey) || [];

            if (queuedOrders.length > 0) {
                await redis.del(queueKey);
            }

            return sendJson(res, 200, queuedOrders);
        }

        // 11. تسجيل دخول الموظف المستورد من قاعدة بيانات الديسكتوب
        if (pathname === '/api/web/user-login' && req.method === 'POST') {
            let b = await readJson(req);
            const agency_key = String(b.agency_key || '').trim();
            const username = String(b.username || '').trim();
            const password = String(b.password || '');

            if (!agency_key || !username || !password) {
                return sendJson(res, 400, { success: false, message: "بيانات الدخول غير مكتملة." });
            }

            const data = await redis.get(`agency:${agency_key}`);
            const owner = await redis.get(`keyidx:${agency_key}`);
            const ownerUser = owner ? await redis.get(`user:${owner}`) : null;

            const cleanUser = username.toLowerCase();
            const syncedUsers = data && Array.isArray(data.users) ? data.users : [];

            // 1. فحص مستخدمي الوكالة المتزامنين من الديسكتوب
            const matchedUser = syncedUsers.find(u => {
                const uName = String(u.Username || u.username || '').toLowerCase();
                const fName = String(u.FullName || u.fullName || u.full_name || '').toLowerCase();
                return uName === cleanUser || fName === cleanUser;
            });

            if (matchedUser) {
                const passHash = matchedUser.PasswordHash || matchedUser.password_hash || matchedUser.passwordHash;
                const isPassValid = verifyDesktopPassword(password, passHash);
                if (!isPassValid) {
                    return sendJson(res, 401, { success: false, message: "كلمة المرور غير صحيحة." });
                }
                return sendJson(res, 200, {
                    success: true,
                    user: {
                        id: matchedUser.Id || matchedUser.id || 1,
                        username: matchedUser.Username || matchedUser.username,
                        full_name: matchedUser.FullName || matchedUser.fullName || matchedUser.full_name,
                        role: matchedUser.Role || matchedUser.role || 'محاسب',
                        job_title: matchedUser.JobTitle || matchedUser.job_title || matchedUser.Role || 'محاسب',
                        permissions: matchedUser.Permissions || matchedUser.permissions || 'ALL'
                    }
                });
            }

            // 2. حساب المالك الرئيسي كـ Fallback
            if (ownerUser && (ownerUser.username.toLowerCase() === cleanUser || cleanUser === 'admin')) {
                const salt = ownerUser.salt;
                const hash = await hashPassword(password, salt);
                if (hash === ownerUser.password_hash) {
                    return sendJson(res, 200, {
                        success: true,
                        user: {
                            id: 1,
                            username: ownerUser.username,
                            full_name: `${ownerUser.agency_name} (المدير العام)`,
                            role: 'admin',
                            job_title: 'مدير عام',
                            permissions: 'ALL'
                        }
                    });
                }
            }

            if (syncedUsers.length === 0) {
                return sendJson(res, 404, { 
                    success: false, 
                    message: "لم يتم استقبال مستخدمي الوكالة من الكمبيوتر بعد. يرجى فتح برنامج ميزان على الكمبيوتر والضغط على (مزامنة فورية) من شاشة الربط السحابي." 
                });
            }

            return sendJson(res, 401, { success: false, message: "اسم المستخدم أو كلمة المرور غير صحيحة." });
        }

        // 12. إنشاء وتوجيه كافة العمليات المحاسبية من السيرفر السحابي
        if (pathname === '/api/web/create-action' && req.method === 'POST') {
            let b = await readJson(req);
            const { agency_key, action_type, user_name, data, source } = b;

            if (!agency_key || !action_type || !data) {
                return sendJson(res, 400, { success: false, message: "بيانات المعاملة غير مكتملة." });
            }

            const queueKey = `orders_queue:${agency_key}`;
            const queuedOrders = await redis.get(queueKey) || [];

            const dateStr = data.Date || new Date().toISOString().slice(0, 10);
            const userTag = user_name || "مستخدم";
            const sourceText = source === 'mobile' ? 'مستخدم الهاتف' : 'مستخدم السيرفر';
            const authorFormatted = `${userTag} (${sourceText})`;
            const prefix = source === 'mobile' ? 'MOB' : 'SRV';
            const seq = Math.floor(1000 + Math.random() * 9000);

            switch (action_type) {
                case 'SALE_INVOICE': {
                    const invNo = `${prefix}-${dateStr.replace(/-/g, '')}-${seq}`;
                    const items = Array.isArray(data.Items) ? data.Items : [data];
                    items.forEach((it, idx) => {
                        queuedOrders.push({
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
                            GrossWeight: Number(it.GrossWeight || it.Weight || 0),
                            Price: Number(it.Price || 0),
                            Discount: Number(it.Discount || 0),
                            Value: Number(it.Value || (it.Weight > 0 ? it.Weight * it.Price : it.Qty * it.Price)),
                            PaidAmount: Number(idx === 0 ? (data.PaidAmount || 0) : 0),
                            RemainingAmount: Number(idx === 0 ? (data.RemainingAmount || 0) : 0),
                            PaymentMethod: data.PaymentMethod || "نقدي (كاش)",
                            CreatedBy: authorFormatted,
                            Notes: `فاتورة صادرة من ${sourceText}`
                        });
                    });
                    break;
                }
                case 'LOAD_SUPPLY':
                    queuedOrders.push({
                        Date: dateStr,
                        Vehicle: data.Vehicle,
                        Supplier: data.Supplier,
                        Item: data.Item,
                        QtyIn: Number(data.QtyIn || 0),
                        WeightIn: Number(data.WeightIn || 0),
                        Freight: Number(data.Freight || 0),
                        Commission: Number(data.Commission || 5),
                        CreatedBy: authorFormatted
                    });
                    break;
                case 'COLLECTION':
                    queuedOrders.push({
                        ReceiptNo: `REC-${prefix}-${seq}`,
                        Date: dateStr,
                        Customer: data.Customer,
                        Amount: Number(data.Amount || 0),
                        PaymentMethod: data.PaymentMethod || "نقدي (كاش)",
                        CreatedBy: authorFormatted,
                        Notes: data.Notes || `سند تحصيل من ${sourceText}`
                    });
                    break;
                case 'EXPENSE':
                    queuedOrders.push({
                        Date: dateStr,
                        Category: data.Category || "مصاريف نثرية عامة",
                        Description: data.Description || `صرف من ${sourceText}`,
                        Amount: Number(data.Amount || 0),
                        PaymentMethod: data.PaymentMethod || "نقدي (كاش)",
                        CreatedBy: authorFormatted
                    });
                    break;
                case 'PURCHASE':
                    queuedOrders.push({
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
                        Date: dateStr,
                        Customer: data.Customer,
                        Kind: action_type === 'CRATE_RETURN' ? 'استرجاع' : 'تسليم',
                        CrateType: data.CrateType || "برنيكة بلاستيك",
                        Qty: Number(data.Qty || 0),
                        Price: Number(data.Price || 70),
                        Amount: Number(data.Amount || (data.Qty * (data.Price || 70))),
                        CreatedBy: authorFormatted,
                        Notes: `حركة أوعية من ${sourceText}`
                    });
                    break;
                case 'WEIGHBRIDGE_TICKET':
                    queuedOrders.push({
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

            return sendJson(res, 200, {
                success: true,
                message: `تم تسجيل المعاملة بنجاح باسم [${authorFormatted}] وأُرسلت للمزامنة مع الكمبيوتر.`
            });
        }

        // 13. بوابة الويب السحابية الشاملة لكافة الأقسام والخدمات مع دعم حقول الديسكتوب المتزامنة
        if (pathname === '/app') {
            const key = String(query.key || '').trim();
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
            const crates = Array.isArray(data.crates) ? data.crates : [];
            const purchases = Array.isArray(data.purchases) ? data.purchases : [];
            const bankAccounts = Array.isArray(data.bank_accounts) ? data.bank_accounts : [];
            const checks = Array.isArray(data.checks) ? data.checks : [];
            const weighbridgeTickets = Array.isArray(data.weighbridge_tickets) ? data.weighbridge_tickets : [];

            // دوال استخراج القيم الآمنة لتفادي حساسية الأحرف
            const getName = o => o.Name || o.name || o.FullName || o.fullName || '';
            const getSupplier = o => o.Supplier || o.supplier || '';
            const getPrice = o => Number(o.DefaultPrice || o.defaultPrice || o.Price || o.price || 0);
            const getBalance = o => Number(o.Balance || o.balance || 0);
            const getVehicle = o => o.Vehicle || o.vehicle || '';
            const getDate = o => o.Date || o.date || '';
            const getItem = o => o.Item || o.item || '';

            return sendHtml(res, 200, `<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(data.agency_name)} | المنظومة السحابية الشاملة</title>
<style>
body { font-family: -apple-system, Tahoma, 'Cairo', sans-serif; background: #200308; margin: 0; padding: 12px; color: #FAF4F1; }
#loginScreen { display: flex; justify-content: center; align-items: center; min-height: 90vh; }
.login-box { background: #2A040B; border: 1.8px solid #D4AF37; border-radius: 16px; max-width: 420px; width: 100%; padding: 28px; text-align: right; box-shadow: 0 15px 40px rgba(0,0,0,0.6); }
.login-header { text-align: center; margin-bottom: 20px; }
.login-header h2 { margin: 0 0 6px 0; color: #D4AF37; font-size: 22px; }
.login-header p { margin: 0; color: #C8B8B5; font-size: 13px; }
.badge { background: #5A0817; color: #FAF4F1; padding: 6px 10px; border-radius: 6px; font-weight: bold; font-size: 12.5px; text-align: center; margin-bottom: 15px; border: 1px solid #D4AF37; }

#mainAppScreen { display: none; background: #FAF4F1; border-radius: 12px; padding: 12px; color: #1E1E1E; box-shadow: 0 8px 30px rgba(0,0,0,0.5); }
.header { background: #2A040B; color: #FFF; padding: 16px; border-radius: 12px; text-align: center; border-bottom: 3px solid #D4AF37; margin-bottom: 12px; }
.header h2 { margin: 0; color: #D4AF37; font-size: 20px; }
.user-bar { background: #38050E; color: #D4AF37; padding: 8px 12px; border-radius: 8px; margin-top: 8px; font-size: 13px; display: flex; justify-content: space-between; align-items: center; }
.nav-scroll { display: flex; gap: 6px; overflow-x: auto; margin-bottom: 12px; padding-bottom: 6px; }
.tab-btn { background: #2A040B; color: #FAF4F1; border: 1px solid #D4AF37; padding: 9px 12px; border-radius: 8px; font-weight: bold; cursor: pointer; white-space: nowrap; font-size: 12.5px; font-family: inherit; }
.tab-btn.active { background: #5A0817; color: #D4AF37; border-color: #D4AF37; }
.tab-content { display: none; }
.tab-content.active { display: block; }
.card { background: #FFF; border-radius: 10px; padding: 14px; margin-bottom: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); border-right: 4px solid #5A0817; color: #1E1E1E; }
.val { font-size: 20px; font-weight: bold; color: #0D7857; margin-top: 4px; }
.form-card { background: #FFF; border-radius: 10px; padding: 16px; margin-bottom: 14px; border: 1.5px solid #D4AF37; box-shadow: 0 4px 12px rgba(0,0,0,0.08); color: #1E1E1E; }
label { font-size: 12.5px; font-weight: bold; margin-top: 8px; display: block; color: #5A0817; }
input, select, textarea { width: 100%; box-sizing: border-box; padding: 10px; margin-top: 4px; border-radius: 6px; border: 1px solid #C8B8B5; font-size: 13.5px; background: #FFF; color: #1E1E1E; font-family: inherit; }
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
                <button class="logout-btn" onclick="handleLogout()">🚪 تسجيل الخروج</button>
            </div>
        </div>

        <!-- شريط التبويبات لكافة خدمات الديسكتوب -->
        <div class="nav-scroll">
            <button class="tab-btn active" onclick="switchTab('tab-dash', this)">📊 المؤشرات الحية</button>
            <button class="tab-btn" onclick="switchTab('tab-pos', this)">🛒 نقطة البيع (POS)</button>
            <button class="tab-btn" onclick="switchTab('tab-sales-reg', this)">📋 سجل المبيعات</button>
            <button class="tab-btn" onclick="switchTab('tab-load', this)">🚚 تنزيل سيارة</button>
            <button class="tab-btn" onclick="switchTab('tab-stock', this)">🚛 جرد الأرضية</button>
            <button class="tab-btn" onclick="switchTab('tab-col', this)">🧾 سندات التحصيل</button>
            <button class="tab-btn" onclick="switchTab('tab-pending', this)">📄 الفواتير الآجلة</button>
            <button class="tab-btn" onclick="switchTab('tab-exp', this)">💸 الخزينة والمصروفات</button>
            <button class="tab-btn" onclick="switchTab('tab-pur', this)">📥 فواتير المشتريات</button>
            <button class="tab-btn" onclick="switchTab('tab-crate', this)">📦 حركة الصناديق</button>
            <button class="tab-btn" onclick="switchTab('tab-bank', this)">🏦 البنوك والشيكات</button>
            <button class="tab-btn" onclick="switchTab('tab-wb', this)">⚖️ ميزان بسكول</button>
            <button class="tab-btn" onclick="switchTab('tab-master', this)">👥 دليل الحسابات</button>
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

        <!-- 2. نقطة البيع (POS) -->
        <div id="tab-pos" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">🛒 إصدار فاتورة مبيعات سحابية</h3>
                <form id="f-pos" onsubmit="handlePosSubmit(event)">
                    <label>العميل / المشتري</label>
                    <select name="Customer" id="posCustSelect" onchange="updateCustDebtHint()" required>
                        <option value="عميل نقدي">عميل نقدي</option>
                        ${customers.map(c => `<option value="${esc(getName(c))}" data-debt="${getBalance(c)}">${esc(getName(c))} (مديونية: ${getBalance(c).toLocaleString()} ج)</option>`).join('')}
                    </select>
                    <div id="custDebtHint" style="font-size:11.5px;color:#B45309;margin-top:3px;font-weight:bold;"></div>

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

                    <button type="submit" class="submit-btn">💾 حفظ الفاتورة وتمريرها للسيرفر</button>
                </form>
            </div>
        </div>

        <!-- 3. سجل المبيعات -->
        <div id="tab-sales-reg" class="tab-content">
            <h3>📋 سجل فواتير المبيعات</h3>
            <table>
                <tr><th>الفاتورة</th><th>التاريخ</th><th>العميل</th><th>الصنف</th><th>الوزن</th><th>الإجمالي</th><th>المدفوع</th></tr>
                ${recentSales.map(s => `
                    <tr>
                        <td><b>${esc(s.InvoiceNo || s.invoiceNo)}</b></td>
                        <td>${esc(s.Date || s.date)}</td>
                        <td>${esc(s.Customer || s.customer)}</td>
                        <td>${esc(s.Item || s.item)}</td>
                        <td>${Number(s.Weight || s.weight || 0).toLocaleString()} ك</td>
                        <td>${Number(s.Value || s.value || 0).toLocaleString()} ج</td>
                        <td>${Number(s.PaidAmount || s.paidAmount || 0).toLocaleString()} ج</td>
                    </tr>
                `).join('')}
            </table>
        </div>

        <!-- 4. تنزيل سيارة -->
        <div id="tab-load" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">🚚 توريد وتنزيل سيارة بالأرضية</h3>
                <form onsubmit="handleLoadSubmit(event)">
                    <label>المورد / التاجر</label>
                    <select name="Supplier" required>
                        ${suppliers.map(s => `<option value="${esc(getName(s))}">${esc(getName(s))}</option>`).join('')}
                    </select>
                    <label>رقم / بيان السيارة</label>
                    <input type="text" name="Vehicle" placeholder="مثال: 5412 نقل" required />
                    <label>الصنف</label>
                    <select name="Item" required>
                        ${items.map(i => `<option value="${esc(getName(i))}">${esc(getName(i))}</option>`).join('')}
                    </select>
                    <div class="grid-2">
                        <div>
                            <label>العدد الوارد (صناديق)</label>
                            <input type="number" name="QtyIn" value="0" step="1" required />
                        </div>
                        <div>
                            <label>الوزن الوارد (كجم)</label>
                            <input type="number" name="WeightIn" value="0" step="0.5" required />
                        </div>
                    </div>
                    <div class="grid-2">
                        <div>
                            <label>نولون النقل (ج)</label>
                            <input type="number" name="Freight" value="0" />
                        </div>
                        <div>
                            <label>نسبة العمولة (%)</label>
                            <input type="number" name="Commission" value="5" step="0.5" />
                        </div>
                    </div>
                    <button type="submit" class="submit-btn">🚚 تثبيت السيارة بالأرضية</button>
                </form>
            </div>
        </div>

        <!-- 5. جرد الأرضية -->
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

        <!-- 6. سندات التحصيل -->
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

            <h3>سندات التحصيل السابقة</h3>
            <table>
                <tr><th>رقم السند</th><th>التاريخ</th><th>العميل</th><th>المبلغ</th><th>طريقة الدفع</th></tr>
                ${collections.map(c => `
                    <tr>
                        <td><b>${esc(c.ReceiptNo || c.receiptNo)}</b></td>
                        <td>${esc(c.Date || c.date)}</td>
                        <td>${esc(c.Customer || c.customer)}</td>
                        <td>${Number(c.Amount || c.amount || 0).toLocaleString()} ج</td>
                        <td>${esc(c.PaymentMethod || c.paymentMethod)}</td>
                    </tr>
                `).join('')}
            </table>
        </div>

        <!-- 7. الفواتير الآجلة -->
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

        <!-- 8. الخزينة والمصروفات -->
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
                <tr><th>التاريخ</th><th>البند</th><th>البيان</th><th>المبلغ</th></tr>
                ${expenses.map(e => `
                    <tr>
                        <td>${esc(e.Date || e.date)}</td>
                        <td>${esc(e.Category || e.category)}</td>
                        <td>${esc(e.Description || e.description)}</td>
                        <td>${Number(e.Amount || e.amount || 0).toLocaleString()} ج</td>
                    </tr>
                `).join('')}
            </table>
        </div>

        <!-- 9. فواتير المشتريات -->
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

        <!-- 10. حركة الصناديق -->
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
                    <button type="submit" class="submit-btn">📦 تثبيت حركة الصناديق</button>
                </form>
            </div>
        </div>

        <!-- 11. البنوك والشيكات -->
        <div id="tab-bank" class="tab-content">
            <h3>🏦 الحسابات البنكية والشيكات</h3>
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

        <!-- 12. ميزان بسكول -->
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

        <!-- 13. دليل الحسابات -->
        <div id="tab-master" class="tab-content">
            <h3>👥 العملاء والموردين (${customers.length} عميل / ${suppliers.length} مورد)</h3>
            <table>
                <tr><th>الاسم</th><th>الصفة</th><th>المديونية / الرصيد</th></tr>
                ${customers.map(c => `<tr><td>${esc(getName(c))}</td><td>عميل</td><td>${getBalance(c).toLocaleString()} ج</td></tr>`).join('')}
                ${suppliers.map(s => `<tr><td>${esc(getName(s))}</td><td>مورد</td><td>عمولة: ${esc(s.DefaultCommission || s.defaultCommission || 0)}%</td></tr>`).join('')}
            </table>
        </div>
    </div>

    <script>
    const AGENCY_KEY = "${esc(key)}";
    let currentUser = JSON.parse(localStorage.getItem('mizan_staff_' + AGENCY_KEY) || 'null');

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
        document.getElementById(tabId).classList.add('active');
        btn.classList.add('active');
    }

    function updateCustDebtHint() {
        const sel = document.getElementById('posCustSelect');
        const opt = sel.options[sel.selectedIndex];
        const debt = opt.getAttribute('data-debt');
        const hint = document.getElementById('custDebtHint');
        if (debt && parseFloat(debt) !== 0) {
            hint.textContent = '⚠️ الحساب السابق للعميل: ' + Number(debt).toLocaleString() + ' ج';
        } else {
            hint.textContent = '';
        }
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
        if (ok) { f.reset(); calcPosTotal(); }
    }

    async function handleLoadSubmit(e) {
        e.preventDefault();
        const f = e.target;
        const data = {
            Supplier: f.Supplier.value,
            Vehicle: f.Vehicle.value,
            Item: f.Item.value,
            QtyIn: parseFloat(f.QtyIn.value) || 0,
            WeightIn: parseFloat(f.WeightIn.value) || 0,
            Freight: parseFloat(f.Freight.value) || 0,
            Commission: parseFloat(f.Commission.value) || 5
        };
        const ok = await sendAction('LOAD_SUPPLY', data);
        if (ok) f.reset();
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
            Price: parseFloat(f.Price.value) || 70
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
