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
    changelog: "Ø§Ù„Ù…Ù†Ø¸ÙˆÙ…Ø© Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠØ© Ø§Ù„Ù…ÙˆØ­Ø¯Ø© Ø§Ù„Ù…ØªÙˆØ§ÙÙ‚Ø© 100% Ù…Ø¹ Ø£Ø¬Ù‡Ø²Ø© Ø§Ù„ÙƒÙ…Ø¨ÙŠÙˆØªØ± ÙˆÙ…ÙˆØ§Ø²ÙŠÙ† Ø§Ù„Ø£Ø³ÙˆØ§Ù‚"
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
    const subject = 'ÙƒÙˆØ¯ Ø§Ù„ØªØ­Ù‚Ù‚ Ù…Ù† Ø­Ø³Ø§Ø¨Ùƒ ÙÙŠ Ù…ÙŠØ²Ø§Ù†';
    const text = `ÙƒÙˆØ¯ Ø§Ù„ØªØ­Ù‚Ù‚ Ø§Ù„Ø®Ø§Øµ Ø¨Ùƒ: ${code}\nØµØ§Ù„Ø­ Ù„Ù…Ø¯Ø© 10 Ø¯Ù‚Ø§Ø¦Ù‚.`;
    const html = `<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;font-size:16px">
        <p>Ù…Ø±Ø­Ø¨Ø§Ù‹ØŒ Ù„ØªÙØ¹ÙŠÙ„ Ø­Ø³Ø§Ø¨ ÙˆÙƒØ§Ù„Ø© <b>${esc(agencyName)}</b> ÙÙŠ Ù…ÙŠØ²Ø§Ù† Ø§Ø³ØªØ®Ø¯Ù… Ø§Ù„ÙƒÙˆØ¯ Ø§Ù„ØªØ§Ù„ÙŠ:</p>
        <p style="font-size:32px;letter-spacing:6px;font-weight:bold">${code}</p>
        <p style="color:#666">ØµØ§Ù„Ø­ Ù„Ù…Ø¯Ø© 10 Ø¯Ù‚Ø§Ø¦Ù‚.</p></div>`;

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
        from: process.env.MAIL_FROM || `"Ù…ÙŠØ²Ø§Ù†" <${process.env.SMTP_USER}>`,
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
        if (pathname === '/' || pathname === '') {
            return sendHtml(res, 200, shell('Ø®Ø§Ø¯Ù… Ù…ÙŠØ²Ø§Ù† Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠ', `
                <div class="box" style="text-align:center">
                    <h2>ðŸš€ Ø®Ø§Ø¯Ù… Ù…ÙŠØ²Ø§Ù† Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠ Ø§Ù„Ù…ÙˆØ­Ø¯</h2>
                    <p style="color:#C8B8B5;">Ø¥Ø¯Ø§Ø±Ø© ÙˆÙ…ØªØ§Ø¨Ø¹Ø© ÙˆÙ…Ø²Ø§Ù…Ù†Ø© ÙƒØ§ÙØ© Ø¹Ù…Ù„ÙŠØ§Øª Ø§Ù„ÙˆÙƒØ§Ù„Ø© Ù„Ø­Ø¸Ø© Ø¨Ù„Ø­Ø¸Ø© Ù…Ø¹ Ø£Ø¬Ù‡Ø²Ø© Ø§Ù„ÙƒÙ…Ø¨ÙŠÙˆØªØ± ÙˆØ§Ù„Ù…ÙˆØ§Ø²ÙŠÙ†.</p>
                    <a class="btn" href="/login">ðŸ”‘ ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø¯Ø®ÙˆÙ„ Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠ</a>
                    <a class="btn small" href="/register">ðŸ“ Ø¥Ù†Ø´Ø§Ø¡ Ø­Ø³Ø§Ø¨ ÙˆÙƒØ§Ù„Ø© Ø¬Ø¯ÙŠØ¯</a>
                </div>`));
        }

        // Ù…Ø³Ø§Ø± Ø§Ø³ØªØ¹Ø±Ø§Ø¶ Ø§Ù„ÙØ§ØªÙˆØ±Ø© Ø§Ù„Ø¥Ù„ÙƒØªØ±ÙˆÙ†ÙŠØ© Ø¹Ø¨Ø± Ù…Ø³Ø­ ÙƒÙˆØ¯ Ø§Ù„Ù€ QR
        if (pathname === '/invoice' || pathname === '/api/invoice') {
            const invNo = String(query.id || query.inv || '').trim();
            const key = String(query.key || '').trim();

            let targetAgencyData = null;
            if (key) {
                targetAgencyData = await redis.get(`agency:${key}`);
            } else {
                // Ø§Ù„Ø¨Ø­Ø« ÙÙŠ Ø§Ù„ÙˆÙƒØ§Ù„Ø§Øª Ø§Ù„Ù†Ø´Ø·Ø© Ø¹Ù† Ø±Ù‚Ù… Ø§Ù„ÙØ§ØªÙˆØ±Ø©
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
                return sendHtml(res, 404, shell('ÙØ§ØªÙˆØ±Ø© ØºÙŠØ± Ù…ÙˆØ¬ÙˆØ¯Ø©', `
                    <div class="box" style="text-align:center;">
                        <h2>âš ï¸ Ù„Ù… ÙŠØªÙ… Ø§Ù„Ø¹Ø«ÙˆØ± Ø¹Ù„Ù‰ Ø§Ù„ÙØ§ØªÙˆØ±Ø©</h2>
                        <p style="color:#C8B8B5;">Ø±Ù‚Ù… Ø§Ù„ÙØ§ØªÙˆØ±Ø© Ø§Ù„Ù…Ø·Ù„ÙˆØ¨Ø© [${esc(invNo)}] ØºÙŠØ± Ù…Ø³Ø¬Ù„ ÙÙŠ Ø§Ù„Ø³ÙŠØ±ÙØ± Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠ Ø£Ùˆ ØªÙ… Ø£Ø±Ø´ÙØªÙ‡.</p>
                    </div>`));
            }

            const first = sales[0];
            const totalVal = sales.reduce((acc, x) => acc + Number(x.Value || x.value || 0), 0);
            const paidVal = Number(first.PaidAmount || first.paidAmount || 0);
            const remVal = Math.max(0, totalVal - paidVal);

            return sendHtml(res, 200, `<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
<meta charset="UTF-8"><title>ÙØ§ØªÙˆØ±Ø© Ø¥Ù„ÙƒØªØ±ÙˆÙ†ÙŠØ© Ù…Ø¹ØªÙ…Ø¯Ø© #${esc(invNo)}</title>
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
    <h2>ðŸ¢ ${esc(targetAgencyData.agency_name || "ÙˆÙƒØ§Ù„Ø© Ù…ÙŠØ²Ø§Ù†")}</h2>
    <div style="text-align:center;font-weight:bold;color:#5A0817;">ðŸ“„ ÙØ§ØªÙˆØ±Ø© Ù…Ø¨ÙŠØ¹Ø§Øª Ø¥Ù„ÙƒØªØ±ÙˆÙ†ÙŠØ© Ù…Ø¹ØªÙ…Ø¯Ø© #${esc(invNo)}</div>
    <div style="font-size:12px;color:#666;text-align:center;margin-bottom:10px;">Ø§Ù„ØªØ§Ø±ÙŠØ®: ${esc(first.Date || first.date)} | Ø§Ù„Ø¹Ù…ÙŠÙ„: <b>${esc(first.Customer || first.customer)}</b></div>
    <table>
        <thead><tr><th>Ø§Ù„ØµÙ†Ù</th><th>Ø§Ù„Ø¹Ø¯Ø¯</th><th>Ø§Ù„ÙˆØ²Ù†</th><th>Ø§Ù„Ø³Ø¹Ø±</th><th>Ø§Ù„Ø¥Ø¬Ù…Ø§Ù„ÙŠ</th></tr></thead>
        <tbody>
            ${sales.map(s => `<tr>
                <td><b>${esc(s.Item || s.item)}</b></td>
                <td>${Number(s.Qty || s.qty || 0).toLocaleString()} Ù‚</td>
                <td>${Number(s.Weight || s.weight || 0).toLocaleString()} Ùƒ</td>
                <td>${Number(s.Price || s.price || 0).toLocaleString()} Ø¬</td>
                <td>${Number(s.Value || s.value || 0).toLocaleString()} Ø¬</td>
            </tr>`).join('')}
        </tbody>
    </table>
    <div class="tot">Ø§Ù„Ù…Ø¬Ù…ÙˆØ¹ Ø§Ù„ÙƒÙ„ÙŠ: ${totalVal.toLocaleString()} Ø¬Ù†ÙŠÙ‡</div>
    <div style="margin-top:6px;font-size:13px;display:flex;justify-content:space-between;">
        <span>Ø§Ù„Ù…Ø¯ÙÙˆØ¹: ${paidVal.toLocaleString()} Ø¬</span>
        <span style="color:#DC2626;font-weight:bold;">Ø§Ù„Ù…ØªØ¨Ù‚ÙŠ: ${remVal.toLocaleString()} Ø¬</span>
    </div>
    <div style="margin-top:15px;text-align:center;font-size:11px;color:#888;border-top:1px dashed #CCC;padding-top:10px;">
        âš–ï¸ Ù…Ù†Ø¸ÙˆÙ…Ø© Ù…ÙŠØ²Ø§Ù† Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠØ© Ù„Ø¥Ø¯Ø§Ø±Ø© ÙˆÙ…Ø­Ø§Ø³Ø¨Ø© Ø§Ù„ÙˆÙƒØ§Ù„Ø§Øª ÙˆØ§Ù„Ø£Ø³ÙˆØ§Ù‚
    </div>
</div>
</body></html>`);
        }

        if (pathname === '/register' && req.method === 'GET') {
            const needCode = !!process.env.REGISTER_CODE;
            const em = emailEnabled(), wa = waEnabled();
            return sendHtml(res, 200, shell('Ø¥Ù†Ø´Ø§Ø¡ Ø­Ø³Ø§Ø¨ ÙˆÙƒØ§Ù„Ø© Ø¬Ø¯ÙŠØ¯ | Ù…ÙŠØ²Ø§Ù†', `
                <div class="box">
                    <h2>ðŸ“ Ø¥Ù†Ø´Ø§Ø¡ Ø­Ø³Ø§Ø¨ ÙˆÙƒØ§Ù„Ø© Ø¬Ø¯ÙŠØ¯</h2>
                    <form id="f" autocomplete="off">
                        <label>Ø§Ù„Ø¨Ø±ÙŠØ¯ Ø§Ù„Ø¥Ù„ÙƒØªØ±ÙˆÙ†ÙŠ</label>
                        <input type="email" name="email" required />
                        <label>Ø§Ø³Ù… Ø§Ù„ÙˆÙƒØ§Ù„Ø©</label>
                        <input type="text" name="agency_name" maxlength="60" required />
                        <label>Ø§Ø³Ù… Ø§Ù„Ù…Ø³ØªØ®Ø¯Ù… Ø§Ù„Ø±Ø¦ÙŠØ³ÙŠ</label>
                        <input type="text" name="username" pattern="[A-Za-z0-9_]{3,30}" minlength="3" maxlength="30" required />
                        <label>ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ± (8 Ø£Ø­Ø±Ù Ø¹Ù„Ù‰ Ø§Ù„Ø£Ù‚Ù„)</label>
                        <input type="password" name="password" minlength="8" required />
                        <label>ØªØ£ÙƒÙŠØ¯ ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ±</label>
                        <input type="password" name="password2" minlength="8" required />
                        <label>Ø§Ø³ØªÙ„Ø§Ù… ÙƒÙˆØ¯ Ø§Ù„ØªØ­Ù‚Ù‚ Ø¹Ù† Ø·Ø±ÙŠÙ‚</label>
                        <div>
                            ${em ? `<label class="radio"><input type="radio" name="channel" value="email" checked />Ø§Ù„Ø¨Ø±ÙŠØ¯ Ø§Ù„Ø¥Ù„ÙƒØªØ±ÙˆÙ†ÙŠ</label>` : ''}
                            ${wa ? `<label class="radio"><input type="radio" name="channel" value="whatsapp" ${em ? '' : 'checked'} />ÙˆØ§ØªØ³Ø§Ø¨</label>` : ''}
                        </div>
                        <div id="phoneBox" style="display:none">
                            <label>Ø±Ù‚Ù… Ø§Ù„ÙˆØ§ØªØ³Ø§Ø¨ (Ù…Ø«Ø§Ù„: 01012345678)</label>
                            <input type="tel" name="phone" />
                        </div>
                        ${needCode ? `<label>ÙƒÙˆØ¯ Ø§Ù„ØªØ³Ø¬ÙŠÙ„</label><input type="text" name="register_code" required />` : ''}
                        <button type="submit">Ø¥Ù†Ø´Ø§Ø¡ Ø§Ù„Ø­Ø³Ø§Ø¨ ÙˆØ¥Ø±Ø³Ø§Ù„ Ø§Ù„ÙƒÙˆØ¯</button>
                        <div class="msg" id="msg"></div>
                    </form>
                    <a class="btn small" href="/login">Ù„Ø¯ÙŠÙƒ Ø­Ø³Ø§Ø¨ØŸ Ø³Ø¬Ù‘Ù„ Ø§Ù„Ø¯Ø®ÙˆÙ„</a>
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
                  if(d.password!==d.password2){msg.textContent='ÙƒÙ„Ù…ØªØ§ Ø§Ù„Ù…Ø±ÙˆØ± ØºÙŠØ± Ù…ØªØ·Ø§Ø¨Ù‚ØªÙŠÙ†';return;}
                  var btn=f.querySelector('button');btn.disabled=true;
                  fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)})
                  .then(function(r){return r.json();})
                  .then(function(j){
                    btn.disabled=false;
                    if(!j.success){msg.textContent=j.message||'Ø­Ø¯Ø« Ø®Ø·Ø£';return;}
                    window.location.href='/verify?u='+encodeURIComponent(j.username)+'&to='+encodeURIComponent(j.sent_to||'');
                  }).catch(function(){btn.disabled=false;msg.textContent='ØªØ¹Ø°Ø± Ø§Ù„Ø§ØªØµØ§Ù„ Ø¨Ø§Ù„Ø³ÙŠØ±ÙØ±';});
                });
                `));
        }

        if (pathname === '/api/register' && req.method === 'POST') {
            if (!(await rateLimit(req, 'register', 10))) return sendJson(res, 429, { success: false, message: 'Ù…Ø­Ø§ÙˆÙ„Ø§Øª ÙƒØ«ÙŠØ±Ø©.' });
            let b = await readJson(req);
            const email = String(b.email || '').trim().toLowerCase();
            const agencyName = String(b.agency_name || '').trim();
            const username = String(b.username || '').trim().toLowerCase();
            const password = String(b.password || '');
            const channel = String(b.channel || 'email');

            if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return sendJson(res, 400, { success: false, message: 'Ø§Ù„Ø¨Ø±ÙŠØ¯ ØºÙŠØ± ØµØ­ÙŠØ­.' });
            if (!agencyName || !/^[a-z0-9_]{3,30}$/.test(username) || password.length < 8)
                return sendJson(res, 400, { success: false, message: 'Ø§Ù„Ø¨ÙŠØ§Ù†Ø§Øª ØºÙŠØ± Ù…ÙƒØªÙ…Ù„Ø©.' });

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
            if (!userOk) return sendJson(res, 409, { success: false, message: 'Ø§Ø³Ù… Ø§Ù„Ù…Ø³ØªØ®Ø¯Ù… Ù…Ø³Ø¬Ù„ Ù…Ø³Ø¨Ù‚Ø§Ù‹.' });
            await redis.set(`email:${email}`, username, { nx: true, ex: UNVERIFIED_TTL });

            try { await issueCode(record); }
            catch { await dropAccount(record); return sendJson(res, 502, { success: false, message: 'ØªØ¹Ø°Ø± Ø¥Ø±Ø³Ø§Ù„ ÙƒÙˆØ¯ Ø§Ù„ØªØ­Ù‚Ù‚.' }); }

            return sendJson(res, 200, { success: true, need_verify: true, username, sent_to: maskFor(record) });
        }

        if (pathname === '/verify' && req.method === 'GET') {
            return sendHtml(res, 200, shell('ØªØ£ÙƒÙŠØ¯ Ø§Ù„Ø­Ø³Ø§Ø¨ | Ù…ÙŠØ²Ø§Ù†', `
                <div class="box" id="formBox">
                    <h2>ðŸ“© ØªØ£ÙƒÙŠØ¯ ØªÙØ¹ÙŠÙ„ Ø§Ù„Ø­Ø³Ø§Ø¨</h2>
                    <p class="note" id="info" style="text-align:center">Ø£Ø¯Ø®Ù„ ÙƒÙˆØ¯ Ø§Ù„ØªØ­Ù‚Ù‚ Ø§Ù„Ù…ÙƒÙˆÙ‘Ù† Ù…Ù† 6 Ø£Ø±Ù‚Ø§Ù….</p>
                    <form id="f">
                        <label>ÙƒÙˆØ¯ Ø§Ù„ØªØ­Ù‚Ù‚</label>
                        <input type="text" name="code" inputmode="numeric" maxlength="6" pattern="[0-9]{6}" required autocomplete="one-time-code" dir="ltr" style="text-align:center;letter-spacing:6px;font-size:22px" />
                        <button type="submit">ØªØ£ÙƒÙŠØ¯ Ø§Ù„Ø­Ø³Ø§Ø¨</button>
                        <div class="msg" id="msg"></div>
                    </form>
                    <button class="small" type="button" id="resend">ðŸ” Ø¥Ø±Ø³Ø§Ù„ ÙƒÙˆØ¯ Ø¬Ø¯ÙŠØ¯</button>
                </div>
                <div class="box" id="resBox" style="display:none">
                    <h2>âœ… ØªÙ… ØªÙØ¹ÙŠÙ„ Ø­Ø³Ø§Ø¨ Ø§Ù„ÙˆÙƒØ§Ù„Ø© Ø¨Ù†Ø¬Ø§Ø­</h2>
                    <label>Ø§Ù„Ø±Ø§Ø¨Ø· Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠ Ù„Ù„ÙˆÙƒØ§Ù„Ø©</label>
                    <input type="text" id="link" readonly />
                    <button class="small" type="button" onclick="copyFrom('link')">ðŸ“‹ Ù†Ø³Ø® Ø§Ù„Ø±Ø§Ø¨Ø·</button>
                    <label>ÙƒÙˆØ¯ Ø±Ø¨Ø· Ø§Ù„ÙˆÙƒØ§Ù„Ø©</label>
                    <input type="text" id="key" readonly />
                    <button class="small" type="button" onclick="copyFrom('key')">ðŸ“‹ Ù†Ø³Ø® Ø§Ù„ÙƒÙˆØ¯</button>
                    <a class="btn" id="openPortalBtn" href="#">ðŸš€ ÙØªØ­ Ø¨ÙˆØ§Ø¨Ø© Ø§Ù„ÙˆÙƒØ§Ù„Ø© Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠØ©</a>
                </div>`, `
                var q=new URLSearchParams(location.search),u=q.get('u')||'';
                var f=document.getElementById('f'),msg=document.getElementById('msg'),info=document.getElementById('info');
                if(q.get('to')){info.textContent='Ø£Ø±Ø³Ù„Ù†Ø§ ÙƒÙˆØ¯ Ø§Ù„ØªØ­Ù‚Ù‚ Ø¥Ù„Ù‰: '+q.get('to');}
                function show(text,ok){msg.style.color=ok?'#7fd6a8':'';msg.textContent=text;}
                f.addEventListener('submit',function(e){
                  e.preventDefault();show('',false);
                  var btn=f.querySelector('button');btn.disabled=true;
                  fetch('/api/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,code:f.code.value.trim()})})
                  .then(function(r){return r.json();})
                  .then(function(j){
                    btn.disabled=false;
                    if(!j.success){show(j.message||'Ø­Ø¯Ø« Ø®Ø·Ø£',false);return;}
                    document.getElementById('formBox').style.display='none';
                    document.getElementById('resBox').style.display='block';
                    document.getElementById('link').value=j.link;
                    document.getElementById('key').value=j.agency_key;
                    document.getElementById('openPortalBtn').href=j.link;
                  }).catch(function(){btn.disabled=false;show('ØªØ¹Ø°Ø± Ø§Ù„Ø§ØªØµØ§Ù„ Ø¨Ø§Ù„Ø³ÙŠØ±ÙØ±',false);});
                });
                function copyFrom(id){var el=document.getElementById(id);el.select();if(navigator.clipboard){navigator.clipboard.writeText(el.value);}}
                `));
        }

        if (pathname === '/api/verify' && req.method === 'POST') {
            let b = await readJson(req);
            const username = String(b.username || '').trim().toLowerCase();
            const code = String(b.code || '').trim();
            const user = await redis.get(`user:${username}`);

            if (!user) return sendJson(res, 404, { success: false, message: 'Ø§Ù„Ø­Ø³Ø§Ø¨ ØºÙŠØ± Ù…ÙˆØ¬ÙˆØ¯.' });
            const otp = await redis.get(`otp:${username}`);
            if (!otp || otp.expires < Date.now()) return sendJson(res, 400, { success: false, message: 'Ø§Ù†ØªÙ‡Øª ØµÙ„Ø§Ø­ÙŠØ© Ø§Ù„ÙƒÙˆØ¯.' });

            const given = Buffer.from(otpHash(user.salt, code));
            const real = Buffer.from(otp.hash);
            if (given.length !== real.length || !crypto.timingSafeEqual(given, real))
                return sendJson(res, 400, { success: false, message: 'Ø§Ù„ÙƒÙˆØ¯ ØºÙŠØ± ØµØ­ÙŠØ­.' });

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
            return sendHtml(res, 200, shell('ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø¯Ø®ÙˆÙ„ | Ù…ÙŠØ²Ø§Ù†', `
                <div class="box">
                    <h2>ðŸ”‘ ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø¯Ø®ÙˆÙ„ Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠ</h2>
                    <form id="f">
                        <label>Ø§Ø³Ù… Ø§Ù„Ù…Ø³ØªØ®Ø¯Ù… Ø§Ù„Ø±Ø¦ÙŠØ³ÙŠ</label>
                        <input type="text" name="username" required autocomplete="username" />
                        <label>ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ±</label>
                        <input type="password" name="password" required autocomplete="current-password" />
                        <button type="submit">Ø¯Ø®ÙˆÙ„</button>
                        <div class="msg" id="msg"></div>
                    </form>
                    <a class="btn small" href="/register">Ù„ÙŠØ³ Ù„Ø¯ÙŠÙƒ Ø­Ø³Ø§Ø¨ØŸ Ø£Ù†Ø´Ø¦ ÙˆØ§Ø­Ø¯Ø§Ù‹</a>
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
                    if(!j.success){msg.textContent=j.message||'Ø­Ø¯Ø« Ø®Ø·Ø£';return;}
                    window.location.href=j.link;
                  }).catch(function(){btn.disabled=false;msg.textContent='ØªØ¹Ø°Ø± Ø§Ù„Ø§ØªØµØ§Ù„ Ø¨Ø§Ù„Ø³ÙŠØ±ÙØ±';});
                });
                `));
        }

        if (pathname === '/api/login' && req.method === 'POST') {
            let b = await readJson(req);
            const username = String(b.username || '').trim().toLowerCase();
            const password = String(b.password || '');
            const user = await redis.get(`user:${username}`);

            const salt = user ? user.salt : 'x'.repeat(32);
            const hash = await hashPassword(password, salt);
            if (!user || hash !== user.password_hash) {
                return sendJson(res, 401, { success: false, message: 'Ø¨ÙŠØ§Ù†Ø§Øª Ø§Ù„Ø¯Ø®ÙˆÙ„ ØºÙŠØ± ØµØ­ÙŠØ­Ø©.' });
            }

            return sendJson(res, 200, {
                success: true,
                agency_name: user.agency_name,
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
                message: "Ø£Ù†Øª ØªØ¹Ù…Ù„ Ø¹Ù„Ù‰ Ø£Ø­Ø¯Ø« Ø¥ØµØ¯Ø§Ø± Ù…Ø¹ØªÙ…Ø¯.",
                changelog: versionInfo.changelog
            });
        }

        // Ø§Ø³ØªÙ‚Ø¨Ø§Ù„ ÙˆÙ…Ø²Ø§Ù…Ù†Ø© ÙƒØ§Ù…Ù„ Ø¬Ø¯Ø§ÙˆÙ„ Ø§Ù„Ù…Ù†Ø¸ÙˆÙ…Ø© Ù…Ù† Ø£Ø¬Ù‡Ø²Ø© Ø§Ù„ÙƒÙ…Ø¨ÙŠÙˆØªØ±
        if ((pathname === '/api/sync/push' || pathname === '/api/sync') && req.method === 'POST') {
            let body = await readJson(req);
            const agency_key = String(body.agency_key || body.key || body.apiKey || req.headers['x-api-key'] || query.key || '').trim();
            if (!agency_key) return sendJson(res, 400, { success: false, message: "ÙƒÙˆØ¯ Ø§Ù„ÙˆÙƒØ§Ù„Ø© Ù…Ø·Ù„ÙˆØ¨." });

            let owner = await redis.get(`keyidx:${agency_key}`);
            let user = owner ? await redis.get(`user:${owner}`) : null;
            if (!owner) await redis.set(`keyidx:${agency_key}`, "desktop_client");

            await redis.set(`agency:${agency_key}`, {
                agency_name: body.agency_name || (user ? user.agency_name : "ÙˆÙƒØ§Ù„Ø© Ù…ÙŠØ²Ø§Ù†"),
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

            return sendJson(res, 200, { success: true, message: "ØªÙ… Ø§Ø³ØªÙ‚Ø¨Ø§Ù„ ÙƒØ§Ù…Ù„ Ø¬Ø¯Ø§ÙˆÙ„ Ø§Ù„ÙˆÙƒØ§Ù„Ø© Ø¨Ø§Ù„Ø³ÙŠØ±ÙØ± Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠ Ø¨Ù†Ø¬Ø§Ø­." });
        }

        // Ø³Ø­Ø¨ Ø§Ù„Ø¹Ù…Ù„ÙŠØ§Øª Ø§Ù„Ù…Ù†Ø´Ø£Ø© Ø³Ø­Ø§Ø¨ÙŠØ§Ù‹ Ø¥Ù„Ù‰ Ø§Ù„Ø¯ÙŠØ³ÙƒØªÙˆØ¨
        if (pathname === '/api/mobile/orders' && req.method === 'GET') {
            const agency_key = String(query.key || req.headers['x-api-key'] || '').trim();
            if (!agency_key) return sendJson(res, 400, { success: false, message: "ÙƒÙˆØ¯ Ø§Ù„ÙˆÙƒØ§Ù„Ø© Ù…Ø·Ù„ÙˆØ¨." });

            const queueKey = `orders_queue:${agency_key}`;
            const queuedOrders = await redis.get(queueKey) || [];
            if (queuedOrders.length > 0) await redis.del(queueKey);

            return sendJson(res, 200, queuedOrders);
        }

        // ØªØ³Ø¬ÙŠÙ„ Ø¯Ø®ÙˆÙ„ Ø§Ù„Ù…ÙˆØ¸Ù Ø§Ù„Ù…Ø³ØªÙˆØ±Ø¯ Ù…Ù† Ø§Ù„Ø¯ÙŠØ³ÙƒØªÙˆØ¨
        if (pathname === '/api/web/user-login' && req.method === 'POST') {
            let b = await readJson(req);
            const agency_key = String(b.agency_key || '').trim();
            const username = String(b.username || '').trim();
            const password = String(b.password || '');

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
                    return sendJson(res, 401, { success: false, message: "ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ± ØºÙŠØ± ØµØ­ÙŠØ­Ø©." });
                }
                return sendJson(res, 200, {
                    success: true,
                    user: {
                        id: matchedUser.Id || matchedUser.id || 1,
                        username: matchedUser.Username || matchedUser.username,
                        full_name: matchedUser.FullName || matchedUser.fullName || matchedUser.full_name,
                        role: matchedUser.Role || matchedUser.role || 'Ù…Ø­Ø§Ø³Ø¨',
                        job_title: matchedUser.JobTitle || matchedUser.job_title || 'Ù…Ø­Ø§Ø³Ø¨'
                    }
                });
            }

            if (ownerUser && (ownerUser.username.toLowerCase() === cleanUser || cleanUser === 'admin')) {
                const hash = await hashPassword(password, ownerUser.salt);
                if (hash === ownerUser.password_hash) {
                    return sendJson(res, 200, {
                        success: true,
                        user: { id: 1, username: ownerUser.username, full_name: `${ownerUser.agency_name} (Ø§Ù„Ù…Ø¯ÙŠØ± Ø§Ù„Ø¹Ø§Ù…)`, role: 'admin', job_title: 'Ù…Ø¯ÙŠØ± Ø¹Ø§Ù…' }
                    });
                }
            }

            return sendJson(res, 401, { success: false, message: "Ø¨ÙŠØ§Ù†Ø§Øª Ø§Ù„Ø¯Ø®ÙˆÙ„ ØºÙŠØ± ØµØ­ÙŠØ­Ø©." });
        }

        // Ø¥Ù†Ø´Ø§Ø¡ Ø§Ù„Ø¹Ù…Ù„ÙŠØ§Øª (Ø¥Ø¶Ø§ÙØ©ØŒ ØªØ¹Ø¯ÙŠÙ„ØŒ Ø­Ø°Ù) Ù…Ø¹ ØªØ²ÙˆÙŠØ¯ ÙƒÙ„ Ø¹Ù…Ù„ÙŠØ© Ø¨Ù€ OrderId ÙØ±ÙŠØ¯ Ù„Ù…Ù†Ø¹ ØªÙƒØ±Ø§Ø± Ø§Ù„Ù…Ø²Ø§Ù…Ù†Ø©
        if (pathname === '/api/web/create-action' && req.method === 'POST') {
            let b = await readJson(req);
            const { agency_key, action_type, user_name, data, source } = b;
            if (!agency_key || !action_type || !data) return sendJson(res, 400, { success: false, message: "Ø¨ÙŠØ§Ù†Ø§Øª Ù†Ø§Ù‚ØµØ©." });

            const queueKey = `orders_queue:${agency_key}`;
            const queuedOrders = await redis.get(queueKey) || [];

            const dateStr = data.Date || new Date().toISOString().slice(0, 10);
            const authorFormatted = `${user_name || "Ù…Ø³ØªØ®Ø¯Ù…"} (${source === 'mobile' ? 'Ù…Ø³ØªØ®Ø¯Ù… Ø§Ù„Ù‡Ø§ØªÙ' : 'Ù…Ø³ØªØ®Ø¯Ù… Ø§Ù„Ø³ÙŠØ±ÙØ±'})`;
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
                            Customer: data.Customer || "Ø¹Ù…ÙŠÙ„ Ù†Ù‚Ø¯ÙŠ",
                            Item: it.Item,
                            Supplier: it.Supplier || "Ø¹Ø§Ù…",
                            LoadKey: it.LoadKey || data.LoadKey || "",
                            Salesman: data.Salesman || "Ø¹Ø§Ù…",
                            Grade: it.Grade || "ÙØ±Ø² Ø£ÙˆÙ„ Ù…Ù…ØªØ§Ø²",
                            CrateType: it.CrateType || "Ø¨Ø±Ù†ÙŠÙƒØ© Ø¨Ù„Ø§Ø³ØªÙŠÙƒ",
                            Qty: Number(it.Qty || 0),
                            Weight: Number(it.Weight || 0),
                            Price: Number(it.Price || 0),
                            Discount: Number(it.Discount || 0),
                            Value: Number(it.Value || 0),
                            PaidAmount: Number(idx === 0 ? (data.PaidAmount || 0) : 0),
                            RemainingAmount: Number(idx === 0 ? (data.RemainingAmount || 0) : 0),
                            PaymentMethod: data.PaymentMethod || "Ù†Ù‚Ø¯ÙŠ (ÙƒØ§Ø´)",
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
                        PaymentMethod: data.PaymentMethod || "Ù†Ù‚Ø¯ÙŠ (ÙƒØ§Ø´)",
                        CreatedBy: authorFormatted,
                        Notes: data.Notes || `Ø³Ù†Ø¯ ØªØ­ØµÙŠÙ„`
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
                        Category: data.Category || "Ù…ØµØ§Ø±ÙŠÙ Ù†Ø«Ø±ÙŠØ© Ø¹Ø§Ù…Ø©",
                        Description: data.Description || `ØµØ±Ù Ù†Ø«Ø±ÙŠ`,
                        Amount: Number(data.Amount || 0),
                        PaymentMethod: data.PaymentMethod || "Ù†Ù‚Ø¯ÙŠ (ÙƒØ§Ø´)",
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
                        Category: data.Category || "Ø´Ø±Ø§Ø¡ Ø¨Ø¶Ø§Ø¹Ø© ØªØ¬Ø§Ø±ÙŠØ© (ØªØ¶Ø§Ù Ù„Ù„Ø£Ø±Ø¶ÙŠØ©)",
                        Supplier: data.Supplier,
                        Item: data.Item,
                        Qty: Number(data.Qty || 0),
                        Weight: Number(data.Weight || 0),
                        Price: Number(data.Price || 0),
                        Value: Number(data.Value || 0),
                        PaidAmount: Number(data.PaidAmount || 0),
                        RemainingAmount: Number(data.RemainingAmount || 0),
                        PaymentMethod: data.PaymentMethod || "Ù†Ù‚Ø¯ÙŠ (ÙƒØ§Ø´)",
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
                        Kind: action_type === 'CRATE_RETURN' ? 'Ø§Ø³ØªØ±Ø¬Ø§Ø¹' : 'ØªØ³Ù„ÙŠÙ…',
                        CrateType: data.CrateType || "Ø¨Ø±Ù†ÙŠÙƒØ© Ø¨Ù„Ø§Ø³ØªÙŠÙƒ",
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
                        DriverName: data.DriverName || "Ø³Ø§Ø¦Ù‚ Ø­Ø±",
                        Supplier: data.Supplier,
                        Item: data.Item,
                        GrossWeight: Number(data.GrossWeight || 0),
                        TareWeight: Number(data.TareWeight || 0),
                        CreatedBy: authorFormatted
                    });
                    break;
            }

            await redis.set(queueKey, queuedOrders, { ex: 60 * 60 * 24 * 7 });
            return sendJson(res, 200, { success: true, message: `ØªÙ… ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ù…Ø¹Ø§Ù…Ù„Ø© Ø¨Ù†Ø¬Ø§Ø­ ÙˆØªÙˆÙ„ÙŠØ¯ Ø§Ù„Ù…Ø¹Ø±Ù [${uniqueOrderId}] ÙˆØªÙ…Ø±ÙŠØ±Ù‡Ø§ Ù„Ù„Ù…Ø²Ø§Ù…Ù†Ø©.` });
        }

        // 13. Ø¨ÙˆØ§Ø¨Ø© Ø§Ù„ÙˆÙŠØ¨ Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠØ© Ø§Ù„Ø´Ø§Ù…Ù„Ø© Ù„ÙƒØ§ÙØ© Ø§Ù„Ø£Ù‚Ø³Ø§Ù… Ø§Ù„Ù€ 16
        if (pathname === '/app') {
            const key = String(query.key || '').trim();
            const data = key ? await redis.get(`agency:${key}`) : null;

            if (!data) {
                return sendHtml(res, 200, shell('Ø¨Ø§Ù†ØªØ¸Ø§Ø± Ø§Ù„Ù…Ø²Ø§Ù…Ù†Ø© | Ù…ÙŠØ²Ø§Ù†', `
                    <div class="box" style="text-align:center">
                        <h2>â³ Ø§Ù„Ø­Ø³Ø§Ø¨ Ø¬Ø§Ù‡Ø² ÙˆØ¨Ø§Ù†ØªØ¸Ø§Ø± Ø§Ù„Ù…Ø²Ø§Ù…Ù†Ø©</h2>
                        <p style="color:#C8B8B5;font-size:13px;line-height:1.8;">
                            1. Ø§ÙØªØ­ Ø¨Ø±Ù†Ø§Ù…Ø¬ <b>Ù…ÙŠØ²Ø§Ù†</b> Ø¹Ù„Ù‰ Ø§Ù„ÙƒÙ…Ø¨ÙŠÙˆØªØ±.<br>
                            2. Ø§Ø¯Ø®Ù„ Ø¹Ù„Ù‰ <b>(Ø§Ù„Ø¥Ø¹Ø¯Ø§Ø¯Ø§Øª âš™ï¸ âž” Ø§Ù„Ø±Ø¨Ø· ÙˆØ§Ù„Ù…Ø²Ø§Ù…Ù†Ø© Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠØ© ðŸ“±)</b>.<br>
                            3. ØªØ£ÙƒØ¯ Ù…Ù† Ø¥Ø¯Ø®Ø§Ù„ ÙƒÙˆØ¯ Ø§Ù„ÙˆÙƒØ§Ù„Ø© Ø§Ù„ØªØ§Ù„ÙŠ:<br>
                            <b style="color:#D4AF37;font-size:16px;background:#1A0206;padding:4px 8px;border-radius:4px;display:inline-block;margin:6px 0;">${esc(key || 'ÙŠØ±Ø¬Ù‰ ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø¯Ø®ÙˆÙ„ Ø£ÙˆÙ„Ø§Ù‹')}</b><br>
                            4. Ø§Ø¶ØºØ· Ø¹Ù„Ù‰ Ø²Ø± <b>(ðŸ”„ Ù…Ø²Ø§Ù…Ù†Ø© ÙÙˆØ±ÙŠØ© Ø§Ù„Ø¢Ù†)</b> Ø¨Ø§Ù„ÙƒÙ…Ø¨ÙŠÙˆØªØ±.<br>
                        </p>
                        <button class="btn" onclick="location.reload()">ðŸ”„ ØªØ­Ø¯ÙŠØ« Ø§Ù„ØµÙØ­Ø© Ø¨Ø¹Ø¯ Ø§Ù„Ù…Ø²Ø§Ù…Ù†Ø©</button>
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
                AgencyName: data.agency_name || "ÙˆÙƒØ§Ù„Ø© Ù…ÙŠØ²Ø§Ù†"
            });
            const qrImageUrl = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(pairingConfigJson)}`;

            return sendHtml(res, 200, `<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(data.agency_name)} | Ù…Ù†Ø¸ÙˆÙ…Ø© Ù…ÙŠØ²Ø§Ù† Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠØ©</title>
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

    <!-- 1. Ø´Ø§Ø´Ø© ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø¯Ø®ÙˆÙ„ Ø§Ù„Ù…Ø³Ø¨Ù‚Ø© Ù„Ù„Ù…ÙˆØ¸ÙÙŠÙ† -->
    <div id="loginScreen">
        <div class="login-box">
            <div class="login-header">
                <h2>ðŸ¢ ${esc(data.agency_name)}</h2>
                <p>Ù…Ù†Ø¸ÙˆÙ…Ø© Ù…ÙŠØ²Ø§Ù† | ØªØ³Ø¬ÙŠÙ„ Ø¯Ø®ÙˆÙ„ Ø§Ù„Ù…ÙˆØ¸ÙÙŠÙ†</p>
            </div>
            
            <div class="badge">ðŸ” Ø¨ÙˆØ§Ø¨Ø© ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø¯Ø®ÙˆÙ„ Ø§Ù„Ø¢Ù…Ù†Ø©</div>

            <form onsubmit="handleUserLogin(event)">
                <label style="color:#D4AF37;">Ø§Ø®ØªØ± Ø§Ù„Ù…Ø³ØªØ®Ø¯Ù… / Ø§Ù„Ù…ÙˆØ¸Ù</label>
                ${users && users.length > 0 ? `
                <select id="loginUserSelect" onchange="syncSelectedUserText()" required style="background:#FAF4F1;">
                    ${users.map(u => `<option value="${esc(u.Username || u.username)}">${esc(u.FullName || u.fullName || u.Username)} (${esc(u.JobTitle || u.job_title || u.Role || 'Ù…Ø­Ø§Ø³Ø¨')})</option>`).join('')}
                </select>
                <input type="hidden" id="loginUserInput" value="${esc(users[0].Username || users[0].username)}" />
                ` : `
                <input type="text" id="loginUserInput" placeholder="Ø§Ø³Ù… Ø§Ù„Ù…Ø³ØªØ®Ø¯Ù… Ø£Ùˆ admin" required style="background:#FAF4F1;" />
                `}

                <label style="color:#D4AF37;">ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ±</label>
                <input type="password" id="loginPassInput" placeholder="Ø£Ø¯Ø®Ù„ ÙƒÙ„Ù…Ø© Ø§Ù„Ù…Ø±ÙˆØ± Ø§Ù„Ø®Ø§ØµØ© Ø¨Ùƒ" required style="background:#FAF4F1;" />

                <button type="submit" class="submit-btn" style="background:#5A0817;margin-top:20px;">ðŸš€ Ø¯Ø®ÙˆÙ„ Ù„Ù„Ù…Ù†Ø¸ÙˆÙ…Ø©</button>
                <div class="msg" id="loginErrorMsg"></div>
            </form>
        </div>
    </div>

    <!-- 2. Ø§Ù„Ø´Ø§Ø´Ø© Ø§Ù„Ø±Ø¦ÙŠØ³ÙŠØ© Ù„Ø¬Ù…ÙŠØ¹ Ø§Ù„Ø£Ù‚Ø³Ø§Ù… ÙˆØ§Ù„Ø®Ø¯Ù…Ø§Øª -->
    <div id="mainAppScreen">
        <div class="header">
            <h2>ðŸ¢ ${esc(data.agency_name)}</h2>
            <div style="font-size:11px; color:#C8B8B5; margin-top:4px;">Ø§Ù„ÙŠÙˆÙ…ÙŠØ©: ${esc(data.logical_date)} | Ø¢Ø®Ø± Ù…Ø²Ø§Ù…Ù†Ø©: ${new Date(data.last_sync).toLocaleTimeString('ar-EG', { timeZone: 'Africa/Cairo' })}</div>
            <div class="user-bar">
                <span id="activeUserLabel">ðŸ‘¤ Ø§Ù„Ù…ÙˆØ¸Ù: --</span>
                <div>
                    <button type="button" class="tab-btn" style="background:#D4AF37;color:#200308;padding:4px 10px;font-size:11px;margin-left:6px;" onclick="switchTab('tab-key', this)">ðŸ”‘ ÙƒÙˆØ¯ Ø§Ù„ÙˆÙƒØ§Ù„Ø© ÙˆØ§Ù„Ø§Ù‚ØªØ±Ø§Ù†</button>
                    <button class="logout-btn" onclick="handleLogout()">ðŸšª Ø®Ø±ÙˆØ¬</button>
                </div>
            </div>
        </div>

        <!-- Ø´Ø±ÙŠØ· Ø§Ù„ÙÙ„ØªØ±Ø© Ø§Ù„ØªØ§Ø±ÙŠØ®ÙŠØ© -->
        <div class="date-bar">
            <label>ðŸ“… Ù…Ù†:</label>
            <input type="date" id="filterFromDate" onchange="applyGlobalDateFilter()" />
            <label>Ø¥Ù„Ù‰:</label>
            <input type="date" id="filterToDate" onchange="applyGlobalDateFilter()" />
            <button type="button" class="quick-btn" onclick="setDateRange('today')">Ø§Ù„ÙŠÙˆÙ…</button>
            <button type="button" class="quick-btn" onclick="setDateRange('month')">Ø§Ù„Ø´Ù‡Ø± Ø§Ù„Ø­Ø§Ù„ÙŠ</button>
            <button type="button" class="quick-btn" onclick="setDateRange('all')">Ø¹Ø±Ø¶ Ø§Ù„ÙƒÙ„</button>
        </div>

        <!-- Ø´Ø±ÙŠØ· Ø§Ù„ØªÙ†Ù‚Ù„ Ù„Ù„Ø£Ù‚Ø³Ø§Ù… -->
        <div class="nav-scroll">
            <button class="tab-btn active" onclick="switchTab('tab-dash', this)">ðŸ“Š Ø§Ù„Ù…Ø¤Ø´Ø±Ø§Øª Ø§Ù„Ø­ÙŠØ©</button>
            <button class="tab-btn" onclick="switchTab('tab-pos', this)">ðŸ›’ Ù†Ù‚Ø·Ø© Ø§Ù„Ø¨ÙŠØ¹ (POS)</button>
            <button class="tab-btn" onclick="switchTab('tab-sales-reg', this)">ðŸ“‹ Ø³Ø¬Ù„ Ø§Ù„Ù…Ø¨ÙŠØ¹Ø§Øª</button>
            <button class="tab-btn" onclick="switchTab('tab-load', this)">ðŸšš Ø³Ø§Ø­Ø© ØªÙˆØ±ÙŠØ¯ Ø§Ù„Ø³ÙŠØ§Ø±Ø§Øª</button>
            <button class="tab-btn" onclick="switchTab('tab-settle', this)">ðŸš› ØªØµÙÙŠØ© Ø³ÙŠØ§Ø±Ø§Øª Ø§Ù„Ø£Ù…Ø§Ù†Ø©</button>
            <button class="tab-btn" onclick="switchTab('tab-stock', this)">ðŸ“¦ Ø¬Ø±Ø¯ Ø¨Ø¶Ø§Ø¹Ø© Ø§Ù„Ø£Ø±Ø¶ÙŠØ©</button>
            <button class="tab-btn" onclick="switchTab('tab-col', this)">ðŸ§¾ Ø³Ù†Ø¯Ø§Øª Ø§Ù„ØªØ­ØµÙŠÙ„</button>
            <button class="tab-btn" onclick="switchTab('tab-pending', this)">ðŸ“„ Ø§Ù„ÙÙˆØ§ØªÙŠØ± Ø§Ù„Ø¢Ø¬Ù„Ø©</button>
            <button class="tab-btn" onclick="switchTab('tab-exp', this)">ðŸ’¸ Ø§Ù„Ø®Ø²ÙŠÙ†Ø© ÙˆØ§Ù„Ù…ØµØ±ÙˆÙØ§Øª</button>
            <button class="tab-btn" onclick="switchTab('tab-pur', this)">ðŸ“¥ ÙÙˆØ§ØªÙŠØ± Ø§Ù„Ù…Ø´ØªØ±ÙŠØ§Øª</button>
            <button class="tab-btn" onclick="switchTab('tab-crate', this)">ðŸ“¦ Ø­Ø±ÙƒØ© Ø§Ù„ØµÙ†Ø§Ø¯ÙŠÙ‚ ÙˆØ§Ù„Ø±Ù‡Ù†</button>
            <button class="tab-btn" onclick="switchTab('tab-bank', this)">ðŸ¦ Ø§Ù„Ø¨Ù†ÙˆÙƒ ÙˆØ§Ù„Ø´ÙŠÙƒØ§Øª</button>
            <button class="tab-btn" onclick="switchTab('tab-wb', this)">âš–ï¸ Ù…ÙŠØ²Ø§Ù† Ø¨Ø³ÙƒÙˆÙ„</button>
            <button class="tab-btn" onclick="switchTab('tab-master', this)">ðŸ‘¥ Ø¯Ù„ÙŠÙ„ Ø§Ù„Ø­Ø³Ø§Ø¨Ø§Øª</button>
            <button class="tab-btn" onclick="switchTab('tab-key', this)">ðŸ”‘ ÙƒÙˆØ¯ Ø§Ù„ÙˆÙƒØ§Ù„Ø© ÙˆØ§Ù„Ø§Ù‚ØªØ±Ø§Ù†</button>
            <button class="tab-btn" onclick="switchTab('tab-printer', this)">ðŸ–¨ï¸ Ø¥Ø¹Ø¯Ø§Ø¯Ø§Øª Ø§Ù„Ø·Ø§Ø¨Ø¹Ø§Øª</button>
        </div>

        <!-- 1. Ø§Ù„Ù…Ø¤Ø´Ø±Ø§Øª Ø§Ù„Ø­ÙŠØ© -->
        <div id="tab-dash" class="tab-content active">
            <div class="card">
                <div>ðŸ’° Ù†Ù‚Ø¯ÙŠØ© Ø§Ù„Ø¯Ø±Ø¬ Ø§Ù„Ø­Ø§Ù„ÙŠØ©:</div>
                <div class="val">${Number(m.drawer_cash || 0).toLocaleString()} Ø¬</div>
            </div>
            <div class="card">
                <div>ðŸ’µ Ù…Ø¨ÙŠØ¹Ø§Øª Ø§Ù„ÙŠÙˆÙ…:</div>
                <div class="val" style="color:#5A0817;">${Number(m.today_sales || 0).toLocaleString()} Ø¬</div>
            </div>
            <div class="card">
                <div>ðŸ“ˆ Ø£Ø±Ø¨Ø§Ø­ Ø§Ù„ÙˆÙƒØ§Ù„Ø© Ø§Ù„ÙŠÙˆÙ…ÙŠØ©:</div>
                <div class="val">${Number(m.net_profit || 0).toLocaleString()} Ø¬</div>
            </div>
            <div class="card">
                <div>ðŸ“¦ Ø¨Ø±Ø§Ù†ÙŠÙƒ Ù…ØªØ¯Ø§ÙˆÙ„Ø© Ø¨Ø§Ù„Ø³ÙˆÙ‚:</div>
                <div class="val" style="color:#B45309;">${Number(m.crates_in_market || 0).toLocaleString()} Ø¨Ø±Ù†ÙŠÙƒØ©</div>
            </div>
        </div>

        <!-- Ø´Ø§Ø´Ø© Ø¹Ø±Ø¶ ÙƒÙˆØ¯ Ø§Ù„ÙˆÙƒØ§Ù„Ø© ÙˆØ§Ù„Ø§Ù‚ØªØ±Ø§Ù† Ø§Ù„ÙÙˆØ±ÙŠ Ø¨Ø§Ù„Ù€ QR -->
        <div id="tab-key" class="tab-content">
            <div class="form-card" style="text-align:center;">
                <h3 style="margin-top:0;color:#5A0817;">ðŸ”‘ ÙƒÙˆØ¯ Ø±Ø¨Ø· Ø§Ù„ÙˆÙƒØ§Ù„Ø© Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠ ÙˆØ§Ù‚ØªØ±Ø§Ù† Ø§Ù„Ù‡ÙˆØ§ØªÙ</h3>
                <p style="color:#666;font-size:12.5px;">Ø§Ø³ØªØ®Ø¯Ù… Ù‡Ø°Ø§ Ø§Ù„ÙƒÙˆØ¯ Ø£Ùˆ Ø§Ù…Ø³Ø­ Ø§Ù„Ø¨Ø§Ø±ÙƒÙˆØ¯ Ø¨Ø§Ù„ÙƒØ§Ù…ÙŠØ±Ø§ Ù„Ø±Ø¨Ø· Ø£Ø¬Ù‡Ø²Ø© Ø§Ù„ÙƒÙ…Ø¨ÙŠÙˆØªØ± ÙˆØ§Ù„Ù‡ÙˆØ§ØªÙ Ø¨Ù‡Ø°Ù‡ Ø§Ù„ÙˆÙƒØ§Ù„Ø© ÙÙˆØ±Ø§Ù‹.</p>

                <div style="background:#FFF;border:2px dashed #D4AF37;border-radius:12px;padding:15px;display:inline-block;margin:10px auto;">
                    <img src="${esc(qrImageUrl)}" alt="QR Code" style="width:200px;height:200px;display:block;margin:auto;" />
                    <div style="font-size:11px;color:#888;margin-top:6px;">Ø§Ù…Ø³Ø­ Ù…Ù† ÙƒØ§Ù…ÙŠØ±Ø§ Ø§Ù„Ù‡Ø§ØªÙ Ø£Ùˆ Ø¨Ø±Ù†Ø§Ù…Ø¬ Ø§Ù„ÙƒÙ…Ø¨ÙŠÙˆØªØ±</div>
                </div>

                <div style="max-width:380px;margin:auto;text-align:right;">
                    <label>ÙƒÙˆØ¯ Ø±Ø¨Ø· Ø§Ù„ÙˆÙƒØ§Ù„Ø© Ø§Ù„Ø³Ø±ÙŠ (Agency Sync Key):</label>
                    <div style="display:flex;gap:6px;">
                        <input type="text" id="dispKey" value="${esc(key)}" readonly style="text-align:center;font-weight:bold;font-family:Consolas;letter-spacing:1px;" />
                        <button type="button" class="btn" style="width:auto;margin:4px 0 0 0;padding:8px 14px;" onclick="copyText('dispKey')">ðŸ“‹ Ù†Ø³Ø®</button>
                    </div>

                    <label style="margin-top:12px;">Ø±Ø§Ø¨Ø· Ø§Ù„Ø³ÙŠØ±ÙØ± Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠ (Cloud Server URL):</label>
                    <div style="display:flex;gap:6px;">
                        <input type="text" id="dispUrl" value="${esc(currentOrigin)}" readonly style="text-align:center;font-family:Consolas;" />
                        <button type="button" class="btn" style="width:auto;margin:4px 0 0 0;padding:8px 14px;" onclick="copyText('dispUrl')">ðŸ“‹ Ù†Ø³Ø®</button>
                    </div>
                </div>

                <div style="background:#FDF4DF;border:1px solid #D4AF37;border-radius:8px;padding:10px;margin-top:16px;text-align:right;font-size:12px;line-height:1.8;">
                    <b>ðŸ’¡ Ø®Ø·ÙˆØ§Øª Ø±Ø¨Ø· Ø¨Ø±Ù†Ø§Ù…Ø¬ Ø§Ù„ÙƒÙ…Ø¨ÙŠÙˆØªØ±:</b><br>
                    1. Ø§ÙØªØ­ Ø¨Ø±Ù†Ø§Ù…Ø¬ <b>Ù…ÙŠØ²Ø§Ù†</b> Ø¹Ù„Ù‰ Ø§Ù„ÙƒÙ…Ø¨ÙŠÙˆØªØ± âž” <b>Ø§Ù„Ø¥Ø¹Ø¯Ø§Ø¯Ø§Øª</b> âž” <b>Ø§Ù„Ø±Ø¨Ø· ÙˆØ§Ù„Ù…Ø²Ø§Ù…Ù†Ø© Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠØ©</b>.<br>
                    2. Ø§Ù„ØµÙ‚ <b>Ø±Ø§Ø¨Ø· Ø§Ù„Ø³ÙŠØ±ÙØ±</b> ÙÙŠ Ø®Ø§Ù†Ø© (Ø¹Ù†ÙˆØ§Ù† Ø§Ù„Ø³ÙŠØ±ÙØ± Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠ).<br>
                    3. Ø§Ù„ØµÙ‚ <b>ÙƒÙˆØ¯ Ø§Ù„ÙˆÙƒØ§Ù„Ø©</b> ÙÙŠ Ø®Ø§Ù†Ø© (ÙƒÙˆØ¯ Ø±Ø¨Ø· Ø§Ù„ÙˆÙƒØ§Ù„Ø© Ø§Ù„Ø³Ø±ÙŠ) ÙˆØ§Ø¶ØºØ· Ø­ÙØ¸ Ø«Ù… <b>(Ù…Ø²Ø§Ù…Ù†Ø© ÙÙˆØ±ÙŠØ© Ø§Ù„Ø¢Ù†)</b>.
                </div>
            </div>
        </div>

        <!-- 2. Ù†Ù‚Ø·Ø© Ø§Ù„Ø¨ÙŠØ¹ ÙˆØ³Ù„Ø© Ø§Ù„ÙÙˆØ§ØªÙŠØ± (POS) -->
        <div id="tab-pos" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">ðŸ›’ Ø¥ØµØ¯Ø§Ø± ÙØ§ØªÙˆØ±Ø© Ù…Ø¨ÙŠØ¹Ø§Øª Ø³Ø­Ø§Ø¨ÙŠØ©</h3>
                <form id="f-pos" onsubmit="handlePosSubmit(event)">
                    <label>Ø§Ù„Ø¹Ù…ÙŠÙ„ / Ø§Ù„Ù…Ø´ØªØ±ÙŠ</label>
                    <select name="Customer" id="posCustSelect" required>
                        <option value="Ø¹Ù…ÙŠÙ„ Ù†Ù‚Ø¯ÙŠ">Ø¹Ù…ÙŠÙ„ Ù†Ù‚Ø¯ÙŠ</option>
                        ${customers.map(c => `<option value="${esc(getName(c))}">${esc(getName(c))} (Ù…Ø¯ÙŠÙˆÙ†ÙŠØ©: ${getBalance(c).toLocaleString()} Ø¬)</option>`).join('')}
                    </select>

                    <label>Ø³ÙŠØ§Ø±Ø© Ø§Ù„Ù…ÙˆØ±Ø¯ / Ø§Ù„Ø­Ù…ÙˆÙ„Ø©</label>
                    <select name="LoadKey" id="posLoadSelect">
                        <option value="" data-supplier="">Ù…Ø¨ÙŠØ¹Ø§Øª Ù…Ø¨Ø§Ø´Ø±Ø© (Ø¨Ø¯ÙˆÙ† Ø³ÙŠØ§Ø±Ø©)</option>
                        ${loads.map(l => `<option value="${esc(getSupplier(l))} | ${esc(getVehicle(l))} | ${esc(getDate(l))}" data-supplier="${esc(getSupplier(l))}">${esc(getSupplier(l))} | ${esc(getVehicle(l))} (${esc(getItem(l))})</option>`).join('')}
                    </select>

                    <label>Ø§Ù„ØµÙ†Ù</label>
                    <select name="Item" id="posItemSelect" required>
                        ${items.map(i => `<option value="${esc(getName(i))}" data-supplier="${esc(getSupplier(i))}" data-price="${getPrice(i)}">${esc(getName(i))} - [${esc(getSupplier(i))}]</option>`).join('')}
                    </select>

                    <div class="grid-2">
                        <div>
                            <label>Ø§Ù„Ø¹Ø¯Ø¯ (ØµÙ†Ø§Ø¯ÙŠÙ‚)</label>
                            <input type="number" name="Qty" id="posQty" value="0" step="1" oninput="calcPosTotal()" />
                        </div>
                        <div>
                            <label>Ø§Ù„ÙˆØ²Ù† (ÙƒØ¬Ù…)</label>
                            <input type="number" name="Weight" id="posWeight" value="0" step="0.1" oninput="calcPosTotal()" />
                        </div>
                    </div>

                    <div class="grid-2">
                        <div>
                            <label>Ø§Ù„Ø³Ø¹Ø± (Ø¬Ù†ÙŠÙ‡)</label>
                            <input type="number" name="Price" id="posPrice" value="0" step="0.5" required oninput="calcPosTotal()" />
                        </div>
                        <div>
                            <label>Ø§Ù„Ø®ØµÙ…</label>
                            <input type="number" name="Discount" id="posDisc" value="0" step="1" oninput="calcPosTotal()" />
                        </div>
                    </div>

                    <label>Ø·Ø±ÙŠÙ‚Ø© Ø§Ù„Ø³Ø¯Ø§Ø¯</label>
                    <select name="PaymentMethod" id="posPayMethod" onchange="calcPosTotal()">
                        <option value="Ù†Ù‚Ø¯ÙŠ (ÙƒØ§Ø´)">Ù†Ù‚Ø¯ÙŠ (ÙƒØ§Ø´)</option>
                        <option value="Ø¢Ø¬Ù„ Ø¹Ù„Ù‰ Ø§Ù„Ø­Ø³Ø§Ø¨">Ø¢Ø¬Ù„ Ø¹Ù„Ù‰ Ø§Ù„Ø­Ø³Ø§Ø¨</option>
                        <option value="Ø¥Ù†Ø³ØªØ§Ø¨Ø§ÙŠ (InstaPay)">Ø¥Ù†Ø³ØªØ§Ø¨Ø§ÙŠ (InstaPay)</option>
                        <option value="ÙÙˆØ¯Ø§ÙÙˆÙ† ÙƒØ§Ø´ / Ù…Ø­ÙØ¸Ø©">ÙÙˆØ¯Ø§ÙÙˆÙ† ÙƒØ§Ø´ / Ù…Ø­ÙØ¸Ø©</option>
                    </select>

                    <div class="card" style="margin-top:12px;background:#FDF4DF;border-right-color:#D4AF37;">
                        <div>Ø§Ù„Ø¥Ø¬Ù…Ø§Ù„ÙŠ Ø§Ù„Ù…Ø·Ù„ÙˆØ¨: <b id="posTotalTxt" style="font-size:18px;color:#5A0817;">0 Ø¬</b></div>
                    </div>

                    <button type="submit" class="submit-btn">ðŸ’¾ Ø­ÙØ¸ Ø§Ù„ÙØ§ØªÙˆØ±Ø© ÙˆØªÙ…Ø±ÙŠØ±Ù‡Ø§ Ù„Ù„Ù…Ø²Ø§Ù…Ù†Ø©</button>
                </form>
            </div>
        </div>

        <!-- 3. Ø³Ø¬Ù„ Ø§Ù„Ù…Ø¨ÙŠØ¹Ø§Øª ÙˆØ§Ù„ÙŠÙˆÙ…ÙŠØ© Ø§Ù„Ù…ÙØµÙ„Ø© -->
        <div id="tab-sales-reg" class="tab-content">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <h3 style="margin:0;">ðŸ“‹ Ø³Ø¬Ù„ ÙÙˆØ§ØªÙŠØ± Ø§Ù„Ù…Ø¨ÙŠØ¹Ø§Øª</h3>
                <span id="salesSummaryBadge" style="font-weight:bold;color:#5A0817;"></span>
            </div>
            <table>
                <thead>
                    <tr><th>Ø§Ù„ÙØ§ØªÙˆØ±Ø©</th><th>Ø§Ù„ØªØ§Ø±ÙŠØ®</th><th>Ø§Ù„Ø¹Ù…ÙŠÙ„</th><th>Ø§Ù„ØµÙ†Ù</th><th>Ø§Ù„ÙˆØ²Ù†</th><th>Ø§Ù„Ø¥Ø¬Ù…Ø§Ù„ÙŠ</th><th>Ø§Ù„Ù…Ø¯ÙÙˆØ¹</th><th>Ø¥Ø¬Ø±Ø§Ø¡</th></tr>
                </thead>
                <tbody id="salesTableBody">
                    ${recentSales.map(s => `
                        <tr data-date="${esc((s.Date || s.date || '').slice(0, 10))}">
                            <td><b>${esc(s.InvoiceNo || s.invoiceNo)}</b></td>
                            <td>${esc(s.Date || s.date)}</td>
                            <td>${esc(s.Customer || s.customer)}</td>
                            <td>${esc(s.Item || s.item)}</td>
                            <td>${Number(s.Weight || s.weight || 0).toLocaleString()} Ùƒ</td>
                            <td>${Number(s.Value || s.value || 0).toLocaleString()} Ø¬</td>
                            <td>${Number(s.PaidAmount || s.paidAmount || 0).toLocaleString()} Ø¬</td>
                            <td><button type="button" style="background:#DC2626;color:white;border:none;border-radius:4px;padding:3px 8px;cursor:pointer;" onclick="deleteInvoiceAction('${esc(s.InvoiceNo || s.invoiceNo)}')">ðŸ—‘ï¸ Ø­Ø°Ù</button></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <!-- 4. Ø³Ø§Ø­Ø© ØªÙˆØ±ÙŠØ¯ Ø§Ù„Ø³ÙŠØ§Ø±Ø§Øª -->
        <div id="tab-load" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">ðŸšš ØªÙˆØ±ÙŠØ¯ ÙˆØªÙ†Ø²ÙŠÙ„ Ø³ÙŠØ§Ø±Ø© Ø¨Ø§Ù„Ø£Ø±Ø¶ÙŠØ©</h3>
                <div class="grid-2">
                    <div>
                        <label>Ø§Ù„Ù…ÙˆØ±Ø¯ / Ø§Ù„ØªØ§Ø¬Ø±</label>
                        <select id="loadSuppSelect" required>
                            ${suppliers.map(s => `<option value="${esc(getName(s))}">${esc(getName(s))}</option>`).join('')}
                        </select>
                    </div>
                    <div>
                        <label>Ø±Ù‚Ù… / Ø¨ÙŠØ§Ù† Ø§Ù„Ø³ÙŠØ§Ø±Ø©</label>
                        <input type="text" id="loadVehInput" placeholder="Ù…Ø«Ø§Ù„: 5412 Ù†Ù‚Ù„" required />
                    </div>
                </div>

                <div class="grid-2">
                    <div>
                        <label>Ù†ÙˆÙ„ÙˆÙ† Ø§Ù„Ù†Ù‚Ù„ Ø§Ù„Ø¥Ø¬Ù…Ø§Ù„ÙŠ (Ø¬)</label>
                        <input type="number" id="loadFreightInput" value="0" />
                    </div>
                    <div>
                        <label>Ù†Ø³Ø¨Ø© Ø§Ù„Ø¹Ù…ÙˆÙ„Ø© (%)</label>
                        <input type="number" id="loadCommInput" value="5" step="0.5" />
                    </div>
                </div>

                <div style="background:#F9FAFB;border:1px solid #D4AF37;border-radius:8px;padding:10px;margin-top:12px;">
                    <h4 style="margin:0 0 8px 0;color:#5A0817;">ðŸ“¦ Ø¥Ø¶Ø§ÙØ© ØµÙ†Ù Ù„Ø­Ù…ÙˆÙ„Ø© Ø§Ù„Ø³ÙŠØ§Ø±Ø©:</h4>
                    <div class="grid-2">
                        <div>
                            <label>Ø§Ù„ØµÙ†Ù</label>
                            <select id="loadItemSelect">
                                ${items.map(i => `<option value="${esc(getName(i))}">${esc(getName(i))}</option>`).join('')}
                            </select>
                        </div>
                        <div>
                            <label>Ø§Ù„Ø¹Ø¯Ø¯ Ø§Ù„ÙˆØ§Ø±Ø¯ (ØµÙ†Ø§Ø¯ÙŠÙ‚)</label>
                            <input type="number" id="loadItemQty" value="50" step="1" />
                        </div>
                    </div>
                    <div>
                        <label>Ø§Ù„ÙˆØ²Ù† Ø§Ù„ÙˆØ§Ø±Ø¯ (ÙƒØ¬Ù…)</label>
                        <input type="number" id="loadItemWt" value="1250" step="0.5" />
                    </div>
                    <button type="button" class="btn" style="background:#0D7857;margin-top:10px;" onclick="addItemToLoadCart()">âž• Ø¥Ø¶Ø§ÙØ© Ø§Ù„ØµÙ†Ù Ù„Ù„Ø³ÙŠØ§Ø±Ø©</button>
                </div>

                <h4 style="margin:12px 0 4px 0;">Ø§Ù„Ø£ØµÙ†Ø§Ù Ø§Ù„Ù…Ø­Ù…Ù„Ø©:</h4>
                <table id="loadItemsTable">
                    <thead><tr><th>Ø§Ù„ØµÙ†Ù</th><th>Ø§Ù„Ø¹Ø¯Ø¯</th><th>Ø§Ù„ÙˆØ²Ù†</th><th>Ø­Ø°Ù</th></tr></thead>
                    <tbody id="loadItemsTbody">
                        <tr><td colspan="4" style="text-align:center;color:#666;">Ù„Ù… ÙŠØªÙ… Ø¥Ø¶Ø§ÙØ© Ø£ØµÙ†Ø§Ù Ù„Ù„Ø³ÙŠØ§Ø±Ø© Ø¨Ø¹Ø¯</td></tr>
                    </tbody>
                </table>

                <button type="button" class="submit-btn" style="margin-top:16px;" onclick="submitFullVehicleLoad()">ðŸšš ØªØ«Ø¨ÙŠØª ÙˆØ­ÙØ¸ Ø§Ù„Ø³ÙŠØ§Ø±Ø© Ø¨Ø§Ù„Ø£Ø±Ø¶ÙŠØ©</button>
            </div>
        </div>

        <!-- 5. ØªØµÙÙŠØ© Ø³ÙŠØ§Ø±Ø§Øª Ø§Ù„Ø£Ù…Ø§Ù†Ø© -->
        <div id="tab-settle" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">ðŸš› ØªØµÙÙŠØ© ÙˆØ¥Ù‚ÙØ§Ù„ Ø³ÙŠØ§Ø±Ø© Ø£Ù…Ø§Ù†Ø©</h3>
                <label>Ø§Ø®ØªØ± Ø§Ù„Ø³ÙŠØ§Ø±Ø© Ù„Ù„ØªØµÙÙŠØ©</label>
                <select id="settleLoadSelect" onchange="updateSettlePreview()">
                    <option value="">-- Ø§Ø®ØªØ± Ø§Ù„Ø³ÙŠØ§Ø±Ø© --</option>
                    ${loads.map(l => `<option value="${esc(getSupplier(l))} | ${esc(getVehicle(l))} | ${esc(getDate(l))}" data-supplier="${esc(getSupplier(l))}" data-vehicle="${esc(getVehicle(l))}" data-freight="${l.Freight || l.freight || 0}" data-comm="${l.Commission || l.commission || 5}">${esc(getSupplier(l))} | ${esc(getVehicle(l))} (${esc(getItem(l))})</option>`).join('')}
                </select>
                <div id="settlePreviewBox" style="margin-top:12px;display:none;" class="card">
                    <div>Ø§Ù„Ù…ÙˆØ±Ø¯: <b id="settleSuppTxt"></b></div>
                    <div>Ù†ÙˆÙ„ÙˆÙ† Ø§Ù„Ù†Ù‚Ù„: <b id="settleFreightTxt">0 Ø¬</b></div>
                    <div>Ù†Ø³Ø¨Ø© Ø§Ù„Ø¹Ù…ÙˆÙ„Ø©: <b id="settleCommTxt">5%</b></div>
                </div>
            </div>
        </div>

        <!-- 6. Ø¬Ø±Ø¯ Ø¨Ø¶Ø§Ø¹Ø© Ø§Ù„Ø£Ø±Ø¶ÙŠØ© -->
        <div id="tab-stock" class="tab-content">
            <h3>ðŸšš Ø¨Ø¶Ø§Ø¹Ø© Ø§Ù„Ø£Ø±Ø¶ÙŠØ© ÙˆØ§Ù„Ø³ÙŠØ§Ø±Ø§Øª Ø§Ù„Ù…ÙØªÙˆØ­Ø© (${esc(floorStock.length)})</h3>
            <table>
                <tr><th>Ø§Ù„ØµÙ†Ù</th><th>Ø§Ù„Ø³ÙŠØ§Ø±Ø©</th><th>Ø§Ù„Ù…ÙˆØ±Ø¯</th><th>Ø¨Ø§Ù‚ÙŠ Ø¹Ø¯Ø¯</th><th>Ø¨Ø§Ù‚ÙŠ ÙˆØ²Ù†</th></tr>
                ${floorStock.map(f => `
                    <tr>
                        <td><b>${esc(f.Item || f.item)}</b></td>
                        <td>${esc(f.Vehicle || f.vehicle)}</td>
                        <td>${esc(f.Supplier || f.supplier)}</td>
                        <td>${Number(f.QtyRemaining || f.qtyRemaining || 0).toLocaleString()} Ù‚</td>
                        <td>${Number(f.WeightRemaining || f.weightRemaining || 0).toLocaleString()} Ùƒ</td>
                    </tr>
                `).join('')}
            </table>
        </div>

        <!-- 7. Ø³Ù†Ø¯Ø§Øª Ø§Ù„ØªØ­ØµÙŠÙ„ ÙˆØ§Ù„Ù…Ù‚Ø¨ÙˆØ¶Ø§Øª -->
        <div id="tab-col" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">ðŸ§¾ ØªØ³Ø¬ÙŠÙ„ Ø³Ù†Ø¯ Ù‚Ø¨Ø¶ ÙˆØªØ­ØµÙŠÙ„</h3>
                <form onsubmit="handleColSubmit(event)">
                    <label>Ø§Ù„Ø¹Ù…ÙŠÙ„</label>
                    <select name="Customer" required>
                        ${customers.map(c => `<option value="${esc(getName(c))}">${esc(getName(c))} (Ù…Ø¯ÙŠÙˆÙ†ÙŠØ©: ${getBalance(c).toLocaleString()} Ø¬)</option>`).join('')}
                    </select>
                    <label>Ø§Ù„Ù…Ø¨Ù„Øº Ø§Ù„Ù…Ø­ØµÙ„ (Ø¬Ù†ÙŠÙ‡)</label>
                    <input type="number" name="Amount" step="1" required />
                    <label>Ø·Ø±ÙŠÙ‚Ø© Ø§Ù„Ø¯ÙØ¹</label>
                    <select name="PaymentMethod">
                        <option value="Ù†Ù‚Ø¯ÙŠ (ÙƒØ§Ø´)">Ù†Ù‚Ø¯ÙŠ (ÙƒØ§Ø´)</option>
                        <option value="Ø¥Ù†Ø³ØªØ§Ø¨Ø§ÙŠ (InstaPay)">Ø¥Ù†Ø³ØªØ§Ø¨Ø§ÙŠ (InstaPay)</option>
                        <option value="ÙÙˆØ¯Ø§ÙÙˆÙ† ÙƒØ§Ø´ / Ù…Ø­ÙØ¸Ø©">ÙÙˆØ¯Ø§ÙÙˆÙ† ÙƒØ§Ø´ / Ù…Ø­ÙØ¸Ø©</option>
                    </select>
                    <label>Ø§Ù„Ø¨ÙŠØ§Ù† / Ù…Ù„Ø§Ø­Ø¸Ø§Øª</label>
                    <input type="text" name="Notes" value="Ø³Ø¯Ø§Ø¯ Ø¯ÙØ¹Ø© Ø¨Ø§Ù„Ø­Ø³Ø§Ø¨" />
                    <button type="submit" class="submit-btn">ðŸ§¾ Ø­ÙØ¸ ÙˆØªØ£ÙƒÙŠØ¯ Ø³Ù†Ø¯ Ø§Ù„Ù‚Ø¨Ø¶</button>
                </form>
            </div>

            <h3>Ø³Ù†Ø¯Ø§Øª Ø§Ù„ØªØ­ØµÙŠÙ„ Ø§Ù„Ù…Ø³Ø¬Ù„Ø©</h3>
            <table>
                <thead>
                    <tr><th>Ø±Ù‚Ù… Ø§Ù„Ø³Ù†Ø¯</th><th>Ø§Ù„ØªØ§Ø±ÙŠØ®</th><th>Ø§Ù„Ø¹Ù…ÙŠÙ„</th><th>Ø§Ù„Ù…Ø¨Ù„Øº</th><th>Ø·Ø±ÙŠÙ‚Ø© Ø§Ù„Ø¯ÙØ¹</th><th>Ø¥Ø¬Ø±Ø§Ø¡</th></tr>
                </thead>
                <tbody id="colTableBody">
                    ${collections.map(c => `
                        <tr data-date="${esc((c.Date || c.date || '').slice(0, 10))}">
                            <td><b>${esc(c.ReceiptNo || c.receiptNo)}</b></td>
                            <td>${esc(c.Date || c.date)}</td>
                            <td>${esc(c.Customer || c.customer)}</td>
                            <td>${Number(c.Amount || c.amount || 0).toLocaleString()} Ø¬</td>
                            <td>${esc(c.PaymentMethod || c.paymentMethod)}</td>
                            <td><button type="button" style="background:#DC2626;color:white;border:none;border-radius:4px;padding:3px 8px;cursor:pointer;" onclick="deleteColAction('${esc(c.ReceiptNo || c.receiptNo)}')">ðŸ—‘ï¸ Ø­Ø°Ù</button></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <!-- 8. Ø§Ù„ÙÙˆØ§ØªÙŠØ± Ø§Ù„Ø¢Ø¬Ù„Ø© ÙˆØ§Ù„Ø°Ù…Ù… -->
        <div id="tab-pending" class="tab-content">
            <h3>ðŸ“„ ÙƒØ´Ù Ø§Ù„ÙÙˆØ§ØªÙŠØ± Ø§Ù„Ø¢Ø¬Ù„Ø© ØºÙŠØ± Ø§Ù„Ù…Ø³Ø¯Ø¯Ø© Ø¨Ø§Ù„ÙƒØ§Ù…Ù„</h3>
            <table>
                <tr><th>Ø§Ù„ÙØ§ØªÙˆØ±Ø©</th><th>Ø§Ù„ØªØ§Ø±ÙŠØ®</th><th>Ø§Ù„Ø¹Ù…ÙŠÙ„</th><th>Ø§Ù„Ø¥Ø¬Ù…Ø§Ù„ÙŠ</th><th>Ø§Ù„Ù…ØªØ¨Ù‚ÙŠ Ø§Ù„Ø¢Ø¬Ù„</th></tr>
                ${recentSales.filter(s => (s.RemainingAmount || s.remainingAmount) > 0).map(s => `
                    <tr>
                        <td><b>${esc(s.InvoiceNo || s.invoiceNo)}</b></td>
                        <td>${esc(s.Date || s.date)}</td>
                        <td>${esc(s.Customer || s.customer)}</td>
                        <td>${Number(s.Value || s.value || 0).toLocaleString()} Ø¬</td>
                        <td style="color:#DC2626;font-weight:bold;">${Number(s.RemainingAmount || s.remainingAmount || 0).toLocaleString()} Ø¬</td>
                    </tr>
                `).join('')}
            </table>
        </div>

        <!-- 9. Ø§Ù„Ø®Ø²ÙŠÙ†Ø© ÙˆØ§Ù„Ù…ØµØ±ÙˆÙØ§Øª ÙˆØ§Ù„Ø±ÙˆØ§ØªØ¨ -->
        <div id="tab-exp" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">ðŸ’¸ ØµØ±Ù ÙˆØªØ³Ø¬ÙŠÙ„ Ù…ØµØ±ÙˆÙ</h3>
                <form onsubmit="handleExpSubmit(event)">
                    <label>Ø¨Ù†Ø¯ Ø§Ù„Ù…ØµØ±ÙˆÙ</label>
                    <select name="Category">
                        <option value="Ø¥ÙƒØ±Ø§Ù…ÙŠØ§Øª ÙˆØ¹ØªØ§Ù„Ø© Ø§Ù„Ø£Ø±Ø¶ÙŠØ©">Ø¥ÙƒØ±Ø§Ù…ÙŠØ§Øª ÙˆØ¹ØªØ§Ù„Ø© Ø§Ù„Ø£Ø±Ø¶ÙŠØ©</option>
                        <option value="Ø¨ÙˆÙÙŠÙ‡ ÙˆØ¶ÙŠØ§ÙØ©">Ø¨ÙˆÙÙŠÙ‡ ÙˆØ¶ÙŠØ§ÙØ©</option>
                        <option value="Ù†ÙˆÙ„ÙˆÙ† ÙˆÙ†Ù‚Ù„">Ù†ÙˆÙ„ÙˆÙ† ÙˆÙ†Ù‚Ù„</option>
                        <option value="ØµÙŠØ§Ù†Ø© ÙˆÙ…Ø³ØªÙ„Ø²Ù…Ø§Øª">ØµÙŠØ§Ù†Ø© ÙˆÙ…Ø³ØªÙ„Ø²Ù…Ø§Øª</option>
                        <option value="Ø±ÙˆØ§ØªØ¨ Ù…ÙˆØ¸ÙÙŠÙ† ÙˆØ¹Ù…Ø§Ù„">Ø±ÙˆØ§ØªØ¨ Ù…ÙˆØ¸ÙÙŠÙ† ÙˆØ¹Ù…Ø§Ù„</option>
                        <option value="Ù…ØµØ§Ø±ÙŠÙ Ù†Ø«Ø±ÙŠØ© Ø¹Ø§Ù…Ø©">Ù…ØµØ§Ø±ÙŠÙ Ù†Ø«Ø±ÙŠØ© Ø¹Ø§Ù…Ø©</option>
                    </select>
                    <label>Ø§Ù„Ø¨ÙŠØ§Ù† / ØªÙØ§ØµÙŠÙ„ Ø§Ù„ØµØ±Ù</label>
                    <input type="text" name="Description" required />
                    <label>Ø§Ù„Ù…Ø¨Ù„Øº Ø§Ù„Ù…Ù†ØµØ±Ù (Ø¬Ù†ÙŠÙ‡)</label>
                    <input type="number" name="Amount" step="1" required />
                    <button type="submit" class="submit-btn">ðŸ’¸ Ø®ØµÙ… ÙˆØµØ±Ù Ø§Ù„Ù…ØµØ±ÙˆÙ</button>
                </form>
            </div>

            <h3>Ø§Ù„Ù…ØµØ±ÙˆÙØ§Øª Ø§Ù„Ù…Ø³Ø¬Ù„Ø©</h3>
            <table>
                <thead>
                    <tr><th>Ø§Ù„ØªØ§Ø±ÙŠØ®</th><th>Ø§Ù„Ø¨Ù†Ø¯</th><th>Ø§Ù„Ø¨ÙŠØ§Ù†</th><th>Ø§Ù„Ù…Ø¨Ù„Øº</th><th>Ø¥Ø¬Ø±Ø§Ø¡</th></tr>
                </thead>
                <tbody id="expTableBody">
                    ${expenses.map(e => `
                        <tr data-date="${esc((e.Date || e.date || '').slice(0, 10))}">
                            <td>${esc(e.Date || e.date)}</td>
                            <td>${esc(e.Category || e.category)}</td>
                            <td>${esc(e.Description || e.description)}</td>
                            <td>${Number(e.Amount || e.amount || 0).toLocaleString()} Ø¬</td>
                            <td><button type="button" style="background:#DC2626;color:white;border:none;border-radius:4px;padding:3px 8px;cursor:pointer;" onclick="deleteExpAction(${e.Id || e.id || 0})">ðŸ—‘ï¸ Ø­Ø°Ù</button></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <!-- 10. ÙÙˆØ§ØªÙŠØ± Ø§Ù„Ù…Ø´ØªØ±ÙŠØ§Øª -->
        <div id="tab-pur" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">ðŸ“¥ ØªØ³Ø¬ÙŠÙ„ ÙØ§ØªÙˆØ±Ø© Ø´Ø±Ø§Ø¡ Ø¨Ø¶Ø§Ø¹Ø© ÙˆØ£ØµÙˆÙ„</h3>
                <form onsubmit="handlePurSubmit(event)">
                    <label>Ø¨Ù†Ø¯ Ø§Ù„Ø´Ø±Ø§Ø¡</label>
                    <select name="Category">
                        <option value="Ø´Ø±Ø§Ø¡ Ø¨Ø¶Ø§Ø¹Ø© ØªØ¬Ø§Ø±ÙŠØ© (ØªØ¶Ø§Ù Ù„Ù„Ø£Ø±Ø¶ÙŠØ©)">Ø´Ø±Ø§Ø¡ Ø¨Ø¶Ø§Ø¹Ø© ØªØ¬Ø§Ø±ÙŠØ© (ØªØ¶Ø§Ù Ù„Ù„Ø£Ø±Ø¶ÙŠØ©)</option>
                        <option value="Ø´Ø±Ø§Ø¡ Ø£Ø«Ø§Ø« ÙˆØ¯ÙŠÙƒÙˆØ±">Ø´Ø±Ø§Ø¡ Ø£Ø«Ø§Ø« ÙˆØ¯ÙŠÙƒÙˆØ±</option>
                        <option value="Ø´Ø±Ø§Ø¡ Ø£Ø¬Ù‡Ø²Ø© ÙˆÙ…ÙˆØ§Ø²ÙŠÙ†">Ø´Ø±Ø§Ø¡ Ø£Ø¬Ù‡Ø²Ø© ÙˆÙ…ÙˆØ§Ø²ÙŠÙ†</option>
                    </select>
                    <label>Ø§Ù„Ù…ÙˆØ±Ø¯ / Ø§Ù„Ø¬Ù‡Ø©</label>
                    <select name="Supplier" required>
                        ${suppliers.map(s => `<option value="${esc(getName(s))}">${esc(getName(s))}</option>`).join('')}
                    </select>
                    <label>Ø§Ù„ØµÙ†Ù / Ø§Ù„Ø¨ÙŠØ§Ù†</label>
                    <input type="text" name="Item" required />
                    <div class="grid-2">
                        <div>
                            <label>Ø§Ù„ÙƒÙ…ÙŠØ©</label>
                            <input type="number" name="Qty" value="1" />
                        </div>
                        <div>
                            <label>Ø§Ù„ÙˆØ²Ù† (ÙƒØ¬Ù…)</label>
                            <input type="number" name="Weight" value="0" />
                        </div>
                    </div>
                    <div class="grid-2">
                        <div>
                            <label>Ø¥Ø¬Ù…Ø§Ù„ÙŠ Ø§Ù„Ù‚ÙŠÙ…Ø© (Ø¬)</label>
                            <input type="number" name="Value" step="1" required />
                        </div>
                        <div>
                            <label>Ø§Ù„Ù…Ø¯ÙÙˆØ¹ Ù†Ù‚Ø¯Ø§Ù‹</label>
                            <input type="number" name="PaidAmount" value="0" />
                        </div>
                    </div>
                    <button type="submit" class="submit-btn">ðŸ“¥ Ø­ÙØ¸ ÙØ§ØªÙˆØ±Ø© Ø§Ù„Ø´Ø±Ø§Ø¡</button>
                </form>
            </div>
        </div>

        <!-- 11. Ø­Ø±ÙƒØ© Ø§Ù„ØµÙ†Ø§Ø¯ÙŠÙ‚ ÙˆØ§Ù„Ø¨Ø±Ø§Ù†ÙŠÙƒ -->
        <div id="tab-crate" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">ðŸ“¦ Ø­Ø±ÙƒØ© ÙˆØªØ£Ù…ÙŠÙ† Ø§Ù„ØµÙ†Ø§Ø¯ÙŠÙ‚ ÙˆØ§Ù„Ø¨Ø±Ø§Ù†ÙŠÙƒ</h3>
                <form onsubmit="handleCrateSubmit(event)">
                    <label>Ø§Ù„Ø¹Ù…ÙŠÙ„</label>
                    <select name="Customer" required>
                        ${customers.map(c => `<option value="${esc(getName(c))}">${esc(getName(c))}</option>`).join('')}
                    </select>
                    <label>Ù†ÙˆØ¹ Ø§Ù„Ø­Ø±ÙƒØ©</label>
                    <select name="Kind">
                        <option value="ØªØ³Ù„ÙŠÙ…">ØªØ³Ù„ÙŠÙ… Ù„Ù„Ø¹Ù…ÙŠÙ„ (+)</option>
                        <option value="Ø§Ø³ØªØ±Ø¬Ø§Ø¹">Ø§Ø³ØªØ±Ø¬Ø§Ø¹ Ù…Ù† Ø§Ù„Ø¹Ù…ÙŠÙ„ (-)</option>
                    </select>
                    <div class="grid-2">
                        <div>
                            <label>Ø¹Ø¯Ø¯ Ø§Ù„ØµÙ†Ø§Ø¯ÙŠÙ‚</label>
                            <input type="number" name="Qty" value="0" step="1" required />
                        </div>
                        <div>
                            <label>Ø³Ø¹Ø± Ø§Ù„ØªØ£Ù…ÙŠÙ† (Ø¬)</label>
                            <input type="number" name="Price" value="70" />
                        </div>
                    </div>
                    <label>
                        <input type="checkbox" name="IsCashCollected" style="width:auto;margin-left:6px;" checked />
                        ØªØ³ÙˆÙŠØ© Ø±Ù‡Ù† Ø§Ù„ØªØ£Ù…ÙŠÙ† Ù†Ù‚Ø¯Ø§Ù‹ Ø¨Ø§Ù„Ø¯Ø±Ø¬
                    </label>
                    <button type="submit" class="submit-btn">ðŸ“¦ ØªØ«Ø¨ÙŠØª Ø­Ø±ÙƒØ© Ø§Ù„ØµÙ†Ø§Ø¯ÙŠÙ‚</button>
                </form>
            </div>
        </div>

        <!-- 12. Ø§Ù„Ø¨Ù†ÙˆÙƒ ÙˆØ§Ù„Ø´ÙŠÙƒØ§Øª -->
        <div id="tab-bank" class="tab-content">
            <h3>ðŸ¦ Ø§Ù„Ø­Ø³Ø§Ø¨Ø§Øª Ø§Ù„Ø¨Ù†ÙƒÙŠØ© Ø§Ù„Ø¬Ø§Ø±ÙŠØ©</h3>
            <table>
                <tr><th>Ø§Ù„Ø¨Ù†Ùƒ / Ø§Ù„Ø­Ø³Ø§Ø¨</th><th>Ø±Ù‚Ù… Ø§Ù„Ø­Ø³Ø§Ø¨</th><th>Ø§Ù„Ø±ØµÙŠØ¯</th></tr>
                ${bankAccounts.map(b => `
                    <tr>
                        <td><b>${esc(b.BankName || b.bankName)}</b> (${esc(b.AccountName || b.accountName)})</td>
                        <td>${esc(b.AccountNumber || b.accountNumber)}</td>
                        <td>${Number(b.Balance || b.balance || 0).toLocaleString()} Ø¬</td>
                    </tr>
                `).join('')}
            </table>
        </div>

        <!-- 13. Ù…ÙŠØ²Ø§Ù† Ø¨Ø³ÙƒÙˆÙ„ Ø§Ù„Ø³ÙŠØ§Ø±Ø§Øª -->
        <div id="tab-wb" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">âš–ï¸ ØªØ³Ø¬ÙŠÙ„ ÙƒØ§Ø±ØªØ© Ù…ÙŠØ²Ø§Ù† Ø¨Ø³ÙƒÙˆÙ„</h3>
                <form onsubmit="handleWbSubmit(event)">
                    <label>Ø±Ù‚Ù… Ø§Ù„Ø³ÙŠØ§Ø±Ø©</label>
                    <input type="text" name="Vehicle" required />
                    <label>Ø§Ø³Ù… Ø§Ù„Ø³Ø§Ø¦Ù‚</label>
                    <input type="text" name="DriverName" value="Ø³Ø§Ø¦Ù‚ Ø­Ø±" />
                    <label>Ø§Ù„Ù…ÙˆØ±Ø¯</label>
                    <select name="Supplier" required>
                        ${suppliers.map(s => `<option value="${esc(getName(s))}">${esc(getName(s))}</option>`).join('')}
                    </select>
                    <label>Ø§Ù„ØµÙ†Ù</label>
                    <select name="Item" required>
                        ${items.map(i => `<option value="${esc(getName(i))}">${esc(getName(i))}</option>`).join('')}
                    </select>
                    <div class="grid-2">
                        <div>
                            <label>Ø§Ù„ÙˆØ²Ù† Ø§Ù„Ù‚Ø§Ø¦Ù… (ÙƒØ¬Ù…)</label>
                            <input type="number" name="GrossWeight" step="10" required />
                        </div>
                        <div>
                            <label>ÙˆØ²Ù† Ø§Ù„ÙØ§Ø±Øº (ÙƒØ¬Ù…)</label>
                            <input type="number" name="TareWeight" step="10" required />
                        </div>
                    </div>
                    <button type="submit" class="submit-btn">âš–ï¸ Ø¥ØµØ¯Ø§Ø± ÙˆØ­ÙØ¸ ÙƒØ§Ø±ØªØ© Ø§Ù„Ø¨Ø³ÙƒÙˆÙ„</button>
                </form>
            </div>
        </div>

        <!-- 14. Ø¯Ù„ÙŠÙ„ Ø§Ù„Ø­Ø³Ø§Ø¨Ø§Øª -->
        <div id="tab-master" class="tab-content">
            <h3>ðŸ‘¥ Ø§Ù„Ø¹Ù…Ù„Ø§Ø¡ ÙˆØ§Ù„Ù…ÙˆØ±Ø¯ÙŠÙ† (${customers.length} Ø¹Ù…ÙŠÙ„ / ${suppliers.length} Ù…ÙˆØ±Ø¯)</h3>
            <table>
                <tr><th>Ø§Ù„Ø§Ø³Ù…</th><th>Ø§Ù„ØµÙØ©</th><th>Ø§Ù„Ù…Ø¯ÙŠÙˆÙ†ÙŠØ© / Ø§Ù„Ø±ØµÙŠØ¯</th></tr>
                ${customers.map(c => `<tr><td>${esc(getName(c))}</td><td>Ø¹Ù…ÙŠÙ„</td><td>${getBalance(c).toLocaleString()} Ø¬</td></tr>`).join('')}
                ${suppliers.map(s => `<tr><td>${esc(getName(s))}</td><td>Ù…ÙˆØ±Ø¯</td><td>Ø¹Ù…ÙˆÙ„Ø©: ${esc(s.DefaultCommission || s.defaultCommission || 0)}%</td></tr>`).join('')}
            </table>
        </div>

        <!-- 15. Ø¥Ø¹Ø¯Ø§Ø¯Ø§Øª Ø§Ù„Ø·Ø§Ø¨Ø¹Ø§Øª ÙˆØ§Ù„Ø´Ø¨ÙƒØ© -->
        <div id="tab-printer" class="tab-content">
            <div class="form-card">
                <h3 style="margin-top:0;color:#5A0817;">ðŸ–¨ï¸ Ø¥Ø¹Ø¯Ø§Ø¯Ø§Øª Ø§Ù„Ø·Ø§Ø¨Ø¹Ø§Øª ÙˆØ§Ù„Ø´Ø¨ÙƒØ© (Mobile &amp; Thermal Printing)</h3>
                <label>Ù…Ù‚Ø§Ø³ Ø§Ù„Ø·Ø¨Ø§Ø¹Ø© Ø§Ù„Ø§ÙØªØ±Ø§Ø¶ÙŠ Ø¹Ù„Ù‰ Ø§Ù„Ù‡Ø§ØªÙ ÙˆØ§Ù„Ù…ØªØµÙØ­</label>
                <select id="webPrinterSize" onchange="savePrinterPrefs()">
                    <option value="80mm">Ø­Ø±Ø§Ø±ÙŠ 80mm Ø±ÙˆÙ„ ÙƒØ§Ø´ÙŠØ± (Ø¨Ù„ÙˆØªÙˆØ« / Ø´Ø¨ÙƒØ©)</option>
                    <option value="58mm">Ø­Ø±Ø§Ø±ÙŠ 58mm Ø±ÙˆÙ„ ØµØºÙŠØ±</option>
                    <option value="A5">ÙˆØ±Ù‚ Ø¹Ø§Ø¯ÙŠ A5 (Ù†ØµÙ ÙˆØ±Ù‚Ø©)</option>
                    <option value="A4">ÙˆØ±Ù‚ Ø¹Ø§Ø¯ÙŠ A4 (ÙˆØ±Ù‚Ø© ÙƒØ§Ù…Ù„Ø©)</option>
                </select>

                <label>Ø¹Ù†ÙˆØ§Ù† IP Ø·Ø§Ø¨Ø¹Ø© Ø§Ù„Ø´Ø¨ÙƒØ© Ø§Ù„Ø­Ø±Ø§Ø±ÙŠØ© (Network Thermal IP / Ø§Ø®ØªÙŠØ§Ø±ÙŠ)</label>
                <input type="text" id="netPrinterIp" placeholder="Ù…Ø«Ø§Ù„: 192.168.1.200:9100" onchange="savePrinterPrefs()" />

                <label style="margin-top:12px;">
                    <input type="checkbox" id="chkAutoPrintWeb" onchange="savePrinterPrefs()" style="width:auto;margin-left:6px;" checked />
                    ØªØ´ØºÙŠÙ„ Ù†Ø§ÙØ°Ø© Ø§Ù„Ø·Ø¨Ø§Ø¹Ø© ØªÙ„Ù‚Ø§Ø¦ÙŠØ§Ù‹ ÙÙˆØ± Ø­ÙØ¸ Ø§Ù„ÙØ§ØªÙˆØ±Ø© Ø¹Ù„Ù‰ Ø§Ù„Ù‡Ø§ØªÙ
                </label>

                <button type="button" class="submit-btn" style="background:#0D7857;" onclick="testWebPrint()">ðŸ–¨ï¸ ØªØ¬Ø±Ø¨Ø© Ø·Ø¨Ø§Ø¹Ø© Ø¥ÙŠØµØ§Ù„ Ø§Ø®ØªØ¨Ø§Ø±ÙŠ Ø§Ù„Ø¢Ù†</button>
            </div>
        </div>
    </div>

    <!-- Ù…Ø³Ø§Ø­Ø© Ø§Ù„Ø·Ø¨Ø§Ø¹Ø© Ø§Ù„Ù…Ø®ÙÙŠØ© -->
    <div id="printArea" style="display:none;"></div>

    <script>
    const AGENCY_KEY = "${esc(key)}";
    let currentUser = JSON.parse(localStorage.getItem('mizan_staff_' + AGENCY_KEY) || 'null');
    let vehicleCargoItems = [];

    function syncScreenState() {
        if (currentUser && currentUser.full_name) {
            document.getElementById('loginScreen').style.display = 'none';
            document.getElementById('mainAppScreen').style.display = 'block';
            document.getElementById('activeUserLabel').innerHTML = 'ðŸ‘¤ Ø§Ù„Ù…ÙˆØ¸Ù: <b>' + currentUser.full_name + '</b> (' + (currentUser.job_title || currentUser.role) + ')';
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
            navigator.clipboard.writeText(el.value).then(() => alert('ØªÙ… Ø§Ù„Ù†Ø³Ø® Ù„Ù„Ø­Ø§ÙØ¸Ø© Ø¨Ù†Ø¬Ø§Ø­!'));
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
        msg.textContent = 'Ø¬Ø§Ø±ÙŠ Ø§Ù„ØªØ­Ù‚Ù‚ Ù…Ù† Ø§Ù„Ø­Ø³Ø§Ø¨...';
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
            if (!j.success) { msg.textContent = j.message || 'Ø¨ÙŠØ§Ù†Ø§Øª Ø§Ù„Ø¯Ø®ÙˆÙ„ ØºÙŠØ± ØµØ­ÙŠØ­Ø©'; return; }
            currentUser = j.user;
            localStorage.setItem('mizan_staff_' + AGENCY_KEY, JSON.stringify(currentUser));
            document.getElementById('loginPassInput').value = '';
            msg.textContent = '';
            syncScreenState();
        } catch {
            msg.textContent = 'ØªØ¹Ø°Ø± Ø§Ù„Ø§ØªØµØ§Ù„ Ø¨Ø§Ù„Ø³ÙŠØ±ÙØ±.';
        }
    }

    function handleLogout() {
        if (confirm('Ù‡Ù„ ØªØ±ÙŠØ¯ Ø¨Ø§Ù„ØªØ£ÙƒÙŠØ¯ ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø®Ø±ÙˆØ¬ ÙˆÙ‚ÙÙ„ Ø§Ù„Ø´Ø§Ø´Ø©ØŸ')) {
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
        document.getElementById('posTotalTxt').textContent = Math.round(tot).toLocaleString() + ' Ø¬';
    }

    function addItemToLoadCart() {
        const item = document.getElementById('loadItemSelect').value;
        const q = parseFloat(document.getElementById('loadItemQty').value) || 0;
        const w = parseFloat(document.getElementById('loadItemWt').value) || 0;
        if (q <= 0 && w <= 0) { alert('Ø£Ø¯Ø®Ù„ ÙƒÙ…ÙŠØ© Ø£Ùˆ ÙˆØ²Ù† ØµØ­ÙŠØ­'); return; }
        
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
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#666;">Ù„Ù… ÙŠØªÙ… Ø¥Ø¶Ø§ÙØ© Ø£ØµÙ†Ø§Ù Ù„Ù„Ø³ÙŠØ§Ø±Ø© Ø¨Ø¹Ø¯</td></tr>';
            return;
        }
        tbody.innerHTML = vehicleCargoItems.map((it, idx) => `
            <tr>
                <td><b>${esc(it.Item)}</b></td>
                <td>${it.QtyIn} Ù‚</td>
                <td>${it.WeightIn} Ùƒ</td>
                <td><button type="button" style="background:#DC2626;color:white;border:none;border-radius:4px;padding:2px 8px;cursor:pointer;" onclick="removeLoadItem(${idx})">âœ•</button></td>
            </tr>
        `).join('');
    }

    async function submitFullVehicleLoad() {
        const supp = document.getElementById('loadSuppSelect').value;
        const veh = document.getElementById('loadVehInput').value.trim();
        const fr = parseFloat(document.getElementById('loadFreightInput').value) || 0;
        const comm = parseFloat(document.getElementById('loadCommInput').value) || 5;

        if (!veh) { alert('ÙŠØ±Ø¬Ù‰ Ø¥Ø¯Ø®Ø§Ù„ Ø±Ù‚Ù… Ø£Ùˆ Ø¨ÙŠØ§Ù† Ø§Ù„Ø³ÙŠØ§Ø±Ø©'); return; }
        if (vehicleCargoItems.length === 0) { alert('ÙŠØ±Ø¬Ù‰ Ø¥Ø¶Ø§ÙØ© ØµÙ†Ù ÙˆØ§Ø­Ø¯ Ø¹Ù„Ù‰ Ø§Ù„Ø£Ù‚Ù„ Ù„Ù„Ø³ÙŠØ§Ø±Ø©'); return; }

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
            customer: "Ø¹Ù…ÙŠÙ„ ØªØ¬Ø±ÙŠØ¨ÙŠ",
            item: "Ø·Ù…Ø§Ø·Ù… ÙØ§Ø®Ø±Ø©",
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
        area.innerHTML = `
            <div style="font-family:Tahoma,sans-serif;width:280px;margin:auto;text-align:right;font-size:12px;padding:10px;">
                <h3 style="text-align:center;margin:0 0 5px 0;">${esc(inv.agencyName)}</h3>
                <div style="text-align:center;font-size:11px;border-bottom:1px dashed #000;padding-bottom:5px;">ÙØ§ØªÙˆØ±Ø© Ù…Ø¨ÙŠØ¹Ø§Øª #${esc(inv.invoiceNo)}</div>
                <div style="margin:6px 0;">Ø§Ù„Ø¹Ù…ÙŠÙ„: ${esc(inv.customer)}</div>
                <div style="margin:6px 0;">Ø§Ù„ØµÙ†Ù: ${esc(inv.item)} (${inv.qty}Ù‚ / ${inv.weight}Ùƒ @ ${inv.price}Ø¬)</div>
                <div style="font-weight:bold;font-size:14px;border-top:1px dashed #000;border-bottom:1px dashed #000;padding:5px 0;">Ø§Ù„Ø¥Ø¬Ù…Ø§Ù„ÙŠ: ${inv.total.toLocaleString()} Ø¬Ù†ÙŠÙ‡</div>
                <div style="text-align:center;margin-top:10px;font-size:10px;">Ù…Ù†Ø¸ÙˆÙ…Ø© Ù…ÙŠØ²Ø§Ù† Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠØ©</div>
            </div>
        `;
        window.print();
        setTimeout(() => { area.style.display = 'none'; }, 1000);
    }

    async function sendAction(action_type, data) {
        if (!currentUser || !currentUser.full_name) {
            alert('Ø§Ù†ØªÙ‡Øª Ø§Ù„Ø¬Ù„Ø³Ø©ØŒ ÙŠØ±Ø¬Ù‰ ØªØ³Ø¬ÙŠÙ„ Ø§Ù„Ø¯Ø®ÙˆÙ„ Ù…Ø¬Ø¯Ø¯Ø§Ù‹.');
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
                alert('Ø®Ø·Ø£: ' + (j.message || 'ÙØ´Ù„Øª Ø§Ù„Ø¹Ù…Ù„ÙŠØ©'));
                return false;
            }
        } catch (e) {
            alert('ØªØ¹Ø°Ø± Ø§Ù„Ø§ØªØµØ§Ù„ Ø¨Ø§Ù„Ø³ÙŠØ±ÙØ± Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠ: ' + e.message);
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
        const isCash = f.PaymentMethod.value.includes('Ù†Ù‚Ø¯ÙŠ') || f.Customer.value === 'Ø¹Ù…ÙŠÙ„ Ù†Ù‚Ø¯ÙŠ';

        const itemSelect = document.getElementById('posItemSelect');
        const selectedItemOpt = itemSelect.options[itemSelect.selectedIndex];
        const supplierName = selectedItemOpt.getAttribute('data-supplier') || 'Ø¹Ø§Ù…';

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
            PaymentMethod: 'Ù†Ù‚Ø¯ÙŠ (ÙƒØ§Ø´)'
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
            PaymentMethod: 'Ù†Ù‚Ø¯ÙŠ (ÙƒØ§Ø´)'
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
        const ok = await sendAction(f.Kind.value === 'Ø§Ø³ØªØ±Ø¬Ø§Ø¹' ? 'CRATE_RETURN' : 'CRATE_DELIVERY', data);
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
        if (confirm('Ù‡Ù„ ØªØ±ÙŠØ¯ Ø­Ø°Ù Ø§Ù„ÙØ§ØªÙˆØ±Ø© #' + invNo + ' Ù…Ù† Ø§Ù„Ø³ÙŠØ±ÙØ± ÙˆØ§Ù„Ø¯ÙŠØ³ÙƒØªÙˆØ¨ØŸ')) {
            await sendAction('DELETE_INVOICE', { InvoiceNo: invNo });
        }
    }

    async function deleteColAction(recNo) {
        if (confirm('Ù‡Ù„ ØªØ±ÙŠØ¯ Ø­Ø°Ù Ø³Ù†Ø¯ Ø§Ù„ØªØ­ØµÙŠÙ„ #' + recNo + 'ØŸ')) {
            await sendAction('DELETE_COLLECTION', { ReceiptNo: recNo });
        }
    }

    async function deleteExpAction(expId) {
        if (confirm('Ù‡Ù„ ØªØ±ÙŠØ¯ Ø­Ø°Ù Ù‡Ø°Ø§ Ø§Ù„Ù…ØµØ±ÙˆÙØŸ')) {
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
        return sendJson(res, 500, { success: false, message: 'Ø®Ø·Ø£ ÙÙŠ Ø§Ù„Ø³ÙŠØ±ÙØ± Ø§Ù„Ø³Ø­Ø§Ø¨ÙŠ.' });
    }
};
