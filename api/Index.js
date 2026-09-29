const { Redis } = require('@upstash/redis');

// تخزين دائم على Upstash Redis (بدل الذاكرة اللي بتضيع في Vercel)
const redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN
});

// حماية من حقن HTML
const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// بيانات أحدث إصدار لتحديثات التطبيق
const versionInfo = {
    latest_version: "2.1.0",
    download_url: "https://example.com/downloads/Mizan_Agency_Update.exe",
    changelog: "تحسينات فائقة في محرك الطباعة والربط السحابي ومزامنة الدفاتر"
};

module.exports = async (req, res) => {
    // إعدادات CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-key');

    if (req.method === 'OPTIONS') {
        res.statusCode = 200;
        return res.end();
    }

    // استخراج المسار والمعاملات
    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;
    const query = Object.fromEntries(parsedUrl.searchParams);

    // 1. الصفحة الرئيسية
    if (pathname === '/' || pathname === '') {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.statusCode = 200;
        return res.end(`
            <!DOCTYPE html>
            <html dir="rtl" lang="ar">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>خادم ميزان السحابي</title>
                <style>
                    body { font-family: Tahoma, sans-serif; text-align: center; padding: 50px; background: #200308; color: #FAF4F1; }
                    .card { background: #2A040B; border: 1.5px solid #D4AF37; border-radius: 12px; max-width: 500px; margin: auto; padding: 30px; }
                    a { background: #5A0817; color: white; padding: 12px 25px; text-decoration: none; border-radius: 8px; font-weight: bold; border: 1px solid #D4AF37; display: inline-block; margin-top: 20px; }
                </style>
            </head>
            <body>
                <div class="card">
                    <h1 style="color: #0D7857;">🚀 خادم ميزان السحابي يعمل بنجاح 100%!</h1>
                    <p style="color: #D4AF37;">الخادم جاهز لاستقبال بيانات الوكالات وفحص التحديثات على مدار 24 ساعة.</p>
                    <a href="/app">📱 فتح بوابة الموبايل للوكالات</a>
                </div>
            </body>
            </html>
        `);
    }

    // 2. مسار فحص التحديثات
    if (pathname === '/api/system/check-update') {
        const clientVer = query.version || "1.0.0";
        const hasUpdate = clientVer !== versionInfo.latest_version;

        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.statusCode = 200;
        return res.end(JSON.stringify({
            success: true,
            has_update: hasUpdate,
            client_version: clientVer,
            latest_version: versionInfo.latest_version,
            download_url: versionInfo.download_url,
            message: hasUpdate ? "الرجاء تنزيل التحديث الجديد للعمل بكفاءة أعلى ومزامنة سحابية فائقة السرعة." : "أنت تعمل على أحدث إصدار معتمد.",
            changelog: versionInfo.changelog
        }));
    }

    // 3. مسار مزامنة ورفع البيانات من كمبيوتر الوكالة
    if (pathname === '/api/sync/push' && req.method === 'POST') {
        res.setHeader('Content-Type', 'application/json; charset=utf-8');

        // حماية: لو PUSH_SECRET متضاف في Vercel لازم الكمبيوتر يبعته في header اسمه x-api-key
        if (process.env.PUSH_SECRET && req.headers['x-api-key'] !== process.env.PUSH_SECRET) {
            res.statusCode = 401;
            return res.end(JSON.stringify({ success: false, message: "غير مصرح." }));
        }

        let bodyStr = '';
        for await (const chunk of req) bodyStr += chunk;

        try {
            const body = JSON.parse(bodyStr || '{}');
            const { agency_key, agency_name, drawer_cash, today_sales, net_profit, open_cars_count, floor_stock, recent_sales } = body;

            if (!agency_key) {
                res.statusCode = 400;
                return res.end(JSON.stringify({ success: false, message: "كود الوكالة مطلوب." }));
            }

            await redis.set(`agency:${agency_key}`, {
                agency_name: agency_name || "وكالة ميزان",
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

            res.statusCode = 200;
            return res.end(JSON.stringify({ success: true, message: "تمت المزامنة بنجاح في السيرفر السحابي." }));
        } catch (err) {
            res.statusCode = 500;
            return res.end(JSON.stringify({ success: false, error: err.message }));
        }
    }

    // 4. بوابة الموبايل للعميل
    if (pathname === '/app') {
        const key = query.key;
        const data = key ? await redis.get(`agency:${key}`) : null;

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.statusCode = 200;

        if (!data) {
            return res.end(`
            <!DOCTYPE html>
            <html dir="rtl" lang="ar">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>بوابة الوكالة السحابية | ميزان</title>
                <style>
                    body { font-family: -apple-system, Tahoma, sans-serif; background: #200308; color: #FAF4F1; padding: 25px; text-align: center; }
                    .box { background: #2A040B; border: 1.5px solid #D4AF37; border-radius: 12px; max-width: 400px; margin: 50px auto; padding: 25px; }
                    input { width: 100%; box-sizing: border-box; padding: 12px; margin: 15px 0; border-radius: 8px; border: 1px solid #D4AF37; font-size: 16px; text-align: center; font-weight: bold; background: #FAF4F1; color: #1E1E1E; }
                    button { width: 100%; background: #5A0817; color: white; border: 1px solid #D4AF37; padding: 12px; border-radius: 8px; font-weight: bold; font-size: 16px; cursor: pointer; }
                </style>
            </head>
            <body>
                <div class="box">
                    <h2 style="color:#D4AF37;">🏢 بوابة الوكالة السحابية</h2>
                    <p style="font-size:13px; color:#C8B8B5;">${key ? 'الكود غير صحيح أو لم تتم أي مزامنة بعد. ' : ''}أدخل كود وكالتك السري للمتابعة الحية من هاتفك:</p>
                    <form action="/app" method="GET">
                        <input type="text" name="key" placeholder="كود الوكالة" required />
                        <button type="submit">🚀 دخول للوكالة</button>
                    </form>
                </div>
            </body>
            </html>
            `);
        }

        const m = data.metrics || {};
        return res.end(`
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
    res.end("Not Found");
};
