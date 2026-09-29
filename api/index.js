// ذاكرة سحابية للوكالات
const agencyStores = {};

// بيانات أحدث إصدار لتحديثات التطبيق
const versionInfo = {
    latest_version: "2.1.0",
    download_url: "https://example.com/downloads/Mizan_Agency_Update.exe",
    changelog: "تحسينات فائقة في محرك الطباعة والربط السحابي ومزامنة الدفاتر"
};

module.exports = (req, res) => {
    // السماح بالاتصال من أي مكان (CORS)
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    const url = req.url || '/';

    // 1. الصفحة الرئيسية لفحص عمل السيرفر
    if (url === '/' || url === '/api' || url === '/api/') {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(`
            <div style="font-family: Tahoma, sans-serif; text-align: center; padding: 50px; background: #200308; color: #FAF4F1; min-height: 100vh;">
                <h1 style="color: #0D7857;">🚀 خادم ميزان السحابي يعمل بنجاح 100% على Vercel!</h1>
                <p style="font-size: 16px; color: #D4AF37;">الخادم جاهز لاستقبال بيانات الوكالات وفحص التحديثات على مدار 24 ساعة.</p>
                <div style="margin-top: 30px;">
                    <a href="/app" style="background: #5A0817; color: white; padding: 12px 25px; text-decoration: none; border-radius: 8px; font-weight: bold; border: 1px solid #D4AF37;">📱 فتح بوابة الموبايل للوكالات</a>
                </div>
            </div>
        `);
    }

    // 2. مسار فحص التحديثات لتطبيق الديسكتوب
    if (url.startsWith('/api/system/check-update')) {
        const clientVer = (req.query && req.query.version) || "1.0.0";
        const hasUpdate = clientVer !== versionInfo.latest_version;

        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        return res.status(200).json({
            success: true,
            has_update: hasUpdate,
            client_version: clientVer,
            latest_version: versionInfo.latest_version,
            download_url: versionInfo.download_url,
            message: hasUpdate ? "الرجاء تنزيل التحديث الجديد للعمل بكفاءة أعلى ومزامنة سحابية فائقة السرعة." : "أنت تعمل على أحدث إصدار معتمد.",
            changelog: versionInfo.changelog
        });
    }

    // 3. مسار مزامنة ورفع البيانات من كمبيوتر الوكالة
    if (url.startsWith('/api/sync/push')) {
        if (req.method !== 'POST') {
            return res.status(405).json({ success: false, message: "Method Not Allowed" });
        }

        const body = req.body || {};
        const { agency_key, agency_name, drawer_cash, today_sales, net_profit, open_cars_count, floor_stock, recent_sales } = body;

        if (!agency_key) {
            return res.status(400).json({ success: false, message: "كود الوكالة مطلوب." });
        }

        agencyStores[agency_key] = {
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
        };

        return res.status(200).json({ success: true, message: "تمت المزامنة بنجاح في السيرفر السحابي." });
    }

    // 4. بوابة الموبايل لصاحب الوكالة
    if (url.startsWith('/app')) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        const key = req.query && req.query.key;

        if (!key || !agencyStores[key]) {
            return res.status(200).send(`
            <!DOCTYPE html>
            <html dir="rtl" lang="ar">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>بوابة الوكالة السحابية | ميزان</title>
                <style>
                    body { font-family: -apple-system, Tahoma, sans-serif; background: #200308; color: #FAF4F1; padding: 25px; text-align: center; }
                    .box { background: #2A040B; border: 1.5px solid #D4AF37; border-radius: 12px; max-width: 400px; margin: 50px auto; padding: 25px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
                    input { width: 100%; box-sizing: border-box; padding: 12px; margin: 15px 0; border-radius: 8px; border: 1px solid #D4AF37; font-size: 16px; text-align: center; font-weight: bold; background: #FAF4F1; color: #1E1E1E; }
                    button { width: 100%; background: #5A0817; color: white; border: 1px solid #D4AF37; padding: 12px; border-radius: 8px; font-weight: bold; font-size: 16px; cursor: pointer; }
                </style>
            </head>
            <body>
                <div class="box">
                    <h2 style="color:#D4AF37;">🏢 بوابة الوكالة السحابية</h2>
                    <p style="font-size:13px; color:#C8B8B5;">أدخل كود وكالتك السري للمتابعة الحية من هاتفك:</p>
                    <form action="/app" method="GET">
                        <input type="text" name="key" placeholder="مثال: AGENCY-001" required />
                        <button type="submit">🚀 دخول للوكالة</button>
                    </form>
                </div>
            </body>
            </html>
            `);
        }

        const data = agencyStores[key];
        return res.status(200).send(`
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${data.agency_name} | المتابعة الحية</title>
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
                <h2>🏢 ${data.agency_name}</h2>
                <div style="font-size:11px; color:#C8B8B5; margin-top:4px;">آخر تحديث من الكمبيوتر: ${new Date(data.last_sync).toLocaleTimeString('ar-EG')}</div>
            </div>

            <button class="reload-btn" onclick="location.reload()">🔄 تحديث الأرقام الحية الآن</button>

            <div class="card">
                <div>💰 نقدية الدرج الحالية:</div>
                <div class="val">${Number(data.metrics.drawer_cash).toLocaleString()} ج</div>
            </div>

            <div class="card">
                <div>💵 مبيعات اليوم:</div>
                <div class="val" style="color:#5A0817;">${Number(data.metrics.today_sales).toLocaleString()} ج</div>
            </div>

            <div class="card">
                <div>📈 أرباح الوكالة اليومية:</div>
                <div class="val">${Number(data.metrics.net_profit).toLocaleString()} ج</div>
            </div>

            <h3>🚚 بضاعة الأرضية والسيارات (${data.metrics.open_cars_count || 0})</h3>
            <table>
                <tr><th>الصنف</th><th>السيارة</th><th>باقي عدد</th><th>باقي وزن</th></tr>
                ${(data.floor_stock || []).slice(0, 20).map(f => `
                    <tr>
                        <td><b>${f.Item}</b></td>
                        <td>${f.Vehicle}</td>
                        <td>${f.QtyRemaining} ق</td>
                        <td>${f.WeightRemaining} ك</td>
                    </tr>
                `).join('')}
            </table>
        </body>
        </html>
        `);
    }

    return res.status(404).send("Page not found");
};
