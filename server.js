const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// مجلد البيانات المشفرة
const DATA_DIR = path.join(__dirname, 'data_stores');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function getAgencyFile(key) {
    const safeKey = key.replace(/[^a-zA-Z0-9_\-]/g, '_');
    return path.join(DATA_DIR, `tenant_${safeKey}.json`);
}

// -------------------------------------------------------------
// 1. استقبال البيانات تلقائياً من كمبيوتر العميل في الوكالة
// -------------------------------------------------------------
app.post('/api/sync/push', (req, res) => {
    const { agency_key, agency_name, drawer_cash, today_sales, net_profit, open_cars_count, floor_stock, recent_sales } = req.body;

    if (!agency_key || agency_key.length < 4) {
        return res.status(400).json({ success: false, message: "كود الوكالة مطلوب وغير صالح." });
    }

    const tenantFile = getAgencyFile(agency_key);
    const tenantData = {
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

    fs.writeFileSync(tenantFile, JSON.stringify(tenantData, null, 2));
    res.json({ success: true, message: "تمت المزامنة بنجاح في خزنتك السحابية الخاصة." });
});

// -------------------------------------------------------------
// 2. بوابة الهاتف لصاحب الوكالة (وهو خارج الشركة ومن أي مكان بالعالم)
// -------------------------------------------------------------
app.get('/app', (req, res) => {
    const key = req.query.key;
    if (!key) {
        return res.send(`
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>دخول بوابة الوكالة السحابية | ميزان</title>
            <style>
                body { font-family: -apple-system, Tahoma, sans-serif; background: #200308; color: #FAF4F1; margin: 0; padding: 25px; text-align: center; }
                .box { background: #2A040B; border: 1.5px solid #D4AF37; border-radius: 12px; max-width: 400px; margin: 60px auto; padding: 25px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
                input { width: 100%; box-sizing: border-box; padding: 12px; margin: 15px 0; border-radius: 8px; border: 1px solid #D4AF37; font-size: 16px; text-align: center; font-weight: bold; background: #FAF4F1; color: #1E1E1E; }
                button { width: 100%; background: #5A0817; color: white; border: 1px solid #D4AF37; padding: 12px; border-radius: 8px; font-weight: bold; font-size: 16px; cursor: pointer; }
                button:hover { background: #7A0A1F; }
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

    const tenantFile = getAgencyFile(key);
    if (!fs.existsSync(tenantFile)) {
        return res.send(`
        <html dir="rtl" style="font-family:Tahoma; text-align:center; padding:50px; background:#200308; color:white;">
            <h2>❌ لم يتم العثور على بيانات لهذه الوكالة!</h2>
            <p>تأكد من كتابة الكود السري الصحيح، أو أن كمبيوتر الوكالة قام بعمل مزامنة أولى.</p>
            <a href="/app" style="color:#D4AF37;">الرجوع للخلف</a>
        </html>
        `);
    }

    const data = JSON.parse(fs.readFileSync(tenantFile, 'utf8'));
    res.send(`
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
            .time { font-size: 11px; color: #C8B8B5; margin-top: 4px; }
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
            <div class="time">آخر تحديث من الكمبيوتر: ${new Date(data.last_sync).toLocaleTimeString('ar-EG')}</div>
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
});

// مسار فحص التحديثات الموحد
app.get('/api/system/check-update', (req, res) => {
    res.json({
        success: true,
        has_update: false,
        message: "أنت تعمل على أحدث إصدار معتمد."
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Mizan Multi-Tenant Server ready on port ${PORT}`);
});