'use strict';
const CSS = `
#app{text-align:right}
.wrap{max-width:1100px;margin:0 auto}
.card{background:#2A040B;border:1.5px solid #D4AF37;border-radius:14px;padding:18px;margin:12px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}
.opt{background:#1A0206;border:2px solid #5A0817;border-radius:12px;padding:14px;cursor:pointer;text-align:center}
.opt:hover{border-color:#D4AF37}
.opt.sel{border-color:#D4AF37;background:#3A0810;box-shadow:0 0 0 2px #D4AF3755}
.opt.off{opacity:.45;cursor:not-allowed}
.price{font-size:26px;font-weight:800;color:#D4AF37}
.badge{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;font-weight:700;color:#111}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin:12px 0}
.tab{width:auto!important;padding:8px 16px!important;background:#2A040B!important}
.tab.on{background:#D4AF37!important;color:#200308!important}
.stat{background:#1A0206;border-radius:12px;padding:14px;text-align:center}
.stat b{display:block;font-size:26px;color:#D4AF37}
table.t{width:100%;border-collapse:collapse;font-size:13px}
table.t th{color:#D4AF37;text-align:right;padding:8px;border-bottom:1px solid #D4AF37;white-space:nowrap}
table.t td{padding:8px;border-bottom:1px solid #4a0a14;vertical-align:middle}
.b2{width:auto!important;display:inline-block;padding:6px 12px!important;font-size:13px;margin:2px}
.danger{background:#7f1d1d!important}
.okb{background:#14532d!important}
.modal-bg{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.65);display:flex;align-items:flex-start;justify-content:center;overflow:auto;padding:20px;z-index:50}
.modal{background:#2A040B;border:1.5px solid #D4AF37;border-radius:14px;max-width:780px;width:100%;padding:20px;text-align:right}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#14532d;color:#fff;padding:10px 20px;border-radius:8px;z-index:99;font-weight:700}
.toast.bad{background:#991b1b}
.wa{display:inline-flex;align-items:center;gap:8px;background:#25D366;color:#053;padding:9px 16px;border-radius:99px;font-weight:800;text-decoration:none}
.acct{background:#1A0206;border-radius:8px;padding:10px;margin:8px 0;direction:ltr;text-align:left;word-break:break-all;color:#D4AF37;font-family:monospace;white-space:pre-wrap}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.muted{color:#C8B8B5;font-size:13px}
.bar{height:10px;background:#1A0206;border-radius:99px;overflow:hidden;margin:8px 0}
.bar>i{display:block;height:100%;background:#D4AF37}
.hd{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
img.rc{max-width:100%;border-radius:8px;border:1px solid #D4AF37}
`;

/* ------------------------------------------------------------------ */
function helpers() {
    var H = {};
    H.LBL = { active: 'نشط', trial: 'تجريبي', expired: 'منتهي', locked: 'مقفول', disabled: 'معطّل', pending: 'غير مفعّل' };
    H.CLR = { active: '#22c55e', trial: '#38bdf8', expired: '#f59e0b', locked: '#ef4444', disabled: '#ef4444', pending: '#9ca3af',
              approved: '#22c55e', rejected: '#ef4444', failed: '#ef4444' };
    H.PLBL = { pending: 'قيد المراجعة', approved: 'تم القبول', rejected: 'مرفوض', failed: 'فشل' };

    H.h = function (tag, attrs, kids) {
        var e = document.createElement(tag);
        if (attrs) for (var k in attrs) {
            var v = attrs[k];
            if (k === 'class') e.className = v;
            else if (k === 'style') e.style.cssText = v;
            else if (k.slice(0, 2) === 'on') e.addEventListener(k.slice(2), v);
            else if (v === true) e.setAttribute(k, '');
            else if (v !== false && v != null) e.setAttribute(k, v);
        }
        var add = function (c) {
            if (c == null || c === false) return;
            if (Array.isArray(c)) { c.forEach(add); return; }
            e.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
        };
        add(kids);
        return e;
    };
    H.money = function (n, cur) { return Number(n || 0).toLocaleString('en-US') + ' ' + (cur || ''); };
    H.date = function (iso) { return iso ? String(iso).slice(0, 10) : '-'; };
    H.badge = function (state, txt) {
        return H.h('span', { class: 'badge', style: 'background:' + (H.CLR[state] || '#999') }, txt || H.LBL[state] || state);
    };
    H.toast = function (msg, bad) {
        var t = H.h('div', { class: 'toast' + (bad ? ' bad' : '') }, msg);
        document.body.appendChild(t);
        setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 3200);
    };
    H.api = async function (path, o) {
        o = o || {};
        var hd = { 'Content-Type': 'application/json' };
        if (o.token) hd.Authorization = 'Bearer ' + o.token;
        var r, j = {};
        try {
            r = await fetch(path, { method: o.method || (o.body ? 'POST' : 'GET'), headers: hd, body: o.body ? JSON.stringify(o.body) : undefined });
        } catch (e) { return { ok: false, status: 0, message: 'تعذر الاتصال بالسيرفر' }; }
        try { j = await r.json(); } catch (e) { j = {}; }
        j.ok = r.ok && j.success !== false;
        j.status = r.status;
        return j;
    };
    H.copy = function (t) {
        var done = function () { H.toast('تم النسخ ✔'); };
        if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(t).then(done, done); return; }
        var a = document.createElement('textarea'); a.value = t; document.body.appendChild(a); a.select();
        try { document.execCommand('copy'); } catch (e) {}
        document.body.removeChild(a); done();
    };
    H.wa = function (num, text) {
        return 'https://wa.me/' + String(num || '').replace(/\D/g, '') + '?text=' + encodeURIComponent(text || '');
    };
    H.waIcon = function (size) {
        var s = document.createElement('span');
        s.style.display = 'inline-flex';
        s.innerHTML = '<svg width="' + size + '" height="' + size + '" viewBox="0 0 24 24" fill="#053"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>';
        return s;
    };
    H.waBtn = function (cfg, text, label) {
        if (!cfg.whatsapp) return null;
        return H.h('a', { class: 'wa', href: H.wa(cfg.whatsapp, text), target: '_blank', rel: 'noopener' },
            [H.waIcon(22), label || cfg.company]);
    };
    H.modal = function (title, body) {
        var bg = H.h('div', { class: 'modal-bg' });
        var close = function () { if (bg.parentNode) bg.parentNode.removeChild(bg); };
        bg.appendChild(H.h('div', { class: 'modal' }, [
            H.h('div', { class: 'hd' }, [H.h('h2', { style: 'margin:0' }, title), H.h('button', { class: 'b2 danger', onclick: close }, '✖ إغلاق')]),
            body
        ]));
        document.body.appendChild(bg);
        return { close: close };
    };
    H.field = function (label, input) { return H.h('div', null, [H.h('label', null, label), input]); };
    H.tabs = function (defs, cur, onPick) {
        return H.h('div', { class: 'tabs' }, defs.map(function (d) {
            return H.h('button', { class: 'tab' + (d[0] === cur ? ' on' : ''), onclick: function () { onPick(d[0]); } }, d[1]);
        }));
    };
    return H;
}

/* ------------------------------------------------------------------ */
/* لوحة الدفع: اختيار الباقة وطريقة الدفع والدفع من داخل الموقع */
function payPanel(H, root, C) {
    var h = H.h;
    var S = { plan: null, method: null, timer: null, receipt: null };
    var planKeys = Object.keys(C.plans).filter(function (k) { return C.plans[k].enabled; });
    var mKeys = Object.keys(C.methods).filter(function (k) { return C.methods[k].enabled; });
    var monthly = C.plans.monthly && C.plans.monthly.enabled ? C.plans.monthly.price : 0;
    S.plan = planKeys.indexOf('monthly') > -1 ? 'monthly' : planKeys[0];

    function waText(extra) {
        var p = C.plans[S.plan];
        var lines = ['السلام عليكم، ' + C.company, 'اسم الوكالة: ' + (C.agency_name || '-'), 'كود الوكالة: ' + C.key];
        if (p) lines.push('الباقة: ' + p.label + ' (' + H.money(p.price, C.currency) + ')');
        if (S.method) lines.push('طريقة الدفع: ' + C.methods[S.method].label);
        if (extra) lines.push(extra);
        return lines.join('\n');
    }
    function stop() { if (S.timer) { clearInterval(S.timer); S.timer = null; } }

    function planCard(k) {
        var p = C.plans[k];
        var perMonth = Math.round(p.price / p.months);
        var save = monthly && p.months > 1 ? Math.round((1 - p.price / (monthly * p.months)) * 100) : 0;
        return h('div', { class: 'opt' + (S.plan === k ? ' sel' : ''), onclick: function () { S.plan = k; draw(); } }, [
            h('b', null, p.label),
            h('div', { class: 'price' }, H.money(p.price, C.currency)),
            h('div', { class: 'muted' }, p.months + ' شهر • ' + H.money(perMonth, C.currency) + ' / شهر'),
            save > 0 ? H.badge('active', 'وفّر ' + save + '%') : null
        ]);
    }
    function methodCard(k) {
        var m = C.methods[k];
        var icon = { instapay: '📲', vodafone: '📱', bank: '🏦', card: '💳' }[k] || '💰';
        return h('div', { class: 'opt' + (S.method === k ? ' sel' : ''), onclick: function () { S.method = k; draw(); } },
            [h('div', { style: 'font-size:26px' }, icon), h('b', null, m.label)]);
    }

    function resizeImage(file, cb) {
        var fr = new FileReader();
        fr.onload = function () {
            var img = new Image();
            img.onload = function () {
                var max = 1100, w = img.width, hh = img.height, r = Math.min(1, max / Math.max(w, hh));
                var c = document.createElement('canvas'); c.width = Math.round(w * r); c.height = Math.round(hh * r);
                c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
                cb(c.toDataURL('image/jpeg', 0.6));
            };
            img.onerror = function () { cb(null); };
            img.src = fr.result;
        };
        fr.readAsDataURL(file);
    }

    function poll(id, box) {
        stop();
        S.timer = setInterval(async function () {
            var r = await H.api('/api/pay/status?id=' + encodeURIComponent(id) + '&key=' + encodeURIComponent(C.key));
            if (!r.ok) return;
            if (r.status_text === 'approved') { stop(); done(box, r); }
            else if (r.status_text === 'rejected' || r.status_text === 'failed') {
                stop();
                box.textContent = '';
                box.appendChild(h('div', { class: 'card' }, [
                    h('h3', null, r.status_text === 'rejected' ? '❌ تم رفض الطلب' : '❌ فشلت عملية الدفع'),
                    h('p', { class: 'muted' }, r.reason || 'تواصل معنا وسنساعدك.'),
                    h('button', { onclick: function () { draw(); } }, 'حاول مرة أخرى'), H.waBtn(C, waText('بخصوص طلب رقم ' + id))
                ]));
            }
        }, 5000);
    }
    function done(box, r) {
        box.textContent = '';
        box.appendChild(h('div', { class: 'card', style: 'text-align:center' }, [
            h('h2', null, '✅ تم تفعيل اشتراكك'),
            h('p', null, 'ينتهي في: ' + H.date(r.paid_until)),
            h('a', { class: 'btn', href: '/app?key=' + encodeURIComponent(C.key) }, 'فتح لوحة الوكالة'),
            C.onPaid ? h('button', { class: 'small', onclick: C.onPaid }, 'رجوع لحسابي') : null
        ]));
    }
    function waitingView(box, id, text) {
        box.textContent = '';
        box.appendChild(h('div', { class: 'card', style: 'text-align:center' }, [
            h('h2', null, '⏳ ' + text),
            h('p', { class: 'muted' }, 'رقم طلبك: ' + id + ' — هيتفعل اشتراكك تلقائياً بمجرد الاعتماد، وتقدر تقفل الصفحة وترجع لها.'),
            h('p', null, 'لتسريع التفعيل ابعت كود الوكالة على واتساب بضغطة واحدة:'),
            H.waBtn(C, waText('رقم الطلب: ' + id + '\nتم الدفع، برجاء التفعيل.'), C.company)
        ]));
        poll(id, box);
    }

    function manualForm(box) {
        var m = C.methods[S.method], p = C.plans[S.plan];
        var payer = h('input', { placeholder: 'اسمك أو رقم الموبايل اللي حوّلت منه' });
        var ref = h('input', { placeholder: 'رقم العملية / المرجع (اختياري)' });
        var note = h('input', { placeholder: 'ملاحظات (اختياري)' });
        var file = h('input', { type: 'file', accept: 'image/*' });
        var msg = h('div', { class: 'msg' });
        file.addEventListener('change', function () {
            S.receipt = null;
            if (file.files && file.files[0]) resizeImage(file.files[0], function (d) { S.receipt = d; if (!d) msg.textContent = 'تعذر قراءة الصورة'; });
        });
        var btn = h('button', { onclick: async function () {
            if (!payer.value.trim()) { msg.textContent = 'اكتب اسم أو رقم المحوِّل'; return; }
            btn.disabled = true; msg.textContent = '';
            var r = await H.api('/api/pay/request', { body: { agency_key: C.key, plan: S.plan, method: S.method,
                payer: payer.value, reference: ref.value, note: note.value, receipt: S.receipt } });
            btn.disabled = false;
            if (!r.ok) { msg.textContent = r.message || 'حدث خطأ'; return; }
            waitingView(box, r.id, 'تم استلام طلب الدفع');
        } }, '✅ تأكيد الدفع وإرسال الطلب');
        return h('div', { class: 'card' }, [
            h('h3', null, m.label),
            h('p', null, ['المبلغ المطلوب: ', h('b', { style: 'color:#D4AF37' }, H.money(p.price, C.currency))]),
            m.details ? h('div', { class: 'acct' }, m.details) : null,
            m.details ? h('button', { class: 'b2 small', onclick: function () { H.copy(m.details); } }, '📋 نسخ البيانات') : null,
            h('p', { class: 'muted' }, 'حوّل المبلغ ثم املأ البيانات بالأسفل (ابقَ في هذه الصفحة):'),
            H.field('بيانات المحوِّل', payer), H.field('رقم العملية', ref), H.field('صورة الإيصال (يُفضَّل)', file), H.field('ملاحظات', note),
            btn, msg
        ]);
    }
    function cardForm(box) {
        var msg = h('div', { class: 'msg' });
        var btn = h('button', { onclick: async function () {
            btn.disabled = true; msg.textContent = 'جاري تجهيز صفحة الدفع الآمنة...';
            var r = await H.api('/api/pay/card', { body: { agency_key: C.key, plan: S.plan } });
            if (!r.ok) { btn.disabled = false; msg.textContent = r.message || 'تعذر بدء الدفع'; return; }
            box.textContent = '';
            box.appendChild(h('div', { class: 'card' }, [
                h('h3', null, '💳 الدفع بالكارت — رقم الطلب ' + r.id),
                h('iframe', { src: r.iframe_url, style: 'width:100%;height:640px;border:0;background:#fff;border-radius:8px', allow: 'payment' }),
                h('p', { class: 'muted' }, 'بعد إتمام الدفع هيتفعل الاشتراك تلقائياً هنا.')
            ]));
            poll(r.id, box);
        } }, '💳 ادفع الآن بالفيزا / ماستر كارد');
        return h('div', { class: 'card' }, [
            h('h3', null, 'الدفع بالكارت'),
            h('p', { class: 'muted' }, 'هتدفع داخل نفس الصفحة عبر بوابة دفع آمنة، ومش بنحفظ بيانات الكارت.'),
            btn, msg
        ]);
    }

    function draw() {
        stop();
        root.textContent = '';
        var detail = h('div');
        root.appendChild(h('div', { class: 'card' }, [
            h('div', { class: 'hd' }, [h('h3', { style: 'margin:0' }, '1) اختر الباقة'), H.waBtn(C, waText(), C.company)]),
            h('div', { class: 'grid', style: 'margin-top:10px' }, planKeys.map(planCard))
        ]));
        if (!mKeys.length) {
            root.appendChild(h('div', { class: 'card' }, [h('p', null, 'طرق الدفع غير مفعّلة حالياً، تواصل معنا:'), H.waBtn(C, waText())]));
            return;
        }
        root.appendChild(h('div', { class: 'card' }, [
            h('h3', { style: 'margin-top:0' }, '2) اختر طريقة الدفع'),
            h('div', { class: 'grid' }, mKeys.map(methodCard))
        ]));
        root.appendChild(detail);
        if (S.method && mKeys.indexOf(S.method) > -1) detail.appendChild(S.method === 'card' ? cardForm(detail) : manualForm(detail));
    }
    draw();
    return { destroy: stop };
}

/* ------------------------------------------------------------------ */
/* صفحة الدفع المباشرة (لما الاشتراك ينتهي) */
function payPage(H, mountPay) {
    var C = window.__CFG, h = H.h, root = document.getElementById('app');
    root.appendChild(h('div', { class: 'wrap' }, [
        h('div', { class: 'card', style: 'text-align:center' }, [
            h('h2', null, C.locked ? '🔒 الخدمة السحابية متوقفة' : '⏰ انتهى الاشتراك'),
            h('p', { class: 'muted' }, 'جدّد اشتراكك للاستمرار في استخدام النسخة السحابية (الويب والموبايل). برنامج الديسك توب مجاني ويعمل بدون توقف.'),
            h('p', null, ['كود الوكالة: ', h('b', { style: 'color:#D4AF37;direction:ltr;display:inline-block;word-break:break-all' }, C.key)])
        ]),
        h('div', { id: 'panel' })
    ]));
    mountPay(H, document.getElementById('panel'), C);
}

/* ------------------------------------------------------------------ */
/* بوابة المستخدم /account */
function accountPage(H, mountPay) {
    var h = H.h, root = document.getElementById('app'), T = localStorage.getItem('mz_token'), tab = 'home', D = null, panelHandle = null;
    if (!T) { location.href = '/login'; return; }
    function api(p, body) { return H.api(p, { token: T, body: body }); }
    function logout() { api('/api/account/logout', {}).then(function () { localStorage.removeItem('mz_token'); location.href = '/login'; }); }

    async function load() {
        var r = await api('/api/account/me');
        if (r.status === 401) { localStorage.removeItem('mz_token'); location.href = '/login'; return; }
        if (!r.ok) { root.textContent = r.message || 'خطأ'; return; }
        D = r; draw();
    }
    function payCfg() {
        var c = Object.assign({}, D.cfg, { key: D.user.agency_key, agency_name: D.user.agency_name });
        c.onPaid = function () { tab = 'home'; load(); };
        return c;
    }
    function homeTab() {
        var s = D.sub, pct = s.days_left == null ? 0 : Math.max(0, Math.min(100, Math.round(s.days_left / (s.cycle_days || 30) * 100)));
        return h('div', null, [
            h('div', { class: 'card' }, [
                h('div', { class: 'hd' }, [h('h3', { style: 'margin:0' }, 'حالة الاشتراك'), H.badge(s.state)]),
                s.state === 'disabled' ? h('p', null, 'الحساب معطّل، تواصل مع الدعم.') : [
                    h('p', null, s.paid_until ? 'ينتهي في ' + H.date(s.paid_until) + (s.days_left != null ? ' — متبقي ' + Math.max(0, s.days_left) + ' يوم' : '') : 'لا يوجد اشتراك'),
                    h('div', { class: 'bar' }, h('i', { style: 'width:' + pct + '%' })),
                    s.plan ? h('p', { class: 'muted' }, 'الباقة الأخيرة: ' + (D.cfg.plans[s.plan] ? D.cfg.plans[s.plan].label : s.plan)) : null
                ],
                h('div', { class: 'row' }, [
                    h('button', { class: 'b2', onclick: function () { tab = 'pay'; draw(); } }, '💳 تجديد / ترقية'),
                    h('a', { class: 'btn b2 okb', href: '/app?key=' + encodeURIComponent(D.user.agency_key) }, '📊 فتح لوحة الوكالة')
                ])
            ]),
            h('div', { class: 'card' }, [
                h('h3', { style: 'margin-top:0' }, 'كود الوكالة (للربط مع برنامج الديسك توب)'),
                h('div', { class: 'acct' }, D.user.agency_key),
                h('div', { class: 'row' }, [
                    h('button', { class: 'b2', onclick: function () { H.copy(D.user.agency_key); } }, '📋 نسخ الكود'),
                    H.waBtn(Object.assign({}, D.cfg), 'السلام عليكم، ' + D.cfg.company + '\nاسم الوكالة: ' + D.user.agency_name + '\nكود الوكالة: ' + D.user.agency_key + '\nأحتاج مساعدة.', D.cfg.company)
                ]),
                h('p', { class: 'muted' }, 'برنامج الديسك توب مجاني 100% ولا يتوقف أبداً.')
            ])
        ]);
    }
    function payTab() {
        var box = h('div');
        setTimeout(function () { panelHandle = mountPay(H, box, payCfg()); }, 0);
        return box;
    }
    function historyTab() {
        var rows = D.payments;
        if (!rows.length) return h('div', { class: 'card' }, 'لا توجد مدفوعات بعد.');
        return h('div', { class: 'card', style: 'overflow-x:auto' }, h('table', { class: 't' }, [
            h('tr', null, ['رقم الطلب', 'التاريخ', 'الباقة', 'المبلغ', 'الطريقة', 'الحالة'].map(function (t) { return h('th', null, t); })),
        ].concat(rows.map(function (p) {
            return h('tr', null, [h('td', null, p.id), h('td', null, H.date(p.created_at)),
                h('td', null, (D.cfg.plans[p.plan] || {}).label || p.plan), h('td', null, H.money(p.amount, p.currency)),
                h('td', null, (D.cfg.methods[p.method] || {}).label || p.method), h('td', null, H.badge(p.status, H.PLBL[p.status]))]);
        }))));
    }
    function settingsTab() {
        var nm = h('input', { value: D.user.agency_name }), ph = h('input', { value: D.user.phone || '', placeholder: 'رقم الموبايل' });
        var op = h('input', { type: 'password', autocomplete: 'current-password' }), np = h('input', { type: 'password', autocomplete: 'new-password' });
        var dp = h('input', { type: 'password' }), du = h('input', { placeholder: 'اكتب اسم المستخدم للتأكيد' });
        return h('div', null, [
            h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, 'بيانات الحساب'),
                H.field('اسم الوكالة', nm), H.field('الموبايل', ph),
                h('p', { class: 'muted' }, 'اسم المستخدم: ' + D.user.username + ' • البريد: ' + D.user.email),
                h('button', { onclick: async function () {
                    var r = await api('/api/account/profile', { agency_name: nm.value, phone: ph.value });
                    H.toast(r.ok ? 'تم الحفظ ✔' : (r.message || 'خطأ'), !r.ok); if (r.ok) load();
                } }, 'حفظ')]),
            h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, 'تغيير كلمة المرور'),
                H.field('كلمة المرور الحالية', op), H.field('الجديدة (8 أحرف على الأقل)', np),
                h('button', { onclick: async function () {
                    var r = await api('/api/account/password', { old_password: op.value, new_password: np.value });
                    H.toast(r.ok ? 'تم التغيير، سجّل دخولك من جديد' : (r.message || 'خطأ'), !r.ok);
                    if (r.ok) { localStorage.removeItem('mz_token'); setTimeout(function () { location.href = '/login'; }, 1500); }
                } }, 'تغيير')]),
            h('div', { class: 'card' }, [h('button', { class: 'danger', onclick: logout }, '🚪 تسجيل الخروج')]),
            h('div', { class: 'card', style: 'border-color:#ef4444' }, [h('h3', { style: 'margin-top:0;color:#ef4444' }, 'حذف الحساب نهائياً'),
                h('p', { class: 'muted' }, 'سيتم حذف الحساب وبيانات المزامنة السحابية. برنامج الديسك توب وبياناتك عليه لا تتأثر.'),
                H.field('كلمة المرور', dp), H.field('تأكيد', du),
                h('button', { class: 'danger', onclick: async function () {
                    if (!confirm('متأكد من حذف الحساب؟ لا يمكن التراجع.')) return;
                    var r = await api('/api/account/delete', { password: dp.value, confirm: du.value });
                    if (r.ok) { localStorage.removeItem('mz_token'); location.href = '/register'; } else H.toast(r.message || 'خطأ', true);
                } }, 'حذف الحساب')])
        ]);
    }
    function draw() {
        if (panelHandle) { panelHandle.destroy(); panelHandle = null; }
        root.textContent = '';
        var body = tab === 'home' ? homeTab() : tab === 'pay' ? payTab() : tab === 'hist' ? historyTab() : settingsTab();
        root.appendChild(h('div', { class: 'wrap' }, [
            h('div', { class: 'card hd' }, [h('h2', { style: 'margin:0' }, '👤 ' + D.user.agency_name), H.waBtn(D.cfg, 'السلام عليكم، ' + D.cfg.company, D.cfg.company)]),
            H.tabs([['home', '🏠 الرئيسية'], ['pay', '💳 الاشتراك والدفع'], ['hist', '🧾 المدفوعات'], ['set', '⚙️ الإعدادات']], tab, function (t) { tab = t; draw(); }),
            body
        ]));
    }
    load();
}

/* ------------------------------------------------------------------ */
/* لوحة المطوّر /admin */
function adminPage(H) {
    var h = H.h, root = document.getElementById('app'), T = sessionStorage.getItem('mz_admin') || '', tab = 'over', users = [], filt = { q: '', st: '' }, pst = 'pending';
    function A(p, body) { return H.api(p, { token: T, body: body }); }

    function loginView() {
        root.textContent = '';
        var tk = h('input', { type: 'password', placeholder: 'ADMIN_TOKEN' }), msg = h('div', { class: 'msg' });
        var go = async function () {
            T = tk.value.trim();
            var r = await A('/api/admin/overview');
            if (!r.ok) { msg.textContent = r.status === 429 ? 'محاولات كثيرة، حاول لاحقاً' : 'رمز غير صحيح'; return; }
            sessionStorage.setItem('mz_admin', T); main();
        };
        tk.addEventListener('keydown', function (e) { if (e.key === 'Enter') go(); });
        root.appendChild(h('div', { class: 'card', style: 'max-width:420px;margin:60px auto' }, [h('h2', null, '🛠️ لوحة المطوّر'), tk, h('button', { onclick: go }, 'دخول'), msg]));
    }
    function main() {
        root.textContent = '';
        var content = h('div');
        root.appendChild(h('div', { class: 'wrap' }, [
            h('div', { class: 'hd' }, [h('h2', { style: 'margin:0' }, '🛠️ لوحة تحكم ميزان'),
                h('button', { class: 'b2 danger', onclick: function () { sessionStorage.removeItem('mz_admin'); T = ''; loginView(); } }, 'خروج')]),
            H.tabs([['over', '📊 نظرة عامة'], ['acc', '👥 الحسابات'], ['pay', '🧾 طلبات الدفع'], ['upd', '🚀 التحديثات'], ['set', '⚙️ الإعدادات'], ['log', '📜 السجل'], ['bak', '💾 نسخ احتياطي']], tab,
                function (t) { tab = t; main(); }),
            content
        ]));
        ({ over: overView, acc: accView, pay: payView, upd: updView, set: setView, log: logView, bak: bakView })[tab](content);
    }

    async function overView(c) {
        var r = await A('/api/admin/overview'); if (!r.ok) return;
        var k = r.counts, cards = [['إجمالي الحسابات', k.total], ['نشط (مدفوع)', k.active], ['تجريبي', k.trial], ['منتهي', k.expired], ['مقفول', k.locked], ['معطّل', k.disabled],
            ['طلبات دفع معلّقة', r.pending_payments], ['إيراد الشهر', H.money(r.revenue_month, r.currency)], ['إجمالي الإيراد', H.money(r.revenue_total, r.currency)]];
        c.appendChild(h('div', { class: 'grid' }, cards.map(function (x) { return h('div', { class: 'stat' }, [h('b', null, x[1]), x[0]]); })));
        c.appendChild(h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, '⏳ اشتراكات تنتهي خلال 7 أيام'),
            r.expiring.length ? h('table', { class: 't' }, r.expiring.map(function (u) {
                return h('tr', null, [h('td', null, u.username), h('td', null, u.agency_name), h('td', null, H.date(u.paid_until)), h('td', null, u.days_left + ' يوم'),
                    h('td', null, h('button', { class: 'b2', onclick: function () { openUser(u.username); } }, 'إدارة'))]);
            })) : h('p', { class: 'muted' }, 'لا يوجد.')]));
    }

    async function accView(c) {
        var r = await A('/api/admin/list'); if (!r.ok) return; users = r.users;
        var q = h('input', { placeholder: 'بحث بالاسم / الوكالة / البريد', value: filt.q, style: 'flex:1' });
        var st = h('select', { style: 'width:auto' }, [['', 'كل الحالات']].concat(Object.keys(H.LBL).map(function (s) { return [s, H.LBL[s]]; })).map(function (o) {
            return h('option', { value: o[0], selected: filt.st === o[0] }, o[1]); }));
        var tb = h('div', { style: 'overflow-x:auto' });
        function paint() {
            filt.q = q.value.trim().toLowerCase(); filt.st = st.value; tb.textContent = '';
            var rows = users.filter(function (u) { return (!filt.st || u.state === filt.st) && (!filt.q || (u.username + ' ' + u.agency_name + ' ' + u.email + ' ' + (u.phone || '')).toLowerCase().indexOf(filt.q) > -1); });
            tb.appendChild(h('table', { class: 't' }, [h('tr', null, ['المستخدم', 'الوكالة', 'التواصل', 'الحالة', 'ينتهي', 'الباقة', ''].map(function (t) { return h('th', null, t); }))]
                .concat(rows.map(function (u) {
                    return h('tr', null, [h('td', null, u.username), h('td', null, u.agency_name), h('td', null, (u.phone || '') + ' ' + u.email), h('td', null, H.badge(u.state)),
                        h('td', null, u.paid_until ? H.date(u.paid_until) + ' (' + u.days_left + 'ي)' : '-'), h('td', null, u.plan || '-'),
                        h('td', null, h('button', { class: 'b2', onclick: function () { openUser(u.username); } }, 'إدارة'))]);
                }))));
        }
        q.addEventListener('input', paint); st.addEventListener('change', paint);
        c.appendChild(h('div', { class: 'card' }, [h('div', { class: 'row' }, [q, st, h('span', { class: 'muted' }, users.length + ' حساب')]), tb]));
        paint();
    }

    async function openUser(username) {
        var r = await A('/api/admin/user?username=' + encodeURIComponent(username)); if (!r.ok) { H.toast(r.message || 'خطأ', true); return; }
        var u = r.user, box = h('div'), m;
        var act = async function (body, okMsg) {
            var x = await A('/api/admin/subscription', Object.assign({ username: username }, body));
            H.toast(x.ok ? (okMsg || 'تم ✔') : (x.message || 'خطأ'), !x.ok);
            if (x.ok) { if (x.temp_password) { prompt('كلمة المرور المؤقتة (انسخها وأرسلها للعميل):', x.temp_password); } m.close(); if (x.deleted) { main(); return; } openUser(username); if (tab === 'acc') main(); }
        };
        var num = h('input', { type: 'number', value: 30, min: 1, style: 'width:100px' });
        var unit = h('select', { style: 'width:auto' }, [h('option', { value: 'days' }, 'يوم'), h('option', { value: 'months' }, 'شهر')]);
        var until = h('input', { type: 'date', value: r.sub && r.sub.paid_until ? r.sub.paid_until.slice(0, 10) : '', style: 'width:auto' });
        var note = h('textarea', { rows: 2 }, r.sub && r.sub.note || ''); note.value = r.sub && r.sub.note || '';
        var delc = h('input', { placeholder: 'اكتب اسم المستخدم للتأكيد' });
        box.appendChild(h('div', null, [
            h('div', { class: 'row' }, [H.badge(r.state), h('span', null, u.agency_name + ' — ' + u.email + ' — ' + (u.phone || 'بدون موبايل')),
                r.sub && r.sub.paid_until ? h('span', { class: 'muted' }, 'ينتهي ' + H.date(r.sub.paid_until) + ' (' + r.days_left + ' يوم)') : null]),
            h('div', { class: 'acct' }, u.agency_key),
            h('div', { class: 'row' }, [h('button', { class: 'b2', onclick: function () { H.copy(u.agency_key); } }, '📋 نسخ الكود'),
                h('a', { class: 'btn b2', href: '/app?key=' + u.agency_key, target: '_blank' }, '📊 فتح لوحته'),
                u.phone ? h('a', { class: 'wa', href: H.wa(u.phone, 'السلام عليكم ' + u.agency_name), target: '_blank' }, [H.waIcon(18), 'واتساب العميل']) : null]),
            h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, '⏱️ مدة التمديد'),
                h('div', { class: 'row' }, [num, unit, h('button', { class: 'b2 okb', onclick: function () {
                    var n = Number(num.value); var b = { action: 'extend' }; b[unit.value] = n; act(b, 'تم التمديد'); } }, '➕ تمديد')]),
                h('div', { class: 'row' }, [
                    h('button', { class: 'b2', onclick: function () { act({ action: 'extend', months: 1 }); } }, '+ شهر'),
                    h('button', { class: 'b2', onclick: function () { act({ action: 'extend', months: 6 }); } }, '+ 6 شهور'),
                    h('button', { class: 'b2', onclick: function () { act({ action: 'extend', months: 12 }); } }, '+ سنة'),
                    h('button', { class: 'b2', onclick: function () { act({ action: 'extend', days: 7 }); } }, '+ 7 أيام')]),
                h('div', { class: 'row' }, [h('label', { style: 'margin:0' }, 'ضبط تاريخ الانتهاء:'), until,
                    h('button', { class: 'b2', onclick: function () { act({ action: 'set_until', until: until.value }); } }, 'حفظ التاريخ'),
                    h('button', { class: 'b2 danger', onclick: function () { if (confirm('إنهاء الاشتراك الآن؟')) act({ action: 'expire' }); } }, 'إنهاء الآن')])]),
            h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, '🔐 التحكم'),
                h('div', { class: 'row' }, [
                    r.state === 'locked' || r.state === 'expired' ? h('button', { class: 'b2 okb', onclick: function () { act({ action: 'unlock' }); } }, '🔓 فتح الخدمة')
                        : h('button', { class: 'b2 danger', onclick: function () { if (confirm('قفل الخدمة السحابية؟')) act({ action: 'lock' }); } }, '🔒 قفل الخدمة'),
                    u.disabled ? h('button', { class: 'b2 okb', onclick: function () { act({ action: 'enable' }); } }, '✅ تفعيل الحساب')
                        : h('button', { class: 'b2 danger', onclick: function () { if (confirm('تعطيل الحساب؟')) act({ action: 'disable' }); } }, '⛔ تعطيل الحساب'),
                    h('button', { class: 'b2', onclick: function () { if (confirm('إنشاء كلمة مرور مؤقتة؟')) act({ action: 'reset_password' }); } }, '🔑 إعادة تعيين كلمة المرور')])]),
            h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, '📝 ملاحظات داخلية'), note,
                h('button', { class: 'b2', onclick: function () { act({ action: 'note', note: note.value }); } }, 'حفظ الملاحظة')]),
            h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, '📊 بيانات المزامنة'),
                h('p', { class: 'muted' }, 'آخر مزامنة: ' + H.date(r.agency.last_sync) + ' • عملاء ' + r.agency.customers + ' • موردين ' + r.agency.suppliers + ' • أصناف ' + r.agency.items + ' • مستخدمين ' + r.agency.users)]),
            h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, '🧾 مدفوعاته'),
                r.payments.length ? h('table', { class: 't' }, r.payments.map(function (p) {
                    return h('tr', null, [h('td', null, p.id), h('td', null, H.date(p.created_at)), h('td', null, p.plan), h('td', null, H.money(p.amount, p.currency)), h('td', null, p.method), h('td', null, H.badge(p.status, H.PLBL[p.status]))]);
                })) : h('p', { class: 'muted' }, 'لا يوجد.')]),
            h('div', { class: 'card', style: 'border-color:#ef4444' }, [h('h3', { style: 'margin-top:0;color:#ef4444' }, 'حذف الحساب نهائياً'), delc,
                h('button', { class: 'b2 danger', onclick: function () { if (delc.value === username && confirm('حذف نهائي؟')) act({ action: 'delete' }, 'تم الحذف'); else H.toast('اكتب اسم المستخدم للتأكيد', true); } }, '🗑️ حذف')])
        ]));
        m = H.modal('إدارة: ' + username, box);
    }

    async function payView(c) {
        var sel = h('select', { style: 'width:auto' }, [['pending', 'معلّقة'], ['approved', 'مقبولة'], ['rejected', 'مرفوضة'], ['failed', 'فاشلة'], ['', 'الكل']].map(function (o) {
            return h('option', { value: o[0], selected: pst === o[0] }, o[1]); }));
        sel.addEventListener('change', function () { pst = sel.value; main(); });
        var r = await A('/api/admin/payments?status=' + encodeURIComponent(pst)); if (!r.ok) return;
        c.appendChild(h('div', { class: 'card row' }, [h('label', { style: 'margin:0' }, 'الحالة:'), sel, h('span', { class: 'muted' }, r.payments.length + ' طلب')]));
        r.payments.forEach(function (p) {
            var mo = h('input', { type: 'number', value: p.months, min: 1, style: 'width:80px' });
            c.appendChild(h('div', { class: 'card' }, [
                h('div', { class: 'hd' }, [h('b', null, '#' + p.id + ' — ' + p.username + ' (' + p.agency_name + ')'), H.badge(p.status, H.PLBL[p.status])]),
                h('p', null, p.plan + ' • ' + H.money(p.amount, p.currency) + ' • ' + p.method + ' • ' + H.date(p.created_at)),
                h('p', { class: 'muted' }, 'المحوِّل: ' + (p.payer || '-') + ' • المرجع: ' + (p.reference || '-') + (p.note ? ' • ' + p.note : '') + (p.reason ? ' • سبب: ' + p.reason : '')),
                h('div', { class: 'row' }, [
                    p.has_receipt ? h('button', { class: 'b2', onclick: async function () {
                        var x = await A('/api/admin/receipt?id=' + p.id); if (x.ok) H.modal('إيصال #' + p.id, h('img', { class: 'rc', src: x.receipt })); } }, '🖼️ الإيصال') : null,
                    p.status === 'pending' ? [h('label', { style: 'margin:0' }, 'شهور:'), mo,
                        h('button', { class: 'b2 okb', onclick: async function () {
                            var x = await A('/api/admin/payment', { id: p.id, action: 'approve', months: Number(mo.value) }); H.toast(x.ok ? 'تم الاعتماد وتفعيل الاشتراك ✔' : x.message, !x.ok); main(); } }, '✅ اعتماد'),
                        h('button', { class: 'b2 danger', onclick: async function () {
                            var why = prompt('سبب الرفض:'); if (why === null) return;
                            var x = await A('/api/admin/payment', { id: p.id, action: 'reject', reason: why }); H.toast(x.ok ? 'تم الرفض' : x.message, !x.ok); main(); } }, '❌ رفض')] : null
                ])
            ]));
        });
    }


    /* ---------- التحديثات: نشر إصدار + رفع الملف + إشعار المستخدمين ---------- */
    async function updView(c) {
        var r = await A('/api/admin/update'); if (!r.ok) { H.toast(r.message || 'خطأ', true); return; }
        var cur = r.current, fileInfo = { url: '', size: 0, name: '', sha: '' };
        var fmtSize = function (n) { return n ? (n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.round(n / 1024) + ' KB') : '-'; };

        /* الإصدار المنشور حالياً */
        c.appendChild(h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, '📦 الإصدار المنشور حالياً'),
            cur ? h('div', null, [
                h('div', { class: 'row' }, [H.badge('active', 'v' + cur.version), cur.mandatory ? H.badge('locked', 'إجباري') : null,
                    h('span', { class: 'muted' }, 'نُشر ' + H.date(cur.published_at) + ' • الحجم ' + fmtSize(cur.size) + (cur.min_version ? ' • أقل إصدار مسموح ' + cur.min_version : ''))]),
                h('p', { style: 'white-space:pre-line;margin:8px 0' }, cur.changelog || 'بدون ملاحظات'),
                h('div', { class: 'row' }, [h('a', { class: 'btn b2', href: cur.download_url, target: '_blank', rel: 'noopener' }, '⬇️ رابط التحميل'),
                    h('span', { class: 'muted' }, 'تم إشعار ' + r.notified + ' حساب بالبريد')])
            ]) : h('p', { class: 'muted' }, 'لم يتم نشر أي إصدار بعد (السيرفر بيرد بالإصدار الافتراضي).')]));

        /* نشر إصدار جديد */
        var ver = h('input', { placeholder: 'مثال: 1.2.0', style: 'max-width:200px' }), minv = h('input', { placeholder: 'اختياري: 1.1.0', style: 'max-width:200px' });
        var log = h('textarea', { rows: 5, placeholder: 'سطر لكل ميزة/إصلاح' });
        var mand = h('input', { type: 'checkbox', style: 'width:auto' }), notif = h('input', { type: 'checkbox', style: 'width:auto' });
        notif.checked = r.mail_ready;
        var urlIn = h('input', { placeholder: 'https://... رابط التحميل المباشر', dir: 'ltr' });
        var sha = h('input', { placeholder: 'SHA-256 (بيتحسب تلقائياً عند رفع ملف)', dir: 'ltr' });
        var fileIn = h('input', { type: 'file', accept: '.exe,.msi,.msix,.zip,.7z' });
        var prog = h('div', { class: 'muted' }), pubMsg = h('div', { class: 'msg' });

        fileIn.addEventListener('change', async function () {
            var f = fileIn.files[0]; if (!f) return;
            if (!r.blob_ready) { prog.textContent = 'رفع الملفات غير مفعّل على السيرفر (BLOB_READ_WRITE_TOKEN) — استخدم رابط تحميل خارجي.'; fileIn.value = ''; return; }
            prog.textContent = 'جاري التجهيز...'; var hashP = null;
            if (f.size <= 300 * 1048576 && window.crypto && crypto.subtle) {
                hashP = f.arrayBuffer().then(function (b) { return crypto.subtle.digest('SHA-256', b); }).then(function (d) {
                    return Array.prototype.map.call(new Uint8Array(d), function (x) { return ('0' + x.toString(16)).slice(-2); }).join(''); }).catch(function () { return ''; });
            }
            try {
                var mod = await import('https://esm.sh/@vercel/blob@2.8.0/client');
                var safe = f.name.replace(/[^\w.\-]+/g, '_');
                var blob = await mod.upload('updates/' + safe, f, { access: 'public', multipart: true, handleUploadUrl: '/api/admin/update/upload',
                    headers: { Authorization: 'Bearer ' + T },
                    onUploadProgress: function (e) { prog.textContent = 'جاري الرفع: ' + Math.round(e.percentage) + '%'; } });
                fileInfo = { url: blob.url, size: f.size, name: f.name, sha: '' };
                urlIn.value = blob.url;
                if (hashP) { fileInfo.sha = await hashP; sha.value = fileInfo.sha; }
                prog.textContent = '✔ تم رفع الملف (' + fmtSize(f.size) + ')';
            } catch (e) { prog.textContent = '❌ فشل الرفع: ' + (e && e.message || e); }
        });

        async function notifyAll(version, reset) {
            var total = 0, failed = 0, rr;
            for (var i = 0; i < 200; i++) {
                rr = await A('/api/admin/update/notify', { version: version, reset: i === 0 && !!reset });
                if (!rr.ok) { H.toast(rr.message || 'فشل الإرسال', true); break; }
                total += rr.sent; failed += rr.failed; pubMsg.textContent = 'جاري إرسال الإشعارات... تم ' + total + ' • متبقي ' + rr.remaining;
                if (!rr.remaining || (rr.sent === 0)) break;
            }
            pubMsg.textContent = 'تم إرسال ' + total + ' إشعار' + (failed ? ' • فشل ' + failed : '');
            H.toast(pubMsg.textContent, failed > 0); main();
        }

        c.appendChild(h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, '🚀 نشر إصدار جديد'),
            h('div', { class: 'row' }, [H.field('رقم الإصدار', ver), H.field('أقل إصدار مسموح (اختياري)', minv)]),
            H.field('ما الجديد؟ (سجل التغييرات)', log),
            H.field('ملف التحديث (exe / msi / zip)', fileIn), prog,
            H.field('أو رابط تحميل مباشر', urlIn), H.field('SHA-256 (اختياري)', sha),
            h('label', { style: 'display:flex;gap:8px;align-items:center' }, [mand, 'تحديث إجباري (البرنامج لازم يتحدث للاستمرار)']),
            h('label', { style: 'display:flex;gap:8px;align-items:center' }, [notif, 'أرسل إشعار بالبريد لكل المشتركين (نشط/تجريبي) بعد النشر']),
            r.mail_ready ? null : h('p', { class: 'muted' }, '⚠️ خدمة البريد غير مفعّلة، الإشعار هيظهر داخل البرنامج فقط.'),
            h('button', { onclick: async function () {
                var body = { action: 'publish', version: ver.value.trim(), min_version: minv.value.trim(), changelog: log.value, mandatory: mand.checked,
                    download_url: urlIn.value.trim(), sha256: sha.value.trim(), size: urlIn.value.trim() === fileInfo.url ? fileInfo.size : 0, file_name: urlIn.value.trim() === fileInfo.url ? fileInfo.name : '' };
                if (!body.version || !body.download_url) { H.toast('رقم الإصدار ورابط التحميل مطلوبين', true); return; }
                if (!confirm('نشر الإصدار ' + body.version + (body.mandatory ? ' كتحديث إجباري' : '') + ' لكل المستخدمين؟')) return;
                var x = await A('/api/admin/update', body);
                if (x.need_confirm && confirm(x.message + '\nتنشره كدة؟')) { body.allow_downgrade = true; x = await A('/api/admin/update', body); }
                if (!x.ok) { H.toast(x.message || 'فشل النشر', true); return; }
                H.toast('تم نشر الإصدار ✔');
                if (notif.checked && r.mail_ready) await notifyAll(body.version, false); else main();
            } }, '🚀 نشر الإصدار'), pubMsg]));

        /* إعادة إرسال الإشعار */
        if (cur && r.mail_ready) c.appendChild(h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, '🔔 إشعارات الإصدار ' + cur.version),
            h('p', { class: 'muted' }, 'بيتبعت بالدفعات لمن لم يصله فقط، فتقدر تكمل لو توقف.'),
            h('div', { class: 'row' }, [h('button', { class: 'b2', onclick: function () { notifyAll(cur.version, false); } }, '📨 إرسال لمن لم يصله'),
                h('button', { class: 'b2 danger', onclick: function () { if (confirm('إعادة الإرسال للجميع؟')) notifyAll(cur.version, true); } }, '🔁 إعادة الإرسال للجميع')])]));

        /* السجل */
        c.appendChild(h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, '🗂️ الإصدارات السابقة'),
            r.history.length ? h('div', { style: 'overflow-x:auto' }, h('table', { class: 't' }, [h('tr', null, ['الإصدار', 'التاريخ', 'الحجم', 'إجباري', ''].map(function (t) { return h('th', null, t); }))]
                .concat(r.history.map(function (x) {
                    var isCur = cur && cur.version === x.version;
                    return h('tr', null, [h('td', null, 'v' + x.version + (isCur ? ' ✅' : '')), h('td', null, H.date(x.published_at)), h('td', null, fmtSize(x.size)), h('td', null, x.mandatory ? 'نعم' : '-'),
                        h('td', null, isCur ? '' : [h('button', { class: 'b2', onclick: async function () {
                            if (!confirm('تفعيل الإصدار ' + x.version + ' كإصدار حالي؟')) return;
                            var y = await A('/api/admin/update', { action: 'activate', version: x.version }); H.toast(y.ok ? 'تم ✔' : y.message, !y.ok); main(); } }, 'تفعيل'),
                            h('button', { class: 'b2 danger', onclick: async function () {
                                if (!confirm('حذف سجل الإصدار ' + x.version + '؟ (الملف نفسه مش بيتمسح)')) return;
                                var y = await A('/api/admin/update', { action: 'delete', version: x.version }); H.toast(y.ok ? 'تم ✔' : y.message, !y.ok); main(); } }, 'حذف')])]);
                })))) : h('p', { class: 'muted' }, 'لا يوجد.')]));
    }

    async function setView(c) {
        var r = await A('/api/admin/settings'); if (!r.ok) return;
        var S = r.settings, I = {};
        function inp(id, label, val, type) { I[id] = h('input', { type: type || 'text', value: val == null ? '' : val }); I[id].value = val == null ? '' : val; return H.field(label, I[id]); }
        function chk(id, label, val) { I[id] = h('input', { type: 'checkbox', style: 'width:auto' }); I[id].checked = !!val; return h('label', { style: 'display:flex;gap:8px;align-items:center' }, [I[id], label]); }
        var planBlocks = ['monthly', 'semi', 'yearly'].map(function (k) {
            var p = S.plans[k];
            return h('div', { class: 'card' }, [h('h4', { style: 'margin-top:0' }, 'باقة: ' + k),
                chk('p_' + k + '_on', 'مفعّلة', p.enabled), inp('p_' + k + '_label', 'الاسم', p.label), inp('p_' + k + '_months', 'عدد الشهور', p.months, 'number'), inp('p_' + k + '_price', 'السعر', p.price, 'number')]);
        });
        var mBlocks = ['instapay', 'vodafone', 'bank'].map(function (k) {
            var m = S.methods[k];
            return h('div', { class: 'card' }, [h('h4', { style: 'margin-top:0' }, m.label), chk('m_' + k + '_on', 'مفعّلة', m.enabled), inp('m_' + k + '_d', 'البيانات اللي هتظهر للعميل (رقم/حساب)', m.details)]);
        });
        c.appendChild(h('div', null, [
            h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, 'بيانات الشركة'), inp('company', 'اسم الشركة (يظهر على زر الواتس)', S.company_name),
                inp('whatsapp', 'رقم الواتس اب (بصيغة دولية بدون +، مثال 201000000000)', S.whatsapp), inp('currency', 'العملة', S.currency),
                inp('trial', 'أيام الفترة التجريبية للحسابات الجديدة', S.trial_days, 'number'), inp('grace', 'أيام السماح بعد الانتهاء', S.grace_days, 'number')]),
            h('div', { class: 'grid' }, planBlocks), h('div', { class: 'grid' }, mBlocks),
            h('div', { class: 'card' }, [h('h4', { style: 'margin-top:0' }, 'الدفع بالكارت (Paymob)'), chk('card_on', 'مفعّل', S.methods.card.pref),
                h('p', { class: 'muted' }, r.card_ready ? '✔ بيانات Paymob مضبوطة في Vercel.' : '⚠️ لازم تضيف PAYMOB_API_KEY و PAYMOB_INTEGRATION_ID و PAYMOB_IFRAME_ID و PAYMOB_HMAC في Vercel.')]),
            h('button', { onclick: async function () {
                var s = { company_name: I.company.value, whatsapp: I.whatsapp.value, currency: I.currency.value, trial_days: Number(I.trial.value), grace_days: Number(I.grace.value), plans: {}, methods: {} };
                ['monthly', 'semi', 'yearly'].forEach(function (k) { s.plans[k] = { enabled: I['p_' + k + '_on'].checked, label: I['p_' + k + '_label'].value, months: Number(I['p_' + k + '_months'].value), price: Number(I['p_' + k + '_price'].value) }; });
                ['instapay', 'vodafone', 'bank'].forEach(function (k) { s.methods[k] = { enabled: I['m_' + k + '_on'].checked, details: I['m_' + k + '_d'].value }; });
                s.methods.card = { enabled: I.card_on.checked };
                var x = await A('/api/admin/settings', { settings: s }); H.toast(x.ok ? 'تم حفظ الإعدادات ✔' : x.message, !x.ok);
            } }, '💾 حفظ الإعدادات')
        ]));
    }

    async function logView(c) {
        var r = await A('/api/admin/audit'); if (!r.ok) return;
        c.appendChild(h('div', { class: 'card', style: 'overflow-x:auto' }, h('table', { class: 't' }, r.items.map(function (x) {
            return h('tr', null, [h('td', null, String(x.at).replace('T', ' ').slice(0, 19)), h('td', null, x.actor), h('td', null, x.action), h('td', null, x.target || ''), h('td', null, x.detail || '')]);
        }))));
    }

    function bakView(c) {
        var file = h('input', { type: 'file', accept: '.json' });
        c.appendChild(h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, '💾 نسخة احتياطية'),
            h('p', { class: 'muted' }, 'تحميل ملف فيه الحسابات والاشتراكات والمدفوعات والإعدادات (يحتوي على بيانات حساسة، احفظه في مكان آمن).'),
            h('button', { onclick: async function () {
                var r = await fetch('/api/admin/export', { headers: { Authorization: 'Bearer ' + T } });
                if (!r.ok) { H.toast('فشل التحميل', true); return; }
                var b = await r.blob(), a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = 'mizan-backup-' + new Date().toISOString().slice(0, 10) + '.json'; a.click();
            } }, '⬇️ تحميل النسخة')]));
        c.appendChild(h('div', { class: 'card' }, [h('h3', { style: 'margin-top:0' }, '♻️ استرجاع'),
            h('p', { class: 'muted' }, 'بيضيف الحسابات الناقصة فقط ولا يكتب فوق الموجود.'), file,
            h('button', { onclick: async function () {
                if (!file.files[0]) return; var txt = await file.files[0].text(), j;
                try { j = JSON.parse(txt); } catch (e) { H.toast('ملف غير صالح', true); return; }
                var x = await A('/api/admin/import', j); H.toast(x.ok ? 'تم: ' + x.added + ' سجل' : x.message, !x.ok);
            } }, 'رفع واسترجاع')]));
    }

    T ? A('/api/admin/overview').then(function (r) { r.ok ? main() : loginView(); }) : loginView();
}

/* ------------------------------------------------------------------ */
/* نسيت كلمة المرور */
function forgotPage(H) {
    var h = H.h, root = document.getElementById('app');
    var id = h('input', { placeholder: 'اسم المستخدم أو البريد' }), msg = h('div', { class: 'msg' });
    var code = h('input', { placeholder: 'كود من 6 أرقام', inputmode: 'numeric' }), pw = h('input', { type: 'password', placeholder: 'كلمة المرور الجديدة (8 أحرف+)' });
    var step2 = h('div', { style: 'display:none' }, [H.field('الكود', code), H.field('كلمة المرور الجديدة', pw),
        h('button', { onclick: async function () {
            var r = await H.api('/api/reset', { body: { identity: id.value, code: code.value, password: pw.value } });
            if (r.ok) { H.toast('تم تغيير كلمة المرور ✔'); setTimeout(function () { location.href = '/login'; }, 1200); } else msg.textContent = r.message || 'خطأ';
        } }, 'تغيير كلمة المرور')]);
    root.appendChild(h('div', { class: 'card', style: 'max-width:440px;margin:40px auto' }, [h('h2', null, '🔑 استرجاع كلمة المرور'), H.field('الحساب', id),
        h('button', { onclick: async function () {
            var r = await H.api('/api/forgot', { body: { identity: id.value } });
            msg.textContent = r.message || ''; if (r.ok) step2.style.display = 'block';
        } }, 'إرسال الكود'), step2, msg, h('a', { class: 'btn small', href: '/login' }, 'رجوع لتسجيل الدخول')]));
}

/* بناء نص السكربت اللي يتبعت للمتصفح */
function build(cfg, page) {
    return 'window.__CFG=' + JSON.stringify(cfg || {}).replace(/</g, '\\u003c') +
        ';var H=(' + helpers.toString() + ')();var mountPay=' + payPanel.toString() +
        ';(' + page.toString() + ')(H,mountPay);';
}

module.exports = { CSS, build, payPage, accountPage, adminPage, forgotPage };
