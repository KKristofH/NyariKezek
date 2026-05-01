'use strict';
require('dotenv').config();

const express   = require('express');
const rateLimit = require('express-rate-limit');
const path      = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

// ── Biztonsági fejlécek ──────────────────────────────────────────
app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

// Érzékeny fájlok védelme
app.use((req, res, next) => {
    const blocked = new Set(['server.js', 'package.json', 'package-lock.json', '.env']);
    if (blocked.has(path.basename(req.path))) return res.status(403).end();
    next();
});

app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname)));

// ── XSS escape ───────────────────────────────────────────────────
function esc(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

// ── Rate limit: max 5 üzenet / 15 perc ──────────────────────────
const contactLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Túl sok kérés, próbáld újra 15 perc múlva.' }
});

// ── POST /api/contact ────────────────────────────────────────────
app.post('/api/contact', contactLimiter, async (req, res) => {
    const { from_name, from_email, phone, message } = req.body;
    const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!from_name || !from_email || !message)
        return res.status(400).json({ error: 'Név, e-mail és üzenet kötelező.' });
    if (!EMAIL_RE.test(from_email))
        return res.status(400).json({ error: 'Érvénytelen e-mail cím.' });

    if (!process.env.RESEND_API_KEY || !process.env.NOTIFY_EMAIL) {
        console.error('Resend nincs konfigurálva (.env)');
        return res.status(500).json({ error: 'Szerver konfiguráció hiányzik.' });
    }

    const recipients = process.env.NOTIFY_EMAIL.split(',').map(e => e.trim());
    const safeName   = esc(from_name);
    const safeEmail  = esc(from_email);
    const safePhone  = esc(phone || '–');
    const safeMsg    = esc(message).replace(/\n/g, '<br>');

    try {
        const response = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                from:     'NyáriKezek Weboldal <onboarding@resend.dev>',
                to:       recipients,
                reply_to: from_email,
                subject:  `Új üzenet a weboldalról – ${safeName}`,
                html: `
                    <div style="font-family:Inter,Arial,sans-serif;max-width:560px;margin:0 auto;border:1px solid #e2e8f0;border-top:4px solid #2f7d4f">
                        <div style="background:#2f7d4f;padding:20px 28px">
                            <p style="color:#fff;font-weight:900;font-size:18px;margin:0">NyáriKezek</p>
                            <p style="color:#bff0c3;font-size:13px;margin:4px 0 0">Új kapcsolatfelvétel a weboldalról</p>
                        </div>
                        <div style="padding:28px">
                            <table style="width:100%;border-collapse:collapse">
                                <tr><td style="font-size:11px;font-weight:700;text-transform:uppercase;color:#64748b;width:35%;padding:8px 16px 8px 0;border-bottom:1px solid #e2e8f0;vertical-align:top">Név</td><td style="font-size:14px;color:#1e293b;padding:8px 0;border-bottom:1px solid #e2e8f0">${safeName}</td></tr>
                                <tr><td style="font-size:11px;font-weight:700;text-transform:uppercase;color:#64748b;padding:8px 16px 8px 0;border-bottom:1px solid #e2e8f0;vertical-align:top">E-mail</td><td style="font-size:14px;color:#1e293b;padding:8px 0;border-bottom:1px solid #e2e8f0"><a href="mailto:${safeEmail}" style="color:#2f7d4f">${safeEmail}</a></td></tr>
                                <tr><td style="font-size:11px;font-weight:700;text-transform:uppercase;color:#64748b;padding:8px 16px 8px 0;border-bottom:1px solid #e2e8f0;vertical-align:top">Telefon</td><td style="font-size:14px;color:#1e293b;padding:8px 0;border-bottom:1px solid #e2e8f0">${safePhone}</td></tr>
                            </table>
                            <div style="margin-top:20px;padding:16px;background:#f8fafc;border-left:3px solid #2f7d4f">
                                <p style="font-size:11px;font-weight:700;text-transform:uppercase;color:#64748b;margin:0 0 8px">Üzenet</p>
                                <p style="font-size:14px;color:#334155;margin:0;line-height:1.6">${safeMsg}</p>
                            </div>
                        </div>
                        <div style="padding:14px 28px;background:#f8fafc;border-top:1px solid #e2e8f0">
                            <p style="font-size:11px;color:#94a3b8;margin:0">Automatikus értesítés · NyáriKezek weboldal</p>
                        </div>
                    </div>`
            }),
        });

        if (!response.ok) {
            const err = await response.json();
            console.error('Resend hiba:', err);
            return res.status(500).json({ error: 'E-mail küldési hiba.' });
        }

        console.log(`✉️  E-mail elküldve → ${recipients.join(', ')} (${safeName})`);
        res.json({ success: true });

    } catch (err) {
        console.error('Hálózati hiba:', err.message);
        res.status(500).json({ error: 'E-mail küldési hiba.' });
    }
});

// ── Indítás ──────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════╗
║       NyáriKezek – Backend szerver       ║
╠══════════════════════════════════════════╣
║  Weboldal  →  http://localhost:${PORT}       ║
╚══════════════════════════════════════════╝`);
    if (!process.env.RESEND_API_KEY) {
        console.warn('\n⚠️  Resend API kulcs hiányzik! Töltsd ki a .env fájlt.');
    } else {
        console.log(`\n✉️  Értesítési cím: ${process.env.NOTIFY_EMAIL}`);
    }
});
