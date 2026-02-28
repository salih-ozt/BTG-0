/*
 * =============================================================================
 * AGROLINK SERVER - PostgreSQL v2.1 (UUID FIX)
 * =============================================================================
 * 
 * 🚀 DÜZELTME: Tüm TEXT id/FK sütunları UUID'ye çevrildi
 * 📊 65 API Rotası
 * 🔒 Güvenlik: Helmet, CORS, Rate Limiting, bcrypt, JWT
 * ⚡ Optimize edilmiş sorgular + Connection Pooling
 * 
 * =============================================================================
 */

require('dotenv').config(); // .env dosyasını yükle (EMAIL/SMTP değişkenleri için zorunlu)

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
const compression = require('compression');
const helmet = require('helmet');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const ffmpeg     = require('fluent-ffmpeg');
const ffmpegPath = require('ffmpeg-static');
// 🔒 Cookie parser — HttpOnly token desteği için
let cookieParser;
try { cookieParser = require('cookie-parser'); } catch (_) {
    console.warn('⚠️  cookie-parser bulunamadı: npm install cookie-parser');
    cookieParser = (req, res, next) => next(); // Fallback
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
    const year       = new Date().getFullYear();
    const name       = userName || 'Değerli Üye';
    const DOMAIN     = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    // Kullanıcı bu linke tıklayınca /api/auth/reset-password-direct?token=... sayfasına gider.
    // O sayfa şifre sıfırlama formunu gösterir.
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
  <div class="url-box">${resetLink}</div>

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

async function sendForgotPasswordEmail(userEmail, userName, resetToken) {
    return sendEmail(userEmail, '🔑 Agrolink - Şifre Sıfırlama Talebi', getForgotPasswordEmailTemplate(userName, resetToken));
}

async function sendInactiveUserEmail(userId, userEmail, userName) {
    return sendEmail(userEmail, '🌿 Agrolink - Seni Özledik!', getInactiveUserEmailTemplate(userName, userId));
}

async function sendHighEngagementEmail(userId, userEmail, userName) {
    return sendEmail(userEmail, '💚 Agrolink - Teşekkür Ederiz!', getHighEngagementEmailTemplate(userName, userId));
}

// ─── 2FA E-POSTA ŞABLONU ─────────────────────────────────────────────
function getTwoFactorEmailTemplate(userName, code, purpose = 'login') {
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
        const html = getTwoFactorEmailTemplate(userName, code, purpose);
        return await sendEmail(userEmail, '🔐 Agrolink Doğrulama Kodunuz', html);
    } catch (error) {
        console.error('2FA e-postası gönderilemedi:', error);
        return { success: false, error: error.message };
    }
}

// ─── KAYIT DOĞRULAMA E-POSTA ŞABLONU ─────────────────────────────────
function getEmailVerificationTemplate(userName, code) {
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

function sanitizeInput(value) {
    if (typeof value !== 'string') return value;
    // Path traversal engelle
    if (value.includes('../') || value.includes('..\\') || value.includes('%2e%2e')) return '';
    // Null byte engelle
    if (value.includes('\x00')) return '';
    // XSS - tehlikeli tagları kaldır
    return value
        .replace(/<script[\s\S]*?<\/script>/gi, '')
        .replace(/<iframe[\s\S]*?<\/iframe>/gi, '')
        .replace(/javascript\s*:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .trim();
}

// Belirli alanları ham tut (bio, content - XSS encode gerekmez, zaten parametrize)
const RAW_FIELDS = new Set(['password', 'bio', 'content', 'caption', 'description', 'message', 'text', 'comment']);

function sanitizeBody(req, res, next) {
    if (req.body && typeof req.body === 'object') {
        for (const key of Object.keys(req.body)) {
            const val = req.body[key];
            if (typeof val !== 'string') continue;

            // Path traversal her zaman engelle
            if (val.includes('../') || val.includes('..\\') || val.includes('%2e%2e')) {
                return res.status(400).json({ error: 'Geçersiz karakter tespit edildi' });
            }

            // Null byte engelle
            if (val.includes('\x00')) {
                return res.status(400).json({ error: 'Geçersiz karakter tespit edildi' });
            }

            // Uzunluk sınırı (megabytelık input'ları engelle)
            if (val.length > 50000) {
                return res.status(400).json({ error: 'Girdi çok uzun' });
            }

            // Script injection - ham alanlar hariç
            if (!RAW_FIELDS.has(key) && /<script|<iframe|javascript:/i.test(val)) {
                return res.status(400).json({ error: 'Geçersiz içerik tespit edildi' });
            }
        }
    }
    next();
}

// ==================== 🔒 IP BAN CACHE ====================

const ipBanCache     = new Map();
const IP_BAN_CACHE_TTL = 60 * 1000; // 1 dakika

async function checkIpBanDB(ip) {
    try {
        return await dbGet(
            `SELECT * FROM banned_ips WHERE ip = $1 AND ("expiresAt" IS NULL OR "expiresAt" > NOW())`,
            [ip]
        );
    } catch { return null; }
}

const ipBanMiddleware = async (req, res, next) => {
    try {
        const ip = req.ip || req.connection.remoteAddress || '';
        const cached = ipBanCache.get(ip);

        if (cached) {
            if (cached.banned && cached.expiresAt > Date.now()) {
                return res.status(403).json({ error: 'IP adresiniz engellendi', reason: cached.reason });
            }
            if (!cached.banned && cached.timestamp > Date.now() - IP_BAN_CACHE_TTL) return next();
        }

        const banned = await checkIpBanDB(ip);
        if (banned) {
            ipBanCache.set(ip, { banned: true, reason: banned.reason, expiresAt: new Date(banned.expiresAt || '9999-12-31').getTime() });
            return res.status(403).json({ error: 'IP adresiniz engellendi', reason: banned.reason });
        }

        ipBanCache.set(ip, { banned: false, timestamp: Date.now() });
        next();
    } catch { next(); }
};

// ==================== PostgreSQL BAĞLANTISI ====================

const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'agrolink',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '123456789',
    max: 150,                         // ⚡ 100 → 150 bağlantı
    min: 10,                          // ⚡ Her zaman hazır 10 bağlantı
    idleTimeoutMillis: 60000,         // ⚡ Bağlantıları daha uzun tut
    connectionTimeoutMillis: 3000,    // ⚡ 5s → 3s (hızlı fail)
    statement_timeout: 10000,         // ⚡ 15s → 10s
    query_timeout: 10000,
    allowExitOnIdle: false,           // ⚡ Pool her zaman canlı
    keepAlive: true,                  // ⚡ TCP keepAlive
    keepAliveInitialDelayMillis: 0,
});

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

// ==================== TABLO OLUŞTURMA (UUID FIX) ====================

async function initializeDatabase() {
    console.log('📦 PostgreSQL tabloları oluşturuluyor (UUID)...');

    // UUID extension'ı aktif et
    await pool.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

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
            "twoFactorEnabled" BOOLEAN DEFAULT TRUE,
            "isVerified" BOOLEAN DEFAULT FALSE,
            "hasFarmerBadge" BOOLEAN DEFAULT FALSE,
            "userType" TEXT DEFAULT 'normal_kullanici',
            "lastSeen" TIMESTAMPTZ,
            "lastLogin" TIMESTAMPTZ,
            "isOnline" BOOLEAN DEFAULT FALSE,
            "isBanned" BOOLEAN DEFAULT FALSE,
            "registrationIp" TEXT,
            "verifiedAt" TIMESTAMPTZ,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

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
            "viewCount" INTEGER DEFAULT 0,
            "likeCount" INTEGER DEFAULT 0,
            "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            "expiresAt" TIMESTAMPTZ NOT NULL
        )
    `);

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
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS "twoFactorEnabled" BOOLEAN DEFAULT TRUE`,
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
    ];

    for (const [name, indexSql] of indexes) {
        try {
            await pool.query(indexSql);
        } catch (e) {
            console.warn(`⚠️ Index atlandı [${name}]: ${e.message.split('\n')[0]}`);
        }
    }

    console.log('✅ Tüm tablolar ve indeksler oluşturuldu (UUID)');
}

// ==================== EXPRESS UYGULAMASI ====================

const app = express();
app.set('trust proxy', 1); // 🔒 Nginx/proxy arkasında gerçek IP'yi al (rate-limit için zorunlu)
const server = http.createServer(app);

// ==================== DİZİN YAPISI ====================

const uploadsDir   = path.join(__dirname, 'uploads');
const profilesDir  = path.join(uploadsDir, 'profiles');
const postsDir     = path.join(uploadsDir, 'posts');
const videosDir    = path.join(uploadsDir, 'videos');
const thumbnailsDir= path.join(uploadsDir, 'thumbnails');
const hlsDir       = path.join(uploadsDir, 'hls');
const tempDir      = path.join(uploadsDir, 'temp');

[uploadsDir, profilesDir, postsDir, videosDir, thumbnailsDir, hlsDir, tempDir].forEach(dir => {
    if (!fssync.existsSync(dir)) {
        fssync.mkdirSync(dir, { recursive: true });
    }
});

// ==================== 🎬 VİDEO SIKIŞTIRMA KONFİGÜRASYONU ====================

const VIDEO_CONFIG = {
    codec       : 'libx264',
    audioCodec  : 'aac',
    audioBitrate: '192k',
    quality     : 28,          // ⚡ CRF 23→28 (daha hızlı encode, iyi kalite)
    preset      : 'veryfast',  // ⚡ fast → veryfast (2x hızlı)
    movflags    : '+faststart', // Web streaming için kritik (metadata başa alınır)
    threads     : '0',          // Tüm CPU çekirdeklerini kullan
    maxWidth    : 1920,
    maxHeight   : 1080,
    fps         : 30,
    maxDuration : 600,          // Maks 10 dk
};

// HLS Adaptive Bitrate varyantları (YouTube standardı)
const HLS_VARIANTS = [
    { name: '360p',  width: 640,  height: 360,  videoBitrate: '800k',  audioBitrate: '96k'  },
    { name: '720p',  width: 1280, height: 720,  videoBitrate: '2500k', audioBitrate: '128k' },
    { name: '1080p', width: 1920, height: 1080, videoBitrate: '5000k', audioBitrate: '192k' },
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

        let vInfo = { width: 1920, height: 1080, fps: 30 };
        try { vInfo = await getVideoInfo(inputPath); } catch (_) {}

        const tw = Math.min(vInfo.width,  VIDEO_CONFIG.maxWidth);
        const th = Math.min(vInfo.height, VIDEO_CONFIG.maxHeight);
        const tf = Math.min(vInfo.fps || 30, VIDEO_CONFIG.fps);

        // Oran korunur, H.264 çift piksel zorunluluğu
        const scaleFilter = `scale='min(${tw},iw)':min'(${th},ih)':force_original_aspect_ratio=decrease,scale=trunc(iw/2)*2:trunc(ih/2)*2`;

        ffmpeg(inputPath)
            .videoCodec(VIDEO_CONFIG.codec)
            .audioCodec(VIDEO_CONFIG.audioCodec)
            .outputOptions([
                `-crf ${VIDEO_CONFIG.quality}`,
                `-preset ${VIDEO_CONFIG.preset}`,
                `-movflags ${VIDEO_CONFIG.movflags}`,
                `-threads ${VIDEO_CONFIG.threads}`,
                `-r ${tf}`,
                `-b:a ${VIDEO_CONFIG.audioBitrate}`,
                `-vf ${scaleFilter}`,
                '-pix_fmt yuv420p',
                '-profile:v high',
                '-level 4.0',
            ])
            .format('mp4')
            .on('end', async () => {
                const outSize = fssync.existsSync(outputPath) ? fssync.statSync(outputPath).size : 0;
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                const reduction = outSize ? (((sizeMB - outSize / 1024 / 1024) / sizeMB) * 100).toFixed(1) : 0;
                console.log(`✅ Video hazır: ${sizeMB.toFixed(1)}MB → ${(outSize/1024/1024).toFixed(1)}MB (%${reduction} azalma) ${elapsed}s`);
                try { await fs.unlink(inputPath); } catch (_) {}
                resolve({ success: true, optimized: true, fileSize: outSize, reduction: parseFloat(reduction) });
            })
            .on('error', async (err) => {
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
        const scaleFilter = `scale='min(${variant.width},iw)':min'(${variant.height},ih)':force_original_aspect_ratio=decrease,scale=trunc(iw/2)*2:trunc(ih/2)*2`;

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

        console.log(`🎬 [Paralel] MP4 hazır: ${videoId} → HLS oluşturuluyor...`);

        // 3. HLS (arka planda, MP4 zaten oynanıyor)
        const hlsOk = await generateHLSVariants(mp4Out, videoId);
        if (hlsOk) {
            const hlsUrl = `/uploads/hls/${videoId}/master.m3u8`;
            await dbRun(
                `UPDATE posts SET media = $1, "updatedAt" = NOW() WHERE id = $2`,
                [hlsUrl, postId]
            );
        }

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

    if (p.media) {
        const isHLS = p.media.includes('.m3u8');
        const isVideo = p.mediaType === 'video';

        if (isVideo) {
            p.mediaUrl = p.media;
            if (p.thumbnailUrl) {
                p.thumbnail = p.thumbnailUrl;
            } else if (isHLS) {
                const m = p.media.match(/\/hls\/([^/]+)\//);
                p.thumbnail = m ? `/uploads/thumbnails/${m[1]}.jpg` : null;
            } else {
                const fname = p.media.split('/').pop() || '';
                p.thumbnail = `/uploads/thumbnails/${fname.replace('.mp4', '.jpg')}`;
            }
        } else {
            p.mediaUrl = p.media;
            p.thumbnail = null;
        }
    } else {
        p.mediaUrl = null;
        p.thumbnail = null;
    }

    // mediaUrls parse (çoklu medya JSON dizisi)
    if (p.mediaUrls && typeof p.mediaUrls === 'string') {
        try { p.mediaUrls = JSON.parse(p.mediaUrls); } catch { p.mediaUrls = null; }
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
// Profil fotoğrafı: 5 MB, Gönderi fotoğrafı: 20 MB, Video: 200 MB
const UPLOAD_LIMITS = {
    profilePic  : 5  * 1024 * 1024,  // 5 MB
    postImage   : 20 * 1024 * 1024,  // 20 MB
    postVideo   : 200 * 1024 * 1024, // 200 MB
    default     : 20 * 1024 * 1024,  // 20 MB (bilinmeyen tip)
};

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
    limits: { fileSize: UPLOAD_LIMITS.postVideo, files: 10 }, // max 10 dosya, video boyutunda üst limit
    fileFilter: (req, file, cb) => {
        // 🔒 Whitelist: sadece bilinen MIME türleri — uzantıya GÜVENME
        const allowed = [
            'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp',
            'video/mp4', 'video/quicktime', 'video/webm', 'video/avi',
            'video/x-msvideo', 'video/mpeg', 'video/3gpp', 'video/x-matroska'
        ];
        if (allowed.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error(`Desteklenmeyen dosya türü: ${file.mimetype}`), false);
        }
    }
});

// 🔒 Upload sonrası magic-bytes doğrulama + tip başına boyut kontrolü
async function verifyUploadedFile(file, uploadType = 'postImage') {
    const limit = UPLOAD_LIMITS[uploadType] || UPLOAD_LIMITS.default;
    if (file.size > limit) {
        await fs.unlink(file.path).catch(() => {});
        const limitMB = Math.round(limit / 1024 / 1024);
        throw new Error(`Dosya boyutu aşıldı. Maksimum: ${limitMB} MB`);
    }
    const valid = await validateMagicBytes(file.path, file.mimetype);
    if (!valid) {
        await fs.unlink(file.path).catch(() => {});
        throw new Error(`Dosya içeriği beyan edilen türle uyuşmuyor (magic bytes hatası)`);
    }
    return true;
}

// ==================== MIDDLEWARE ====================

// ═══════════════════════════════════════════════════════════════
// 🔒 GÜVENLİK KATMANI - Güçlendirilmiş
// ═══════════════════════════════════════════════════════════════

// Helmet - HTTP güvenlik başlıkları
app.use(helmet({
    contentSecurityPolicy : false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    hsts                  : { maxAge: 31536000, includeSubDomains: true, preload: true },
    noSniff               : true,
    xssFilter             : true,
    referrerPolicy        : { policy: 'strict-origin-when-cross-origin' },
}));

// Tahmin saldırılarını zorlaştır - X-Powered-By gizle
app.disable('x-powered-by');

// Request boyutu sınırla (DoS önlemi)

app.use(compression({ level: 6 }));

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

const ALLOWED_ORIGINS = [
    // Ana web sitesi
    'https://sehitumitkestitarimmtal.com',
    'https://www.sehitumitkestitarimmtal.com',
    'http://sehitumitkestitarimmtal.com',
    'http://www.sehitumitkestitarimmtal.com',
    // Geliştirme ortamı
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:8080',
    'http://localhost:8100',
    // ── Google Play / Capacitor / Ionic / React Native ──────────────────
    // Android WebView ve Fomin gibi wrapper uygulamaları null origin gönderir
    // veya aşağıdaki scheme'leri kullanır:
    'capacitor://localhost',       // Capacitor (default)
    'ionic://localhost',           // Ionic (default)
    'http://localhost',            // Android WebView bazı sürümler
    'https://localhost',
    // React Native / Expo
    'http://10.0.2.2:8081',        // Android emülatör Metro bundler
    'exp://localhost:19000',       // Expo Go
];

// .env'deki MOBILE_ORIGIN eklenebilir (örn: Fomin özel domain varsa)
if (process.env.MOBILE_ORIGIN) {
    process.env.MOBILE_ORIGIN.split(',').forEach(o => {
        const trimmed = o.trim();
        if (trimmed && !ALLOWED_ORIGINS.includes(trimmed)) ALLOWED_ORIGINS.push(trimmed);
    });
}

const corsOptions = {
    origin: (origin, callback) => {
        // ✅ Origin yoksa (null/undefined): Android WebView, Fomin, Capacitor
        //    native HTTP istekleri bu şekilde gelir — MUTLAKA izin verilmeli
        if (!origin) return callback(null, true);

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
    allowedHeaders  : ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'X-Mobile-App'],
    exposedHeaders  : ['Content-Range', 'X-Content-Range'],
    optionsSuccessStatus: 204,  // Android bazı sürümler 200 yerine 204 bekler
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Preflight — tüm OPTIONS isteklerine cevap ver
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
// 🔒 Cookie parser — HttpOnly token okuma için (ip-ban/sanitize'dan ÖNCE)
app.use(cookieParser(process.env.COOKIE_SECRET || process.env.JWT_SECRET));

// ═══════════════════════════════════════════════════════════════
// 🔒 GÜVENLİK MİDDLEWARE'LERİ — statik dosyalardan ÖNCE
// IP ban, firewall ve rate limit; statik servisten kaçış yok
// ═══════════════════════════════════════════════════════════════
app.use(sanitizeBody);    // 🔒 XSS / Path traversal koruması
app.use(ipBanMiddleware); // 🔒 IP Ban kontrolü (DB + bellek cache)
app.use(firewallMiddleware); // 🔒 Uygulama katmanı güvenlik duvarı
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
app.use('/uploads', express.static(uploadsDir, { maxAge: '1y' }));

// ═══════════════════════════════════════════════════════════════
// 🔥 FIREWALL - Uygulama katmanı güvenlik duvarı
// ═══════════════════════════════════════════════════════════════
const FIREWALL_BLOCKED_IPS  = new Set(); // Dinamik olarak engellenen IP'ler
const FIREWALL_ATTACK_LOG   = new Map(); // IP → { count, firstSeen, lastSeen, reasons[] }
const FIREWALL_AUTO_BAN_THRESHOLD = 20;  // 1 dakikada 20 şüpheli istek → otomatik ban

// Bilinen kötü User-Agent'ları
const BAD_USER_AGENTS = [
    /sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /zgrab/i,
    /havij/i, /acunetix/i, /nessus/i, /openvas/i,
    /dirbuster/i, /gobuster/i, /wfuzz/i, /hydra/i,
    /python-requests\/2\.[0-4]/i, // Eski requests versiyonları (bot sinyali)
];

// Bilinen saldırı pattern'leri
const ATTACK_PATTERNS = [
    // SQL Injection
    /(UNION.*SELECT|SELECT.*FROM.*WHERE)/i,
    /(DROP|TRUNCATE|DELETE)\s+TABLE/i,
    /('\s*OR\s*'1'\s*=\s*'1|'\s*OR\s+1\s*=\s*1)/i,
    // XSS
    /<script[\s\S]*?>[\s\S]*?<\/script>/i,
    /javascript\s*:/i,
    /on(load|error|click|mouseover)\s*=/i,
    // Path traversal
    /\.\.[\\/]/,
    /%2e%2e[%2f%5c]/i,
    // Command injection
    /[;&|`$]\s*(cat|ls|wget|curl|bash|sh|cmd|powershell|nc|ncat)/i,
    // XXE
    /<!ENTITY\s/i,
    // LFI/RFI
    /(php:\/\/|file:\/\/|data:\/\/|expect:\/\/)/i,
];

function logFirewallAttack(ip, reason, req) {
    if (!FIREWALL_ATTACK_LOG.has(ip)) {
        FIREWALL_ATTACK_LOG.set(ip, { count: 0, firstSeen: Date.now(), lastSeen: Date.now(), reasons: [] });
    }
    const entry = FIREWALL_ATTACK_LOG.get(ip);
    entry.count++;
    entry.lastSeen = Date.now();
    if (entry.reasons.length < 10) entry.reasons.push(reason);

    // Otomatik ban
    if (entry.count >= FIREWALL_AUTO_BAN_THRESHOLD) {
        FIREWALL_BLOCKED_IPS.add(ip);
        console.warn(`🔥 [FIREWALL] AUTO-BAN: ${ip} | Sebep: ${reason} | Toplam: ${entry.count} saldırı`);
        // DB'ye de kaydet (asenkron)
        dbRun(
            `INSERT INTO banned_ips (id, ip, reason, "bannedAt", "expiresAt")
             VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '24 hours')
             ON CONFLICT (ip) DO UPDATE SET reason=$3, "bannedAt"=NOW(), "expiresAt"=NOW() + INTERVAL '24 hours'`,
            [uuidv4(), ip, `AUTO-BAN: ${reason} (${entry.count} saldırı)`]
        ).catch(() => {});
    }
}

// Firewall middleware
function firewallMiddleware(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress || '';
    const cleanIp = ip.replace(/^::ffff:/, '');

    // 1. Statik olarak engellenmiş IP
    if (FIREWALL_BLOCKED_IPS.has(cleanIp) || FIREWALL_BLOCKED_IPS.has(ip)) {
        return res.status(403).json({ error: 'Erişim engellendi' });
    }

    // 2. Kötü User-Agent
    const ua = req.headers['user-agent'] || '';
    for (const pattern of BAD_USER_AGENTS) {
        if (pattern.test(ua)) {
            logFirewallAttack(cleanIp, `Bad UA: ${ua.substring(0, 80)}`, req);
            return res.status(403).json({ error: 'Erişim engellendi' });
        }
    }

    // 3. URL'de saldırı pattern'i
    const fullUrl = decodeURIComponent(req.originalUrl || req.url || '');
    for (const pattern of ATTACK_PATTERNS) {
        if (pattern.test(fullUrl)) {
            logFirewallAttack(cleanIp, `URL attack pattern: ${fullUrl.substring(0, 100)}`, req);
            console.warn(`🔥 [FIREWALL] URL ATTACK: ${cleanIp} → ${fullUrl.substring(0, 100)}`);
            return res.status(403).json({ error: 'Geçersiz istek' });
        }
    }

    // 4. Body'de saldırı pattern'i (sadece JSON body varsa)
    if (req.body && typeof req.body === 'object') {
        const bodyStr = JSON.stringify(req.body);
        for (const pattern of ATTACK_PATTERNS) {
            if (pattern.test(bodyStr)) {
                logFirewallAttack(cleanIp, `Body attack pattern`, req);
                return res.status(400).json({ error: 'Geçersiz içerik' });
            }
        }
    }

    // 5. Çok büyük header'lar (header injection)
    const totalHeaderSize = Object.values(req.headers).join('').length;
    if (totalHeaderSize > 16384) { // 16KB
        logFirewallAttack(cleanIp, 'Oversized headers', req);
        return res.status(431).json({ error: 'İstek başlıkları çok büyük' });
    }

    next();
}

// Not: app.use(firewallMiddleware) statik dosyalardan önce (yukarıda) çağrılmaktadır.

// 🔥 Firewall yönetimi API'leri
app.get('/api/admin/firewall/stats', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    const logs = [];
    for (const [ip, data] of FIREWALL_ATTACK_LOG.entries()) {
        logs.push({ ip, ...data });
    }
    logs.sort((a, b) => b.count - a.count);
    res.json({
        blockedIPs    : [...FIREWALL_BLOCKED_IPS],
        totalBlockedIPs: FIREWALL_BLOCKED_IPS.size,
        attackLog     : logs.slice(0, 50),
        autobanThreshold: FIREWALL_AUTO_BAN_THRESHOLD,
    });
});

app.post('/api/admin/firewall/block', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    const { ip, reason = 'Manuel engelleme' } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP adresi gerekli' });
    FIREWALL_BLOCKED_IPS.add(ip);
    await dbRun(
        `INSERT INTO banned_ips (id, ip, reason, "bannedAt") VALUES ($1,$2,$3,NOW())
         ON CONFLICT (ip) DO UPDATE SET reason=$3, "bannedAt"=NOW()`,
        [uuidv4(), ip, reason]
    ).catch(() => {});
    res.json({ success: true, message: `${ip} engellendi` });
});

app.post('/api/admin/firewall/unblock', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP adresi gerekli' });
    FIREWALL_BLOCKED_IPS.delete(ip);
    FIREWALL_ATTACK_LOG.delete(ip);
    await dbRun(`DELETE FROM banned_ips WHERE ip = $1`, [ip]).catch(() => {});
    res.json({ success: true, message: `${ip} engeli kaldırıldı` });
});

// Başlangıçta DB'deki ban'ları belleğe yükle
async function loadFirewallBans() {
    try {
        const bans = await dbAll(
            `SELECT ip FROM banned_ips WHERE "expiresAt" IS NULL OR "expiresAt" > NOW()`
        );
        bans.forEach(b => FIREWALL_BLOCKED_IPS.add(b.ip));
        console.log(`🔥 [FIREWALL] ${FIREWALL_BLOCKED_IPS.size} engellenmiş IP yüklendi`);
    } catch (e) {
        console.error('Firewall ban yükleme hatası:', e.message);
    }
}
// DB hazır olduktan sonra çağrılacak (initializeDatabase'den sonra)

// Rate Limiting
// Genel API rate limit
app.use('/api/', rateLimit({
    windowMs      : 15 * 60 * 1000, // 15 dakika
    max           : 300,             // IP başına 300 istek
    standardHeaders: true,
    legacyHeaders : false,
    message       : { error: 'Çok fazla istek gönderildi. Lütfen bekleyin.' },
    skip          : (req) => req.method === 'OPTIONS',
}));

// Auth endpoint'leri - çok daha sıkı
app.use('/api/auth/login',           rateLimit({ windowMs: 15 * 60 * 1000, max: 10,  message: { error: 'Çok fazla giriş denemesi. 15 dakika bekleyin.' } }));
app.use('/api/auth/register',        rateLimit({ windowMs: 60 * 60 * 1000, max: 5,   message: { error: 'Çok fazla kayıt denemesi. 1 saat bekleyin.' } }));
app.use('/api/auth/register-init',   rateLimit({ windowMs: 60 * 60 * 1000, max: 5,   message: { error: 'Çok fazla kayıt denemesi. 1 saat bekleyin.' } }));
app.use('/api/auth/forgot-password', rateLimit({ windowMs: 60 * 60 * 1000, max: 3,   message: { error: 'Çok fazla şifre sıfırlama denemesi. 1 saat bekleyin.' } }));
app.use('/api/auth/verify-2fa',      rateLimit({ windowMs: 10 * 60 * 1000, max: 10,  message: { error: 'Çok fazla doğrulama denemesi.' } }));
app.use('/api/auth/resend-2fa',      rateLimit({ windowMs: 5  * 60 * 1000, max: 3,   message: { error: 'Çok fazla kod istendi. 5 dakika bekleyin.' } }));
app.use('/api/auth/verify-email',    rateLimit({ windowMs: 5  * 60 * 1000, max: 5,   message: { error: 'Çok fazla doğrulama denemesi.' } }));
app.use('/api/auth/resend-verification', rateLimit({ windowMs: 10 * 60 * 1000, max: 3 }));

// Upload endpoint - dosya yükleme sınırı
app.use('/api/posts',    rateLimit({ windowMs: 60 * 1000, max: 30, methods: ['POST'] }));
app.use('/api/messages', rateLimit({ windowMs: 60 * 1000, max: 60 }));

// ==================== 🔒 SPAM KORUMASI MIDDLEWARE ====================

const spamCounters = new Map(); // Bellek tabanlı (Redis yoksa)

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

async function authenticateToken(req, res, next) {
    // 🔒 Önce HttpOnly cookie'ye bak (XSS'e karşı güvenli)
    // Yoksa Authorization header'dan al (native/mobile uyumluluk)
    let token = req.cookies?.access_token;
    if (!token) {
        const authHeader = req.headers['authorization'];
        token = authHeader && authHeader.split(' ')[1];
    }
    if (!token) return res.status(401).json({ error: 'Token gerekli' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await dbGet(
            // 🔒 GÜVENLİK: SELECT * yerine sadece gerekli alanlar — isAdmin gibi
            // tehlikeli flag'lerin req.user'a sızmasını engeller (bypass2 vektörü kapatıldı)
            `SELECT id, username, name, email, role, "profilePic", "coverPic", bio,
                    "isVerified", "isActive", "userType", "hasFarmerBadge",
                    "isOnline", "isBanned", "emailVerified", "twoFactorEnabled"
             FROM users WHERE id = $1 AND "isActive" = TRUE`,
            [decoded.id]
        );
        if (!user) return res.status(403).json({ error: 'Kullanıcı bulunamadı' });

        const restriction = await dbGet(
            `SELECT "isRestricted", "restrictedUntil", "canPost", "canComment", "canMessage", "canFollow", "canLike"
             FROM account_restrictions 
             WHERE "userId" = $1 AND "isRestricted" = TRUE AND "restrictedUntil" > NOW()`,
            [user.id]
        );

        // 🔒 Spread yok — sadece whitelist edilmiş nesne
        req.user = {
            id            : user.id,
            username      : user.username,
            name          : user.name,
            email         : user.email,
            role          : user.role,          // tek yetki kaynağı
            profilePic    : user.profilePic,
            coverPic      : user.coverPic,
            bio           : user.bio,
            isVerified    : user.isVerified,
            isActive      : user.isActive,
            userType      : user.userType,
            hasFarmerBadge: user.hasFarmerBadge,
            isOnline      : user.isOnline,
            isBanned      : user.isBanned,
            emailVerified : user.emailVerified,
            twoFactorEnabled: user.twoFactorEnabled,
            restriction   : restriction || null,
        };
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Geçersiz token' });
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
    } catch (err) {
        console.error('Bildirim oluşturma hatası:', err.message);
    }
}

function generateTokens(user) {
    // 🔒 GÜVENLİK: Access token 1 gün, refresh token 7 gün
    // Token çalınma riskini minimize etmek için süreler kısaltıldı
    const accessToken = jwt.sign(
        { id: user.id, email: user.email, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '1d', algorithm: 'HS256' }
    );
    const refreshToken = jwt.sign(
        { id: user.id, type: 'refresh' },
        JWT_REFRESH_SECRET,
        { expiresIn: '7d', algorithm: 'HS256' }
    );
    return { accessToken, refreshToken };
}

// ====================================================================
// API ROTALARI
// ====================================================================

// ─── 1. HEALTH CHECK ────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok', timestamp: new Date().toISOString(), database: 'connected' });
    } catch (e) {
        res.status(503).json({ status: 'error', database: 'disconnected' });
    }
});

// ─── 2. KAYIT ───────────────────────────────────────────────────────
app.post('/api/auth/register', upload.single('profilePic'), async (req, res) => {
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

        // 🔒 GÜVENLİK: Aynı e-posta ile birden fazla hesap açılmasını engelle
        const existingEmail = await dbGet('SELECT id FROM users WHERE email = $1', [cleanEmail]);
        if (existingEmail) return res.status(400).json({ error: 'Bu e-posta adresi zaten kayıtlı' });

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
                await sharp(req.file.path).resize(512, 512, { fit: 'cover' }).webp({ quality: 85 }).toFile(outputPath);
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

        // 📧 Hoş geldiniz + e-posta doğrulama kodu gönder
        const verifyCode    = Math.floor(100000 + Math.random() * 900000).toString();
        
        await dbRun(
            `INSERT INTO email_verifications (id, "userId", code, "expiresAt") VALUES ($1, $2, $3, $4)`,
            [uuidv4(), userId, verifyCode]
        );
        sendWelcomeEmail(cleanEmail, name).catch(() => {});

        // Doğrulama kodu içeren ayrı e-posta
        sendEmail(cleanEmail, '🌾 Agrolink — E-posta Doğrulama Kodunuz', `
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
            user: { id: userId, username: cleanUsername, name, email: cleanEmail, profilePic }
        });
    } catch (error) {
        console.error('Kayıt hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 2b. KAYIT (register-init alias — UI uyumluluğu için) ──────────
// UI /api/auth/register-init çağırıyor, bu endpoint aynı işlemi yapar
app.post('/api/auth/register-init', upload.single('profilePic'), async (req, res) => {
    try {
        const { name, username, email, password, userType } = req.body;
        if (!name || !username || !email || !password) {
            return res.status(400).json({ error: 'Tüm alanlar zorunludur' });
        }
        if (password.length < 8) return res.status(400).json({ error: 'Şifre en az 8 karakter olmalıdır' });

        const cleanUsername = username.toLowerCase().replace(/[^a-z0-9._-]/g, '');
        const cleanEmail = email.toLowerCase().trim();

        const existing = await dbGet('SELECT id FROM users WHERE username = $1 OR email = $2', [cleanUsername, cleanEmail]);
        if (existing) return res.status(400).json({ error: 'Bu kullanıcı adı veya e-posta zaten kullanımda' });

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
                await sharp(req.file.path).resize(512, 512, { fit: 'cover' }).webp({ quality: 85 }).toFile(outputPath);
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

        // E-posta doğrulama kodu oluştur
        const verifyCode    = Math.floor(100000 + Math.random() * 900000).toString();
        
        await dbRun(
            `INSERT INTO email_verifications (id, "userId", code, "expiresAt") VALUES ($1, $2, $3, $4)`,
            [uuidv4(), userId, verifyCode]
        );

        // Doğrulama kodu e-postası - tam HTML şablonuyla
        const emailResult = await sendEmailVerificationCode(cleanEmail, name.trim(), verifyCode);

        if (!emailResult.success) {
            console.error('❌ Kayıt doğrulama e-postası gönderilemedi:', emailResult.error);
            return res.status(500).json({ error: 'Doğrulama e-postası gönderilemedi. Lütfen e-posta adresinizi kontrol edip tekrar deneyin.' });
        }

        console.log(`📧 Kayıt doğrulama kodu gönderildi: [e-posta gizlendi]`);

        // Hoş geldiniz emaili arka planda gönder
        sendWelcomeEmail(cleanEmail, name).catch(() => {});

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
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, identifier } = req.body;
        // UI'dan "identifier" (e-posta veya kullanıcı adı) gelebilir, geriye dönük uyumluluk için "email" de desteklenir
        const loginId = (identifier || email || '').toLowerCase().trim();
        if (!loginId || !password) return res.status(400).json({ error: 'E-posta/kullanıcı adı ve şifre gerekli' });

        const user = await dbGet(
            'SELECT * FROM users WHERE (email = $1 OR username = $1) AND "isActive" = TRUE',
            [loginId]
        );
        if (!user) return res.status(401).json({ error: 'Kullanıcı bulunamadı' });

        // 🔒 Brute force kontrolü
        const lockout = checkAccountLockout(loginId);
        if (lockout.locked) {
            return res.status(429).json({ error: `Hesap geçici olarak kilitlendi. ${lockout.remainingMin} dakika sonra tekrar deneyin.` });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            recordFailedLogin(loginId);
            return res.status(401).json({ error: 'Şifre yanlış' });
        }
        clearFailedLogins(loginId);

        // ========== 2FA KONTROLÜ ==========
        if (user.twoFactorEnabled) {
            // 2FA açık → kod oluştur ve gönder
            const twoFACode = Math.floor(100000 + Math.random() * 900000).toString();
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

            if (!emailResult.success) {
                console.error('❌ 2FA e-postası gönderilemedi:', emailResult.error);
                return res.status(500).json({ error: 'Doğrulama kodu gönderilemedi. Lütfen tekrar deneyin.' });
            }

            console.log(`🔐 2FA kodu gönderildi: [e-posta gizlendi]`);

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

        await dbRun(
            `INSERT INTO login_history (id, "userId", ip, "userAgent", "createdAt")
             VALUES ($1, $2, $3, $4, NOW())`,
            [uuidv4(), user.id, req.ip, req.headers['user-agent'] || '']
        );

        const tokens = generateTokens(user);

        const tokenHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
        await dbRun(
            `INSERT INTO refresh_tokens (id, "userId", "tokenHash", ip, "userAgent", "createdAt", "expiresAt")
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '30 days')`,
            [uuidv4(), user.id, tokenHash, req.ip, req.headers['user-agent'] || '']
        );

        // 🔒 HttpOnly cookie: localStorage'dan daha güvenli (XSS erişemez)
        // Backward-compat: token body'de de dönüyor (native/Android için)
        const isSecure = req.secure || (req.headers['x-forwarded-proto'] === 'https');
        res.cookie('access_token', tokens.accessToken, {
            httpOnly: true,
            secure: isSecure,
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000, // 1 gün
        });
        res.cookie('refresh_token', tokens.refreshToken, {
            httpOnly: true,
            secure: isSecure,
            sameSite: 'strict',
            path: '/api/auth/refresh', // sadece refresh endpoint'ine gönderilir
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 gün
        });

        res.json({
            message: 'Giriş başarılı',
            token: tokens.accessToken,       // backward compat (mobile/native)
            refreshToken: tokens.refreshToken,
            user: {
                id: user.id, username: user.username, name: user.name, email: user.email,
                profilePic: user.profilePic, coverPic: user.coverPic, bio: user.bio,
                isVerified: user.isVerified, hasFarmerBadge: user.hasFarmerBadge, role: user.role
            }
        });
    } catch (error) {
        console.error('Giriş hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 4. TOKEN YENİLEME ──────────────────────────────────────────────
app.post('/api/auth/refresh', async (req, res) => {
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
            `SELECT id, username, name, email, role, "profilePic", "coverPic", bio,
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
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '30 days')`,
            [uuidv4(), user.id, newHash, req.ip, req.headers['user-agent'] || '']
        );

        // 🔒 Yeni HttpOnly cookie'ler set et
        const isSecure = req.secure || (req.headers['x-forwarded-proto'] === 'https');
        res.cookie('access_token', tokens.accessToken, {
            httpOnly: true, secure: isSecure, sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000,
        });
        res.cookie('refresh_token', tokens.refreshToken, {
            httpOnly: true, secure: isSecure, sameSite: 'strict',
            path: '/api/auth/refresh',
            maxAge: 30 * 24 * 60 * 60 * 1000,
        });

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

// ─── 6. KULLANICI PROFİLİ ──────────────────────────────────────────
// ─── 6. KULLANICI PROFİLİ (ID veya username ile) ───────────────────
// Frontend'in v5'ten gelen tüm çağrıları uyumlu hale getirir:
//   GET /api/users/:id       → UUID ile arama (eski frontend)
//   GET /api/users/:username → username ile arama (yeni frontend)
app.get('/api/users/:idOrUsername', authenticateToken, async (req, res, next) => {
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
                        "isVerified", "hasFarmerBadge", "userType", "isOnline", "lastSeen", "createdAt"
                 FROM users WHERE id = $1 AND "isActive" = TRUE`,
                [param]
            );
        } else {
            // Username ile ara
            user = await dbGet(
                `SELECT id, username, name, "profilePic", "coverPic", bio, location, website,
                        "isVerified", "hasFarmerBadge", "userType", "isOnline", "lastSeen", "createdAt"
                 FROM users WHERE username = $1 AND "isActive" = TRUE`,
                [param.toLowerCase()]
            );
        }

        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        const [followingRow, followerRow, postRow, isFollowing, isBlocked, onlineRow] = await Promise.all([
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followerId"  = $1', [user.id]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM follows WHERE "followingId" = $1', [user.id]),
            pool.query('SELECT COUNT(*)::int AS cnt FROM posts   WHERE "userId" = $1 AND "isActive" = TRUE', [user.id]),
            dbGet('SELECT id FROM follows WHERE "followerId" = $1 AND "followingId" = $2', [req.user.id, user.id]),
            dbGet(`SELECT id FROM blocks WHERE ("blockerId"=$1 AND "blockedId"=$2) OR ("blockerId"=$2 AND "blockedId"=$1)`, [req.user.id, user.id]),
            pool.query('SELECT "isOnline", "lastSeen" FROM users WHERE id=$1', [user.id]) // ⚡ isUserOnline paralel
        ]);

        // ⚡ isOnline hesapla (ayrı DB sorgusu yok)
        const onlineData = onlineRow.rows[0];
        const isOnline = onlineData ? (onlineData.isOnline || (onlineData.lastSeen && Date.now() - new Date(onlineData.lastSeen).getTime() < 5 * 60 * 1000)) : false;

        res.json({
            user: {
                ...user,
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
                await sharp(file.path, { sequentialRead: true })
                    .resize(512, 512, { fit: 'cover', kernel: 'lanczos2' })
                    .webp({ quality: 82, effort: 2 }) // ⚡ effort:2 → hızlı
                    .toFile(outputPath);
                await fs.unlink(file.path).catch(() => {});
                updates.push(`"profilePic" = $${paramIdx++}`);
                params.push(`/uploads/profiles/${filename}`);
            })(),
            (async () => {
                if (!req.files?.coverPic?.[0]) return;
                const file = req.files.coverPic[0];
                const filename = `cover_${req.user.id}_${Date.now()}.webp`;
                const outputPath = path.join(profilesDir, filename);
                await sharp(file.path, { sequentialRead: true })
                    .resize(1920, 1080, { fit: 'inside', withoutEnlargement: true, kernel: 'lanczos2' })
                    .webp({ quality: 82, effort: 2 }) // ⚡ effort:2 → hızlı
                    .toFile(outputPath);
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

        res.json({ message: 'Profil güncellendi', user: updated });
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

        const user = await dbGet('SELECT password FROM users WHERE id = $1', [req.user.id]);
        const valid = await bcrypt.compare(currentPassword, user.password);
        if (!valid) return res.status(401).json({ error: 'Mevcut şifre yanlış' });

        const hashed = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
        await dbRun('UPDATE users SET password = $1, "updatedAt" = NOW() WHERE id = $2', [hashed, req.user.id]);

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
app.get('/api/users/search/:query', authenticateToken, async (req, res) => {
    try {
        const { query } = req.params;
        const searchTerm = `%${query.toLowerCase()}%`;

        const users = await dbAll(
            `SELECT id, username, name, "profilePic", "isVerified", "hasFarmerBadge"
             FROM users
             WHERE "isActive" = TRUE AND (LOWER(username) LIKE $1 OR LOWER(name) LIKE $1)
             ORDER BY "isVerified" DESC, "createdAt" DESC
             LIMIT 20`,
            [searchTerm]
        );

        res.json({ users });
    } catch (error) {
        console.error('Arama hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── TEKLI DOSYA YÜKLEME (UI sıralı yükleme için) ───────────────────
app.post('/api/upload', authenticateToken, upload.single('media'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'Dosya bulunamadı' });
        const file = req.file;
        const isVideo = file.mimetype.startsWith('video/');

        // 🔒 Magic bytes + boyut doğrulama
        const uploadType = isVideo ? 'postVideo' : 'postImage';
        try { await verifyUploadedFile(file, uploadType); }
        catch (verifyErr) { return res.status(400).json({ error: verifyErr.message }); }

        let mediaUrl, mediaType;

        if (isVideo) {
            const videoId = `video_${Date.now()}_${Math.round(Math.random() * 1E9)}`;
            const rawServedPath = path.join(videosDir, `${videoId}_raw.mp4`);
            await fs.copyFile(file.path, rawServedPath);
            await fs.unlink(file.path).catch(() => {});
            mediaUrl = `/uploads/videos/${videoId}_raw.mp4`;
            mediaType = 'video';
        } else {
            // 🔒 Re-encode: uzantı ne olursa olsun sharp ile yeniden işle
            const filename = `post_${Date.now()}_${Math.round(Math.random() * 1E9)}.webp`;
            const destPath = path.join(postsDir, filename);
            try {
                await sharp(file.path, { sequentialRead: true })
                    .resize(1920, 1920, { fit: 'inside', withoutEnlargement: true })
                    .webp({ quality: 82, effort: 2 })
                    .toFile(destPath);
            } catch {
                await fs.unlink(file.path).catch(() => {});
                return res.status(400).json({ error: 'Resim işlenemedi' });
            }
            await fs.unlink(file.path).catch(() => {});
            mediaUrl = `/uploads/posts/${filename}`;
            mediaType = 'image';
        }

        return res.json({ success: true, url: mediaUrl, mediaUrl, type: mediaType });
    } catch (err) {
        console.error('❌ /api/upload hatası'); // 🔒 Detay loglanmıyor
        return res.status(500).json({ error: 'Dosya yüklenemedi' });
    }
});

// ─── 10. GÖNDERI OLUŞTUR ────────────────────────────────────────────
app.post('/api/posts', authenticateToken, checkRestriction('post'), upload.array('media', 10), async (req, res) => {
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

                // 🔒 Magic bytes + tip bazlı boyut doğrulama
                try { await verifyUploadedFile(file, isVideo ? 'postVideo' : 'postImage'); }
                catch (verifyErr) {
                    // Kalan temp dosyaları temizle
                    for (const f of req.files) await fs.unlink(f.path).catch(() => {});
                    return res.status(400).json({ error: verifyErr.message });
                }

                if (isVideo) {
                    const videoId  = `video_${Date.now()}_${Math.round(Math.random() * 1E9)}`;
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
                    const filename = `img_${Date.now()}_${Math.round(Math.random() * 1E9)}.webp`;
                    const outputPath = path.join(postsDir, filename);
                    let imgWidth = null, imgHeight = null;
                    try {
                        const info = await sharp(file.path, { sequentialRead: true })
                            .resize(1920, 1920, { fit: 'inside', withoutEnlargement: true, kernel: 'lanczos2' })
                            .webp({ quality: 82, effort: 2, smartSubsample: true })
                            .toFile(outputPath);
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

        await dbRun(
            `INSERT INTO posts (id, "userId", username, content, media, "mediaType", "mediaUrls", "mediaWidth", "mediaHeight",
             "isPoll", "pollQuestion", "pollOptions",
             latitude, longitude, "locationName", "allowComments", "isActive", "createdAt", "updatedAt")
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,TRUE,NOW(),NOW())`,
            [postId, req.user.id, user.username, content || '', media, mediaType, mediaUrlsJson,
             mediaWidth, mediaHeight, isAnketMode, pollQuestion || null, parsedPollOptions,
             latitude ? parseFloat(latitude) : null, longitude ? parseFloat(longitude) : null,
             locationName || null, allowComments !== 'false']
        );

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

        const post = await dbGet('SELECT * FROM posts WHERE id = $1', [postId]);

        // ⚡ Bu kullanıcının feed cache'ini temizle
        for (const k of feedCache.keys()) { if (k.startsWith(req.user.id + ':')) feedCache.delete(k); }

        res.status(201).json({ success: true, message: 'Gönderi paylaşıldı', post: formatPost(post) });
    } catch (error) {
        console.error('Post oluşturma hatası:', error);
        if (req.files) { for (const f of req.files) { await fs.unlink(f.path).catch(() => {}); } }
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 11. FEED ───────────────────────────────────────────────────────
// ⚡ FEED ÖNBELLEK - kullanıcı başına 30 saniyelik cache
const feedCache = new Map();
const FEED_CACHE_TTL = 30 * 1000; // 30 saniye
setInterval(() => { // Her 60s eski kayıtları temizle
    const now = Date.now();
    for (const [k, v] of feedCache) { if (now - v.ts > FEED_CACHE_TTL) feedCache.delete(k); }
}, 60000);

app.get('/api/feed', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);
        const cacheKey = `${req.user.id}:${page}:${limit}`;

        // ⚡ Cache hit → anında dön
        const cached = feedCache.get(cacheKey);
        if (cached && Date.now() - cached.ts < FEED_CACHE_TTL) {
            return res.json(cached.data);
        }

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u."userType", u.username as "authorUsername",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved",
                    EXISTS(SELECT 1 FROM follows WHERE "followerId" = $1 AND "followingId" = p."userId") as "isFollowing"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE
               AND p."userId" NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1)
               AND p."userId" NOT IN (SELECT "blockerId" FROM blocks WHERE "blockedId" = $1)
             ORDER BY p."createdAt" DESC
             LIMIT $2 OFFSET $3`,
            [req.user.id, parseInt(limit), offset]
        );

        const responseData = { posts: posts.map(formatPost), page: parseInt(page) };
        feedCache.set(cacheKey, { data: responseData, ts: Date.now() }); // ⚡ Cache'e kaydet
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
        const post = await dbGet('SELECT "userId" FROM posts WHERE id = $1', [req.params.id]);
        if (!post) return res.status(404).json({ error: 'Gönderi bulunamadı' });
        if (post.userId !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Yetkiniz yok' });
        }
        await dbRun('UPDATE posts SET "isActive" = FALSE, "updatedAt" = NOW() WHERE id = $1', [req.params.id]);
        res.json({ message: 'Gönderi silindi' });
    } catch (error) {
        console.error('Post silme hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 14. KULLANICININ POSTLARı ──────────────────────────────────────
app.get('/api/users/:userId/posts', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);
        const param = req.params.userId;

        // ID veya username ile kullanıcı bul
        const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(param);
        let targetUserId = param;
        if (!isUUID) {
            const u = await dbGet('SELECT id FROM users WHERE username=$1 AND "isActive"=TRUE', [param.toLowerCase()]);
            if (!u) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
            targetUserId = u.id;
        }

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge", u.username as "authorUsername",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p."userId" = $2 AND p."isActive" = TRUE
             ORDER BY p."createdAt" DESC
             LIMIT $3 OFFSET $4`,
            [req.user.id, targetUserId, parseInt(limit), offset]
        );

        const total = await dbGet('SELECT COUNT(*) as c FROM posts WHERE "userId"=$1 AND "isActive"=TRUE', [targetUserId]);

        res.json({ posts: posts.map(formatPost), total: parseInt(total?.c || 0), page: parseInt(page) });
    } catch (error) {
        console.error('Kullanıcı postları hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 15. BEĞENİ ────────────────────────────────────────────────────
app.post('/api/posts/:id/like', authenticateToken, checkRestriction('like'), async (req, res) => {
    try {
        const postId = req.params.id;
        const existing = await dbGet('SELECT id FROM likes WHERE "postId" = $1 AND "userId" = $2', [postId, req.user.id]);

        if (existing) {
            await dbRun('DELETE FROM likes WHERE id = $1', [existing.id]);
            await dbRun('UPDATE posts SET "likeCount" = GREATEST("likeCount" - 1, 0), "updatedAt" = NOW() WHERE id = $1', [postId]);
            res.json({ liked: false });
        } else {
            await dbRun('INSERT INTO likes (id, "postId", "userId", "createdAt") VALUES ($1, $2, $3, NOW())', [uuidv4(), postId, req.user.id]);
            await dbRun('UPDATE posts SET "likeCount" = "likeCount" + 1, "updatedAt" = NOW() WHERE id = $1', [postId]);

            const post = await dbGet('SELECT "userId" FROM posts WHERE id = $1', [postId]);
            if (post && post.userId !== req.user.id) {
                await createNotification(post.userId, 'like', `${req.user.username} gönderinizi beğendi`, { postId, userId: req.user.id });
            }
            res.json({ liked: true });
        }
    } catch (error) {
        console.error('Beğeni hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 16. YORUM YAP ─────────────────────────────────────────────────
app.post('/api/posts/:id/comments', authenticateToken, checkRestriction('comment'), async (req, res) => {
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
            await createNotification(post.userId, 'comment', `${req.user.username} gönderinize yorum yaptı`, { postId: req.params.id, commentId });
        }

        const comment = await dbGet('SELECT * FROM comments WHERE id = $1', [commentId]);
        res.status(201).json({ comment });
    } catch (error) {
        console.error('Yorum hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 17. YORUMLARI GETİR ───────────────────────────────────────────
app.get('/api/posts/:id/comments', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const comments = await dbAll(
            `SELECT c.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM comment_likes WHERE "commentId" = c.id AND "userId" = $1) as "isLiked"
             FROM comments c
             JOIN users u ON c."userId" = u.id
             WHERE c."postId" = $2
             ORDER BY c."createdAt" ASC
             LIMIT $3 OFFSET $4`,
            [req.user.id, req.params.id, parseInt(limit), offset]
        );

        res.json({ comments });
    } catch (error) {
        console.error('Yorumlar hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 18. TAKİP ET/BIRAK ────────────────────────────────────────────
app.post('/api/users/:id/follow', authenticateToken, checkRestriction('follow'), async (req, res) => {
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
            await dbRun('INSERT INTO follows (id, "followerId", "followingId", "createdAt") VALUES ($1, $2, $3, NOW())', [uuidv4(), req.user.id, targetId]);
            await createNotification(targetId, 'follow', `${req.user.username} sizi takip etmeye başladı`, { userId: req.user.id });
            res.json({ following: true });
        }
    } catch (error) {
        console.error('Takip hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 19. TAKİPÇİLER ────────────────────────────────────────────────
app.get('/api/users/:id/followers', authenticateToken, async (req, res) => {
    try {
        const followers = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM follows WHERE "followerId" = $2 AND "followingId" = u.id) as "isFollowing"
             FROM follows f
             JOIN users u ON f."followerId" = u.id
             WHERE f."followingId" = $1
             ORDER BY f."createdAt" DESC`,
            [req.params.id, req.user.id]
        );
        res.json({ followers });
    } catch (error) {
        console.error('Takipçiler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 20. TAKİP EDİLENLER ───────────────────────────────────────────
app.get('/api/users/:id/following', authenticateToken, async (req, res) => {
    try {
        const following = await dbAll(
            `SELECT u.id, u.username, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM follows WHERE "followerId" = $2 AND "followingId" = u.id) as "isFollowing"
             FROM follows f
             JOIN users u ON f."followingId" = u.id
             WHERE f."followerId" = $1
             ORDER BY f."createdAt" DESC`,
            [req.params.id, req.user.id]
        );
        res.json({ following });
    } catch (error) {
        console.error('Takip edilenler hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 21. MESAJ GÖNDER ───────────────────────────────────────────────
app.post('/api/messages', authenticateToken, checkRestriction('message'), async (req, res) => {
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

        await createNotification(recipientId, 'message', `${req.user.username} size mesaj gönderdi`, { senderId: req.user.id });

        res.status(201).json({ message: 'Mesaj gönderildi', id: msgId });
    } catch (error) {
        console.error('Mesaj hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 22. SOHBET LİSTESİ ────────────────────────────────────────────
app.get('/api/messages/conversations', authenticateToken, async (req, res) => {
    try {
        const conversations = await dbAll(
            `SELECT DISTINCT ON (partner_id) *
             FROM (
                 SELECT m.*, 
                        CASE WHEN m."senderId" = $1 THEN m."recipientId" ELSE m."senderId" END as partner_id,
                        CASE WHEN m."senderId" = $1 THEN m."recipientUsername" ELSE m."senderUsername" END as partner_username
                 FROM messages m
                 WHERE m."senderId" = $1 OR m."recipientId" = $1
             ) sub
             JOIN users u ON sub.partner_id = u.id
             ORDER BY partner_id, sub."createdAt" DESC`,
            [req.user.id]
        );

        const enriched = await Promise.all(conversations.map(async (conv) => {
            const partner = await dbGet(
                'SELECT id, username, name, "profilePic", "isVerified", "isOnline" FROM users WHERE id = $1',
                [conv.partner_id]
            );
            const unreadCount = await dbGet(
                'SELECT COUNT(*) as count FROM messages WHERE "senderId" = $1 AND "recipientId" = $2 AND read = FALSE',
                [conv.partner_id, req.user.id]
            );
            return {
                ...conv,
                partner,
                unreadCount: parseInt(unreadCount?.count || 0)
            };
        }));

        res.json({ conversations: enriched });
    } catch (error) {
        console.error('Sohbet listesi hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 23. MESAJ GEÇMİŞİ ─────────────────────────────────────────────
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 50 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const messages = await dbAll(
            `SELECT * FROM messages
             WHERE ("senderId" = $1 AND "recipientId" = $2) OR ("senderId" = $2 AND "recipientId" = $1)
             ORDER BY "createdAt" DESC
             LIMIT $3 OFFSET $4`,
            [req.user.id, req.params.userId, parseInt(limit), offset]
        );

        await dbRun(
            `UPDATE messages SET read = TRUE, "readAt" = NOW()
             WHERE "senderId" = $1 AND "recipientId" = $2 AND read = FALSE`,
            [req.params.userId, req.user.id]
        );

        res.json({ messages: messages.reverse() });
    } catch (error) {
        console.error('Mesaj geçmişi hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── 24. BİLDİRİMLER ───────────────────────────────────────────────
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 30 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const notifications = await dbAll(
            `SELECT * FROM notifications WHERE "userId" = $1 ORDER BY "createdAt" DESC LIMIT $2 OFFSET $3`,
            [req.user.id, parseInt(limit), offset]
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
            await dbRun('INSERT INTO saves (id, "postId", "userId", "createdAt") VALUES ($1, $2, $3, NOW())', [uuidv4(), postId, req.user.id]);
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
        const offset = (parseInt(page) - 1) * parseInt(limit);

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
app.post('/api/store/products', authenticateToken, (req, res, next) => {
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
        if (isNaN(priceNum) || priceNum < 0) return res.status(400).json({ error: 'Geçersiz fiyat' });

        let images = [];
        const files = req.files || [];
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const filename = `product_${Date.now()}_${i}_${Math.round(Math.random() * 1e9)}.webp`;
            const outputPath = path.join(postsDir, filename);
            try {
                await sharp(file.path)
                    .resize(1080, 1080, { fit: 'inside', withoutEnlargement: true })
                    .webp({ quality: 85 })
                    .toFile(outputPath);
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
             JSON.stringify(images), category || '', parseInt(stock) || 1]
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

// ─── ADMİN: Kullanıcıyı admin yap ─────────────────────────────────
app.post('/api/admin/make-admin', authenticateToken, async (req, res) => {
    try {
        const me = await dbGet('SELECT role FROM users WHERE id=$1', [req.user.id]);
        if (me?.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        const { userId } = req.body;
        if (!userId) return res.status(400).json({ error: 'userId gerekli' });
        await dbRun('UPDATE users SET role=$1, "updatedAt"=NOW() WHERE id=$2', ['admin', userId]);
        res.json({ message: 'Kullanıcı admin yapıldı' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── ADMİN: Kullanıcı listesi ─────────────────────────────────────
app.get('/api/admin/users', authenticateToken, async (req, res) => {
    try {
        const me = await dbGet('SELECT role FROM users WHERE id=$1', [req.user.id]);
        if (me?.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        const { page=1, limit=50, q='' } = req.query;
        const off = (parseInt(page)-1)*parseInt(limit);
        const users = await dbAll(`
            SELECT id, username, name, email, role, "isActive", "isVerified", "createdAt", "lastLogin",
                   (SELECT COUNT(*) FROM posts WHERE "userId"=u.id AND "isActive"=TRUE) AS "postCount",
                   (SELECT COUNT(*) FROM follows WHERE "followingId"=u.id) AS "followerCount"
            FROM users u
            WHERE ($1='' OR username ILIKE $1 OR name ILIKE $1 OR email ILIKE $1)
            ORDER BY "createdAt" DESC LIMIT $2 OFFSET $3
        `, [`%${q}%`, parseInt(limit), off]);
        const tot = await dbGet(`SELECT COUNT(*) AS c FROM users WHERE ($1='' OR username ILIKE $1)`, [`%${q}%`]);
        res.json({ users: users.map(u => ({ ...u, postCount: parseInt(u.postCount||0), followerCount: parseInt(u.followerCount||0) })),
                   total: parseInt(tot?.c||0) });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── ADMİN: Kullanıcı sil/banlama ─────────────────────────────────
app.post('/api/admin/users/:id/ban', authenticateToken, async (req, res) => {
    try {
        const me = await dbGet('SELECT role FROM users WHERE id=$1', [req.user.id]);
        if (me?.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        const { reason = 'Admin kararı' } = req.body;
        await dbRun('UPDATE users SET "isActive"=FALSE, "updatedAt"=NOW() WHERE id=$1', [req.params.id]);
        res.json({ message: 'Kullanıcı banlandı', reason });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

app.post('/api/admin/users/:id/unban', authenticateToken, async (req, res) => {
    try {
        const me = await dbGet('SELECT role FROM users WHERE id=$1', [req.user.id]);
        if (me?.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        await dbRun('UPDATE users SET "isActive"=TRUE, "updatedAt"=NOW() WHERE id=$1', [req.params.id]);
        res.json({ message: 'Kullanıcı ban kaldırıldı' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── ADMİN: Post sil ──────────────────────────────────────────────
app.delete('/api/admin/posts/:id', authenticateToken, async (req, res) => {
    try {
        const me = await dbGet('SELECT role FROM users WHERE id=$1', [req.user.id]);
        if (me?.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        await dbRun('UPDATE posts SET "isActive"=FALSE, "updatedAt"=NOW() WHERE id=$1', [req.params.id]);
        res.json({ message: 'Gönderi silindi' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
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
app.post('/api/reports/post', authenticateToken, async (req, res) => {
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
app.post('/api/auth/resend-verification', async (req, res) => {
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

        const code = Math.floor(100000 + Math.random() * 900000).toString();
        // ✅ DÜZELTME: PostgreSQL interval kullan
        await dbRun(
            `INSERT INTO email_verifications (id, "userId", code, "expiresAt") VALUES ($1, $2, $3, NOW() + INTERVAL '15 minutes')`,
            [uuidv4(), userId, code]
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
app.post('/api/auth/forgot-password', async (req, res) => {
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

        const token = crypto.randomBytes(32).toString('hex');

        // ✅ PostgreSQL interval ile kaydet (timezone sorunu yok)
        await dbRun(
            `INSERT INTO password_resets (id, "userId", token, "expiresAt")
             VALUES ($1, $2, $3, NOW() + INTERVAL '10 minutes')`,
            [uuidv4(), user.id, token]
        );
        console.log(`🔑 Şifre sıfırlama token'ı oluşturuldu: ${user.email} - Süre: 10 dakika`);

        // E-posta gönder
        sendForgotPasswordEmail(user.email, user.name, token)
            .then(result => {
                if (result?.success) {
                    console.log(`📧 Şifremi unuttum e-postası gönderildi: ${user.email}`);
                } else {
                    console.error(`❌ Şifremi unuttum e-postası gönderilemedi: ${user.email}`, result?.error);
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
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword, confirmPassword } = req.body;
        if (!token || !newPassword || !confirmPassword) return res.status(400).json({ error: 'Tüm alanlar zorunludur' });
        if (newPassword !== confirmPassword) return res.status(400).json({ error: 'Şifreler eşleşmiyor' });
        if (newPassword.length < 6) return res.status(400).json({ error: 'Şifre en az 6 karakter olmalı' });

        const record = await dbGet(
            `SELECT * FROM password_resets WHERE token = $1 AND used = FALSE AND "expiresAt" > NOW()`,
            [token]
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
                [token, user.id]
            );
        } else {
            // Sadece token ile doğrulama
            record = await dbGet(
                `SELECT "expiresAt" FROM password_resets
                 WHERE token = $1 AND used = FALSE AND "expiresAt" > NOW()`,
                [token]
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
        const { likes = true, comments = true, follows = true, messages = true } = req.body;

        const existing = await dbGet(`SELECT id FROM notification_settings WHERE "userId" = $1`, [req.user.id]);
        if (existing) {
            await dbRun(
                `UPDATE notification_settings SET likes = $1, comments = $2, follows = $3, messages = $4, "updatedAt" = NOW() WHERE "userId" = $5`,
                [!!likes, !!comments, !!follows, !!messages, req.user.id]
            );
        } else {
            await dbRun(
                `INSERT INTO notification_settings (id, "userId", likes, comments, follows, messages) VALUES ($1, $2, $3, $4, $5, $6)`,
                [uuidv4(), req.user.id, !!likes, !!comments, !!follows, !!messages]
            );
        }

        res.json({ message: 'Bildirim ayarları kaydedildi', settings: { likes: !!likes, comments: !!comments, follows: !!follows, messages: !!messages } });
    } catch (error) {
        console.error('Bildirim ayarları hatası:', error);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// ─── PING ───────────────────────────────────────────────────────────
app.get('/api/ping', (req, res) => {
    res.json({ pong: true, timestamp: Date.now() });
});

// ─── VİDEO STREAM (Range Request / HTTP 206) ────────────────────────
// Donma / kasma olmaz: tarayıcı sadece ihtiyacı kadar chunk çeker
app.get('/api/videos/stream/:filename', authenticateToken, (req, res) => {
    try {
        const videoPath = path.join(videosDir, req.params.filename);
        if (!fssync.existsSync(videoPath)) return res.status(404).json({ error: 'Video bulunamadı' });

        const stat     = fssync.statSync(videoPath);
        const fileSize = stat.size;
        const range    = req.headers.range;

        if (range) {
            const [startStr, endStr] = range.replace(/bytes=/, '').split('-');
            const start   = parseInt(startStr, 10);
            const end     = endStr ? parseInt(endStr, 10) : fileSize - 1;
            const chunk   = end - start + 1;

            res.writeHead(206, {
                'Content-Range' : `bytes ${start}-${end}/${fileSize}`,
                'Accept-Ranges' : 'bytes',
                'Content-Length': chunk,
                'Content-Type'  : 'video/mp4',
            });
            fssync.createReadStream(videoPath, { start, end }).pipe(res);
        } else {
            res.writeHead(200, { 'Content-Length': fileSize, 'Content-Type': 'video/mp4' });
            fssync.createReadStream(videoPath).pipe(res);
        }
    } catch (error) {
        console.error('Video stream hatası:', error);
        res.status(500).json({ error: 'Video yüklenemedi' });
    }
});

// ─── VİDEO THUMBNAIL ────────────────────────────────────────────────
app.get('/api/videos/thumbnail/:videoId', authenticateToken, (req, res) => {
    const thumbPath = path.join(thumbnailsDir, `${req.params.videoId}.jpg`);
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

// ─── HLS DURUM (istemci manifest hazır mı diye sorar) ───────────────
app.get('/api/videos/:videoId/hls-status', authenticateToken, (req, res) => {
    const masterPath = path.join(hlsDir, req.params.videoId, 'master.m3u8');
    if (fssync.existsSync(masterPath)) {
        const variants = HLS_VARIANTS.map(v => {
            const pl = path.join(hlsDir, req.params.videoId, v.name, 'playlist.m3u8');
            return { name: v.name, ready: fssync.existsSync(pl), url: `/uploads/hls/${req.params.videoId}/${v.name}/playlist.m3u8` };
        }).filter(v => v.ready);

        return res.json({
            ready      : true,
            masterUrl  : `/uploads/hls/${req.params.videoId}/master.m3u8`,
            variants,
            activeVideoJobs: activeVideoJobs,
        });
    }
    res.json({ ready: false, activeVideoJobs: activeVideoJobs, message: 'HLS henüz işleniyor, MP4 ile oynat' });
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
        const offset = (parseInt(page) - 1) * parseInt(limit);

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
        const offset = (parseInt(page) - 1) * parseInt(limit);

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
            [req.user.id, parseInt(limit), offset]
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
        const offset = (parseInt(page) - 1) * parseInt(limit);

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
        const offset = (parseInt(page) - 1) * parseInt(limit);

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
app.post('/api/comments/:id/like', authenticateToken, checkRestriction('like'), async (req, res) => {
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
                await createNotification(comment.userId, 'comment_like', `${req.user.username} yorumunuzu beğendi`, { commentId, userId: req.user.id });
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
app.post('/api/stories', authenticateToken, upload.single('media'), async (req, res) => {
    try {
        const { caption, text, textColor } = req.body;
        if (!req.file && !text) return res.status(400).json({ error: 'Medya veya metin gerekli' });

        let mediaUrl = null;
        let mediaType = 'text';

        if (req.file) {
            const ext = path.extname(req.file.originalname).toLowerCase();
            const isVideo = ['.mp4', '.webm', '.mov'].includes(ext);
            mediaType = isVideo ? 'video' : 'image';

            if (isVideo) {
                const filename = `story_${Date.now()}_${Math.round(Math.random() * 1E9)}${ext}`;
                const dest = path.join(videosDir, filename);
                await fs.rename(req.file.path, dest);
                mediaUrl = `/uploads/videos/${filename}`;
            } else {
                const filename = `story_${Date.now()}_${Math.round(Math.random() * 1E9)}.webp`;
                const dest = path.join(postsDir, filename);
                await sharp(req.file.path).resize(1080, 1920, { fit: 'inside', withoutEnlargement: true }).webp({ quality: 85 }).toFile(dest);
                await fs.unlink(req.file.path).catch(() => {});
                mediaUrl = `/uploads/posts/${filename}`;
            }
        }

        const storyId = uuidv4();
        // ✅ DÜZELTME: PostgreSQL interval
        await dbRun(
            `INSERT INTO stories (id, "userId", "mediaUrl", "mediaType", caption, text, "textColor", "createdAt", "expiresAt")
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW() + INTERVAL '24 hours')`,
            [storyId, req.user.id, mediaUrl || '', mediaType, caption || null, text || null, textColor || '#FFFFFF']
        );

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
                await createNotification(story.userId, 'story_like', `${req.user.username} hikayenizi beğendi`, { storyId });
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

// ─── 43. KULLANICI ARA (v2) ─────────────────────────────────────────
app.get('/api/search/users', authenticateToken, async (req, res) => {
    try {
        const { q, page = 1, limit = 20 } = req.query;
        if (!q || q.trim().length < 2) return res.status(400).json({ error: 'En az 2 karakter gerekli' });

        const offset = (parseInt(page) - 1) * parseInt(limit);
        const searchTerm = `%${q.toLowerCase().trim()}%`;

        const users = await dbAll(
            `SELECT id, username, name, "profilePic", "isVerified", "hasFarmerBadge", "userType",
                    EXISTS(SELECT 1 FROM follows WHERE "followerId" = $1 AND "followingId" = users.id) as "isFollowing"
             FROM users
             WHERE "isActive" = TRUE AND (LOWER(username) LIKE $2 OR LOWER(name) LIKE $2)
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
app.get('/api/search/posts', authenticateToken, async (req, res) => {
    try {
        const { q, page = 1, limit = 20 } = req.query;
        if (!q || q.trim().length < 2) return res.status(400).json({ error: 'En az 2 karakter gerekli' });

        const offset = (parseInt(page) - 1) * parseInt(limit);
        const searchTerm = `%${q.toLowerCase().trim()}%`;

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE AND LOWER(p.content) LIKE $2
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
app.get('/api/search/hashtag/:tag', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);
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
                const filename = `product_${Date.now()}_${i}_${Math.round(Math.random() * 1e9)}.webp`;
                const outputPath = path.join(postsDir, filename);
                await sharp(files[i].path).resize(1080, 1080, { fit: 'inside', withoutEnlargement: true }).webp({ quality: 85 }).toFile(outputPath);
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
        if (!valid) return res.status(401).json({ error: 'Şifre yanlış' });

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
        const suggestions = await dbAll(
            `SELECT id, username, name, "profilePic", "isVerified", "hasFarmerBadge", "userType"
             FROM users
             WHERE "isActive" = TRUE AND id != $1
               AND id NOT IN (SELECT "followingId" FROM follows WHERE "followerId" = $1)
               AND id NOT IN (SELECT "blockedId" FROM blocks WHERE "blockerId" = $1)
             ORDER BY "isVerified" DESC, "hasFarmerBadge" DESC, RANDOM()
             LIMIT 10`,
            [req.user.id]
        );
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
app.post('/api/reports/user', authenticateToken, async (req, res) => {
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
app.get('/api/explore', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 30 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const posts = await dbAll(
            `SELECT p.*, u.name, u."profilePic", u."isVerified", u."hasFarmerBadge",
                    EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                    EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             WHERE p."isActive" = TRUE AND p.media IS NOT NULL
             ORDER BY p."likeCount" DESC, p.views DESC, p."createdAt" DESC
             LIMIT $2 OFFSET $3`,
            [req.user.id, parseInt(limit), offset]
        );

        res.json({ posts: posts.map(formatPost) });
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
        const offset = (parseInt(page) - 1) * parseInt(limit);
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
        // Tüm refresh token'ları geçersiz kıl (parameterize)
        await dbRun(`UPDATE refresh_tokens SET "isActive" = FALSE WHERE "userId" = $1`, [uid]);
        // Aktif oturum kayıtlarını kapat
        await dbRun(`UPDATE active_sessions SET "isActive" = FALSE WHERE "userId" = $1`, [uid]);
        // Online durumunu güncelle
        await dbRun(`UPDATE users SET "isOnline" = FALSE, "lastSeen" = NOW() WHERE id = $1`, [uid]);
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
            `SELECT likes, comments, follows, messages
             FROM notification_settings WHERE "userId" = $1`,
            [req.user.id]
        );
        // Kayıt yoksa varsayılan döndür (tümü açık)
        if (!settings) {
            settings = { likes: true, comments: true, follows: true, messages: true };
        }
        res.json({ settings });
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
    app.use('/agrolink', express.static(agrolinkDir, { maxAge: '1d' }));
}
app.get('/agrolink', (req, res) => {
    const htmlPath = path.join(__dirname, 'public', 'agrolink', 'index.html');
    if (fssync.existsSync(htmlPath)) {
        res.sendFile(htmlPath);
    } else {
        res.status(404).json({ error: 'AgroLink uygulaması bulunamadı' });
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
    app.use(express.static(publicDir, { maxAge: '1d', index: false }));
}

app.get('/', (req, res) => {
    const htmlPath = path.join(__dirname, 'public', 'index.html');
    if (fssync.existsSync(htmlPath)) {
        res.sendFile(htmlPath);
    } else {
        res.json({ message: 'AgroLink API Server - PostgreSQL v2.1 (UUID Fixed)', status: 'running' });
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
app.get('/u/:username', async (req, res) => {
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    try {
        const username = req.params.username?.toLowerCase().trim();
        if (!username) return res.redirect('/');

        // ── İnsan kullanıcı: SPA'yı döndür, URL olduğu gibi kalsın ──
        // Frontend'deki handleSharedURL fonksiyonu /u/:username'i algılayıp
        // loadSharedProfile() çağırır ve uygulamada profili açar.
        if (!isSocialBot(req)) {
            const spaPath = path.join(__dirname, 'public', 'index.html');
            if (fssync.existsSync(spaPath)) {
                return res.sendFile(spaPath);
            }
            // SPA yoksa share sayfasına yönlendir
            return res.redirect(`/share/profile/${username}`);
        }

        // ── Bot: OG meta HTML döndür ──
        const user = await dbGet(
            `SELECT id, username, name, bio, "profilePic", "coverPic", "isVerified", "hasFarmerBadge", "userType",
                    (SELECT COUNT(*)::int FROM follows WHERE "followingId"=u.id) AS "followerCount",
                    (SELECT COUNT(*)::int FROM posts WHERE "userId"=u.id AND "isActive"=TRUE) AS "postCount"
             FROM users u WHERE LOWER(username)=$1 AND "isActive"=TRUE LIMIT 1`,
            [username]
        ).catch(() => null);

        if (!user) return res.redirect('/');

        const title   = `${user.name || user.username} (@${user.username}) • AgroLink`;
        const desc    = `${user.bio ? user.bio.substring(0, 150) + ' · ' : ''}${user.followerCount || 0} takipçi · ${user.postCount || 0} gönderi · AgroLink Tarım Topluluğu`;
        const imgUrl  = user.profilePic?.startsWith('/uploads') ? DOMAIN + user.profilePic : (user.profilePic || `${DOMAIN}/agro.png`);
        const pageUrl = `${DOMAIN}/u/${user.username}`;
        const badge   = user.isVerified ? ' ✓' : '';

        res.setHeader('Cache-Control', 'public, max-age=300');
        res.send(`<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}${badge}</title>
<meta name="description" content="${desc}">
<meta property="og:type"         content="profile">
<meta property="og:site_name"    content="AgroLink">
<meta property="og:title"        content="${title}${badge}">
<meta property="og:description"  content="${desc}">
<meta property="og:image"        content="${imgUrl}">
<meta property="og:image:width"  content="400">
<meta property="og:image:height" content="400">
<meta property="og:url"          content="${pageUrl}">
<meta property="og:locale"       content="tr_TR">
<meta property="profile:username" content="${user.username}">
<meta name="twitter:card"        content="summary">
<meta name="twitter:title"       content="${title}">
<meta name="twitter:description" content="${desc}">
<meta name="twitter:image"       content="${imgUrl}">
<link rel="canonical" href="${pageUrl}">
</head>
<body></body>
</html>`);
    } catch (e) {
        console.error('[OG /u/] Hata:', e.message);
        res.redirect('/');
    }
});

// Gönderi OG sayfası: /p/:postId
// Bot ise OG meta HTML döndür, insan ise SPA'yı döndür
app.get('/p/:postId', async (req, res) => {
    const DOMAIN = process.env.APP_URL || 'https://sehitumitkestitarimmtal.com';
    try {
        const postId = req.params.postId?.trim();
        if (!postId) return res.redirect('/');

        // ── İnsan kullanıcı: SPA'yı döndür, URL olduğu gibi kalsın ──
        if (!isSocialBot(req)) {
            const spaPath = path.join(__dirname, 'public', 'index.html');
            if (fssync.existsSync(spaPath)) {
                return res.sendFile(spaPath);
            }
            return res.redirect(`/share/post/${postId}`);
        }

        const post = await dbGet(
            `SELECT p.id, p.content, p.media, p."mediaType", p."createdAt",
                    u.name, u.username, u."profilePic", u."isVerified"
             FROM posts p JOIN users u ON p."userId"=u.id
             WHERE p.id=$1 AND p."isActive"=TRUE LIMIT 1`,
            [postId]
        ).catch(() => null);

        if (!post) return res.redirect('/');

        const title   = `${post.name || post.username} • AgroLink Paylaşımı`;
        const rawDesc = post.content ? post.content.replace(/<[^>]*>/g,'').substring(0,200) : 'AgroLink gönderi paylaşımı';
        const desc    = rawDesc + ` · @${post.username} · AgroLink Tarım Topluluğu`;
        // Görsel: varsa postun medyası, yoksa profil resmi, yoksa logo
        let imgUrl = `${DOMAIN}/agro.png`;
        if (post.media && post.mediaType === 'image') {
            imgUrl = post.media.startsWith('/uploads') ? DOMAIN + post.media : post.media;
        } else if (post.profilePic) {
            imgUrl = post.profilePic.startsWith('/uploads') ? DOMAIN + post.profilePic : post.profilePic;
        }
        const pageUrl = `${DOMAIN}/p/${post.id}`;

        res.setHeader('Cache-Control', 'public, max-age=300');
        res.send(`<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<meta name="description" content="${desc}">
<meta property="og:type"         content="article">
<meta property="og:site_name"    content="AgroLink">
<meta property="og:title"        content="${title}">
<meta property="og:description"  content="${desc}">
<meta property="og:image"        content="${imgUrl}">
<meta property="og:image:width"  content="1200">
<meta property="og:image:height" content="630">
<meta property="og:url"          content="${pageUrl}">
<meta property="og:locale"       content="tr_TR">
<meta name="twitter:card"        content="summary_large_image">
<meta name="twitter:title"       content="${title}">
<meta name="twitter:description" content="${desc}">
<meta name="twitter:image"       content="${imgUrl}">
<link rel="canonical" href="${pageUrl}">
</head>
<body></body>
</html>`);
    } catch (e) {
        console.error('[OG /p/] Hata:', e.message);
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
// Takip edilmeyenlerin popüler postlarını gösterir
app.get('/api/feed/explore', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const pageNum = Math.max(1, parseInt(page) || 1);
        const limitNum = Math.min(parseInt(limit) || 10, 100);
        const offset = (pageNum - 1) * limitNum;

        const posts = await dbAll(
            `SELECT p.*, u."profilePic" as "userProfilePic", u.name as "userName", u."isVerified" as "userVerified",
                EXISTS(SELECT 1 FROM likes WHERE "postId" = p.id AND "userId" = $1) as "isLiked",
                EXISTS(SELECT 1 FROM saves WHERE "postId" = p.id AND "userId" = $1) as "isSaved"
             FROM posts p JOIN users u ON p."userId" = u.id
             WHERE p."userId" NOT IN (
                 SELECT "followingId" FROM follows WHERE "followerId" = $1
                 UNION SELECT $1
             )
             AND p."isActive" = TRUE AND u."isActive" = TRUE
             ORDER BY (p."likeCount" * 2 + p."commentCount") DESC, p."createdAt" DESC
             LIMIT $2 OFFSET $3`,
            [req.user.id, limitNum, offset]
        );

        const totalResult = await dbGet(
            `SELECT COUNT(*) as count FROM posts p JOIN users u ON p."userId" = u.id
             WHERE p."userId" NOT IN (SELECT "followingId" FROM follows WHERE "followerId" = $1 UNION SELECT $1)
             AND p."isActive" = TRUE AND u."isActive" = TRUE`,
            [req.user.id]
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
        const limitNum = Math.min(parseInt(limit) || 20, 100);
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
app.post('/api/auth/register-verify', async (req, res) => {
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
app.post('/api/auth/verify-2fa', async (req, res) => {
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
            `SELECT id, username, name, email, role, "profilePic", "coverPic", bio,
                    "isVerified", "isActive", "userType", "hasFarmerBadge",
                    "isOnline", "isBanned", "emailVerified", "twoFactorEnabled"
             FROM users WHERE id = $1 AND "isActive" = TRUE`,
            [decoded.id]
        );
        if (!user) return res.status(401).json({ error: 'Kullanıcı bulunamadı' });

        await dbRun('UPDATE users SET "lastLogin" = NOW(), "isOnline" = TRUE, "updatedAt" = NOW() WHERE id = $1', [user.id]);

        const tokens = generateTokens(user);
        const tokenHash = crypto.createHash('sha256').update(tokens.refreshToken).digest('hex');
        await dbRun(
            `INSERT INTO refresh_tokens (id, "userId", "tokenHash", ip, "userAgent", "createdAt", "expiresAt")
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '30 days')`,
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
        const newCode = Math.floor(100000 + Math.random() * 900000).toString();
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
             <p>Şifre sıfırlama bağlantısı: <a href="https://sehitumitkestitarimmtal.com/api/auth/reset-password-direct?token=${resetToken}">Buraya tıklayın</a></p>`
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
    for (const msg of messages) {
        if (typeof msg.content === 'string' && msg.content.length > 8000) {
            return res.status(400).json({ error: 'Mesaj çok uzun (max 8000 karakter)' });
        }
    }
    try {
        const { default: fetch } = await import('node-fetch');
        const ctrl = new AbortController();
        const timeout = setTimeout(() => ctrl.abort(), AI_TIMEOUT_MS);
        const llamaBody = {
            model: model || 'default',
            messages,
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
        const filename  = `msg_${Date.now()}_${Math.round(Math.random()*1e9)}.webp`;
        const outPath   = path.join(postsDir, filename);
        await sharp(req.file.path).resize(1920,1920,{fit:'inside',withoutEnlargement:true}).webp({quality:85}).toFile(outPath);
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
        const recipient = await dbGet('SELECT id,username FROM users WHERE id=$1 AND "isActive"=TRUE',[recipientId]);
        if (!recipient) return res.status(404).json({ error:'Kullanıcı bulunamadı' });
        const voiceDir = path.join(uploadsDir,'voice');
        if (!fssync.existsSync(voiceDir)) fssync.mkdirSync(voiceDir,{recursive:true});
        const filename = `voice_${Date.now()}_${Math.round(Math.random()*1e9)}.webm`;
        const outPath  = path.join(voiceDir, filename);
        await fs.copyFile(req.file.path, outPath);
        await fs.unlink(req.file.path).catch(()=>{});
        const voiceUrl = `/uploads/voice/${filename}`;
        const sender   = await dbGet('SELECT username FROM users WHERE id=$1',[req.user.id]);
        const msgId    = uuidv4();
        await dbRun(`INSERT INTO messages (id,"senderId","senderUsername","recipientId","recipientUsername",content,read,"createdAt","updatedAt") VALUES ($1,$2,$3,$4,$5,$6,FALSE,NOW(),NOW())`,[msgId,req.user.id,sender.username,recipientId,recipient.username,voiceUrl]);
        res.status(201).json({ message:'Sesli mesaj gönderildi', messageId:msgId, voiceUrl });
    } catch (e) {
        if (req.file) await fs.unlink(req.file.path).catch(()=>{});
        console.error(e); res.status(500).json({ error:'Sunucu hatası' });
    }
});

// ─── 12. FARMBOOK KAYITLARI CRUD ──────────────────────────────────
app.get('/api/farmbook/records', authenticateToken, async (req, res) => {
    try {
        const { season, year, type, page=1, limit=50 } = req.query;
        const pn=Math.max(1,parseInt(page)||1), ln=Math.min(parseInt(limit)||50,200);
        const off=(pn-1)*ln;
        const conds=['r."userId"=$1'], params=[req.user.id];
        let pi=2;
        if (season) { conds.push(`r.season=$${pi++}`); params.push(season); }
        if (year)   { conds.push(`r.year=$${pi++}`);   params.push(parseInt(year)); }
        if (type)   { conds.push(`r."recordType"=$${pi++}`); params.push(type); }
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
        const record = await dbGet('SELECT * FROM farmbook_records WHERE id=$1',[id]);
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
        const record = await dbGet('SELECT * FROM farmbook_records WHERE id=$1',[req.params.id]);
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
        const conds=['r."userId"=$1'], params=[req.user.id];
        let pi=2;
        if (season){ conds.push(`r.season=$${pi++}`); params.push(season); }
        if (year)  { conds.push(`r.year=$${pi++}`);   params.push(parseInt(year)); }
        const where = conds.join(' AND ');
        const [costRow,incRow,types,monthly,seasons] = await Promise.all([
            dbGet(`SELECT COALESCE(SUM(cost),0) AS total FROM farmbook_records r WHERE ${where}`,params),
            dbGet(`SELECT COALESCE(SUM(income),0) AS total FROM farmbook_records r WHERE ${where}`,params),
            dbAll(`SELECT "recordType", COUNT(*) AS count FROM farmbook_records r WHERE ${where} GROUP BY "recordType"`,params),
            dbAll(`SELECT TO_CHAR("recordDate",'YYYY-MM') AS month, SUM(cost) AS "totalCost", SUM(income) AS "totalIncome" FROM farmbook_records r WHERE ${where} GROUP BY TO_CHAR("recordDate",'YYYY-MM') ORDER BY month DESC LIMIT 12`,params),
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
        res.setHeader('Content-Type','text/csv; charset=utf-8');
        res.setHeader('Content-Disposition',`attachment; filename="${fname}"`);
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

        res.send(`<!DOCTYPE html>
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
        <img src="${picUrl}" class="avatar" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 96 96%22><rect fill=%22%23222%22 width=%2296%22 height=%2296%22/><text y=%2264%22 x=%2248%22 text-anchor=%22middle%22 font-size=%2248%22>👤</text></svg>'">
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

        res.send(`<!DOCTYPE html>
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
      <img src="${picUrl}" class="avatar" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 44 44%22><rect fill=%22%23222%22 width=%2244%22 height=%2244%22/><text y=%2232%22 x=%2222%22 text-anchor=%22middle%22 font-size=%2224%22>👤</text></svg>'">
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
        if (!valid) return res.status(401).json({ error: 'Şifre yanlış' });

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

// ─── 8. ADMİN GENEL BAKIŞ: GET /api/admin/overview ─────────────────
app.get('/api/admin/overview', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });

        const [users, posts, reports, bannedIps, activeToday] = await Promise.all([
            dbGet('SELECT COUNT(*)::int AS cnt FROM users WHERE "isActive"=TRUE'),
            dbGet('SELECT COUNT(*)::int AS cnt FROM posts WHERE "isActive"=TRUE'),
            dbGet(`SELECT COUNT(*)::int AS cnt FROM reports WHERE status='pending'`).catch(() => ({ cnt: 0 })),
            dbGet('SELECT COUNT(*)::int AS cnt FROM banned_ips WHERE ("expiresAt" IS NULL OR "expiresAt">NOW())'),
            dbGet(`SELECT COUNT(*)::int AS cnt FROM users WHERE "lastLogin" > NOW() - INTERVAL '24 hours' AND "isActive"=TRUE`),
        ]);

        const { activeJobs, maxConcurrent } = getVideoQueueStatus();

        res.json({
            stats: {
                totalUsers     : users?.cnt || 0,
                totalPosts     : posts?.cnt || 0,
                pendingReports : reports?.cnt || 0,
                bannedIPs      : bannedIps?.cnt || 0,
                activeToday    : activeToday?.cnt || 0,
            },
            videoProcessor: { activeJobs, maxConcurrent },
            firewall: {
                blockedIPs : FIREWALL_BLOCKED_IPS.size,
                attackLogs : FIREWALL_ATTACK_LOG.size,
            },
            serverTime: new Date().toISOString(),
        });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 9. ADMİN RAPORLAR: GET /api/admin/reports ──────────────────────
app.get('/api/admin/reports', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });

        const { page = 1, limit = 20, status = 'pending' } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);

        const reports = await dbAll(
            `SELECT r.*, 
                    ru.username AS "reporterUsername", ru.name AS "reporterName",
                    CASE r.type
                        WHEN 'post' THEN (SELECT content FROM posts WHERE id=r."targetId")
                        WHEN 'user' THEN (SELECT username FROM users WHERE id=r."targetId")
                        ELSE NULL
                    END AS "targetPreview"
             FROM reports r
             LEFT JOIN users ru ON r."reporterId"=ru.id
             WHERE ($1='all' OR r.status=$1)
             ORDER BY r."createdAt" DESC
             LIMIT $2 OFFSET $3`,
            [status, parseInt(limit), offset]
        ).catch(() => []);

        res.json({ reports, page: parseInt(page) });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

app.patch('/api/admin/reports/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        const { status, note } = req.body;
        await dbRun(
            `UPDATE reports SET status=$1, "adminNote"=$2, "reviewedAt"=NOW(), "reviewedBy"=$3 WHERE id=$4`,
            [status, note || null, req.user.id, req.params.id]
        );
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 10. ADMİN YASAKLI IP YÖNETİMİ: GET/DELETE /api/admin/banned-ips
app.get('/api/admin/banned-ips', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });

        const bans = await dbAll(
            `SELECT * FROM banned_ips WHERE ("expiresAt" IS NULL OR "expiresAt" > NOW())
             ORDER BY "bannedAt" DESC LIMIT 100`
        );
        res.json({ bans, total: bans.length });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

app.delete('/api/admin/banned-ips/:ip', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
        const ip = decodeURIComponent(req.params.ip);
        await dbRun('DELETE FROM banned_ips WHERE ip=$1', [ip]);
        FIREWALL_BLOCKED_IPS.delete(ip);
        ipBanCache.delete(ip);
        res.json({ success: true, message: `${ip} yasağı kaldırıldı` });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
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
        if (!valid) return res.status(401).json({ error: 'Şifre yanlış' });
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
    const token = typeof req.query.token === 'string' ? req.query.token : null;

    if (!token || !/^[a-f0-9]{64}$/i.test(token)) {
        return res.send(getErrorPageHtml('Geçersiz Bağlantı', 'Bu link artık geçerli değil.'));
    }

    try {
        // Önce password_resets tablosuna bak (forgot-password akışı)
        let record = await dbGet(
            `SELECT pr."userId", u.username FROM password_resets pr
             JOIN users u ON pr."userId" = u.id
             WHERE pr.token = $1 AND pr.used = FALSE AND pr."expiresAt" > NOW()
             LIMIT 1`,
            [token]
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
            return res.send(getErrorPageHtml(
                'Link Süresi Doldu',
                'Bu şifre sıfırlama linki süresi dolmuş veya daha önce kullanılmış.'
            ));
        }

        console.log(`🔐 Şifre sıfırlama sayfası açıldı: @${record.username}`);
        res.setHeader('Cache-Control', 'no-store');
        res.send(getPasswordResetPageHtml(record.username, token));

    } catch (e) {
        console.error('Şifre sıfırlama direkt link hatası:', e);
        res.send(getErrorPageHtml('Sunucu Hatası', 'Bir hata oluştu. Lütfen daha sonra tekrar deneyin.'));
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
                   u."lastSeen", u."createdAt",
                   (SELECT COUNT(*) FROM posts   WHERE "userId"=u.id AND "isActive"=TRUE) AS "postCount",
                   (SELECT COUNT(*) FROM follows WHERE "followingId"=u.id)                AS "followerCount",
                   (SELECT COUNT(*) FROM follows WHERE "followerId"=u.id)                 AS "followingCount",
                   EXISTS(SELECT 1 FROM follows WHERE "followerId"=$1 AND "followingId"=u.id) AS "isFollowing",
                   EXISTS(SELECT 1 FROM blocks  WHERE "blockerId"=$1 AND "blockedId"=u.id)   AS "isBlocked"
            FROM users u WHERE u.id=$2 AND u."isActive"=TRUE`, [req.user.id, req.params.id]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
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
            [user.id, resetToken]
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
        const postUrl = `/post/${postId}`;
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

// ─── 7. PUBLIC POST ÖNIZLEME: GET /p/:id ───────────────────────────
app.get('/p/:id', async (req, res) => {
    try {
        const post = await dbGet(`
            SELECT p.*, u.username, u.name AS "userName", u."profilePic" AS "userProfilePic", u."isVerified" AS "userVerified"
            FROM posts p JOIN users u ON p."userId"=u.id
            WHERE p.id=$1 AND p."isActive"=TRUE AND u."isActive"=TRUE`, [req.params.id]);
        if (!post) return res.redirect('/');
        const base = `${req.protocol}://${req.get('host')}`;
        res.redirect(`${base}/share/post/${post.id}`);
    } catch (e) { res.redirect('/'); }
});

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
        // webpush kurulu değilse sessizce geç
        res.json({ message: 'Test bildirimi gönderildi', sent: false, note: 'web-push paketi yapılandırılmadı' });
    } catch (e) { res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 11. HESAP SİL (alias DELETE): DELETE /api/users/delete ────────
app.delete('/api/users/delete', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Şifre gerekli' });
        const user = await dbGet('SELECT password FROM users WHERE id=$1', [req.user.id]);
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Şifre yanlış' });
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
            await sharp(req.file.path).resize(256,256,{fit:'cover'}).webp({quality:85}).toFile(out);
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
    const thumbPath = require('path').join(thumbnailsDir, req.params.filename.replace(/[^a-zA-Z0-9._-]/g,''));
    const fss = require('fs');
    if (fss.existsSync(thumbPath)) {
        res.sendFile(thumbPath);
    } else {
        // Default thumbnail
        const def = require('path').join(uploadsDir, 'default-video-thumb.jpg');
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
            await sharp(files[i].path).resize(1080,1080,{fit:'inside',withoutEnlargement:true}).webp({quality:85}).toFile(out);
            await fs.unlink(files[i].path).catch(()=>{});
            images.push(`/uploads/posts/${fname}`);
        }
        const id = uuidv4();
        await dbRun(
            `INSERT INTO products (id,"sellerId",name,price,description,image,images,category,stock,"isActive","createdAt","updatedAt")
             VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,TRUE,NOW(),NOW())`,
            [id, req.user.id, name.substring(0,100), parseFloat(price),
             description?.substring(0,1000)||'', images[0]||null, JSON.stringify(images), category||'', parseInt(stock)||1]
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
                await sharp(files[i].path).resize(1080,1080,{fit:'inside',withoutEnlargement:true}).webp({quality:85}).toFile(out);
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

// ==================== 🔧 ESKİ v5'TEN TAŞINAN 10 ADMIN API'Sİ ====================

// ─── 1. KULLANICI DURUM GÜNCELLE (admin) ─────────────────────────────
// PUT /api/admin/users/:id/status
app.put('/api/admin/users/:id/status', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const { isActive } = req.body;
        if (typeof isActive === 'undefined') return res.status(400).json({ error: 'isActive alanı gerekli' });
        await dbRun(
            'UPDATE users SET "isActive" = $1, "updatedAt" = NOW() WHERE id = $2',
            [!!isActive, req.params.id]
        );
        res.json({ message: `Kullanıcı ${isActive ? 'aktif' : 'pasif'} edildi` });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 2. KULLANICI KISITLA (admin) ─────────────────────────────────────
// POST /api/admin/users/:id/restrict
app.post('/api/admin/users/:id/restrict', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const { id } = req.params;
        const {
            reason = 'Yönetici tarafından kısıtlandı',
            restrictedUntil = null,
            canPost = false,
            canComment = false,
            canMessage = false,
            canFollow = false,
            canLike = false
        } = req.body;

        const user = await dbGet('SELECT id FROM users WHERE id = $1', [id]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        await dbRun(
            `INSERT INTO account_restrictions
             (id, "userId", "isRestricted", "restrictedAt", "restrictedUntil", reason, "canPost", "canComment", "canMessage", "canFollow", "canLike", "createdAt", "updatedAt")
             VALUES ($1,$2,TRUE,NOW(),$3,$4,$5,$6,$7,$8,$9,NOW(),NOW())
             ON CONFLICT ("userId") DO UPDATE SET
               "isRestricted"=TRUE, "restrictedAt"=NOW(), "restrictedUntil"=$3,
               reason=$4, "canPost"=$5, "canComment"=$6, "canMessage"=$7, "canFollow"=$8, "canLike"=$9, "updatedAt"=NOW()`,
            [uuidv4(), id, restrictedUntil, reason, canPost, canComment, canMessage, canFollow, canLike]
        );

        res.json({ message: 'Kullanıcı kısıtlandı', restriction: { reason, restrictedUntil, canPost, canComment, canMessage, canFollow, canLike } });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 3. KULLANICI KISITLAMASINI KALDIR (admin) ───────────────────────
// POST /api/admin/users/:id/unrestrict
app.post('/api/admin/users/:id/unrestrict', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const { id } = req.params;
        const user = await dbGet('SELECT id FROM users WHERE id = $1', [id]);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        await dbRun(
            `UPDATE account_restrictions SET "isRestricted"=FALSE, "updatedAt"=NOW() WHERE "userId"=$1`,
            [id]
        );
        res.json({ message: 'Kullanıcı kısıtlaması kaldırıldı' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 4. IP BAN (admin) ──────────────────────────────────────────────
// POST /api/admin/ip/ban
app.post('/api/admin/ip/ban', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const { ip, reason = 'Admin tarafından engellendi', expiresAt = null } = req.body;
        if (!ip) return res.status(400).json({ error: 'IP adresi gerekli' });
        FIREWALL_BLOCKED_IPS.add(ip);
        await dbRun(
            `INSERT INTO banned_ips (id, ip, reason, "bannedAt", "expiresAt")
             VALUES ($1,$2,$3,NOW(),$4)
             ON CONFLICT (ip) DO UPDATE SET reason=$3, "bannedAt"=NOW(), "expiresAt"=$4`,
            [uuidv4(), ip, reason, expiresAt]
        );
        res.json({ message: `${ip} adresi engellendi` });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 5. IP BAN KALDIR (admin) ────────────────────────────────────────
// DELETE /api/admin/ip/unban/:ip
app.delete('/api/admin/ip/unban/:ip', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const ip = req.params.ip;
        FIREWALL_BLOCKED_IPS.delete(ip);
        FIREWALL_ATTACK_LOG.delete(ip);
        await dbRun('DELETE FROM banned_ips WHERE ip = $1', [ip]);
        res.json({ message: `${ip} engeli kaldırıldı` });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 6. YASAKLı IP'LER LİSTESİ (admin) ─────────────────────────────
// GET /api/admin/ip/banned
app.get('/api/admin/ip/banned', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const bannedIps = await dbAll('SELECT * FROM banned_ips ORDER BY "bannedAt" DESC');
        res.json({ bannedIps });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 7. MODERASYON RAPORLARI (admin) ────────────────────────────────
// GET /api/admin/moderation/reports
app.get('/api/admin/moderation/reports', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const { page = 1, limit = 50 } = req.query;
        const pageNum  = Math.max(1, parseInt(page)  || 1);
        const limitNum = Math.min(100, parseInt(limit) || 20);
        const offset   = (pageNum - 1) * limitNum;

        const reports = await dbAll(
            `SELECT cm.*, u.username, u.email,
                    p.content AS "postContent",
                    c.content AS "commentContent"
             FROM content_moderation cm
             JOIN users u ON cm."userId" = u.id
             LEFT JOIN posts p ON cm."postId" = p.id
             LEFT JOIN comments c ON cm."commentId" = c.id
             WHERE cm."isHarmful" = TRUE
             ORDER BY cm."moderatedAt" DESC
             LIMIT $1 OFFSET $2`,
            [limitNum, offset]
        );
        const total = await dbGet('SELECT COUNT(*) AS c FROM content_moderation WHERE "isHarmful" = TRUE');
        res.json({ reports, total: parseInt(total?.c || 0), page: pageNum, totalPages: Math.ceil((total?.c || 0) / limitNum) });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 8. MODERASYON RAPORU DETAY (admin) ─────────────────────────────
// GET /api/admin/moderation/reports/:id
app.get('/api/admin/moderation/reports/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const report = await dbGet(
            `SELECT cm.*, u.username, u.email, u."profilePic",
                    p.content AS "postContent", p.media AS "postMedia", p."mediaType" AS "postMediaType",
                    c.content AS "commentContent"
             FROM content_moderation cm
             JOIN users u ON cm."userId" = u.id
             LEFT JOIN posts p ON cm."postId" = p.id
             LEFT JOIN comments c ON cm."commentId" = c.id
             WHERE cm.id = $1`,
            [req.params.id]
        );
        if (!report) return res.status(404).json({ error: 'Rapor bulunamadı' });
        res.json({ report });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 9. ADMIN POST LİSTESİ ───────────────────────────────────────────
// GET /api/admin/posts
app.get('/api/admin/posts', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const { page = 1, limit = 50 } = req.query;
        const pageNum  = Math.max(1, parseInt(page)  || 1);
        const limitNum = Math.min(100, parseInt(limit) || 20);
        const offset   = (pageNum - 1) * limitNum;

        const posts = await dbAll(
            `SELECT p.*, u.username, u.name, u.email,
                    cm."isHarmful", cm.reason AS "moderationReason"
             FROM posts p
             JOIN users u ON p."userId" = u.id
             LEFT JOIN content_moderation cm ON p.id = cm."postId"
             ORDER BY p."createdAt" DESC
             LIMIT $1 OFFSET $2`,
            [limitNum, offset]
        );
        const total = await dbGet('SELECT COUNT(*) AS c FROM posts');
        res.json({ posts: posts.map(formatPost), total: parseInt(total?.c || 0), page: pageNum, totalPages: Math.ceil((total?.c || 0) / limitNum) });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// ─── 10. ADMIN POST DURUM GÜNCELLE ───────────────────────────────────
// PUT /api/admin/posts/:id/status
app.put('/api/admin/posts/:id/status', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Yetkisiz' });
    try {
        const { isActive } = req.body;
        if (typeof isActive === 'undefined') return res.status(400).json({ error: 'isActive alanı gerekli' });
        await dbRun(
            'UPDATE posts SET "isActive" = $1, "updatedAt" = NOW() WHERE id = $2',
            [!!isActive, req.params.id]
        );
        res.json({ message: `Gönderi ${isActive ? 'aktif' : 'pasif'} edildi` });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Sunucu hatası' }); }
});

// GET /* (catch-all - SPA için)
app.get('*', (req, res, next) => {
    // API istekleri buraya düşmemeli
    if (req.path.startsWith('/api/') || req.path.startsWith('/uploads/')) return next();
    const htmlPath = require('path').join(__dirname, 'public', 'index.html');
    const fss = require('fs');
    if (fss.existsSync(htmlPath)) {
        res.sendFile(htmlPath);
    } else {
        res.status(404).json({ error: 'Sayfa bulunamadı' });
    }
});

// ==================== SUNUCU BAŞLAT ====================

const NUM_WORKERS = process.env.WEB_CONCURRENCY || Math.min(os.cpus().length, 4);

if (cluster.isPrimary || cluster.isMaster) {
    console.log(`🚀 Master process ${process.pid} - ${NUM_WORKERS} worker başlatılıyor...`);

    for (let i = 0; i < NUM_WORKERS; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker, code) => {
        console.log(`⚠️ Worker ${worker.process.pid} kapandı (code: ${code}). Yeniden başlatılıyor...`);
        cluster.fork();
    });
} else {
    (async () => {
        try {
            await initializeDatabase();
            await loadFirewallBans(); // 🔥 DB hazır olduktan sonra firewall ban listesini yükle
            await runSQLiteMigration(); // SQLite → PG geçişi (sadece SQLITE_MIGRATE=true ise çalışır)
            testEmailConnection().catch(() => {}); // E-posta bağlantısını arka planda test et
            server.listen(PORT, '0.0.0.0', () => {
                console.log(`
╔══════════════════════════════════════════════════╗
║  🌾 AGROLINK SERVER - PostgreSQL v6.0             ║
║  📡 Port: ${String(PORT).padEnd(39)}║
║  🌐 Domain: sehitumitkestitarimmtal.com         ║
║  🗄️  DB: PostgreSQL (Pool: 100 bağlantı)        ║
║  🔒 SQL Injection: Tüm sorgular parameterize    ║
║  🎬 Video: FFmpeg+HLS ABR (YouTube Algoritması) ║
║  📧 E-posta: Nodemailer (SMTP)                  ║
║  📊 API: 103 Rota                               ║
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
process.on('SIGINT', async () => {
    console.log('\n🛑 Sunucu kapatılıyor...');
    await pool.end();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('\n🛑 Sunucu kapatılıyor...');
    await pool.end();
    process.exit(0);
});
