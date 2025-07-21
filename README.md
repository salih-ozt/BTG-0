<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Chatwell S13 - Tam Çalışan Yapay Zeka</title>
<style>
  body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: #121212;
    color: #eee;
    margin: 0; padding: 10px;
    display: flex;
    flex-direction: column;
    height: 100vh;
  }
  #chat {
    flex-grow: 1;
    overflow-y: auto;
    padding: 15px;
    border: 1px solid #444;
    border-radius: 8px;
    background: #1e1e1e;
    margin-bottom: 10px;
  }
  .message {
    margin-bottom: 12px;
    max-width: 75%;
    padding: 10px 14px;
    border-radius: 15px;
    line-height: 1.3;
    word-wrap: break-word;
  }
  .user {
    background: #00bfa5;
    align-self: flex-end;
    color: #121212;
  }
  .bot {
    background: #333;
    align-self: flex-start;
  }
  #inputArea {
    display: flex;
    gap: 8px;
  }
  input[type="text"] {
    flex-grow: 1;
    padding: 12px;
    font-size: 16px;
    border-radius: 10px;
    border: none;
    outline: none;
    background: #222;
    color: #eee;
  }
  button {
    padding: 12px 18px;
    font-size: 16px;
    border-radius: 10px;
    border: none;
    background-color: #00bfa5;
    color: #121212;
    cursor: pointer;
  }
  button#updateBtn {
    background-color: #ff5722;
    margin-bottom: 10px;
  }
  #status {
    font-size: 0.9rem;
    color: #bbb;
    margin-bottom: 8px;
  }
</style>
</head>
<body>

<h1>🤖 Chatwell S13 - Tam Çalışan Yapay Zeka</h1>

<button id="updateBtn">🔄 Kelime Havuzunu Güncelle</button>
<div id="status">Kelime havuzu yüklenmedi.</div>

<div id="chat"></div>

<div id="inputArea">
  <input type="text" id="userInput" placeholder="Sorunu yaz ve Enter'a bas..." autocomplete="off" />
  <button id="sendBtn">Gönder</button>
</div>

<script>
  const chat = document.getElementById("chat");
  const userInput = document.getElementById("userInput");
  const sendBtn = document.getElementById("sendBtn");
  const updateBtn = document.getElementById("updateBtn");
  const status = document.getElementById("status");

  let kelimeHavuzu = [];

  const kelimeBilgisi = {
    "araba": {tip: "isim", anlam: "Genellikle ulaşımda kullanılan dört tekerlekli taşıt."},
    "hızlı": {tip: "sıfat", anlam: "Çabuk hareket eden, süratli."},
    "koşmak": {tip: "fiil", anlam: "Hızlı adımlarla yürümek, koşu yapmak."},
    "kitap": {tip: "isim", anlam: "Okumak için yazılmış yapraklardan oluşan nesne."},
    "bilgi": {tip: "isim", anlam: "Öğrenilen ya da öğrenilen şeyler."},
    "teknoloji": {tip: "isim", anlam: "Bilimsel ve teknik yöntemlerin kullanılması."},
    "yapay zeka": {tip: "isim", anlam: "Bilgisayarların insan benzeri düşünmesini sağlayan teknoloji."}
  };

  const kaliplar = {
    "isim": [
      "{kelime} genellikle {anlam}",
      "{kelime}, {anlam} olarak bilinir.",
      "{kelime} günlük hayatta sıkça kullanılır."
    ],
    "sıfat": [
      "{kelime} bir sıfattır ve {anlam}",
      "{kelime} kelimesi {anlam} anlamına gelir."
    ],
    "fiil": [
      "{kelime} eylemi {anlam}",
      "{kelime} yapmak, {anlam} demektir."
    ]
  };

  function rastgeleKalip(tip) {
    const kalipListesi = kaliplar[tip];
    if (!kalipListesi) return "{kelime}: {anlam}";
    return kalipListesi[Math.floor(Math.random() * kalipListesi.length)];
  }

  function cumleOlustur(kelime) {
    const bilgi = kelimeBilgisi[kelime];
    if (!bilgi) return null;
    const kalip = rastgeleKalip(bilgi.tip);
    return kalip.replace("{kelime}", kelime).replace("{anlam}", bilgi.anlam);
  }

  async function kelimeGuncelle() {
    status.textContent = "Kelime havuzu güncelleniyor...";
    try {
      const res = await fetch("https://raw.githubusercontent.com/salih-ozt/BTG-0/main/index.html");
      if (!res.ok) throw new Error("GitHub’dan veri çekilemedi");
      const text = await res.text();
      kelimeHavuzu = Array.from(new Set(text.match(/\b[\wğüşöçıİĞÜŞÖÇ]{2,}\b/gi).map(w => w.toLowerCase())));
      status.textContent = `Kelime havuzu güncellendi. Toplam ${kelimeHavuzu.length} kelime yüklendi.`;
    } catch (e) {
      status.textContent = "Kelime havuzu güncellenemedi: " + e.message;
    }
  }

  function mesajEkle(metin, sinif) {
    const div = document.createElement("div");
    div.classList.add("message", sinif);
    div.textContent = metin;
    chat.appendChild(div);
    chat.scrollTop = chat.scrollHeight;
  }

  async function wikipediaAra(kelime) {
    try {
      const url = `https://tr.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(kelime)}`;
      const res = await fetch(url);
      if (!res.ok) return null;
      const data = await res.json();
      return data.extract || null;
    } catch {
      return null;
    }
  }

  async function duckDuckGoAra(query) {
    try {
      const url = `https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_redirect=1&skip_disambig=1&kl=tr-tr`;
      const res = await fetch(url);
      const data = await res.json();
      if (data.AbstractText) return data.AbstractText;
      if (data.RelatedTopics && data.RelatedTopics.length > 0) {
        return data.RelatedTopics[0].Text || null;
      }
      return null;
    } catch {
      return null;
    }
  }

  async function wikidataAra(kelime) {
    try {
      const url = `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(kelime)}&language=tr&format=json&origin=*`;
      const res = await fetch(url);
      const data = await res.json();
      if (data.search && data.search.length > 0) {
        return `Wikidata bulgusu: ${data.search[0].label} - ${data.search[0].description || 'Açıklama yok.'}`;
      }
      return null;
    } catch {
      return null;
    }
  }

  async function openLibraryAra(kelime) {
    try {
      const url = `https://openlibrary.org/search.json?q=${encodeURIComponent(kelime)}`;
      const res = await fetch(url);
      const data = await res.json();
      if (data.docs && data.docs.length > 0) {
        const kitap = data.docs[0];
        return `OpenLibrary bulgusu: "${kitap.title}" adlı kitap, yazar: ${kitap.author_name ? kitap.author_name.join(", ") : "Bilinmiyor"}, yayın yılı: ${kitap.first_publish_year || "Bilinmiyor"}`;
      }
      return null;
    } catch {
      return null;
    }
  }

  async function aramaYap(query) {
    let wikiSonuc = await wikipediaAra(query);
    if (wikiSonuc) return wikiSonuc;

    let ddgSonuc = await duckDuckGoAra(query);
    if (ddgSonuc) return ddgSonuc;

    let wikidataSonuc = await wikidataAra(query);
    if (wikidataSonuc) return wikidataSonuc;

    let openLibSonuc = await openLibraryAra(query);
    if (openLibSonuc) return openLibSonuc;

    return "Maalesef bu konuda bilgi bulamadım.";
  }

  async function cevapOlustur(girdi) {
    const girisLower = girdi.toLowerCase().trim();
    const kelimeler = girisLower.split(/\s+/);

    let cevaplar = [];
    for (const kelime of kelimeler) {
      if (kelimeBilgisi[kelime]) {
        const cumle = cumleOlustur(kelime);
        if (cumle) cevaplar.push(cumle);
      }
    }

    if (cevaplar.length > 0) {
      return cevaplar.join(" ");
    }

    mesajEkle(`🔍 "${girdi}" konusu otomatik olarak araştırılıyor...`, "bot");
    const aramaSonucu = await aramaYap(girdi);
    return aramaSonucu;
  }

  async function mesajGonder() {
    const mesaj = userInput.value.trim();
    if (!mesaj) return;

    mesajEkle(mesaj, "user");
    userInput.value = "";

    mesajEkle("... Yanıt hazırlanıyor ...", "bot");
    chat.lastChild.scrollIntoView();

    const yanit = await cevapOlustur(mesaj);

    if (chat.lastChild.textContent === "... Yanıt hazırlanıyor ...") {
      chat.removeChild(chat.lastChild);
    }
    mesajEkle(yanit, "bot");
  }

  sendBtn.addEventListener("click", mesajGonder);
  userInput.addEventListener("keydown", e => {
    if (e.key === "Enter") mesajGonder();
  });

  updateBtn.addEventListener("click", kelimeGuncelle);

  window.onload = async () => {
    mesajEkle("👋 Hoş geldin! Chatwell S13 gelişmiş doğal cümle kurma sistemi çalışıyor. Kelime havuzu yükleniyor...", "bot");
    await kelimeGuncelle();
    mesajEkle("✅ Kelime havuzu yüklendi! Sorunu yaz, anlamlı cümlelerle cevap vereyim.", "bot");
  };
</script>

</body>
</html>
