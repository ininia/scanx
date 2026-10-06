# FAZ 2 — Retro

## Ne iyi gitti
- **Testler gerçek hataları yakaladı:** giriş başarısızlıklarının transaction rollback'iyle kaybolması
  (hesap kilitleme hiç çalışmayacaktı) yazım sırasında fark edildi ve entegrasyon testiyle güvenceye alındı.
- Kiracı izolasyonu üç katmanda doğrulandı: servis (ResolveOrg → 404), RLS (PK ile sorgu bile görünmez),
  HTTP (19 uç nokta × oturum ve token).
- Her test için sıfırdan veritabanı (`internal/testdb`) sayesinde kurulum sihirbazı gerçekçi test edildi.
- Tarayıcıda manuel doğrulama: hizalama, önbellek ve varsayılan URL şeması sorunları bulunup düzeltildi.

## Ne kötü gitti
- Windows'ta Docker bind mount izinleri root olmayan dev konteynerini bozdu (`go.sum` yazılamadı);
  `scripts/dev.sh` Windows'ta root ile çalışıyor, Linux/CI'da imaj kullanıcısıyla.
- `go mod tidy`'ın test dosyası yazılmadan çalıştırılması bağımlılığı sildi (kin-openapi) — tidy en sona.

## Borçlar
- SMTP/e-posta bildirimleri ve davet e-postası (Faz 4).
- Kurulum sihirbazına SSH anahtarı ve tarayıcı politikası adımları (Faz 3–4).
- Tarayıcı tabanlı E2E (chromedp/playwright) yerine HTTP seviyesinde E2E (Faz 8'de değerlendirilecek).
