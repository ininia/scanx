# ADR-007 — Faz 2 kararları: arayüz, i18n, kimlik doğrulama ayrıntıları

- **Durum:** Kabul edildi (Faz 2)

## 1. Tailwind yerine elle yazılmış CSS + tasarım token'ları
ADR-002 Tailwind öngörüyordu. Logodan türetilen tasarım token'ları (`tokens.css`) ile ~300 satırlık
`app.css` aynı işi Node/standalone binary build adımı olmadan yapıyor; CSP (`default-src 'self'`) ile
uyumlu, inline stil yok. Statik dosyalar içerik hash'iyle sürümlenir (`?v=<hash>`, `immutable`).

## 2. i18n katalogları Go map olarak
Şartname `internal/i18n/{tr,en}.toml` diyordu. TOML bağımlılığı yerine derlenen Go map'leri
(`tr.go`, `en.go`) kullanıldı; testler iki dilin anahtar setinin eşitliğini ve şablonlardaki her
`p.T("…")` anahtarının varlığını doğrular. Flash mesajları yalnızca katalogdaki `flash.*`
anahtarlarından gelir (URL'den keyfi metin basılmaz).

## 3. Kiracı bağlamı öncesi aramalar: SECURITY DEFINER fonksiyonlar
API token ve davet doğrulaması org bilinmeden yapılmak zorunda; ilgili tablolar FORCE RLS altında.
RLS'yi genel olarak gevşetmek yerine `scanx_lookup_api_token(hash)` ve `scanx_lookup_invitation(hash)`
fonksiyonları yalnızca **tek bir hash** ile **tek satırın** gerekli alanlarını döndürür
(`SET search_path` sabit, `EXECUTE` sadece `scanx_app`'e).

## 4. CSRF: iki bağımsız katman
Go 1.25 `http.CrossOriginProtection` (Sec-Fetch-Site/Origin) + HMAC'e bağlı double-submit token
(`csrf_token` alanı / `X-CSRF-Token`). Bearer token istekleri muaf. `POST /api/v1/auth/login` yalnızca
cross-origin korumasıyla (betik istemcileri önceden sayfa yüklemez).

## 5. Oturum ve giriş
Sunucu taraflı oturum tablosu, çerezde rastgele 256-bit token (DB'de SHA-256), HTTPS'te `__Host-`
öneki, 12 saat boşta kalma + 7 gün mutlak süre, 2FA sonrası yeni token (fixation koruması).
Başarısız giriş kayıtları transaction içinde **commit edilir** (rollback edilseydi kilitleme çalışmazdı;
entegrasyon testiyle güvence altında). Bilinmeyen e-posta da Argon2 doğrulaması kadar CPU harcar.
TOTP kodları tekrar kullanılamaz (replay guard). Davetler SMTP gerektirmez: bağlantı yöneticiye bir kez
gösterilir.

## 6. Kurulum sihirbazı adımları
Token → yönetici → zorunlu 2FA → sunucu ayarları → ilk organizasyon → özet. SMTP, instance SSH anahtarı
ve tarayıcı politikası adımları ilgili fazlarda eklenecek (Faz 3–4).
