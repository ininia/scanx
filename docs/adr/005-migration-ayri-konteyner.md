# ADR-005 — Migration'lar ayrı, tek seferlik konteynerde çalışır

- **Durum:** Kabul edildi (Faz 0 güvenlik incelemesi bulgusu)

## Bağlam
Şartname (§15) migration'ların "server başlarken otomatik + kilitli" çalışmasını istiyor. Bunu
sunucu içinde yapmak, sunucu sürecine şema sahibi / süper kullanıcı DB kimliğini vermek demek.
Sunucu internete açık tek bileşendir; ele geçirilirse bu kimlikle RLS kapatılabilir veya
politikalar değiştirilebilir → kiracı izolasyonu (§5.4) tek katmana düşer.

## Karar
- Compose'a tek seferlik `migrate` servisi eklenir (`scanx migrate`, aynı imaj). Yalnızca o servis
  `SCANX_DATABASE_ADMIN_URL` alır; `server` ona `service_completed_successfully` ile bağlıdır.
- `server` yalnızca `scanx_app` (NOSUPERUSER, NOBYPASSRLS) kimliğini bilir. Başlangıçta şema sürümünü
  kontrol eder; geride ise açık bir hata ile çıkar (`/health/ready` de `migrations: fail` döner).
- Geliştirici kolaylığı: `SCANX_DATABASE_ADMIN_URL` sunucuya verilirse migration'ı kendisi uygular
  (üretim compose'unda verilmez).
- Advisory lock (goose session locker) korunur; birden fazla `migrate` çalışması güvenlidir.

## Sonuçlar
- Kullanıcı açısından davranış aynı: `docker compose up` migration'ı otomatik uygular.
- `scanx update` (Faz 6) önce `migrate`'i, sonra servisleri yeniden başlatır.
