# scanX tehdit modeli — v0 (Faz 0)

Temel: şartname §5.1. Bu sürüm Faz 0'da gerçekten var olan yüzeyi ve şimdiden alınan kararları kayıt altına alır.

## Varlıklar
1. Müşteri kaynak kodu (geçici, tarama süresince) 2. Bulgular/raporlar (kiracıya özel)
3. Deploy key'ler (şifreli) 4. `SCANX_MASTER_KEY`, DB kimlikleri 5. Kullanıcı hesapları/oturumlar

## Güven sınırları (Faz 0)
```
İnternet ──TLS──▶ nginx (edge ağı) ──▶ server (edge+internal) ──▶ postgres (internal, dışarı kapalı)
                                        migrate (tek seferlik, internal)
```

## Faz 0'da uygulanan önlemler
| Tehdit | Önlem | Kanıt |
|---|---|---|
| Sunucu ele geçirilirse RLS atlanır | Sunucu yalnızca `scanx_app` (NOSUPERUSER, NOBYPASSRLS) kullanır; şema sahibi kimliği sadece `migrate` konteynerinde (ADR-005) | `TestAppRoleIsNotPrivileged`, compose inspect |
| Kiracılar arası veri sızıntısı | `organizations`, `memberships` üzerinde ENABLE+FORCE RLS; bağlam yoksa hiç satır görünmez | `TestRLSIsolatesOrganizations` |
| Sırların log/hata/JSON'a sızması | `secret.Secret` tipi; slog redaction; DB URL hataları genel mesaj | `internal/secret`, `internal/logging`, `TestErrorsDoNotLeakSecrets` |
| İç hata detayının istemciye sızması | Recover → genel 500; readiness yalnızca ok/fail | `TestRecoverHidesPanicDetails`, `TestReady` |
| XSS/clickjacking/MIME sniffing | CSP `default-src 'self'`, `frame-ancestors 'none'`, nosniff, HSTS (https) | `TestSecurityHeaders`, curl |
| Header enjeksiyonu (X-Request-ID) | Yalnızca `[A-Za-z0-9-]{8,64}`, aksi halde yeniden üretilir; nginx kendi id'sini yazar | `TestRequestID` |
| IP sahteciliği | nginx `X-Forwarded-For`'u eklemez, `$remote_addr` ile **ezer** | `deploy/nginx` |
| Konteyner kaçışı / yetki | server/migrate/certinit: read-only rootfs, `cap_drop: ALL`, no-new-privileges, distroless non-root (65532) | compose |
| DB internete açık | postgres yalnızca `internal: true` ağında, port yayınlanmaz | compose |
| Brute force | nginx login 5/dk/IP, genel 20 r/s | `deploy/nginx` |
| Slowloris/büyük gövde | ReadHeaderTimeout 10s, MaxHeaderBytes 1MB, `client_max_body_size 5m` | `internal/app/server.go` |

## Bilinen açıklar / sonraki fazlar
| # | Konu | Plan |
|---|---|---|
| R1 | `set_config(..., is_local=false)` kullanılırsa tenant bağlamı havuzdaki bağlantıda kalır | Faz 2: `tenant` paketi yalnızca `is_local=true` + transaction; havuz `PrepareConn`'da `RESET` + test |
| R2 | `scanx.superadmin` bayrağını uygulama koyuyor (DB rolüyle değil) | Faz 2: ayrı ADR; süper admin işlemleri ayrı fonksiyonlarda + audit |
| R3 | İmajlar tag ile, digest pin'siz (nginx, postgres, distroless) | T-0007b, v1.0 öncesi |
| R4 | GitHub Actions SHA pin'siz | T-0008b |
| R5 | HTTP→HTTPS yönlendirmesi `$host` kullanır (standart dışı portta port düşer) | Faz 6: `SCANX_BASE_URL`'den üretilen nginx config |
| R6 | Worker/Docker socket, sandbox, webhook, SSH key yüzeyi henüz yok | Faz 3–4, §5 kuralları birebir |
