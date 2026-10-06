# FAZ 2 — Sunucu, DB, kimlik doğrulama, çok kiracılık, web arayüzü

## Hedef
Kurulum sihirbazıyla ayağa kalkan, çok kiracılı, 2FA'lı, API'si sözleşmeye bağlı bir platform.

## Görevler
| ID | Görev |
|---|---|
| T-0201 | Migration 00002: oturum, proje, davet, API token, audit log + RLS + lookup fonksiyonları |
| T-0202 | sqlc sorguları + üretilen kod; tenant transaction (`store.DB.Tx`, `is_local` ayarlar) |
| T-0203 | `internal/crypto` (AES-256-GCM, AAD) |
| T-0204 | `internal/auth`: Argon2id, TOTP (RFC 6238), token, CSRF, rate limit, RBAC |
| T-0205 | `internal/service`: kurulum, giriş/2FA, hesap, org/üye/davet/token/audit, projeler |
| T-0206 | `internal/gitutil`: repo URL doğrulama (§6.3) |
| T-0207 | HTTP: auth + CSRF middleware, JSON API (`/api/v1`), `api/openapi.yaml` (3.1) |
| T-0208 | Web arayüzü: templ + htmx, TR/EN, kurulum sihirbazı, dashboard, projeler, üyeler, token, audit, hesap, admin |
| T-0209 | Testler: servis entegrasyon, API sözleşme + tablo bazlı kiracı izolasyonu, web uçtan uca |

## Kabul (şartname §19)
- Kiracı izolasyon testleri %100 uç nokta: `TestTenantIsolationAllEndpoints` (19 uç × oturum + token).
- Sihirbaz uçtan uca çalışır: `TestSetupWizardLoginAndProjects` + tarayıcıda manuel doğrulama.
