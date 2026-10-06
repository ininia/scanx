# scanX görev panosu

Format ve yaşam döngüsü: şartname §20.2–20.4. Ürün adı/karar kayıtları: `docs/adr/`.

---

## T-0001 — Repo iskeleti
- Faz: 0 · Öncelik: P0 · Durum: ACCEPTANCE · Sahibi: Geliştirici
- Kabul kriterleri: `go.mod` (Go 1.27), Makefile, `.golangci.yml`, geliştirme konteyneri, LICENSE, README/CHANGELOG/SECURITY/CONTRIBUTING.
- Kanıt:
  - [Geliştirici] `scripts/dev.sh lint` → `0 issues.`; `scripts/dev.sh test` → tüm paketler ok
- Açık nokta: **LICENSE** metni (AGPL-3.0) gnu.org'dan indirilecek — kullanıcı onayı bekleniyor.

## T-0002 — ADR'ler
- Faz: 0 · P0 · Durum: DONE · Sahibi: Mimar
- Kanıt: ADR-000 (ad/lisans), 001 (River), 002 (templ+htmx), 003 (SAST motorları), 004 (dev/test ortamı), 005 (ayrı migrate konteyneri)

## T-0003 — Config paketi
- Faz: 0 · P0 · Durum: DONE
- Kabul: tüm `SCANX_*` değişkenleri, varsayılanlar §14.2 ile aynı, hatalar toplu ve sır sızdırmadan raporlanır.
- Kanıt: `internal/config` %95.2 kapsam; `TestValidationErrors` (17 durum), `TestErrorsDoNotLeakSecrets`

## T-0004 — slog + redaction
- Faz: 0 · P0 · Durum: DONE
- Kanıt: `internal/logging` %96.4, `internal/secret` %100; `TestRedactsSensitiveKeys`, `TestSecretNeverPrinted` (fmt, %#v, JSON, slog)

## T-0005 — HTTP sunucusu, health, güvenlik başlıkları
- Faz: 0 · P0 · Durum: DONE
- Kanıt: `internal/server` %95.7; `/health/live`, `/health/ready` (+ `/api/v1/health/*`), JSON hata zarfı, request-id, recover
- QA (compose): `curl -k https://localhost:8443/health/ready` → `200 {"status":"ok","checks":{"database":"ok","migrations":"ok"}}`; her güvenlik başlığı tek kez

## T-0006 — goose + ilk migration
- Faz: 0 · P0 · Durum: DONE
- Kanıt: `scripts/dev.sh test-integration` → `TestMigrateIsIdempotentAndCurrent`, `TestAppRoleIsNotPrivileged`, `TestRLSIsolatesOrganizations` PASS (gerçek PostgreSQL 16)

## T-0007 — Dockerfile + compose
- Faz: 0 · P0 · Durum: DONE
- Kanıt: distroless/static non-root imaj; `down -v && up -d --build` → migrate Exited(0), server healthy, nginx TLS 200; server env'de admin kimliği yok
- Alt görev **T-0007b** (BACKLOG, P1): tüm imajları digest ile pin'le.

## T-0008 — GitHub Actions CI
- Faz: 0 · P0 · Durum: BLOCKED
- `.github/workflows/ci.yml` yazıldı (lint, test, test-integration, image + compose smoke).
- Blok: henüz uzak repo yok; ilk push'ta çalıştırılıp kanıt eklenecek. **T-0008b**: action'ları SHA ile pin'le.

## T-0009 — Faz 0 test planı + entegrasyon altyapısı
- Faz: 0 · P0 · Durum: DONE · Sahibi: QA
- Kanıt: `integration` build etiketi, `scripts/dev.sh test-integration` geçici Postgres + `scanx_app` rolü; ADR-004

## T-0010 — Tehdit modeli v0
- Faz: 0 · P0 · Durum: DONE · Sahibi: Güvenlik
- Kanıt: `docs/security/threat-model.md`. İnceleme bulgusu → ADR-005 (sunucuda süper kullanıcı kimliği kaldırıldı).

## T-0011 — Tarayıcı araştırması
- Faz: 0 · P0 · Durum: IN_PROGRESS · Sahibi: Güvenlik + Geliştirici
- Çıktı: `docs/research/scanners.md`, `docs/research/licenses.md`

## T-0012 — Marka/tasarım token'ları
- Faz: 0 (kullanıcı talebi) · P1 · Durum: IN_REVIEW
- Kanıt: `internal/ui/static/css/tokens.css`, `scanx-mark.svg`, `docs/design/brand.md`
- Bekleyen: orijinal logo dosyası → `internal/ui/static/img/scanx-logo.png` (+ varsa SVG)
