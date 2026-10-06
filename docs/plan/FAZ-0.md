# FAZ 0 — İskelet

**Kaynak:** `Kalkan_Proje_Dokumani.md` v1.0 (ürün adı scanX olarak değiştirildi, bkz. ADR-000).

## Hedef
Çalışan, test edilebilir, güvenli varsayılanlarla gelen bir Go iskeleti:
`docker compose up` → `GET /health/ready` = 200, `make test` yeşil.

## Kapsam
| ID | Görev |
|---|---|
| T-0001 | Repo iskeleti, `go.mod`, Makefile, `.golangci.yml`, LICENSE, geliştirme konteyneri |
| T-0002 | ADR-000 (ad), ADR-001 (kuyruk), ADR-002 (UI), ADR-003 (SAST motorları), ADR-004 (geliştirme/test ortamı) |
| T-0003 | `internal/config` — env yükleme, doğrulama, testler |
| T-0004 | `internal/logging` — slog kurulumu, `Secret` tipi, redaction, testler |
| T-0005 | `internal/http` — sunucu, health uçları, güvenlik başlıkları, request-id, recover |
| T-0006 | `internal/store` — pgx havuzu, goose (gömülü) + ilk migration |
| T-0007 | Multi-stage Dockerfile (distroless, non-root) + compose (postgres, server, nginx) |
| T-0008 | GitHub Actions CI: lint, test, entegrasyon testi, build, image |
| T-0009 | Faz 0 test planı + entegrasyon test altyapısı |
| T-0010 | Tehdit modeli v0 |
| T-0011 | `docs/research/` — tarayıcı CLI/format/lisans notları (başlangıç) |

## Kapsam dışı
Worker, tarayıcılar, UI sayfaları, auth (Faz 1–3).

## Riskler
- Geliştirme makinesinde Go yok → tüm build/test Docker içinde (ADR-004).
- Repo: github.com/ininia/scanx (İninia organizasyonu).

## Demo senaryosu
```bash
cp deploy/.env.example deploy/.env   # gizlileri doldur (scripts/gen-secrets.sh)
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
curl -k https://localhost/health/ready   # {"status":"ok",...}
scripts/dev.sh test
```
