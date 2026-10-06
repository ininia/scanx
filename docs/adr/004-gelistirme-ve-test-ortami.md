# ADR-004 — Geliştirme ve test ortamı

- **Durum:** Kabul edildi

## Bağlam
Geliştirme makinesi Windows; Go ve `make` kurulu değil, kullanıcı yalnızca Docker kullanılmasını istedi.
Şartname entegrasyon testleri için testcontainers-go öneriyor.

## Karar
- `build/dev/Dockerfile`: Go 1.27 + make + golangci-lint + goose içeren geliştirme imajı.
- `scripts/dev.sh <make-hedefi>`: hedefi bu imajda çalıştırır (modül/derleme önbellekleri adlandırılmış
  volume'larda). Linux/CI'da `make` doğrudan kullanılabilir.
- Entegrasyon testleri `integration` build etiketiyle ayrılır ve `SCANX_TEST_DATABASE_URL` ile verilen
  PostgreSQL'e bağlanır. `make test-integration` bu Postgres'i geçici bir konteynerde kendisi başlatır.
  Windows'ta Docker-in-Docker/testcontainers ağ sorunlarından kaçınmak için testcontainers yerine bu
  yol seçildi; davranış aynı (her koşuda temiz DB).

## Sonuçlar
- Değişken yoksa entegrasyon testleri açık bir gerekçeyle atlanır; `make test-integration` ise değişkeni
  her zaman sağlar, dolayısıyla CI'da atlama olmaz.
