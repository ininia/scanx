# ADR-001 — İş kuyruğu

- **Durum:** Kabul edildi

## Bağlam
Ayrı bir broker (Redis/RabbitMQ) istemiyoruz; kuyruk PostgreSQL'de olmalı (tek yedek). Seçenekler:
1. **River** (`github.com/riverqueue/river`, MPL-2.0): `SKIP LOCKED` tabanlı, yeniden deneme, zamanlanmış iş, unique iş, iptal, periyodik iş, pgx/v5 sürücüsü, kendi migration'ları.
2. Kendi `jobs` tablomuz + `SELECT … FOR UPDATE SKIP LOCKED`.

## Karar
**River** (K4 varsayılanı). Retry/backoff, kilit süresi aşımında iş kurtarma (rescuer), unique jobs ve
iptal gibi Bölüm 4.3 gereksinimlerini hazır karşılıyor. MPL-2.0 dosya bazlı copyleft'tir; AGPL ile uyumludur.

## Sonuçlar
- Şartnamedeki `jobs` tablosu yerine River tabloları (`river_job` vb.) kullanılır; migration'ları River'ın
  `rivermigrate` paketiyle sunucu başlangıcında uygulanır (Faz 3).
- River tabloları kiracı verisi taşımaz; iş yükü (payload) yalnızca `scan_id` içerir, RLS gerektirmez.
- Faz 3'te bağımlılık eklenmeden önce güncel sürüm/lisans `docs/research/deps.md`'de doğrulanır.
