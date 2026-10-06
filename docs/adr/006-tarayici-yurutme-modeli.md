# ADR-006 — Tarayıcı yürütme modeli: all-in-one imaj + iki motor

- **Durum:** Kabul edildi (Faz 1)

## Bağlam
Aynı tarama motoru üç yerde çalışmalı: geliştiricinin makinesi (`scanx scan`), CI (GitHub Action —
Docker-in-Docker istenmiyor, §12.2) ve sunucu worker'ı (Faz 3, her tarama izole). Şartname her araç
için ayrı imaj öneriyor; CI için ise zaten tek imaj (`scanx-scanner-all`) istiyor.

## Karar
1. **Tek tarayıcı imajı** `ghcr.io/ininia/scanx-scanner-all`: tüm araçlar + `scanx` binary'si +
   pin'li kural paketi + offline zafiyet DB'leri. Araç binary'leri resmi release'lerden indirilir ve
   **SHA256 (resmi checksum dosyasıyla) veya cosign imzasıyla doğrulanır**; değerler Dockerfile'da sabittir.
2. **İki motor** (`internal/engine`):
   - `exec`: araçları aynı konteyner içinde alt süreç olarak çalıştırır (argüman dizisi, kabuk yok,
     çalışma dizini kaynak ağacı **dışında**, araç başına zaman aşımı). CI ve imaj içi kullanım.
   - `docker`: `scanx scan` host'ta çalışırken imajı `--network none --read-only --cap-drop ALL
     --security-opt no-new-privileges` ile başlatır, kaynağı **salt-okunur** bağlar ve içeride `exec`
     motorunu çağırır. Bu modda `os/exec` yalnızca `docker` CLI'si için kullanılır (şartname §17
     CLI yerel mod istisnası).
3. Worker (Faz 3) aynı imajı Docker Engine SDK ile, şartname §5.2 sertleştirmesiyle çalıştırır; araç
   bazlı izolasyon gerekirse aynı imaj farklı komutlarla ayrı konteynerlerde koşturulur.
4. Repo içi araç yapılandırmaları **yok sayılır**: her araca scanX'in kendi config'i açıkça verilir
   (ör. gitleaks `-c`, `.gitleaksignore` için scanX yolu). Kod çalıştırabilen yapılandırmalar
   (Psalm autoload, PHPStan bootstrap, ESLint JS config, Checkov external checks) Faz 7'de aynı kuralla eklenir.

## Kural lisansları (ADR-003 eki)
Lisans BSL'e geçtiği için: kural dosyaları imajda **ayrı veri dosyaları** olarak, kendi lisans
metinleri ve `RULES-LICENSES.json` manifestiyle dağıtılır (birleştirme/aggregation). İzinli:
MIT, Apache-2.0, BSD, LGPL, GPL, AGPL (Trail of Bits) — kaynakları açık ve değiştirilmeden.
Yasak: Commons Clause, Semgrep Rules License, GitLab EE, NonCommercial, lisansı belirsiz dosyalar.
Kapı (`internal/rules`) build'i kırar.

## Sonuçlar
- İmaj büyük (DB'ler); Faz 3'te DB'ler ayrı volume'a ve günlük güncelleme işine taşınır.
- Araç sürümü yükseltmek = Dockerfile'da sürüm + checksum değişikliği + altın dosya testleri.
