# FAZ 1 — Tarama motoru + `scanx scan` CLI

## Hedef
`scanx scan --path <repo>` yerel olarak (Docker ile, kod dışarı çıkmadan) ilk 5 araçla tarar,
bulguları normalize eder, tekilleştirir, maskeler; JSON / SARIF / HTML rapor üretir; `--fail-on` ile
doğru çıkış kodunu döner.

## Görevler
| ID | Görev |
|---|---|
| T-0101 | ADR-006 yürütme modeli (all-in-one tarayıcı imajı) |
| T-0102 | `internal/finding`: model, severity normalizasyonu, maskeleme, fingerprint, dedup |
| T-0103 | `internal/detect`: dil/ekosistem tespiti |
| T-0104 | `internal/scanner`: arayüz, registry, SARIF ayrıştırıcı |
| T-0105 | Adaptörler: gitleaks, opengrep, trivy, osv-scanner, syft (+ altın dosya testleri, gerçek araç çıktılarından) |
| T-0106 | `internal/rules`: kural paketi lisans kapısı + `RULES-LICENSES.json` |
| T-0107 | `scanners/all-in-one` imajı: checksum/imza doğrulamalı araçlar, pin'li kurallar, offline DB'ler |
| T-0108 | `internal/engine`: araçları paralel çalıştırma, zaman aşımı, kısmi sonuç |
| T-0109 | `internal/report`: özet, kalite kapısı, JSON/SARIF/HTML |
| T-0110 | `scanx scan` CLI (exec + docker modları), çıkış kodları |
| T-0111 | Fixture repolar (`testdata/repos/*`, FAKE sırlar) + beklenen minimum bulgular |
| T-0112 | CI: tarayıcı imajı build + fixture e2e |

## Kabul
- `scanx scan --path testdata/repos/php-vuln` beklenen minimum bulguları üretir.
- `--fail-on` çıkış kodları: 0 geçti, 1 kapı kaldı, 2 tarama hatası, 3 yapılandırma hatası.
- Altın dosya testleri yeşil; sır değerleri hiçbir çıktıda düz metin olarak yer almaz.

## Riskler
- Araç çıktı formatları: altın dosyalar gerçek çalıştırmalardan alınır (uydurma yok).
- İmaj boyutu (DB'ler): DB'ler ayrı katmanda; Faz 3'te volume + günlük güncelleme işine taşınır.
