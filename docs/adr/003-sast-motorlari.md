# ADR-003 — SAST motorları ve kural kaynakları

- **Durum:** Kabul edildi (kullanıcı kararı K2, 2026-10-06)

## Bağlam
Kullanıcı yönergesi: *"Her zaman açık kaynak; birlikte çalışabiliyorsa her aracı koy, ne kadar ayrıntılı
o kadar iyi."* Semgrep Registry kurallarının çoğu "Semgrep Rules License" altındadır ve rakip ürün/SaaS
içinde kullanımı kısıtlar.

## Karar
1. **Varsayılan çok dilli SAST: Opengrep** (LGPL-2.1, Semgrep CE çatalı) + **yalnızca OSI lisanslı kurallar**
   (kaynak ve lisansları `docs/research/licenses.md`'de listelenir; kural paketi imaja sürüm-pin'li gömülür).
2. **Semgrep CE motoru opsiyonel ikinci adaptör** olarak eklenir; varsayılan kural seti yine açık lisanslı
   paket olur. Kullanıcı kendi Semgrep lisansı/kural yolunu proje ayarında verebilir (kendi sorumluluğu).
3. Dile özel tüm açık kaynak araçlar eklenir (gosec, Bandit, Psalm+PHPStan, njsscan + ESLint security,
   Brakeman — lisans doğrulaması sonrası, SpotBugs/FindSecBugs, Security Code Scan …).
4. Aynı bulgunun birden çok araçtan gelmesi **tekilleştirme** (Bölüm 7.4) ile tek `Issue` altında
   birleşir; `sources` artar, güven yükselir. Yani araç sayısı gürültüyü değil güveni artırır.

## Alternatifler
- Yalnızca Semgrep CE + registry: lisans riski → reddedildi.
- Kendi kural motorumuz: kapsam dışı.

## Sonuçlar
- Her yeni araç için: lisans doğrulaması, sabit sürüm + digest, altın dosya testleri.
- Tarama süresi artar → `SCANX_SCANNER_PARALLELISM` ve profil (`fast`/`default`/`full`) ile yönetilir.
