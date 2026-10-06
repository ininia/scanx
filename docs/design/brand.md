# scanX marka ve tasarım dili

Kaynak: kullanıcının verdiği scanX logosu (2026-10-06) — koyu lacivert italik "scan" yazısı +
neon yeşilden zümrüde gradyanlı, keskin köşeli "X".

## Logo dosyaları
| Dosya | Durum |
|---|---|
| `internal/ui/static/img/scanx-logo.png` | **Bekleniyor** — orijinal logo dosyası buraya konacak (tercihen SVG de: `scanx-logo.svg`) |
| `internal/ui/static/img/scanx-mark.svg` | Logodaki X'ten türetilmiş vektör işaret (favicon, app ikonu, yükleniyor animasyonu) |

Koyu temada logo, lacivert "scan" yerine `--text` (açık) renkle kullanılmalı → orijinalin
beyaz/negatif varyantı gerekir (SVG gelirse CSS ile `fill: currentColor` yapılır).

## Renkler (`internal/ui/static/css/tokens.css`)
| Token | Değer | Kullanım |
|---|---|---|
| `--sx-navy` | `#33405e` | Logo yazısı, açık temada başlıklar, kenarlıklar |
| `--sx-green-1→3` | `#00ec93 → #00c774 → #009e5c` | Vurgu, birincil buton, aktif durum, "geçti/düzeltildi" |
| `--bg` (koyu) | `#070c17` | Varsayılan tema zemini, üzerinde çok hafif yeşil ızgara deseni |
| `--surface-1..3` | `#0d1526 / #131e35 / #1b2945` | Kartlar, tablolar, kenar çubuğu |
| Severity | critical `#ff3d68`, high `#ff8a3d`, medium `#ffc53d`, low `#4da3ff`, info `#8f9db8` | Marka yeşilinden bilinçli olarak ayrık |

Açık temada vurgu `#00a862`'ye koyulaşır (beyaz üzerinde WCAG AA kontrastı).

## Dil
- **Teknolojik ve keskin:** logodaki eğik, köşeli formlar → `--skew: -12deg` ile ince eğik
  çizgiler/ayraçlar, köşe yuvarlaklığı küçük (4–8px).
- **Koyu varsayılan:** güvenlik konsolu hissi; yeşil yalnızca anlam taşıyan yerde (aksiyon, başarı,
  odak) — her yere serpiştirilmez.
- **Tipografi:** başlıklar Space Grotesk, metin Inter, kod/hash/commit JetBrains Mono.
  Fontlar CDN'den değil, binary'ye gömülü sunulur (CSP `default-src 'self'`).
- **Hareket:** tarama sürerken X işaretinde soldan sağa ışık süpürmesi (scan line); kısa,
  `prefers-reduced-motion` ile kapanır.
- **Veri görselleştirme:** severity renkleri sabit; trend grafiklerinde marka yeşili "skor" serisi.
