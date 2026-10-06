# ADR-002 — Web arayüzü teknolojisi

- **Durum:** Kabul edildi

## Karar
`templ` (sunucu tarafı bileşenler, otomatik kaçış) + `htmx` (kısmi yenileme, SSE) + Tailwind (build zamanında
derlenmiş CSS, `embed` ile binary'ye gömülü). SPA yok.

## Gerekçe
Tek binary, ayrı frontend build zinciri yok, katı CSP (`default-src 'self'`, inline script yok) uygulanabilir,
XSS yüzeyi küçük. `templ.Raw` yasak (istisna ADR ile).

## Sonuçlar
- htmx ve diğer JS dosyaları vendored + gömülü sunulur (CDN yok).
- Tailwind standalone CLI yalnızca build imajında çalışır; Node gerekmez.
