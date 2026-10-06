# FAZ 1 — Retro

## Ne iyi gitti
- **Uydurmama kuralı somut değer üretti.** Tüm adaptörler gerçek araç çıktısına göre yazıldı; dokümantasyondan
  gelen yanlış bilgiler (opengrep bayrağı, OSV DB yolu, OSV çıkış davranışı, gitleaks stopword) ilk gerçek
  çalıştırmada yakalandı (`docs/research/verified-corrections.md`).
- **Güvenlik bulguları testle kapandı:** SAST snippet'lerinde sır sızıntısı; repo `.semgrepignore` / `.gitleaks.toml`
  ile tarama atlatma; tedarik zinciri (checksum + cosign doğrulaması).
- **Dogfooding:** scanX kendi kodunda gerçek bir bulgu verdi (`os.IsNotExist` → `errors.Is`) ve geliştirme imajının
  root çalıştığını yakaladı; ikisi de düzeltildi. Self-scan kalite kapısından geçiyor.

## Ne kötü gitti
- Windows + Git Bash ortamında heredoc/kaçış karakterleri birkaç kez dosya bozdu; çok satırlı düzenlemeler için
  Edit/Write araçları kullanılmalı.
- İmaj build süresi (DB indirmeleri) iterasyonu yavaşlattı.

## Borçlar
T-0113 (`.scanx.yml`), T-0114 (digest pin), T-0115 (DB volume + günlük güncelleme). `internal/app` birim test kapsamı
düşük (%36); asıl tarama yolu e2e testiyle kapsanıyor.
