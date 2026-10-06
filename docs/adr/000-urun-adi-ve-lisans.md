# ADR-000 — Ürün adı, repo ve lisans

- **Durum:** Kabul edildi (kullanıcı kararları, 2026-10-06; lisans aynı gün revize edildi)
- **Karar verenler:** Kullanıcı (K1, K3, K10)

## Bağlam
Şartname ürünü "Kalkan" olarak adlandırıyor ve AGPL-3.0 öneriyor. Kullanıcı projeyi **scanX** adıyla,
**İninia** GitHub organizasyonunda public olarak yayınlamak istiyor. Lisans beklentisi:
*"İsteyen alıp kullansın, geliştirip buraya katkı göndersin; ama satamasın. Satmak isterse İninia
Teknoloji Limited Şirketi'ne anlaşılan oranda pay versin."*

## Karar
- Ad: **scanX**. Binary `scanx`, env önekleri `SCANX_*`, Docker etiketleri `scanx.scan` / `scanx.org`.
- Repo: `github.com/ininia/scanx` (public). Go modül yolu aynı. İmajlar: `ghcr.io/ininia/scanx*` (K10: GHCR).
- Lisans: **Business Source License 1.1** (SPDX `BUSL-1.1`), Licensor: İninia Teknoloji Limited Şirketi.
  - Additional Use Grant: kendi kodunu taramak için kurum içi üretim kullanımı serbest; satış,
    ücretli dağıtım, ücretli hosted/SaaS veya ücretli tarama hizmeti ticari lisans gerektirir.
  - Change Date: 2030-10-06 → Change License: **AGPL-3.0-or-later** (her sürüm en geç 4 yıl sonra açık kaynak olur).
- Katkılar için **CLA** (İninia'nın ticari lisans verebilmesi için gerekli).

## Alternatifler
- **AGPL-3.0:** OSI açık kaynak, ama ticari satışı/SaaS'ı yasaklamaz (yalnızca kaynak paylaşımı zorunlu) → kullanıcının "satamasın" şartını karşılamıyor.
- **PolyForm Noncommercial:** şirketlerin kendi iç kullanımını da kısıtlar → benimsemeyi öldürür.
- **Elastic License v2:** yalnızca managed service'i yasaklar, kopya satışını net yasaklamaz.

## Sonuçlar
- Proje OSI tanımında "open source" değil, **source-available**; dokümanlarda böyle anılır.
- Lisans metni yayın öncesi hukukçu tarafından gözden geçirilmeli (kullanıcıya bildirildi).
- Dağıtılan üçüncü parti tarayıcıların lisansları değişmez; `THIRD_PARTY_NOTICES` gerekir (Faz 1).
