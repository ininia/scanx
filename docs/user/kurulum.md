# scanX Kurulum Kılavuzu (DevOps için)

Bu kılavuz yazılım bilgisi gerektirmez. Linux sunucuda komut çalıştırabiliyor ve Docker
kullanabiliyorsanız yeterli.

> **Durum (Faz 2):** Tarama motoru (Bölüm 0) ve web arayüzü çalışıyor: kurulum sihirbazı, kullanıcılar,
> 2FA, organizasyonlar, roller, API token'ları ve projeler. Sunucu tarafında otomatik tarama ve GitHub
> bağlantısı bir sonraki sürümde. Bu kılavuz her fazda güncellenir.

## 0. Hemen dene: bir repoyu tara (sadece Docker)

```bash
git clone https://github.com/ininia/scanx.git
./scanx/scripts/scan.sh /taranacak/repo/yolu
```

- İlk çalıştırmada tarayıcı imajı hazırlanır (araçlar ve zafiyet veritabanları indirilir, 5–10 dk).
- Kodunuz konteynere **salt-okunur** bağlanır, konteynerin **ağı yoktur**, iş bitince silinir.
- Raporlar `./scanx-results/` klasöründe: `scanx.html` (tarayıcıda açın), `scanx.json`,
  `scanx.sarif`, `sbom.cdx.json`.
- Çıkış kodu: `0` geçti · `1` kalite kapısı kaldı (varsayılan: yüksek/kritik bulgu var) · `2` tarama hatası.
- Seçenekler: `--fail-on critical` (sadece kritikler kapıyı kırsın), `--profile full` (daha fazla
  kural, daha çok gürültü), `--exclude docs` (klasör hariç tut), `--history=false` (git geçmişi taranmasın).

---

## 1. Gereksinimler

| Kaynak | En az | Önerilen |
|---|---|---|
| İşletim sistemi | Ubuntu 22.04/24.04, Debian 12, RHEL/Rocky/Alma 9, Amazon Linux 2023 | Ubuntu 24.04 |
| CPU / RAM / Disk | 4 vCPU / 8 GB / 50 GB | 8 vCPU / 16 GB / 200 GB |
| Yazılım | Docker Engine 24+, Docker Compose v2, git, curl | |
| Ağ | 80 ve 443 portları açık (sunucuya erişecek kişiler için) | |

### Docker kurulu değilse (Ubuntu/Debian)
```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER    # sonra oturumu kapatıp açın
docker compose version           # "Docker Compose version v2..." görmelisiniz
```

## 2. Kurulum (tek komut)

```bash
git clone https://github.com/ininia/scanx.git
cd scanx
./deploy/quickstart.sh --domain scan.sirketiniz.com
```

- `--domain`: Kullanıcıların tarayıcıya yazacağı adres. Alan adınız yoksa sunucu IP'sini yazın
  veya parametreyi hiç vermeyin (`localhost` olur).
- 80/443 başka bir uygulama tarafından kullanılıyorsa: `--http-port 8080 --https-port 8443`.

Komut bittiğinde şuna benzer bir çıktı görürsünüz:
```
✔ scanX is running: https://scan.sirketiniz.com
⚠  IMPORTANT: back up /home/ubuntu/scanx/deploy/.env now (especially SCANX_MASTER_KEY).
   One-time setup token: 8410-2d70-8712
```

### ⚠️ Hemen yapın: `deploy/.env` yedeği
Bu dosya tüm parolaları ve **ana şifreleme anahtarını** (`SCANX_MASTER_KEY`) içerir. Kaybolursa
kayıtlı repo anahtarları bir daha çözülemez. Dosyayı şirketinizin parola kasasına
(Vault, 1Password, Bitwarden…) koyun. Dosyayı **asla** git'e, e-postaya veya sohbete koymayın.

## 2.1 Kurulum sihirbazı (tarayıcıda)

1. Komutun yazdığı adresi açın (ör. `https://scan.sirketiniz.com`). Kendinden imzalı sertifika
   kullanıyorsanız tarayıcı bir kez uyarı verir.
2. **Kurulum token'ı**: komut çıktısındaki ya da `deploy/.env` içindeki `SCANX_SETUP_TOKEN` değeri.
3. **Yönetici hesabı**: ad, e-posta, en az 12 karakterlik parola.
4. **İki adımlı doğrulama (zorunlu)**: telefonunuzdaki doğrulama uygulamasıyla (Google/Microsoft
   Authenticator, 1Password…) QR kodu okutun, 6 haneli kodu girin.
5. **Sunucu ayarları**: ad, erişim adresi, dil, saat dilimi.
6. **İlk organizasyon**: örn. şirketinizin adı → **Kurulumu tamamla**.

Kurulum bittikten sonra sihirbaz kapanır ve token geçersiz olur. Ekip arkadaşlarını **Üyeler → Üye
davet et** ile eklersiniz: oluşan bağlantıyı kişiye iletin (e-posta gönderimi sonraki sürümde).

## 3. Çalıştığını doğrulama
```bash
curl -k https://localhost/health/ready
# {"status":"ok","version":"dev","checks":{"database":"ok","migrations":"ok"}}

docker compose -p scanx -f deploy/docker-compose.yml --env-file deploy/.env ps
# server ve postgres "healthy", nginx "Up" olmalı
```

## 4. Güvenlik duvarı
Sadece 80 (HTTPS'e yönlendirme) ve 443 açık olmalı. Veritabanı dışarıya hiç açılmaz.
```bash
# Ubuntu (ufw)
sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw enable
```

## 5. TLS sertifikası
Kurulum otomatik olarak **kendinden imzalı** bir sertifika üretir; tarayıcı ilk girişte uyarı
verir. Kendi sertifikanızı kullanmak için:
```bash
docker run --rm -v scanx_certs:/certs -v "$PWD":/in alpine \
  sh -c 'cp /in/fullchain.pem /certs/cert.pem && cp /in/privkey.pem /certs/key.pem && chmod 600 /certs/key.pem'
docker compose -p scanx -f deploy/docker-compose.yml --env-file deploy/.env restart nginx
```
Let's Encrypt otomasyonu Faz 6'da eklenecek.

## 6. Günlük işlemler

| İşlem | Komut (repo klasöründe) |
|---|---|
| Durum | `docker compose -p scanx -f deploy/docker-compose.yml --env-file deploy/.env ps` |
| Loglar | `docker compose -p scanx -f deploy/docker-compose.yml --env-file deploy/.env logs -f --tail 100` |
| Durdur | `docker compose -p scanx -f deploy/docker-compose.yml --env-file deploy/.env down` |
| Başlat | `./deploy/quickstart.sh` (mevcut ayarlar korunur) |
| Güncelle | `git pull && ./deploy/quickstart.sh` |
| DB yedeği | `docker compose -p scanx -f deploy/docker-compose.yml --env-file deploy/.env exec -T postgres pg_dump -U scanx -Fc scanx > scanx-$(date +%F).dump` |

Servisler `restart: unless-stopped` ile çalışır; sunucu yeniden başlarsa Docker hepsini otomatik
ayağa kaldırır (Docker servisinin açılışta başladığından emin olun: `sudo systemctl enable docker`).

> `docker compose down -v` **verileri siler** (veritabanı dahil). Yalnızca tamamen kaldırmak
> istiyorsanız kullanın.

## 7. Sorun giderme

| Belirti | Çözüm |
|---|---|
| `Docker is installed but not running` | `sudo systemctl start docker`; kullanıcınız `docker` grubunda mı? |
| `port is already allocated` | 80/443'ü başka uygulama kullanıyor → `--http-port 8080 --https-port 8443` |
| `/health/ready` → `"migrations":"fail"` | `docker compose ... logs migrate` çıktısına bakın |
| `/health/ready` → `"database":"fail"` | `docker compose ... logs postgres`; disk dolu mu? (`df -h`) |
| Tarayıcı "güvenli değil" diyor | Kendinden imzalı sertifika — normal. Bölüm 5 ile kendi sertifikanızı koyun |

Hata bildirirken `logs` çıktısını ekleyin, **`.env` içeriğini asla paylaşmayın**.

---

## Yakında: GitHub'a bağlama (Faz 3–4)

Bu adımlar özellik tamamlandığında böyle çalışacak:

1. scanX arayüzünde **Proje ekle** → repo adresini yapıştırın (`git@github.com:firma/uygulama.git`).
2. scanX size bir **deploy key** (açık SSH anahtarı) gösterir → GitHub'da repo
   **Settings → Deploy keys → Add deploy key**, yapıştırın, "Allow write access" **işaretlemeyin**.
3. **Bağlantıyı test et** butonu ile doğrulayın.
4. Taranacak branch'leri seçin (ör. yalnızca `main`).
5. scanX bir **webhook adresi ve gizli anahtar** verir → GitHub'da **Settings → Webhooks → Add
   webhook**, Content type `application/json`, olay olarak "Just the push event".
6. Artık seçtiğiniz branch'e her push'ta tarama otomatik başlar, rapor scanX'te görünür.

GitHub Actions içinden tarama (sunucuya kod göndermeden) için hazır bir Action da Faz 5'te gelecek.
