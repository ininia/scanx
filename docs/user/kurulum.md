# scanX Kurulum Kılavuzu (DevOps için)

Bu kılavuz yazılım bilgisi gerektirmez. Linux sunucuda komut çalıştırabiliyor ve Docker
kullanabiliyorsanız yeterli.

> **Durum (Faz 4):** Sunucu repoyu deploy key ile kendisi çeker ve izole konteynerde tarar; "Şimdi
> tara" butonu, push'ta otomatik tarama (webhook), sonuç/bulgu sayfaları, HTML/JSON/SARIF/SBOM
> raporları ve Slack/Teams/e-posta bildirimleri çalışıyor. GitHub bağlantısı için **Bölüm 8**.

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
| CPU / RAM / Disk | 2 vCPU / **4 GB** / 40 GB | 4 vCPU / 8 GB / 100 GB |
| Yazılım | Docker Engine 24+, Docker Compose v2, git, curl | |
| Ağ | 80 ve 443 portları açık; GitHub webhook'u için sunucu internetten erişilebilir olmalı | |

> **1 GB RAM'li sunucuda** arayüz çalışır ama tarama yapılamaz (tarayıcılar ~3 GB kullanır).
> DigitalOcean'da *Resize* ile en az 4 GB'a çıkarın. Az RAM'de `deploy/.env` içinde
> `SCANX_SCANNER_MEMORY=2g` deneyebilirsiniz.

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

İlk kurulumda tarayıcı imajı da hazırlanır (güvenlik araçları + zafiyet veritabanları, ~1.5 GB,
10–20 dk). Sonraki çalıştırmalar önbellekten hızlıdır.

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
# server ve postgres "healthy"; nginx, worker ve docker-proxy "Up" olmalı
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

## 8. GitHub'a bağlama ve otomatik tarama

### 8.1 Projeyi ekleyin
**Projeler → Proje ekle** → repo adresini yapıştırın:
- Özel (private) repo: **SSH adresi** `git@github.com:firma/uygulama.git`
- Herkese açık repo: HTTPS adresi de olur `https://github.com/firma/uygulama.git` (anahtar gerekmez)

"Taranacak branch'ler"e örn. `main` yazın (`release/*` gibi desenler de olur).

### 8.2 Deploy key'i GitHub'a ekleyin (yalnızca SSH adresinde)
Proje sayfasındaki **1. Deploy key** kartında `ssh-ed25519 …` ile başlayan satırı ⧉ ile kopyalayın.
GitHub'da repo → **Settings → Deploy keys → Add deploy key**:
- Title: `scanX`
- Key: kopyaladığınız satır
- **Allow write access: İŞARETLEMEYİN** (scanX yalnızca okur)

Sonra scanX'te **Bağlantıyı test et** → "Bağlantı başarılı ✓" ve branch listesi görünmeli.

### 8.3 İlk tarama
Sağ üstte branch'i seçip **Şimdi tara**. Tarama sayfası kendiliğinden güncellenir:
Sırada → Kod çekiliyor → Taranıyor → Rapor hazırlanıyor → Tamamlandı. Orta boy bir repo
birkaç dakika sürer. Sonuçta skor, kalite kapısı (Geçti/Kaldı), bulgular ve indirilebilir
raporlar (HTML, JSON, SARIF, SBOM) vardır. Kaynak kod tarama bitince sunucudan silinir.

### 8.4 Push'ta otomatik tarama (webhook)
Proje sayfasındaki **2. Webhook** kartından adresi ve "Gizli anahtarı göster" ile sırrı kopyalayın.
GitHub'da repo → **Settings → Webhooks → Add webhook**:
- Payload URL: scanX'teki webhook adresi (`https://SUNUCU/api/v1/hooks/github/…`)
- Content type: `application/json`
- Secret: scanX'teki gizli anahtar
- SSL verification: kendinden imzalı sertifika kullanıyorsanız **Disable** (gerçek sertifikada Enable)
- "Just the push event" → **Add webhook**

GitHub hemen bir *ping* gönderir; Webhooks → Recent Deliveries'de yeşil tik görmelisiniz.
Artık seçili branch'lere her push'ta tarama kendiliğinden başlar.

> Sunucu adresi (`SCANX_BASE_URL`) GitHub'ın erişebileceği bir adres olmalı (IP veya alan adı).
> Webhook adresi, kurulum sihirbazında girdiğiniz "erişim adresi"nden üretilir.

GitLab / Gitea / Bitbucket için adımlar proje sayfasında sağlayıcıya göre yazılıdır.

### 8.5 Bildirimler
**Bildirimler → Kanal ekle**: Slack veya Teams "Incoming webhook" adresi, kendi sisteminiz için
JSON webhook ya da e-posta. "Test gönder" ile deneyin. E-posta için `deploy/.env`'e
`SCANX_SMTP_HOST`, `SCANX_SMTP_PORT`, `SCANX_SMTP_USERNAME`, `SCANX_SMTP_PASSWORD`, `SCANX_SMTP_FROM`
ekleyip `./deploy/quickstart.sh` çalıştırın.

### 8.6 Kendi Git sunucunuz (GitLab/Gitea şirket içi)
- İç ağdaysa `deploy/.env`: `SCANX_ALLOW_PRIVATE_GIT_HOSTS=true`
- SSH host anahtarı: `ssh-keyscan git.sirket.local` çıktısını `SCANX_SSH_KNOWN_HOSTS=` satırına
  (birden çok satırı `
` ile birleştirerek) ekleyin, sonra `./deploy/quickstart.sh`.

### 8.7 Sorun giderme (tarama)
| Belirti | Çözüm |
|---|---|
| "Git sunucusu erişimi reddetti" | Deploy key repoya eklenmemiş veya yanlış repoya eklenmiş |
| "Tarayıcıların belleği yetmedi" | Sunucu RAM'ini artırın / `SCANX_SCANNER_MEMORY` |
| Tarama "Sırada"da kalıyor | `docker compose … logs worker` — worker çalışıyor mu? |
| Webhook 401 | Secret yanlış kopyalanmış; scanX'te yenileyip GitHub'da güncelleyin |
| Webhook hiç gelmiyor | Sunucu internetten erişilebilir mi, 443 açık mı? GitHub → Recent Deliveries |
