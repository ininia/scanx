# ADR-008 — Faz 3–4: sunucu tarafı tarama, sandbox sürücüsü, webhook ve bildirimler

- **Durum:** Kabul edildi (Faz 3–4)
- **İlgili:** ADR-001 (iş kuyruğu), ADR-006 (tarayıcı yürütme modeli), şartname §4.2, §5.2, §6

## 1. İş kuyruğu: River yerine kendi `jobs` tablosu
ADR-001 River'ı öneriyordu. İhtiyaç şu an iki iş türü (`scan`, `test_connection`) ve tek worker
servisi; `SELECT … FOR UPDATE SKIP LOCKED` ile alınan, kilit süresi (`locked_until`) heartbeat ile
uzatılan basit bir tablo yeterli ve RLS/denetim modelimize birebir uyuyor. Çöken worker'ın işi
kilit süresi dolunca (en çok 3 deneme) başka worker tarafından alınır; denemeler biterse tarama
`failed / worker_lost` olur. Zamanlanmış taramalar ve öncelikler gerekirse River yeniden
değerlendirilecek.

## 2. Docker SDK yerine minimal Engine API istemcisi
`internal/sandbox` yalnızca kullandığımız uçları (container create/start/inspect/logs/archive/kill/
remove, volume, network, image inspect) düz HTTP ile çağırır; Docker SDK'nın büyük bağımlılık
ağacı yok. Bekleme `/wait` yerine `inspect` yoklamasıyla yapılır: docker-socket-proxy'nin 10 dk
sunucu zaman aşımı uzun taramaları kesmesin diye.

## 3. Docker soketine doğrudan değil, filtreli proxy üzerinden erişim
Worker `tecnativa/docker-socket-proxy` (digest ile sabit) üzerinden konuşur; yalnızca
`containers, images, volumes, networks, _ping, version` açık, `exec, build, swarm, secrets, system`
kapalı. Proxy yalnızca `internal: true` olan `dockerapi` ağında, sadece worker erişebilir.
**Bilinen sınır:** `POST=1` açıkken proxy, istenirse ayrıcalıklı konteyner oluşturmayı engellemez;
güvenlik sınırı worker kodunun kendisidir (her konteyner `ContainerSpec.body()` içinde zorunlu
sertleştirmeyle oluşturulur ve birim testi bunu doğrular). İnternete açık `server` servisi
Docker'a hiç erişemez.

## 4. Tarama iki konteynerde, ortak volume ile
1. **git-fetch** (`scanx git-fetch`, tarayıcı imajında): yalnızca `scanx-egress` köprü ağına
   bağlı (ICC kapalı), deploy key ve known_hosts **ortam değişkeniyle** gelir, `/tmp` (tmpfs)
   içine 0600 yazılır. git, depo kaynaklı hook/fsmonitor/file-ext protokolleri/submodule'ler
   kapalı çalışır; branch ve commit argümanları doğrulanır.
2. **scan**: `network none`, salt-okunur kök, `cap-drop ALL`, `no-new-privileges`, pids/bellek/CPU
   sınırı, uid 65532. Raporlar `archive` API ile okunur.
Konteynerler ve volume (yani kaynak kod) her durumda silinir; başlangıçta ve 5 dakikada bir
`scanx.scan` etiketli artıklar temizlenir.

## 5. Host anahtarı sabitleme (TOFU yok)
github.com, gitlab.com, bitbucket.org ve codeberg.org ed25519 anahtarları koda gömülü ve
sağlayıcıların yayımladığı parmak izleriyle test edilir. Diğer sunucular için yönetici
`SCANX_SSH_KNOWN_HOSTS` verir; bilinmeyen sunucuya bağlanılmaz. Özel ağdaki Git sunucuları
(SSRF) `SCANX_ALLOW_PRIVATE_GIT_HOSTS=true` olmadan reddedilir.

## 6. Webhook'lar
`POST /api/v1/hooks/{provider}/{projectID}`: oturum/CSRF yok, proje başına HMAC sırrı
(şifreli saklanır). GitHub `X-Hub-Signature-256`, Gitea/Forgejo `X-Gitea-Signature`, GitLab
`X-Gitlab-Token`, Bitbucket `X-Hub-Signature`, generic `X-Scanx-Signature`. Teslimat kimliği
tekilleştirilir; aynı commit için tek aktif tarama (kısmi unique index); branch filtresi glob
destekler. Proje kimliği bilinmiyorsa veya sır yoksa 404 (bilgi sızdırmaz).

## 7. Bulgu yaşam döngüsü
`issues (project_id, fingerprint)` tekil. Yeni = ilk kez görülen; bir bulgu yalnızca **tam
(partial olmayan) ve varsayılan branch** taramasında görülmezse `fixed` olur (feature branch
taraması ana branch'teki bulguları "düzeldi" yapmasın diye). Kullanıcı kararları (hatalı alarm,
kabul edilen risk, düzeltilmeyecek) yeni taramalarda korunur; düzelmiş bulgu tekrar görünürse
yeniden açılır.

## 8. Bildirimler
Slack, Teams (Adaptive Card), generic webhook (JSON) ve SMTP e-posta. Hedef URL'ler sır kabul
edilir: şifreli saklanır, arayüzde maskelenir, hata mesajlarına URL yazılmaz. Giden HTTP,
çözümlenen IP'ye bağlanırken özel/loopback/link-local adresleri reddeder (DNS rebinding'e karşı)
ve yönlendirme izlemez.
