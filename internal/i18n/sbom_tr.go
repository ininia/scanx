package i18n

// SBOM inventory and continuous vulnerability monitoring.
var trSBOM = map[string]string{
	"nav.sbom":               "SBOM & CVE",
	"sbom.title":             "SBOM & CVE izleme",
	"sbom.subtitle":          "Projelerinizin kullandığı tüm paketlerin envanteri; yeni yayınlanan açıklar kod yeniden taranmadan her gün kontrol edilir.",
	"sbom.export_inventory":  "Envanteri indir (CSV)",
	"sbom.export_vulns":      "Açıkları indir (CSV)",
	"sbom.check_now":         "Şimdi kontrol et",
	"sbom.running":           "Açık veritabanı güncelleniyor ve envanter kontrol ediliyor…",
	"sbom.components":        "Bileşen",
	"sbom.packages_projects": "%d paket · %d proje",
	"sbom.open":              "Açık zafiyet",
	"sbom.crit_high":         "%d kritik · %d yüksek",
	"sbom.resolved30":        "Son 30 günde çözülen",
	"sbom.last_run":          "Son kontrol",
	"sbom.advisories":        "%d bildirim tarandı",
	"sbom.tab.vulns":         "Açıklar",
	"sbom.tab.components":    "Bileşenler",
	"sbom.tab.licenses":      "Lisanslar",
	"sbom.tab.resolved":      "Çözülenler",
	"sbom.search":            "Paket ara (ör. log4j, lodash)…",
	"sbom.run_log":           "Son kontrolün günlüğü",
	"sbom.no_vulns":          "Envanterdeki paketleri etkileyen açık bilinen bir zafiyet yok.",
	"sbom.advisory":          "Bildirim",
	"sbom.package":           "Paket",
	"sbom.version":           "Sürüm",
	"sbom.fixed":             "Düzeltilen sürüm",
	"sbom.no_fix":            "henüz yok",
	"sbom.first_seen":        "İlk görülme",
	"sbom.top_hint":          "En çok projede kullanılan paketler. Bir pakete tıklayarak hangi projelerde hangi sürümün kullanıldığını görün.",
	"sbom.ecosystem":         "Ekosistem",
	"sbom.projects":          "Proje",
	"sbom.versions":          "Sürüm sayısı",
	"sbom.license":           "Lisans",
	"sbom.license_hint":      "Bağımlılıkların lisansları. Güçlü copyleft lisanslar (GPL, AGPL…) yazılımı dağıtırken kaynak kodu paylaşma yükümlülüğü getirebilir.",
	"sbom.copyleft":          "copyleft",
	"sbom.none_resolved":     "Son 30 günde çözülen kayıt yok.",
	"sbom.resolved_at":       "Çözüldü",
	"sbom.notify.project":    "Bağımlılık açıkları",
	"sbom.notify.branch":     "%d proje",
	"sbom.notify.note":       "Kullandığınız paketlerde %d yeni açık yayınlandı.",

	"event.sbom.vuln":     "Kullanılan paketlerde yeni açık yayınlandığında",
	"module.sbom":         "SBOM & CVE izleme",
	"module.sbom.desc":    "Bağımlılık envanteri, lisanslar ve yeni açıkların günlük takibi (repo taramalarından beslenir).",
	"module.sbom.max":     "En fazla (kullanılmıyor)",
	"flash.sbom_checking": "Kontrol sıraya alındı.",
}

func init() {
	for k, v := range trSBOM {
		tr[k] = v
	}
}
