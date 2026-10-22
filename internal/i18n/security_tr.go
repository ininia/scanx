package i18n

// Admin-enforced 2FA and password reset links.
var trSecurity = map[string]string{
	"members.2fa_required":       "2FA zorunlu",
	"members.2fa_required_hint":  "Bu kullanıcı 2FA kurmadan scanX'i kullanamaz.",
	"members.2fa_require":        "2FA zorunlu yap",
	"members.2fa_require_hint":   "2FA'sı açık değilse kullanıcı bir sonraki işleminde 2FA kurmaya yönlendirilir; kurana kadar başka sayfa açamaz.",
	"members.2fa_unrequire":      "Zorunluluğu kaldır",
	"members.2fa_unrequire_hint": "Kullanıcı 2FA'yı isterse kapatabilir hale gelir.",
	"members.reset_link":         "Parola linki",
	"members.reset_hint":         "Tek kullanımlık parola yenileme bağlantısı oluşturur (24 saat geçerli).",
	"members.reset_confirm":      "%s için parola yenileme bağlantısı oluşturulsun mu? Kullanıcının açık oturumları yeni parola belirlendiğinde kapanır.",
	"members.reset_created":      "%s için parola yenileme bağlantısı oluşturuldu. 24 saat geçerli ve tek kullanımlık; yalnızca şimdi gösteriliyor, kullanıcıya güvenli bir kanaldan iletin.",
	"members.invite_2fa":         "2FA zorunlu",
	"members.invite_2fa_hint":    "Davetli kayıt olurken iki adımlı doğrulamayı kurmak zorunda kalır.",
	"invite.require_2fa":         "Bu organizasyon 2FA zorunlu tutuyor: hesabınızı oluşturduktan sonra bir doğrulama uygulamasıyla (Google/Microsoft Authenticator vb.) iki adımlı doğrulamayı kurmanız istenecek.",
	"reset.title":                "Yeni parola belirleyin",
	"reset.body":                 "%s hesabı için yeni bir parola belirleyin.",
	"reset.submit":               "Parolayı kaydet",
	"reset.note":                 "Kaydettiğinizde tüm açık oturumlar kapanır; yeni parolanızla (2FA açıksa doğrulama koduyla) yeniden giriş yaparsınız.",
	"flash.password_reset":       "Parolanız güncellendi. Yeni parolanızla giriş yapın.",
	"account.2fa_required_org":   "Organizasyon yöneticiniz bu hesap için 2FA'yı zorunlu tuttuğundan kapatılamaz.",
}

func init() {
	for k, v := range trSecurity {
		tr[k] = v
	}
}
