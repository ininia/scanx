package dbscan

import (
	"strings"
	"unicode"
)

// Tokens splits an identifier into lower-case words: snake_case,
// kebab-case, camelCase, PascalCase, "spaced names" and digits.
func Tokens(name string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(name)
	for i, r := range rs {
		switch {
		case r == '_' || r == '-' || r == ' ' || r == '.' || r == '$':
			flush()
		case unicode.IsUpper(r):
			// New word on lower→Upper, and on the last upper of an acronym
			// followed by lower (HTTPServer → http, server).
			if len(cur) > 0 {
				prev := rs[i-1]
				nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
				if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
					flush()
				}
			}
			cur = append(cur, r)
		case unicode.IsDigit(r):
			if len(cur) > 0 && !unicode.IsDigit(cur[len(cur)-1]) {
				flush()
			}
			cur = append(cur, r)
		default:
			if len(cur) > 0 && unicode.IsDigit(cur[len(cur)-1]) {
				flush()
			}
			cur = append(cur, r)
		}
	}
	flush()
	return out
}

// Fold lowercases, maps Turkish letters to ASCII and removes separators:
// "Created_Date" and "createdDate" both fold to "createddate".
func Fold(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(foldTR(name)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var trFold = strings.NewReplacer("ç", "c", "Ç", "C", "ğ", "g", "Ğ", "G", "ı", "i", "İ", "I", "ö", "o", "Ö", "O", "ş", "s", "Ş", "S", "ü", "u", "Ü", "U")

func foldTR(s string) string { return trFold.Replace(s) }

// Style classifies an identifier's case style. Single-word names return
// "lower" or "upper" (compatible with several styles) or pascal for
// "Users".
func Style(name string) string {
	hasUnderscore := strings.Contains(name, "_")
	hasLower, hasUpper := false, false
	for _, r := range name {
		if unicode.IsLower(r) {
			hasLower = true
		}
		if unicode.IsUpper(r) {
			hasUpper = true
		}
	}
	first := []rune(name)
	if len(first) == 0 {
		return ""
	}
	switch {
	case strings.ContainsAny(name, " -"):
		return "mixed"
	case hasUnderscore && hasLower && !hasUpper:
		return CaseSnake
	case hasUnderscore && hasUpper && !hasLower:
		return CaseUpperSnake
	case hasUnderscore:
		return "mixed"
	case hasUpper && !hasLower:
		return "upper"
	case !hasUpper:
		return "lower"
	case unicode.IsUpper(first[0]):
		return CasePascal
	default:
		return CaseCamel
	}
}

// StyleCompatible reports whether a name's style fits the expected one.
func StyleCompatible(style, want string) bool {
	switch style {
	case want:
		return true
	case "lower":
		return want == CaseSnake || want == CaseCamel
	case "upper":
		return want == CaseUpperSnake
	}
	return false
}

// Plurality guesses whether the last word of a name is plural.
// Returns "plural", "singular" or "" (cannot tell).
func Plurality(name string) string {
	toks := Tokens(foldTR(name))
	if len(toks) == 0 {
		return ""
	}
	w := toks[len(toks)-1]
	if len(w) < 3 || uncountable[w] {
		return ""
	}
	if irregularPlural[w] {
		return "plural"
	}
	switch {
	case len(w) > 5 && (strings.HasSuffix(w, "leri") || strings.HasSuffix(w, "lari")):
		return "plural" // Turkish plural + possessive: adresleri, urunleri
	case strings.HasSuffix(w, "lar") || strings.HasSuffix(w, "ler"):
		if trWords[w] || trWords[strings.TrimSuffix(strings.TrimSuffix(w, "lar"), "ler")] {
			return "plural"
		}
	case strings.HasSuffix(w, "ss"), strings.HasSuffix(w, "us"), strings.HasSuffix(w, "is"), strings.HasSuffix(w, "ics"):
		return "singular"
	case strings.HasSuffix(w, "s"):
		return "plural"
	}
	return "singular"
}

var (
	uncountable = map[string]bool{
		"data": true, "info": true, "information": true, "metadata": true, "media": true, "news": true, "series": true,
		"species": true, "equipment": true, "staff": true, "history": true, "audit": true, "inventory": true,
		"stock": true, "feedback": true, "software": true, "status": true, "settings": true, "analytics": true,
		"log": true, "logs": true, "cache": true, "config": true, "auth": true,
	}
	irregularPlural = map[string]bool{"people": true, "children": true, "men": true, "women": true, "mice": true, "indices": true, "criteria": true}
)

// neutralTokens never decide the language of a name.
var neutralTokens = map[string]bool{
	"id": true, "no": true, "nr": true, "url": true, "uri": true, "api": true, "ip": true, "tc": true, "sms": true,
	"pk": true, "fk": true, "ix": true, "uk": true, "uid": true, "guid": true, "uuid": true, "json": true, "xml": true,
	"html": true, "pdf": true, "iban": true, "swift": true, "vat": true, "dt": true, "ts": true, "x": true, "y": true,
}

// trWords are common Turkish words in database names (ASCII-folded).
//
//nolint:misspell // Turkish vocabulary, not English misspellings
var trWords = setOf(`
kullanici kullanicilar musteri musteriler siparis siparisler urun urunler fatura faturalar odeme odemeler adres adresler
tarih tarihi ad adi soyad soyadi sifre parola tutar tutari fiyat fiyati miktar miktari adet adedi aciklama aciklamasi durum
durumu kayit kayitlari olusturma olusturan olusturulma guncelleme guncelleyen guncellenme silinme silindi silinen silen
pasif kod kodu numara numarasi telefon eposta sehir ilce ulke firma firmalar sirket personel calisan calisanlar departman
birim gorev gorevler yetki yetkiler islem islemler hareket hareketler stok depo depolar kategori kategoriler marka toplam
indirim vergi sepet yorum yorumlar puan dosya dosyalar belge belgeler resim gorsel mesaj mesajlar bildirim bildirimler ayar
ayarlar kisi kisiler kimlik tckn hesap hesaplar banka kart kartlar sube subeler bolge proje projeler talep talepler sikayet
randevu ogrenci ogrenciler ders dersler sinif ogretmen hasta hastalar doktor arac araclar plaka sofor rota sefer teslimat
kargo iade satis satislar alis alim tedarikci cari borc alacak bakiye tahsilat fis irsaliye teklif teklifler sozlesme
baslangic bitis sure saat gun ay yil donem deger degeri sira sirasi sayi sayisi agirlik renk beden olcu baslik icerik ozet
etiket etiketler giris cikis sonuc onay onaylandi onaylayan iptal gecerli varsayilan eski yeni ust alt ana detay detaylar
liste tur turu cinsiyet dogum yas egitim meslek maas izin izinler mesai vardiya bordro unvan aktiflik silindimi ekleyen
eklenme degistiren degistirme kullaniciadi eklenen yonetici yoneticiler grup gruplar uye uyeler abone aboneler ilan
ilanlar haber haberler duyuru duyurular sayfa sayfalar menu menuler dil diller para birimi kur kurlar fiyatlar gelir gider
masraf masraflar butce cek senet vade taksit taksitler tahsilatlar odemeleri aylik yillik gunluk haftalik
`)

// enWords are common English words in database names.
var enWords = setOf(`
user users customer customers order orders product products invoice invoices payment payments address addresses date name
first last created updated deleted modified status amount price quantity description code number phone email city country
company employee employees department role roles permission permissions account accounts transaction transactions category
categories brand total discount tax cart comment comments file files document documents image images message messages
notification notifications setting settings type value title content start end time active enabled item items detail
details line lines group groups member members owner parent child level count rate currency balance note notes tag tags
event events task tasks project projects report reports supplier suppliers stock warehouse shipment shipping delivery
return refund sale sales purchase contract offer start finish duration hour day month year period sort order key token
session login password hash salt birth gender age salary leave shift vendor client clients service services request
requests ticket tickets reply replies review reviews rating ratings page pages menu language
`)

func setOf(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// trChars matches Turkish-only letters.
func hasTurkishChars(s string) bool { return strings.ContainsAny(s, "çğıöşüÇĞİÖŞÜ") }

// ForeignWords returns the words of name that are not in the expected
// language (en or tr).
func ForeignWords(name, lang string) []string {
	var out []string
	for _, raw := range Tokens(name) {
		t := foldTR(raw)
		if neutralTokens[t] || len(t) < 2 {
			continue
		}
		switch lang {
		case "en":
			if hasTurkishChars(raw) || (trWords[t] && !enWords[t]) || (len(t) > 5 && (strings.HasSuffix(t, "lari") || strings.HasSuffix(t, "leri"))) {
				out = append(out, raw)
			}
		case "tr":
			if enWords[t] && !trWords[t] {
				out = append(out, raw)
			}
		}
	}
	return out
}

// NeedsQuoting reports names with characters that force quoting in SQL
// (spaces, dashes, non-ASCII letters, leading digit).
func NeedsQuoting(name string) bool {
	for i, r := range name {
		if r > unicode.MaxASCII {
			return true
		}
		if !unicode.IsLetter(r) && r != '_' && (i == 0 || !unicode.IsDigit(r)) {
			return true
		}
	}
	return false
}

// reservedCommon are reserved in standard SQL and most engines.
var reservedCommon = setOf(`
all alter and any as asc between by case check column constraint create cross current_date current_time current_timestamp
current_user database default delete desc distinct drop else end exists foreign from full grant group having in index
inner insert intersect into is join key left like not null on or order outer primary procedure references revoke right
rollback schema select session_user set some table then to transaction trigger union unique update user using values view
when where with
`)

var reservedByEngine = map[string]map[string]bool{
	EnginePostgres: setOf(`analyse analyze array asymmetric both cast collate concurrently do fetch freeze ilike leading limit localtime localtimestamp natural notnull offset only overlaps placing returning similar symmetric trailing variadic verbose window`),
	EngineMySQL:    setOf(`accessible condition database databases delayed div dual explain fulltext generated interval keys kill limit lines load lock long match mod range rank read release rename repeat replace require rows separator show signal spatial sql ssl starting usage write zerofill`),
	EngineMSSQL:    setOf(`backup bulk clustered compute contains convert dbcc deny disk distributed dump errlvl exec execute exit external file fillfactor freetext function holdlock identity identity_insert identitycol kill lineno load merge national nocheck nonclustered off offsets open opendatasource openquery openrowset openxml over percent pivot plan print proc public raiserror read readtext reconfigure replication restore restrict return revert rowcount rowguidcol rule save securityaudit semantickeyphrasetable setuser shutdown statistics system_user tablesample textsize top tran truncate try_convert tsequal unpivot updatetext use waitfor while writetext`),
}

// Reserved reports whether name is a reserved word on the engine.
func Reserved(name, engine string) bool {
	l := strings.ToLower(name)
	return reservedCommon[l] || reservedByEngine[engine][l]
}
