package auth

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPasswordHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected format %s", h)
	}
	ok, rehash, err := VerifyPassword("correct horse battery staple", h)
	if !ok || rehash || err != nil {
		t.Fatalf("verify: %v %v %v", ok, rehash, err)
	}
	if ok, _, _ := VerifyPassword("wrong horse battery staple", h); ok {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery staple")
	if h == h2 {
		t.Fatal("salt must be random")
	}
	weak := "$argon2id$v=19$m=1024,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$" + strings.Repeat("A", 43)
	if _, rehash, err := VerifyPassword("x", weak); err != nil || !rehash {
		t.Fatalf("weak params must request rehash: %v %v", rehash, err)
	}
	for _, bad := range []string{"", "$bcrypt$x", "$argon2id$v=18$m=1,t=1,p=1$a$b", "$argon2id$v=19$m=0,t=1,p=1$a$b", "$argon2id$v=19$m=65536,t=3,p=2$!!$b"} {
		if _, _, err := VerifyPassword("x", bad); !errors.Is(err, ErrInvalidHash) {
			t.Errorf("%q: want ErrInvalidHash, got %v", bad, err)
		}
	}
	VerifyDummy("anything") // must not panic
}

func TestValidatePassword(t *testing.T) {
	cases := map[string]error{
		"short":                          ErrPasswordTooShort,
		strings.Repeat("a", 257):         ErrPasswordTooLong,
		"aaaaaaaaaaaaaaaa":               ErrPasswordWeak,
		"Password1234!":                  ErrPasswordWeak,
		"alice-very-long-pass":           ErrPasswordWeak, // contains the e-mail local part
		"Tr0ub4dor&3-horse-staple":       nil,
		"çok güçlü bir parola cümlesi 7": nil,
	}
	for pw, want := range cases {
		if got := ValidatePassword(pw, "alice@example.test"); !errors.Is(got, want) {
			t.Errorf("%q: got %v want %v", pw, got, want)
		}
	}
}

// RFC 6238 Appendix B (SHA-1), last 6 digits of the 8-digit reference codes.
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	vectors := map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"}
	for ts, want := range vectors {
		if got := TOTPCode(secret, ts/30); got != want {
			t.Errorf("T=%d got %s want %s", ts, got, want)
		}
		if _, ok := VerifyTOTP(secret, want, time.Unix(ts, 0)); !ok {
			t.Errorf("T=%d verify failed", ts)
		}
	}
	now := time.Unix(1234567890, 0)
	prev := TOTPCode(secret, now.Unix()/30-1)
	if _, ok := VerifyTOTP(secret, prev, now); !ok {
		t.Error("previous step must be accepted (clock skew)")
	}
	old := TOTPCode(secret, now.Unix()/30-3)
	if _, ok := VerifyTOTP(secret, old, now); ok {
		t.Error("old code accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := VerifyTOTP(secret, bad, now); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, ok := VerifyTOTP(secret, " 005 924 ", now); !ok {
		t.Error("spaces must be ignored")
	}
}

func TestTOTPSecretAndURI(t *testing.T) {
	s, err := NewTOTPSecret()
	if err != nil || len(s) != 20 {
		t.Fatalf("%v %d", err, len(s))
	}
	uri := TOTPURI("scanX", "alice@example.test", s)
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "otpauth" || u.Query().Get("secret") != EncodeTOTPSecret(s) || u.Query().Get("issuer") != "scanX" {
		t.Fatalf("uri %s", uri)
	}
}

func TestReplayGuard(t *testing.T) {
	g := NewReplayGuard()
	now := time.Now()
	if !g.Use("u1", 100, now) || g.Use("u1", 100, now) {
		t.Fatal("replay not detected")
	}
	if !g.Use("u2", 100, now) {
		t.Fatal("different user must be independent")
	}
	if !g.Use("u1", 100, now.Add(5*time.Minute)) {
		t.Fatal("entries must expire")
	}
}

func TestTokens(t *testing.T) {
	p, h, err := NewToken(PrefixPersonal)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p, "scanx_pat_") || len(p) != len("scanx_pat_")+40 || !bytes.Equal(HashToken(p), h) {
		t.Fatalf("token %s", p)
	}
	p2, _, _ := NewToken(PrefixPersonal)
	if p == p2 {
		t.Fatal("tokens must be unique")
	}
	if TokenDisplayPrefix(p) != p[:14] || TokenDisplayPrefix("short") != "short" {
		t.Fatal("display prefix")
	}
	s, sh, err := NewSessionToken()
	if err != nil || len(s) < 40 || !bytes.Equal(HashToken(s), sh) {
		t.Fatal("session token")
	}
}

func TestCSRF(t *testing.T) {
	key := []byte("FAKE-csrf-key-0123456789abcdef0123")
	seed, err := NewCSRFSeed()
	if err != nil {
		t.Fatal(err)
	}
	tok := CSRFToken(key, seed)
	if !VerifyCSRF(key, seed, tok) {
		t.Fatal("valid token rejected")
	}
	other, _ := NewCSRFSeed()
	for name, ok := range map[string]bool{
		"other seed":  VerifyCSRF(key, other, tok),
		"empty token": VerifyCSRF(key, seed, ""),
		"empty seed":  VerifyCSRF(key, "", tok),
		"other key":   VerifyCSRF([]byte("other"), seed, tok),
		"seed as tok": VerifyCSRF(key, seed, seed),
	} {
		if ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRBAC(t *testing.T) {
	if !Can(RoleOwner, ActOwnershipGrant) || Can(RoleAdmin, ActOwnershipGrant) {
		t.Fatal("ownership")
	}
	if !Can(RoleAdmin, ActMembersManage) || Can(RoleMember, ActMembersManage) {
		t.Fatal("members")
	}
	if !Can(RoleMember, ActProjectWrite) || Can(RoleViewer, ActProjectWrite) {
		t.Fatal("project write")
	}
	if !Can(RoleViewer, ActProjectRead) || Can(Role("guest"), ActProjectRead) || Can(RoleOwner, Action("nuke")) {
		t.Fatal("unknown roles/actions must be denied")
	}
	if !ValidRole("viewer") || ValidRole("root") {
		t.Fatal("ValidRole")
	}
}

func TestPrincipal(t *testing.T) {
	p := &Principal{UserID: uuid.New()}
	if p.ViaToken() || !p.HasScope("write") {
		t.Fatal("session principals have all scopes")
	}
	tp := &Principal{TokenID: uuid.New(), TokenScopes: []string{"read"}}
	if !tp.HasScope("read") || tp.HasScope("write") {
		t.Fatal("token scopes")
	}
	wp := &Principal{TokenID: uuid.New(), TokenScopes: []string{"write"}}
	if !wp.HasScope("read") {
		t.Fatal("write implies read")
	}
	ctx := WithPrincipal(context.Background(), p)
	if PrincipalFrom(ctx) != p || PrincipalFrom(context.Background()) != nil {
		t.Fatal("context")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(5, time.Minute, 5)
	now := time.Now()
	for i := 0; i < 5; i++ {
		if !l.AllowAt("1.2.3.4", now) {
			t.Fatalf("request %d denied", i)
		}
	}
	if l.AllowAt("1.2.3.4", now) {
		t.Fatal("6th request in a minute allowed")
	}
	if !l.AllowAt("5.6.7.8", now) {
		t.Fatal("other key must be independent")
	}
	if !l.AllowAt("1.2.3.4", now.Add(13*time.Second)) {
		t.Fatal("tokens must refill")
	}
}
