package inspect

import (
	"net"
	"strings"
	"testing"

	"github.com/ininia/scanx/internal/dbscan"
)

func TestParseGrantsReadOnly(t *testing.T) {
	ro := &dbscan.ReadOnlyCheck{}
	roles := parseGrants([]string{
		"GRANT USAGE ON *.* TO `scan`@`%`",
		"GRANT SELECT, SHOW VIEW ON `erp`.* TO `scan`@`%`",
		"GRANT SELECT (`id`, `name`) ON `erp`.`users` TO `scan`@`%`",
		"GRANT `reporting`@`%` TO `scan`@`%`",
	}, ro)
	if len(ro.Violations) != 0 || len(roles) != 1 || roles[0] != "`reporting`@`%`" {
		t.Fatalf("%+v roles %v", ro, roles)
	}
}

func TestParseGrantsWrite(t *testing.T) {
	cases := []string{
		"GRANT ALL PRIVILEGES ON *.* TO `root`@`localhost` WITH GRANT OPTION",
		"GRANT SELECT, INSERT, UPDATE ON `erp`.* TO `app`@`%`",
		"GRANT PROXY ON ``@`` TO `root`@`localhost`",
		"GRANT SELECT ON `erp`.* TO `x`@`%` WITH GRANT OPTION",
	}
	for _, c := range cases {
		ro := &dbscan.ReadOnlyCheck{}
		parseGrants([]string{c}, ro)
		if len(ro.Violations) == 0 {
			t.Errorf("%q accepted", c)
		}
	}
}

func TestEncodeDecode(t *testing.T) {
	in := &Result{
		OK: true, ReadOnly: &dbscan.ReadOnlyCheck{OK: true, User: "scan"},
		Snapshot: &dbscan.Snapshot{Engine: "postgres", Tables: []dbscan.Table{{Name: "users"}}},
	}
	line, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode([]byte("noise\n" + ResultPrefix + line + "\n"))
	if err != nil || !out.OK || out.Snapshot.Tables[0].Name != "users" || out.ReadOnly.User != "scan" {
		t.Fatalf("%+v %v", out, err)
	}
	if _, err := Decode([]byte("nothing")); err == nil {
		t.Fatal("expected error")
	}
}

func TestBlocked(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "::1", "0.0.0.0", "fe80::1"} {
		if !Blocked(net.ParseIP(ip)) {
			t.Errorf("%s allowed", ip)
		}
	}
	for _, ip := range []string{"10.0.0.5", "192.168.1.10", "172.20.0.3", "8.8.8.8"} {
		if Blocked(net.ParseIP(ip)) {
			t.Errorf("%s blocked", ip)
		}
	}
}

func TestClassifyAndTypes(t *testing.T) {
	if c, _ := classify(errString(`pq: password authentication failed for user "x"`)); c != "auth" {
		t.Fatal(c)
	}
	if c, _ := classify(errString("dial tcp 10.0.0.1:5432: i/o timeout")); c != "connect" {
		t.Fatal(c)
	}
	if ft, n := mssqlFullType("nvarchar", 200, 0, 0); ft != "nvarchar(100)" || n != 100 {
		t.Fatal(ft, n)
	}
	if ft, _ := mssqlFullType("varchar", -1, 0, 0); ft != "varchar(max)" {
		t.Fatal(ft)
	}
	if !strings.HasPrefix(pgType("int4"), "integer") {
		t.Fatal(pgType("int4"))
	}
}

type errString string

func (e errString) Error() string { return string(e) }
