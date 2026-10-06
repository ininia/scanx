package report

import (
	_ "embed"
	"html/template"
	"io"
	"strconv"
	"strings"

	"github.com/ininia/scanx/internal/finding"
)

//go:embed templates/report.html.tmpl
var htmlTemplate string

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"sevClass": func(s finding.Severity) string { return "sev-" + s.String() },
	"join":     strings.Join,
	"gateClass": func(g Gate) string {
		if g.Result == "fail" {
			return "gate-fail"
		}
		return "gate-pass"
	},
	"scoreClass": func(score int) string {
		switch {
		case score >= 80:
			return "score-good"
		case score >= 50:
			return "score-mid"
		default:
			return "score-bad"
		}
	},
	"secs": func(ms int64) string { return strconv.FormatFloat(float64(ms)/1000, 'f', 1, 64) + "s" },
}).Parse(htmlTemplate))

// WriteHTML renders a self-contained HTML report (no external resources, no
// JavaScript). All values are escaped by html/template.
func (r *Report) WriteHTML(w io.Writer) error {
	return htmlTmpl.Execute(w, r)
}
