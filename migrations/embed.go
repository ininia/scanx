// Package migrations embeds the goose SQL migrations into the binary.
package migrations

import "embed"

// FS holds all *.sql migrations.
//
//go:embed *.sql
var FS embed.FS
