// Package apispec embeds the OpenAPI contract (served at /api/v1/openapi.yaml
// and used by contract tests).
package apispec

import _ "embed"

// OpenAPI is the raw api/openapi.yaml.
//
//go:embed openapi.yaml
var OpenAPI []byte
