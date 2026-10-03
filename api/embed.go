// Package api embeds the OpenAPI document served at GET /openapi.yaml.
package api

import _ "embed"

// OpenAPI is the OpenAPI 3.1 specification of the control-plane API.
//
//go:embed openapi.yaml
var OpenAPI []byte
