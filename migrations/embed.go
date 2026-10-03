// Package migrations embeds the ordered SQL schema migrations. Files are
// applied in lexical order by internal/store.Migrate and recorded in
// schema_migrations; never edit a migration that has shipped, add a new one.
package migrations

import "embed"

// FS holds every *.sql migration.
//
//go:embed *.sql
var FS embed.FS
