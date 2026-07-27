package store

import "errors"

// ErrNotFound is returned by every lookup that comes back empty, so callers
// never have to reason about database/sql.ErrNoRows.
var ErrNotFound = errors.New("store: not found")
