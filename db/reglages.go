package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// The settings of the site, in the reglages table: today the keys of the
// notifications (push.go).

// GetReglage returns the value of a setting, or "" when it was never set.
func GetReglage(ctx context.Context, db *sql.DB, cle string) (string, error) {
	var v string
	err := db.QueryRowContext(ctx, `SELECT valeur FROM reglages WHERE cle = ?`, cle).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("while reading setting %s: %w", cle, err)
	}
	return v, nil
}

// InitReglage sets a setting only if it has no value yet, and returns the
// value it ends up with. Two processes racing get the same value.
func InitReglage(ctx context.Context, db *sql.DB, cle, valeur string) (string, error) {
	if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO reglages (cle, valeur) VALUES (?, ?)`, cle, valeur); err != nil {
		return "", fmt.Errorf("while initialising setting %s: %w", cle, err)
	}
	return GetReglage(ctx, db, cle)
}
