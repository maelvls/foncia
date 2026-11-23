package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// PushAbonnementDB is a device that asked for the notifications of the site
// (Web Push). See migrations/0007_push.sql.
type PushAbonnementDB struct {
	Endpoint string
	P256dh   string
	Auth     string
	Email    string
	UA       string
	// Kind of news → on. A kind missing is on.
	Events    map[string]bool
	CreatedAt time.Time
}

// ErrTropDAbonnements is returned by UpsertPushAbonnement when the new device
// would be one too many.
var ErrTropDAbonnements = errors.New("too many push subscriptions")

// UpsertPushAbonnement adds a device, or updates the one with the same
// endpoint: its date is kept, and its choices too when a.Events is nil. A new
// device is refused with ErrTropDAbonnements when its e-mail already has
// maxParEmail devices or the table maxTotal rows.
func UpsertPushAbonnement(ctx context.Context, db *sql.DB, a PushAbonnementDB, maxParEmail, maxTotal int) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("while starting transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var events string
	err = tx.QueryRowContext(ctx, `SELECT events FROM push_abonnements WHERE endpoint = ?`, a.Endpoint).Scan(&events)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		var parEmail, total int
		err = tx.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE email = ?), count(*) FROM push_abonnements`, a.Email).Scan(&parEmail, &total)
		if err != nil {
			return fmt.Errorf("while counting push subscriptions: %w", err)
		}
		if parEmail >= maxParEmail || total >= maxTotal {
			return ErrTropDAbonnements
		}
		if a.Events == nil {
			a.Events = map[string]bool{}
		}
		b, err := json.Marshal(a.Events)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO push_abonnements (endpoint, p256dh, auth, email, ua, events, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			a.Endpoint, a.P256dh, a.Auth, a.Email, a.UA, string(b), formatTime(a.CreatedAt))
		if err != nil {
			return fmt.Errorf("while adding push subscription: %w", err)
		}
	case err != nil:
		return fmt.Errorf("while reading push subscription: %w", err)
	default:
		if a.Events != nil {
			b, err := json.Marshal(a.Events)
			if err != nil {
				return err
			}
			events = string(b)
		}
		_, err = tx.ExecContext(ctx, `UPDATE push_abonnements SET p256dh = ?, auth = ?, email = ?, ua = ?, events = ? WHERE endpoint = ?`,
			a.P256dh, a.Auth, a.Email, a.UA, events, a.Endpoint)
		if err != nil {
			return fmt.Errorf("while updating push subscription: %w", err)
		}
	}
	return tx.Commit()
}

// DeletePushAbonnement removes a device, and tells whether it was there. With
// an email, only a device of that person is removed.
func DeletePushAbonnement(ctx context.Context, db *sql.DB, endpoint, email string) (bool, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM push_abonnements WHERE endpoint = ? AND (? = '' OR email = ?)`, endpoint, email, email)
	if err != nil {
		return false, fmt.Errorf("while removing push subscription: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ListPushAbonnements returns the devices, oldest first. With an email, only
// the devices of that person.
func ListPushAbonnements(ctx context.Context, db *sql.DB, email string) ([]PushAbonnementDB, error) {
	rows, err := db.QueryContext(ctx, `SELECT endpoint, p256dh, auth, email, ua, events, created_at FROM push_abonnements WHERE ? = '' OR email = ? ORDER BY created_at, endpoint`, email, email)
	if err != nil {
		return nil, fmt.Errorf("while listing push subscriptions: %w", err)
	}
	defer rows.Close()

	var out []PushAbonnementDB
	for rows.Next() {
		var a PushAbonnementDB
		var events, created string
		if err := rows.Scan(&a.Endpoint, &a.P256dh, &a.Auth, &a.Email, &a.UA, &events, &created); err != nil {
			return nil, fmt.Errorf("while scanning push subscription: %w", err)
		}
		if err := json.Unmarshal([]byte(events), &a.Events); err != nil {
			return nil, fmt.Errorf("while parsing the events of a push subscription: %w", err)
		}
		if a.CreatedAt, err = parseTime("created_at", created); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
