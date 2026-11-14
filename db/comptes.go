package db

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ExpenseRow is an expense together with its primary key, which the rest of
// the code never needed until expenses could be attached to an affaire.
type ExpenseRow struct {
	ID string
	ExpenseDocumentDB
}

func scanExpenseRow(rows *sql.Rows) (ExpenseRow, error) {
	var e ExpenseRow
	var date string
	err := rows.Scan(&e.ID, &e.InvoiceID, &e.Label, &e.Amount, &date, &e.FilePath, &e.HashFile,
		&e.Source, &e.AccountingKey.Allocation, &e.AccountingKey.ExpenseType)
	if err != nil {
		return ExpenseRow{}, err
	}
	e.Date, err = parseTime("date", date)
	return e, err
}

// GetExpenseRows returns every expense, most recent first.
func GetExpenseRows(ctx context.Context, db *sql.DB) ([]ExpenseRow, error) {
	return queryAll(ctx, db, "SELECT id, "+expenseColumns+" FROM expenses ORDER BY date DESC, id", scanExpenseRow)
}

// GetExpenseRow returns sql.ErrNoRows when the id is unknown.
func GetExpenseRow(ctx context.Context, db *sql.DB, id string) (ExpenseRow, error) {
	rows, err := queryAll(ctx, db, "SELECT id, "+expenseColumns+" FROM expenses WHERE id = ?", scanExpenseRow, id)
	if err != nil {
		return ExpenseRow{}, err
	}
	if len(rows) == 0 {
		return ExpenseRow{}, sql.ErrNoRows
	}
	return rows[0], nil
}

// GetAccountDocumentDB returns sql.ErrNoRows when the id is unknown.
func GetAccountDocumentDB(ctx context.Context, db *sql.DB, id string) (AccountDocumentDB, error) {
	docs, err := queryAll(ctx, db, "SELECT "+accountDocumentColumns+" FROM account_documents WHERE id = ?", scanAccountDocument, id)
	if err != nil {
		return AccountDocumentDB{}, err
	}
	if len(docs) == 0 {
		return AccountDocumentDB{}, sql.ErrNoRows
	}
	return docs[0], nil
}

type BudgetDB struct {
	Annee     int
	Montant   Amount
	Note      string
	UpdatedBy string
	UpdatedAt time.Time
}

// GetBudget returns ok=false when no budget was entered for that year.
func GetBudget(ctx context.Context, db *sql.DB, annee int) (b BudgetDB, ok bool, err error) {
	var updatedAt string
	err = db.QueryRowContext(ctx, `SELECT annee, montant, note, updated_by, updated_at FROM budgets WHERE annee = ?`, annee).
		Scan(&b.Annee, &b.Montant, &b.Note, &b.UpdatedBy, &updatedAt)
	if err == sql.ErrNoRows {
		return BudgetDB{}, false, nil
	}
	if err != nil {
		return BudgetDB{}, false, fmt.Errorf("while reading budget: %w", err)
	}
	b.UpdatedAt, err = parseTime("updated_at", updatedAt)
	return b, err == nil, err
}

func SetBudget(ctx context.Context, db *sql.DB, b BudgetDB) error {
	_, err := db.ExecContext(ctx, `
INSERT INTO budgets (annee, montant, note, updated_by, updated_at) VALUES (?,?,?,?,?)
ON CONFLICT(annee) DO UPDATE SET montant = excluded.montant, note = excluded.note,
    updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		b.Annee, int(b.Montant), b.Note, b.UpdatedBy, formatTime(time.Now()))
	if err != nil {
		return fmt.Errorf("while saving budget: %w", err)
	}
	return nil
}

// ParseEuros turns what a person types ("1 234,50", "39.85 €", "142") into
// cents. Both the comma and the dot are accepted as the decimal separator.
func ParseEuros(s string) (Amount, error) {
	orig := s
	s = strings.NewReplacer(" ", "", " ", "", " ", "", "€", "", "EUR", "").Replace(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ",", ".")
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	if s == "" {
		return 0, fmt.Errorf("montant vide")
	}
	whole, frac, _ := strings.Cut(s, ".")
	if len(frac) > 2 || strings.Contains(frac, ".") {
		return 0, fmt.Errorf("montant invalide : %q", orig)
	}
	frac += strings.Repeat("0", 2-len(frac))
	if whole == "" {
		whole = "0"
	}
	w, err1 := strconv.Atoi(whole)
	f, err2 := strconv.Atoi(frac)
	if err1 != nil || err2 != nil || w < 0 || f < 0 {
		return 0, fmt.Errorf("montant invalide : %q", orig)
	}
	cents := w*100 + f
	if neg {
		cents = -cents
	}
	return Amount(cents), nil
}

// Input renders the amount the way ParseEuros reads it, for form fields.
func (a Amount) Input() string {
	return strings.TrimSuffix(a.String(), " €")
}

// GetMissionDB returns the mission without its work orders, or sql.ErrNoRows.
func GetMissionDB(ctx context.Context, db *sql.DB, id string) (MissionDB, error) {
	ms, err := queryAll(ctx, db, "SELECT id, number, kind, label, status, started_at, description FROM missions WHERE id = ?", scanMission, id)
	if err != nil {
		return MissionDB{}, err
	}
	if len(ms) == 0 {
		return MissionDB{}, sql.ErrNoRows
	}
	return ms[0], nil
}
