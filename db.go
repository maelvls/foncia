package main

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/maelvls/foncia/logutil"
)

// The `path` is the path to the SQLite database. Example: "/var/lib/foncia.db".
func createDB(ctx context.Context, path string) error {
	if path == "" {
		return fmt.Errorf("missing required value: path")
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("failed to open database at %q: %w", path, err)
	}
	defer db.Close()

	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS missions (
			id TEXT UNIQUE,
			number TEXT,                 -- Foncia's ID for the intervention
			kind TEXT,
			label TEXT,
			status TEXT,
			started_at TEXT,             -- time.RFC3339
			description TEXT
		);`)
	if err != nil {
		return fmt.Errorf("failed to create table 'missions': %w", err)
	}
	_, err = db.ExecContext(ctx, `create index IF NOT EXISTS idx_entries_started_at on missions (started_at);`)
	if err != nil {
		return fmt.Errorf("failed to create index 'idx_entries_started_at': %w", err)
	}
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS work_orders (
			id TEXT UNIQUE,
			mission_id TEXT NOT NULL,
			number TEXT,
			label TEXT,
			repair_date_start TEXT,      -- time.RFC3339
			repair_date_end TEXT,        -- time.RFC3339
			supplier_id TEXT,
			supplier_name TEXT,
			supplier_activity TEXT,
			FOREIGN KEY(mission_id) REFERENCES missions(id)
		);`)
	if err != nil {
		return fmt.Errorf("failed to create table 'work_orders': %w", err)
	}
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS expenses (
			invoice_id TEXT,       -- May be "" if no invoice file
			label TEXT,
			amount INTEGER,
			date TEXT,             -- time.RFC3339
			file_path TEXT,        -- May be "" if no invoice file
			hash_file TEXT         -- May be "" if no invoice file
		);
		`)
	if err != nil {
		return fmt.Errorf("failed to create table 'expenses': %w", err)
	}
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS suppliers (
			id TEXT UNIQUE,
			name TEXT,
			activity TEXT
		);
		CREATE TABLE IF NOT EXISTS contract_documents (
			id TEXT UNIQUE,
			supplier_id TEXT NOT NULL,
			file_path TEXT,
			hash_file TEXT,
			FOREIGN KEY(supplier_id) REFERENCES suppliers(id)
		);
		`)
	if err != nil {
		return fmt.Errorf("failed to create table 'contract_documents': %w", err)
	}

	return nil
}

func upsertSuppliersToDB(ctx context.Context, db *sql.DB, suppliers []Supplier) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("while starting transaction: %v", err)
	}
	defer func() {
		err = tx.Rollback()
		if err != nil && err != sql.ErrTxDone {
			logutil.Errorf("while rolling back transaction: %v", err)
		}
	}()

	for _, s := range suppliers {
		req := "UPDATE suppliers SET name = ?, activity = ? WHERE id = ?;"
		res, err := tx.ExecContext(ctx, req, s.Name, s.Activity, s.ID)
		if err != nil {
			return fmt.Errorf("while updating suppliers: %v", err)
		}

		// If no row was updated, insert a new one.
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("while getting rows affected: %v", err)
		}
		if n > 0 {
			logutil.Debugf("db: updated supplier %q: %+v", s.ID, s)
			continue
		} else {
			req := "INSERT INTO suppliers (id, name, activity) VALUES (?, ?, ?);"
			_, err := tx.ExecContext(ctx, req, s.ID, s.Name, s.Activity)
			if err != nil {
				return fmt.Errorf("while inserting suppliers: %v", err)
			}
			logutil.Debugf("db: added supplier %q: %+v", s.ID, s)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("while committing transaction: %v", err)
	}
	return nil
}

func upsertDocumentsWithDB(ctx context.Context, db *sql.DB, documents []Document) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("while starting transaction: %v", err)
	}
	defer func() {
		err = tx.Rollback()
		if err != nil && err != sql.ErrTxDone {
			logutil.Errorf("while rolling back transaction: %v", err)
		}
	}()

	for _, d := range documents {
		req := "UPDATE contract_documents SET supplier_id = ?, file_path = ?, hash_file = ?  WHERE id = ?;"
		res, err := tx.ExecContext(ctx, req, d.SupplierID, d.FilePath, d.HashFile, d.ID)
		if err != nil {
			return fmt.Errorf("while updating documents: %v", err)
		}

		// If no row was updated, insert a new one.
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("while getting rows affected: %v", err)
		}
		if n > 0 {
			logutil.Debugf("db: updated document %q: %+v", d.ID, d)
			continue
		} else {
			req := "INSERT INTO contract_documents (id, supplier_id, file_path, hash_file) VALUES (?, ?, ?, ?);"
			_, err := tx.ExecContext(ctx, req, d.ID, d.SupplierID, d.FilePath, d.HashFile)
			if err != nil {
				return fmt.Errorf("while inserting into contract_documents: %v", err)
			}
			logutil.Debugf("db: added document %q: %+v", d.ID, d)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("while committing transaction: %v", err)
	}
	return nil
}

func upsertExpensesWithDB(ctx context.Context, db *sql.DB, expense ...Expense) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("while starting transaction: %v", err)
	}
	defer func() {
		err = tx.Rollback()
		if err != nil && err != sql.ErrTxDone {
			logutil.Errorf("while rolling back transaction: %v", err)
		}
	}()

	for _, e := range expense {
		req := "UPDATE expenses SET invoice_id = ?, amount = ?, file_path = ?, hash_file = ? where date = ? and label = ?;"
		values := []interface{}{e.InvoiceID, e.Amount, e.FilePath, e.HashFile, e.Date.Format(time.RFC3339), e.Label}
		res, err := tx.ExecContext(ctx, req, values...)
		if err != nil {
			return fmt.Errorf("while updating expenses: %v", err)
		}

		// If no row was updated, insert a new one.
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("while getting rows affected: %v", err)
		}
		if n > 0 {
			logutil.Debugf("db: updated expense %q: %+v", e.Date, e)
		} else {
			req := "INSERT INTO expenses (invoice_id, label, amount, date, file_path, hash_file) VALUES (?, ?, ?, ?, ?, ?);"
			values := []interface{}{e.InvoiceID, e.Label, e.Amount, e.Date.Format(time.RFC3339), e.FilePath, e.HashFile}
			_, err := tx.ExecContext(ctx, req, values...)
			if err != nil {
				return fmt.Errorf("while inserting expenses: %v", err)
			}
			logutil.Debugf("db: added expense %q: %+v", e.Date, e)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("while committing transaction: %v", err)
	}
	return nil
}

// errors.Is(err, sql.NoRows) when not found.
func getExpenseByHashFileDB(ctx context.Context, db *sql.DB, hashFile string) (Expense, error) {
	var e Expense
	var date string
	err := db.QueryRowContext(ctx, "SELECT invoice_id, label, amount, date, file_path, hash_file FROM expenses WHERE hash_file = ?", hashFile).Scan(&e.InvoiceID, &e.Label, &e.Amount, &date, &e.FilePath, &e.HashFile)
	if err != nil {
		return Expense{}, fmt.Errorf("while querying database: %w", err)
	}
	e.Date, err = time.Parse(time.RFC3339, date)
	if err != nil {
		return Expense{}, fmt.Errorf("while parsing 'date': %v", err)
	}
	e.Filename = filepath.Base(e.FilePath)

	return e, nil
}

func getDocumentByHashFile(ctx context.Context, db *sql.DB, hashFile string) (Document, error) {
	var d Document
	err := db.QueryRowContext(ctx, "SELECT id, supplier_id, file_path FROM contract_documents WHERE hash_file = ?", hashFile).Scan(&d.ID, &d.SupplierID, &d.FilePath)
	if err != nil {
		return Document{}, fmt.Errorf("while querying database: %w", err)
	}
	d.Filename = filepath.Base(d.FilePath)

	return d, nil
}

func saveWorkOrdersToDB(ctx context.Context, db *sql.DB, missionIDs []string, workOrdersMap map[string][]WorkOrder) error {
	if len(missionIDs) == 0 {
		return nil
	}

	req := "INSERT INTO work_orders (id, mission_id, number, label, repair_date_start, repair_date_end, supplier_id, supplier_name, supplier_activity) VALUES "
	var values []interface{}
	for _, missionID := range missionIDs {
		workOrders, found := workOrdersMap[missionID]
		if !found {
			continue
		}
		for _, w := range workOrders {
			req += "(?, ?, ?, ?, ?, ?, ?, ?, ?),"
			values = append(values, w.ID, missionID, w.Number, w.Label, w.RepairDateStart.Format(time.RFC3339), w.RepairDateEnd.Format(time.RFC3339), w.Supplier.ID, w.Supplier.Name, w.Supplier.Activity)
		}
	}
	// No need to do anything if there are no work orders to insert.
	if len(values) == 0 {
		return nil
	}
	req = strings.TrimSuffix(req, ",")
	_, err := db.ExecContext(ctx, req, values...)

	logutil.Debugf("sql saveWorkOrdersToDB: %s with:\n", req, fprintfValues(values, ",", "\n", 9))
	if err != nil {
		return fmt.Errorf("while inserting work orders: %v", err)
	}

	return nil
}

// If the request entries look like
//
//	(1, "foo", "bar"),(2, "baz", "qux"),(3, "quux", "corge"),(4, "grault", "garply")
//	<-----entry----->
//	           <---->
//	            value
//
// Example with sep=, and entrySep=\n
//
// 1, foo, bar
// 2, baz, qux
// 3, quux, corge
// 4, grault, garply
func fprintfValues(values []interface{}, sep, entrySep string, valuesPerEntry int) string {
	var b strings.Builder
	for i, v := range values {
		if i%valuesPerEntry == 0 {
			b.WriteString(entrySep)
		}
		b.WriteString(fmt.Sprintf("%v%s", v, sep))
	}
	return b.String()
}

func saveMissionsToDB(ctx context.Context, db *sql.DB, missions ...Mission) error {
	req := "INSERT INTO missions (id, number, kind, label, status, started_at, description) VALUES "
	var values []interface{}
	for _, e := range missions {
		req += "(?, ?, ?, ?, ?, ?, ?),"
		values = append(values, e.ID, e.Number, e.Kind, e.Label, e.Status, e.StartedAt.Format(time.RFC3339), e.Description)
	}
	req = strings.TrimSuffix(req, ",")
	_, err := db.ExecContext(ctx, req, values...)
	if err != nil {
		return fmt.Errorf("while inserting values: %v", err)
	}

	return nil
}

func getMissionsDB(ctx context.Context, db *sql.DB) ([]Mission, error) {
	rows, err := db.QueryContext(ctx, "SELECT id, number, kind, label, status, started_at, description FROM missions ORDER BY started_at DESC")
	if err != nil {
		return nil, fmt.Errorf("while querying database: %v", err)
	}
	defer rows.Close()

	var missions []Mission
	for rows.Next() {
		var m Mission
		var startedAt string
		err = rows.Scan(&m.ID, &m.Number, &m.Kind, &m.Label, &m.Status, &startedAt, &m.Description)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %v", err)
		}

		m.StartedAt, err = time.Parse(time.RFC3339, startedAt)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'started_at': %v", err)
		}
		missions = append(missions, m)
	}

	var missionIDs []string
	for i := range missions {
		missionIDs = append(missionIDs, missions[i].ID)
	}
	workOrderMap, err := getWorkOrdersDB(ctx, db, missionIDs...)
	if err != nil {
		return nil, fmt.Errorf("while getting work orders from DB: %v", err)
	}

	for i := range missions {
		workOrders, found := workOrderMap[missions[i].ID]
		if !found {
			continue
		}
		missions[i].WorkOrders = workOrders
	}
	logutil.Debugf("found %d missions", len(missions))
	return missions, nil
}

func getWorkOrdersDB(ctx context.Context, db *sql.DB, missionIDs ...string) (map[string][]WorkOrder, error) {
	if len(missionIDs) == 0 {
		return nil, nil
	}
	// Join the tables work_orders with suppliers and contract_documents.
	req := `SELECT
				w.id, w.mission_id, w.number, w.label, w.repair_date_start, w.repair_date_end, w.supplier_id,
				s.name, s.activity,
				d.id, d.file_path, d.hash_file
			FROM work_orders w
			LEFT JOIN suppliers s ON s.id = w.supplier_id
			LEFT JOIN contract_documents d ON d.supplier_id = w.supplier_id
			WHERE w.mission_id in (`
	var values []interface{}
	for _, id := range missionIDs {
		req += "?,"
		values = append(values, id)
	}
	req = strings.TrimSuffix(req, ",") + ");"
	logutil.Debugf("sql getWorkOrdersDB: %s", req)

	rows, err := db.QueryContext(ctx, req, values...)
	if err != nil {
		return nil, fmt.Errorf("while querying database: %v", err)
	}
	defer rows.Close()

	workOrderMap := make(map[string][]WorkOrder)
	for rows.Next() {
		var wo WorkOrder
		var missionID, repairDateStart, repairDateEnd string
		var supplName, supplActivity sql.NullString
		var docID, docFilePath, docHashFile sql.NullString
		err = rows.Scan(
			&wo.ID, &missionID, &wo.Number, &wo.Label, &repairDateStart, &repairDateEnd, &wo.Supplier.ID,
			&supplName, &supplActivity,
			&docID, &docFilePath, &docHashFile,
		)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %v", err)
		}

		wo.Supplier.Name = supplName.String
		wo.Supplier.Activity = supplActivity.String
		wo.Supplier.Document.ID = docID.String
		wo.Supplier.Document.FilePath = docFilePath.String
		wo.Supplier.Document.HashFile = docHashFile.String

		wo.RepairDateStart, err = time.Parse(time.RFC3339, repairDateStart)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'repair_date_start': %v", err)
		}
		wo.RepairDateEnd, err = time.Parse(time.RFC3339, repairDateEnd)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'repair_date_end': %v", err)
		}
		wo.Supplier.Document.Filename = filepath.Base(wo.Supplier.Document.FilePath)

		workOrderMap[missionID] = append(workOrderMap[missionID], wo)
	}

	return workOrderMap, nil
}

func getExpensesDB(ctx context.Context, db *sql.DB) ([]Expense, error) {
	rows, err := db.QueryContext(ctx, "SELECT invoice_id, label, amount, date, file_path, hash_file FROM expenses ORDER BY date DESC")
	if err != nil {
		return nil, fmt.Errorf("while querying database: %v", err)
	}
	defer rows.Close()

	var expenses []Expense
	for rows.Next() {
		var e Expense
		var date string
		err = rows.Scan(&e.InvoiceID, &e.Label, &e.Amount, &date, &e.FilePath, &e.HashFile)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %v", err)
		}

		e.Date, err = time.Parse(time.RFC3339, date)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'date': %v", err)
		}

		e.Filename = filepath.Base(e.FilePath)

		expenses = append(expenses, e)
	}

	return expenses, nil
}
