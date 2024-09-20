package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/maelvls/foncia/logutil"
)

func initSchemaDB(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
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

	logutil.Debugf("sql saveWorkOrdersToDB: %s with:%s", req, fprintfValues(values, ",", "\n", 9))
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

func rmLastExpenseDB(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM expenses WHERE rowid = (SELECT max(rowid) FROM expenses);")
	if err != nil {
		return fmt.Errorf("while deleting last expense: %v", err)
	}
	return nil
}
func rmLastMissionDB(db *sql.DB) error {
	// First, remove the work orders associated with the last mission.
	_, err := db.Exec("DELETE FROM work_orders WHERE mission_id = (SELECT id FROM missions ORDER BY started_at DESC LIMIT 1);")
	if err != nil {
		return fmt.Errorf("while deleting work orders: %v", err)
	}

	_, err = db.Exec("DELETE FROM missions WHERE id = (SELECT id FROM missions ORDER BY started_at DESC LIMIT 1);")
	if err != nil {
		return fmt.Errorf("while deleting last mission: %v", err)
	}
	return nil
}

// We consider that the database is empty when there are no missions and no
// expenses.
func isEmptyDB(ctx context.Context, db *sql.DB) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM missions;").Scan(&n)
	if err != nil {
		return false, fmt.Errorf("while querying database: %v", err)
	}

	if n > 0 {
		return false, nil
	}

	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM expenses;").Scan(&n)
	if err != nil {
		return false, fmt.Errorf("while querying database: %v", err)
	}

	if n > 0 {
		return false, nil
	}

	return true, nil
}

// Returns the new items.
func syncLiveMissionsWithDB(ctx context.Context, client *http.Client, db *sql.DB) ([]Mission, error) {
	uuid, err := GetAccountUUID(client)
	if err != nil {
		return nil, fmt.Errorf("while getting account UUID: %v", err)
	}
	missions, _, err := getMissionsLive(client, uuid, "")
	if err != nil {
		return nil, fmt.Errorf("while getting interventions: %v", err)
	}

	missionsInDB, err := getMissionsDB(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("while getting existing missions: %v", err)
	}
	existsInDB := make(map[string]struct{})
	for _, item := range missionsInDB {
		existsInDB[item.ID] = struct{}{}
	}
	var newMissions []Mission
	for _, m := range missions {
		_, already := existsInDB[m.ID]
		if already {
			continue
		}
		newMissions = append(newMissions, m)
		logutil.Debugf("found new mission: %+v", m)
	}

	workOrders := make(map[string][]WorkOrder) // missionID -> work orders

	// Since HTTP request per new mission is made, and there may be 200-300
	// missions, let's do them in batches of 20 so that we can save to DB in
	// regularly so we don't lose all the work if the program crashes (takes a
	// lot of time partly because Synology's disk is slow, partly because there
	// are 200-300 HTTP calls to be made).
	batchSize := 20
	i := 0
	err = DoInBatches(batchSize, newMissions, func(batch []Mission) error {
		i++
		logutil.Debugf("batch %d", i)

		for _, mission := range batch {
			orders, err := getWorkOrdersLive(client, uuid, mission.ID)
			if err != nil {
				return fmt.Errorf("while getting work orders from API: %v", err)
			}
			workOrders[mission.ID] = orders
		}

		logutil.Debugf("saving work orders for %d missions to DB", len(batch))
		missionIDs := make([]string, len(batch))
		for _, m := range batch {
			missionIDs = append(missionIDs, m.ID)
		}

		err = saveWorkOrdersToDB(ctx, db, missionIDs, workOrders)
		if err != nil {
			return fmt.Errorf("while saving work orders: %v", err)
		}

		logutil.Debugf("saving %d missions to DB", batch)
		err = saveMissionsToDB(ctx, db, batch...)
		if err != nil {
			return fmt.Errorf("while saving missions: %v", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return newMissions, nil
}

// Returns new expenses.
func syncExpensesWithDB(ctx context.Context, client *http.Client, db *sql.DB, invoicesDir string) ([]Expense, error) {
	// Create dir if missing.
	err := os.MkdirAll(invoicesDir, 0755)
	if err != nil {
		return nil, fmt.Errorf("while creating directory: %v", err)
	}

	uuid, err := GetAccountUUID(client)
	if err != nil {
		return nil, fmt.Errorf("while getting account UUID: %v", err)
	}
	var expensesLive []Expense
	expensesLive, err = getExpensesCurrentLive(client, uuid)
	if err != nil {
		return nil, fmt.Errorf("while getting expenses: %v", err)
	}
	periods, err := getAccountingPeriodsLive(client, uuid)
	if err != nil {
		return nil, fmt.Errorf("while getting accounting periods: %v", err)
	}
	for _, period := range periods {
		cur, err := getBuildingAccountingRGDDLive(client, uuid, period.ID)
		if err != nil {
			return nil, fmt.Errorf("while getting building accounting RGDD: %v", err)
		}
		expensesLive = append(expensesLive, cur...)
	}

	// Remove duplicates based on the label + date.
	seen := make(map[string]struct{})
	var expensesLiveUnique []Expense
	for _, e := range expensesLive {
		key := e.Label + e.Date.Format(time.RFC3339)
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}
		expensesLiveUnique = append(expensesLiveUnique, e)
	}
	expensesLive = expensesLiveUnique

	expensesInDB, err := getExpensesDB(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("while getting existing expenses: %v", err)
	}
	existsInDB := make(map[time.Time]Expense)
	invoiceIDToExpense := make(map[string]Expense)
	for _, item := range expensesInDB {
		existsInDB[item.Date] = item
		if item.InvoiceID != "" {
			invoiceIDToExpense[item.InvoiceID] = item
		}
	}

	var newExpenses []Expense
	// Save the invoice PDFs to disk.
	err = DoInBatches(20, expensesLive, func(expensesBatch []Expense) error {
		var expensesBatchUpdated []Expense
		for _, e := range expensesBatch {
			// I noticed that certain expenses have an invoiceID but no PDF
			// document attached, and that appears to be the case when the
			// hashFile is empty. So I skip downloading when there is no
			// invoiceID or when the hashFile is empty.
			if e.InvoiceID == "" || e.HashFile == "" {
				continue
			}

			// No need to download if it is already present on disk.
			expenseInDB, isInDB := invoiceIDToExpense[e.InvoiceID]
			if isInDB && fileExists(expenseInDB.FilePath) {
				continue
			}
			if !isInDB {
				logutil.Debugf("expense %s with invoice_id %q not found in DB", e.Date.Format(time.RFC3339), e.InvoiceID)
			}
			if isInDB && !fileExists(expenseInDB.FilePath) {
				logutil.Debugf("file %q not found, downloading invoice %q", expenseInDB.FilePath, e.InvoiceID)
			}

			invoiceURL, err := getInvoiceURL(client, e.InvoiceID)
			if err != nil {
				return fmt.Errorf("while getting invoice URL: %v", err)
			}
			if invoiceURL == "" {
				logutil.Infof("no invoice URL found for invoice ID %q, skipping download. Expense: %+v", e.InvoiceID, e)
				continue
			}
			e.FilePath, err = download(invoiceURL, invoicesDir)
			if err != nil {
				return fmt.Errorf("while downloading invoice: %v", err)
			}

			expensesBatchUpdated = append(expensesBatchUpdated, e)
		}

		var newExpensesInBatch, changedExpencesInBatch []Expense
		for _, expInBatch := range expensesBatchUpdated {
			expDB, found := existsInDB[expInBatch.Date]
			if !found {
				newExpensesInBatch = append(newExpensesInBatch, expInBatch)
				logutil.Debugf("found new expense %q: %s", expInBatch.Date, expInBatch.Label)
				continue
			}

			// Many expenses don't have an invoice PDF attached for a couple of
			// weeks. That's why we want to update the invoice_id if we found
			// that it changed. Note that some fields are unique to the database
			// Expense (Filename, FilePath), that's why we don't compare them.
			// The date and label are used as keys, so they are not compared.
			if expDB.InvoiceID != expInBatch.InvoiceID ||
				expDB.Amount != expInBatch.Amount ||
				expDB.HashFile != expInBatch.HashFile {
				changedExpencesInBatch = append(changedExpencesInBatch, expInBatch)
				logutil.Debugf("found changed expense %q: %s", expInBatch.Date, expInBatch.Label)
			}
		}

		newExpenses = append(newExpenses, newExpensesInBatch...)

		newOrChanged := append(newExpensesInBatch, changedExpencesInBatch...)
		err = upsertExpensesWithDB(ctx, db, newOrChanged...)
		if err != nil {
			return fmt.Errorf("while saving expenses: %v", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return newExpenses, nil
}

func syncSuppliersWithDB(ctx context.Context, client *http.Client, db *sql.DB, invoicesDir string) error {
	uuid, err := GetAccountUUID(client)
	if err != nil {
		return fmt.Errorf("while getting account UUID: %v", err)
	}

	contracts, err := getCouncilMissionSuppliersLive(client, uuid)
	if err != nil {
		return fmt.Errorf("while getting suppliers: %v", err)
	}

	var suppliers []Supplier
	var documents []Document

	for _, c := range contracts {
		suppliers = append(suppliers, c.Supplier)
		for _, d := range c.Documents {
			fileURL, err := getDocumentURL(client, d.HashFile)
			if err != nil {
				return fmt.Errorf("while getting document URL: %v", err)
			}

			d.SupplierID = c.Supplier.ID
			d.FilePath, err = download(fileURL, invoicesDir)
			if err != nil {
				return fmt.Errorf("while downloading document: %v", err)
			}
			d.Filename = filepath.Base(d.FilePath)

			documents = append(documents, d)
		}
	}

	err = upsertSuppliersToDB(ctx, db, suppliers)
	if err != nil {
		return fmt.Errorf("while saving suppliers: %v", err)
	}

	err = upsertDocumentsWithDB(ctx, db, documents)
	if err != nil {
		return fmt.Errorf("while saving documents: %v", err)
	}

	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func DoInBatches[T any](batchSize int, elmts []T, do func([]T) error) error {
	var batch []T

	for i, e := range elmts {
		batch = append(batch, e)

		isLastElmt := i == len(elmts)-1
		batchIsFull := len(batch) == batchSize

		if batchIsFull || isLastElmt {
			err := do(batch)
			if err != nil {
				return fmt.Errorf("while doing in batches: %v", err)
			}
			batch = nil
		}
	}

	return nil
}

func ListCmd(username string, password secret) {
	client, err := authenticatedClient(&http.Client{}, username, password)
	if err != nil {
		logutil.Errorf("while authenticating: %v", err)
		os.Exit(1)
	}

	accUUID, err := GetAccountUUID(client)
	if err != nil {
		logutil.Errorf("while getting account UUID: %v", err)
		os.Exit(1)
	}

	missions, _, err := getMissionsLive(client, accUUID, "")
	if err != nil {
		logutil.Errorf("getting interventions: %v", err)
		os.Exit(1)
	}

	// Print the items starting with the oldest one.
	for i := len(missions) - 1; i >= 0; i-- {
		fmt.Printf("%s %s %s %s %s\n",
			missions[i].StartedAt.Format("02 Jan 2006"),
			logutil.Bold(string(missions[i].Kind)),
			logutil.Yel(missions[i].Label),
			func() string {
				if missions[i].Status == "WORK_IN_PROGRESS" {
					return logutil.Red(missions[i].Status)
				} else {
					return logutil.Green(missions[i].Status)
				}
			}(),
			logutil.Gray(missions[i].Description),
		)
	}
}

// Parse the mission number ("Ordre de service in French") from the subject.
// For example, given the subject:
//
//	"Ordre de service N° OSMIL805898844 – 2NRT POMPE ENVIRONNEMENT - 3 RUE BERTRAN 31200 TOULOUSE"
//
// we want to extract "OSMIL805898844".
func missionNumber(s string) string {
	re := regexp.MustCompile(`N° ([A-Z0-9]+)`)
	m := re.FindStringSubmatch(s)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}
