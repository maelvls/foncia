package db

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/maelvls/foncia/logutil"
)

const missionsTableSQL = `
	CREATE TABLE IF NOT EXISTS missions (
		id TEXT UNIQUE,
		number TEXT,                 -- Foncia's ID for the intervention
		kind TEXT,
		label TEXT,
		status TEXT,
		started_at TEXT,             -- time.RFC3339Nano
		description TEXT
	);
	create index IF NOT EXISTS idx_entries_started_at on missions (started_at);
	`

type MissionDB struct {
	ID          string    // "64850e8019d5d64c415d13dd"
	Number      string    // "7000YRK51"
	Kind        string    // "Incident" | "Repair"
	Label       string    // "ATELIER METALLERIE FERRONNERIE - VALIDATION DEVIS "
	Status      string    // "WORK_IN_PROGRESS"
	StartedAt   time.Time // "2023-04-24T22:00:00.000Z" (time.RFC3339Nano)
	Description string    // "BONJOUR,\n\nVEUILLEZ ENREGISTER LE C02\t\nMERCI CORDIALEMENT"
	WorkOrders  []WorkOrderDB
}

func (m MissionDB) StatusFrench() string {
	switch m.Status {
	case "OPEN":
		return "Nouveau"
	case "WORK_IN_PROGRESS":
		return "En cours"
	case "FINISHED":
		return "Terminé"
	case "CLOSE":
		return "Fermé"
	default:
		return "Unknown: " + m.Status
	}
}

func (m MissionDB) KindFrench() string {
	switch m.Kind {
	case "Incident":
		return "Ticket"
	case "Repair":
		return "Réparation"
	default:
		return "Unknown: " + m.Kind
	}
}

type WorkOrderDB struct {
	ID              string    // "64850e80df57eb4ade3cf63c"
	MissionID       string    // "64850e8019d5d64c415d13dd"
	Number          string    // "OSMIL802702875"
	Label           string    // "BOUVIER SECURITE INCENDIE - DEMANDE INTERVENTION P"
	RepairDateStart time.Time // "2022-10-18T22:00:00.000Z"
	RepairDateEnd   time.Time // "2022-10-18T22:00:00.000Z"
	Supplier        SupplierDB
}

func InitAndUpdateDB(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, missionsTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create table 'missions': %w", err)
	}
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS work_orders (
			id TEXT UNIQUE,
			mission_id TEXT NOT NULL,
			number TEXT,
			label TEXT,
			repair_date_start TEXT,      -- time.RFC3339Nano
			repair_date_end TEXT,        -- time.RFC3339Nano
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
			date TEXT,            -- time.RFC3339Nano
			file_path TEXT,        -- May be "" if no invoice file
			hash_file TEXT         -- May be "" if no invoice file
		);`)
	if err != nil {
		return fmt.Errorf("failed to create table 'expenses': %w", err)
	}
	// Add the source column to the expenses table if this column doesn't exist.
	// First, check if the column exists. Values: "accounting" or "repairs".
	err = addColumnToTable(ctx, db, "expenses", "source", string(SourceUnknown))
	if err != nil {
		return fmt.Errorf("failed to add column 'source' to table 'expenses': %w", err)
	}
	err = addColumnToTable(ctx, db, "expenses", "accounting_allocation", "unknown")
	if err != nil {
		return fmt.Errorf("failed to add column 'accounting_allocation' to table 'expenses': %w", err)
	}
	err = addColumnToTable(ctx, db, "expenses", "accounting_expense_type", "unknown")
	if err != nil {
		return fmt.Errorf("failed to add column 'accounting_expense_type' to table 'expenses': %w", err)
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

	// Create the table for the account documents.
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS account_documents (
			id TEXT UNIQUE,
			file_path TEXT,
			hash_file TEXT
		);
		`)
	if err != nil {
		return fmt.Errorf("failed to create table 'account_documents': %w", err)
	}

	// Add the category, mime_type, and created_at columns to the
	// account_documents table if they don't exist.
	err = addColumnToTable(ctx, db, "account_documents", "category", string(DocumentCategoryUnknown))
	if err != nil {
		return err
	}
	err = addColumnToTable(ctx, db, "account_documents", "mime_type", "application/pdf")
	if err != nil {
		return err
	}
	err = addColumnToTable(ctx, db, "account_documents", "created_at", time.Time{})
	if err != nil {
		return err
	}

	return nil
}

func addColumnToTable(ctx context.Context, db *sql.DB, table, column string, defaultValue any) error {
	var sqlType string
	switch defaultValue.(type) {
	case string:
		sqlType = "TEXT"
	case int:
		sqlType = "INTEGER"
	case time.Time:
		sqlType = "TEXT" // time.RFC3339Nano
	default:
		return fmt.Errorf("unsupported type %T", defaultValue)
	}

	// Add the column to the table if it doesn't exist.
	var columnExists bool
	err := db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM pragma_table_info(?) WHERE name = ?) AS column_exists;", table, column).Scan(&columnExists)
	if err != nil {
		return fmt.Errorf("failed to check if column %q exists in table %q: %w", column, table, err)
	}
	if columnExists {
		return nil
	}

	_, err = db.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s NOT NULL DEFAULT "%s";`, table, column, sqlType, defaultValue))
	if err != nil {
		return fmt.Errorf("failed to add column %q to table %q: %w", column, table, err)
	}

	return nil
}

type SupplierDB struct {
	ID        string
	Name      string // Examples: "2NRT-POMPES ENVIRONNEMENT"
	Activity  string // Examples: "PLOM", "ADBE", "ISOL"
	Documents []SupplierContractDocumentDB
}

func GetSuppliersDB(ctx context.Context, db *sql.DB) ([]SupplierDB, error) {
	// Get the suppliers and documents.
	req := `SELECT id, name, activity FROM suppliers;`
	rows, err := db.QueryContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("while querying database: %w", err)
	}
	defer rows.Close()

	var suppliers []SupplierDB
	for rows.Next() {
		var s SupplierDB
		err = rows.Scan(&s.ID, &s.Name, &s.Activity)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %w", err)
		}
		suppliers = append(suppliers, s)
	}

	// Then, get the documents for each supplier.
	for i := range suppliers {
		docs, err := GetSupplierContractBySupplierIDDB(ctx, db, suppliers[i].ID)
		if err != nil {
			return nil, fmt.Errorf("while getting documents for supplier %q: %v", suppliers[i].ID, err)
		}
		suppliers[i].Documents = docs
	}

	return suppliers, nil
}

func GetSupplierContractBySupplierIDDB(ctx context.Context, db *sql.DB, supplierID string) ([]SupplierContractDocumentDB, error) {
	req := `SELECT id, file_path, hash_file, supplier_id FROM contract_documents WHERE supplier_id = ?;`
	rows, err := db.QueryContext(ctx, req, supplierID)
	if err != nil {
		return nil, fmt.Errorf("while querying database: %w", err)
	}
	defer rows.Close()

	var documents []SupplierContractDocumentDB
	for rows.Next() {
		var d SupplierContractDocumentDB
		err = rows.Scan(&d.ID, &d.FilePath, &d.HashFile, &d.SupplierID)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %w", err)
		}
		documents = append(documents, d)
	}

	return documents, nil
}

type SupplierContractDocumentDB struct {
	ID         string   // The document's ID. Example: "64850e805e5793033297f476"
	HashFile   HashFile // Only set when a document is attached. Example: "64850e805e5793033297f476"
	FilePath   string   // Example: "invoices/2023-03-09_2apf.pdf". Empty when querying live.
	SupplierID string
}

func GetSupplierContractDocsDB(ctx context.Context, db *sql.DB) ([]SupplierContractDocumentDB, error) {
	req := `SELECT id, file_path, hash_file, supplier_id FROM contract_documents;`
	rows, err := db.QueryContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("while querying database: %w", err)
	}
	defer rows.Close()

	var documents []SupplierContractDocumentDB
	for rows.Next() {
		var d SupplierContractDocumentDB
		err = rows.Scan(&d.ID, &d.FilePath, &d.HashFile, &d.SupplierID)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %w", err)
		}
		documents = append(documents, d)
	}

	return documents, nil
}

// Documents are merged using their IDs. O(N^2) but OK because N is small. When
// the previous value (e.g. filepath) was set the current value is empty, the
// previous value is kept.
func MergeSupplierContractDocs(previous, current []SupplierContractDocumentDB) (missing, updated, removed []SupplierContractDocumentDB) {
	// Find the current documents that weren't there previously.
	var newDocs []SupplierContractDocumentDB
	for _, c := range current {
		found := false
		for _, p := range previous {
			if c.ID == p.ID {
				found = true
				break
			}
		}
		if !found {
			newDocs = append(newDocs, c)
		}
	}

	// Find the documents that have changed.
	var changedDocs []SupplierContractDocumentDB
	for _, cur := range current {
		for _, prev := range previous {
			if cur.ID != prev.ID {
				continue
			}

			hasChanged := EqualSupplierDocs(cur, prev)
			if !hasChanged {
				continue
			}
			changedDocs = append(changedDocs, MergeSupplierDoc(prev, cur))
		}
	}

	// Find the documents that have been deleted.
	var deletedDocs []SupplierContractDocumentDB
	for _, p := range previous {
		found := false
		for _, c := range current {
			if c.ID == p.ID {
				found = true
				break
			}
		}
		if !found {
			deletedDocs = append(deletedDocs, p)
		}
	}

	return newDocs, changedDocs, deletedDocs
}

// Documents are merged using their IDs. O(1) operation. Regarding the FilePath,
// When the previous value was set the current value is empty, the previous
// value is kept.
func MergeAccountDocumentsDB(previous, current []AccountDocumentDB) (missing, updated, removed []AccountDocumentDB) {
	// Find the current documents that weren't there previously.
	var newDocs []AccountDocumentDB
	for _, c := range current {
		found := false
		for _, p := range previous {
			if c.ID == p.ID {
				found = true
				break
			}
		}
		if !found {
			newDocs = append(newDocs, c)
		}
	}

	// Find the documents that have changed.
	var changedDocs []AccountDocumentDB
	for _, cur := range current {
		for _, prev := range previous {
			if cur.ID != prev.ID {
				continue
			}

			hasChanged := EqualAccountDocs(prev, cur)
			if !hasChanged {
				continue
			}
			changedDocs = append(changedDocs, MergeAccountDoc(prev, cur))
		}
	}

	// Find the documents that have been deleted.
	var deletedDocs []AccountDocumentDB
	for _, p := range previous {
		found := false
		for _, c := range current {
			if c.ID == p.ID {
				found = true
				break
			}
		}
		if !found {
			deletedDocs = append(deletedDocs, p)
		}
	}

	return newDocs, changedDocs, deletedDocs
}

// The FilePath needs to be carried over. That's why we need this special merge
// function.
func MergeAccountDoc(previous, current AccountDocumentDB) AccountDocumentDB {
	merged := current
	merged.FilePath = previous.FilePath
	return merged
}

func EqualAccountDocs(a, b AccountDocumentDB) bool {
	// We ignore the file path, and compare the rest.
	a.FilePath = ""
	b.FilePath = ""
	return a == b
}

// The FilePath needs to be carried over. That's why we need this special merge
// function.
func MergeSupplierDoc(previous, current SupplierContractDocumentDB) SupplierContractDocumentDB {
	merged := current
	merged.FilePath = previous.FilePath
	return merged
}

func EqualSupplierDocs(a, b SupplierContractDocumentDB) bool {
	// We ignore the file path, and compare the rest.
	a.FilePath = ""
	b.FilePath = ""
	return a == b
}

func GetSupplierContractByHashFileDB(ctx context.Context, db *sql.DB, hashFile string) (SupplierContractDocumentDB, error) {
	var d SupplierContractDocumentDB
	err := db.QueryRowContext(ctx, "SELECT id, file_path, hash_file, supplier_id FROM contract_documents WHERE hash_file = ?", hashFile).Scan(&d.ID, &d.FilePath, &d.HashFile, &d.SupplierID)
	if err != nil {
		return SupplierContractDocumentDB{}, fmt.Errorf("while querying database: %w", err)
	}

	return d, nil
}

func UpsertSuppliersToDB(ctx context.Context, db *sql.DB, suppliers []SupplierDB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("while starting transaction: %w", err)
	}
	defer func() {
		err = tx.Rollback()
		if err != nil && err != sql.ErrTxDone {
			logutil.Errorf("while rolling back transaction: %w", err)
		}
	}()

	// Find the suppliers that are already in the database.
	req := "SELECT id, name, activity FROM suppliers;"
	rows, err := tx.QueryContext(ctx, req)
	if err != nil {
		return fmt.Errorf("while querying database: %w", err)
	}
	defer rows.Close()

	var suppliersInDB []SupplierDB
	for rows.Next() {
		var s SupplierDB
		err = rows.Scan(&s.ID, &s.Name, &s.Activity)
		if err != nil {
			return fmt.Errorf("while scanning row: %w", err)
		}
		suppliersInDB = append(suppliersInDB, s)
	}

	// Find the suppliers that aren't already in the database.
	var newSuppliers []SupplierDB
	for _, s := range suppliers {
		found := false
		for _, sInDB := range suppliersInDB {
			if s.ID == sInDB.ID {
				found = true
				break
			}
		}
		if !found {
			newSuppliers = append(newSuppliers, s)
		}
	}

	// Insert the suppliers that aren't already in the database.
	for _, s := range newSuppliers {
		req := "INSERT INTO suppliers (id, name, activity) VALUES (?, ?, ?);"
		_, err := tx.ExecContext(ctx, req, s.ID, s.Name, s.Activity)
		if err != nil {
			return fmt.Errorf("db: while inserting supplier %q: %v", s.ID, err)
		}
		logutil.Debugf("db: added supplier %q: %+v", s.ID, s)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("while committing transaction: %w", err)
	}
	return nil
}

func UpsertContractDocumentsWithDB(ctx context.Context, db *sql.DB, documents []SupplierContractDocumentDB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("while starting transaction: %w", err)
	}
	defer func() {
		err = tx.Rollback()
		if err != nil && err != sql.ErrTxDone {
			logutil.Errorf("while rolling back transaction: %w", err)
		}
	}()

	for _, e := range documents {
		req := "UPDATE contract_documents SET supplier_id = ?, file_path = ?, hash_file = ? WHERE id = ?;"
		res, err := tx.ExecContext(ctx, req, e.SupplierID, e.FilePath, e.HashFile, e.ID)
		if err != nil {
			return fmt.Errorf("while updating contract documents: %w", err)
		}

		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("while getting rows affected: %w", err)
		}
		if n != 0 {
			logutil.Debugf("db: updated document %q: %+v", e.ID, e)
			continue
		}

		// No existing row was found: insert a new one.
		req = "INSERT INTO contract_documents (id, supplier_id, file_path, hash_file) VALUES (?, ?, ?, ?);"
		_, err = tx.ExecContext(ctx, req, e.ID, e.SupplierID, e.FilePath, e.HashFile)
		if err != nil {
			return fmt.Errorf("while inserting contract documents: %w", err)
		}
		logutil.Debugf("db: added document %q: %+v", e.ID, e)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("while committing transaction: %w", err)
	}
	return nil
}

// FilePath is the only field that ca be updated.
func UpsertExpensesWithDB(ctx context.Context, db *sql.DB, expense ...ExpenseDocumentDB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("while starting transaction: %w", err)
	}
	defer func() {
		err = tx.Rollback()
		if err != nil && err != sql.ErrTxDone {
			logutil.Errorf("while rolling back transaction: %w", err)
		}
	}()

	for _, e := range expense {
		var req string
		var args []interface{}
		switch {
		case e.HashFile != "":
			req = "UPDATE expenses SET invoice_id = ?, label = ?, amount = ?, date = ?, file_path = ?, hash_file = ?, source = ?, accounting_allocation = ?, accounting_expense_type = ? WHERE name = ? AND date = ? AND amount = ? AND accounting_allocation = ? AND accounting_expense_type = ? AND hash_file = ?;"
			args = []interface{}{e.InvoiceID, e.Label, e.Amount, e.Date.Format(time.RFC3339Nano), e.FilePath, e.HashFile, e.Source, e.AccountingKey.Allocation, e.AccountingKey.ExpenseType, e.Label, e.Date.Format(time.RFC3339Nano), e.Amount, e.AccountingKey.Allocation, e.AccountingKey.ExpenseType, e.HashFile}
		default:
			req = "UPDATE expenses SET invoice_id = ?, label = ?, amount = ?, date = ?, file_path = ?, hash_file = ?, source = ?, accounting_allocation = ?, accounting_expense_type = ? WHERE label = ? AND date = ? AND amount = ? AND accounting_allocation = ? AND accounting_expense_type = ?;"
			args = []interface{}{e.InvoiceID, e.Label, e.Amount, e.Date.Format(time.RFC3339Nano), e.FilePath, e.HashFile, e.Source, e.AccountingKey.Allocation, e.AccountingKey.ExpenseType, e.Label, e.Date.Format(time.RFC3339Nano), e.Amount, e.AccountingKey.Allocation, e.AccountingKey.ExpenseType}
		}
		res, err := tx.ExecContext(ctx, req, args...)
		if err != nil {
			return fmt.Errorf("while updating expenses: %w", err)
		}

		// If no row was updated, insert a new one.
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("while getting rows affected: %w", err)
		}
		if n > 0 {
			logutil.Debugf("db: updated expense %q: %+v", e.Date, e)
		} else {
			req := "INSERT INTO expenses (invoice_id, label, amount, date, file_path, hash_file, source, accounting_allocation, accounting_expense_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);"
			args := []interface{}{e.InvoiceID, e.Label, e.Amount, e.Date.Format(time.RFC3339Nano), e.FilePath, e.HashFile, e.Source, e.AccountingKey.Allocation, e.AccountingKey.ExpenseType}
			_, err := tx.ExecContext(ctx, req, args...)
			if err != nil {
				return fmt.Errorf("while inserting expenses: %w", err)
			}
			logutil.Debugf("db: added expense %q: %+v", e.Date, e)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("while committing transaction: %w", err)
	}
	return nil
}

// This "hash file" is an opaque hash that comes from AWS S3. For example, the
// URL will look like this:
//
//	https://fon-mil-prod-plato-prv.s3.eu-west-3.amazonaws.com/9/d/8/7/b/64850e800e5a086a68e9d87b?...
//	                                                                    <------- hashFile ------>
//
// Download API:
//
// The /dl/invoice/:hash_file/[:decorative_name.pdf] endpoint looks like this:
//
//	https://suivi-foncia.dev/dl/invoice/66fbf2a9294cd8ed17d7ce9a/OU%20CHANNA%20-%20CT01037406%20-%202024-10-01%20-%20_27.pdf
//	                                    <----------------------> <--------------------------------------------------------->
//	                                          hash_file                         basename(file_path)
//	                                 (used for fetching from disk)      (just for displaying name in the URL)
//
// But on disk, we store the file as:
//
//	invoices/OU CHANNA - CT01037406 - 2024-10-01 - _27.pdf
//	<---------------------------------------------------->
//	                    file_path
//
// I don't know how to calculate this hash file from the document's content.
type HashFile string

type Amount int

func (a Amount) String() string {
	sign := ""
	if a < 0 {
		sign = "-"
		a = -a
	}
	// 1234567890 -> 1234567,90 €
	return fmt.Sprintf("%s%d,%02d €", sign, a/100, a%100)
}

// To see why there is no primary key ID, see the ID() func below.
//
//	invoice_id TEXT,       -- May be "" if no invoice file
//	label TEXT,
//	amount INTEGER,
//	date TEXT,             -- time.RFC3339Nano
//	file_path TEXT,        -- May be "" if no invoice file
//	hash_file TEXT         -- May be "" if no invoice file
//
// Sometimes, the invoice ID and piece.hashFile are empty, but we still want to
// keep track of the item.
//
//	{
//	    "invoiceId": null,
//	    "piece": null,
//	    "label": "VIRT SMABTP 04/03/2024 84906 ET 84907 C01",
//	    "date": "2024-07-01T21:59:59.000Z",
//	    "amount": {
//	        "value": 350000,
//	        "currency": "EUR",
//	        "__typename": "Credit"
//	    },
//	    "isFromPreviousPeriod": false
//	}
//
// Sometimes, the invoice ID is empty, but the piece.hashFile is set.
//
//	{
//	    "invoiceId": null,
//	    "piece": {
//	        "id": "677ec9dd7fe4cb9b79c48618",
//	        "hashFile": "677ec9dd7fe4cb9b79c48618",
//	        "category": "invoiceFee"
//	    },
//	    "label": "Convocation AG - Courrier du 17/12/2024",
//	    "date": "2025-01-08T18:49:22.027Z",
//	    "amount": {
//	        "value": 2550,
//	        "currency": "EUR",
//	        "__typename": "Debit"
//	    },
//	    "isFromPreviousPeriod": false
//	}
//
//
//	In other cases, the invoice ID is set, but the piece.hashFile is empty.
//
//	{
//	    "id": "66867e37f427db1e7de3adc1",
//	    "label": "SAS ALPES CONTROLES - BUREAU CONTROLE BARD/ISO 243100L1 310C2147 - 22/04/24",
//	    "date": "2024-07-04T10:49:27.350Z",
//	    "invoiceId": "662754b5777741968892fda5",
//	    "piece": null,
//	    "toAllocate": {
//	        "value": 60338,
//	        "currency": "EUR"
//	    },
//	}
//
// Also, an invoiceID amd HashFile may be re-used across multiple items. See
// AccountingKey for an example.
type ExpenseDocumentDB struct {
	Label  string    // Example: "MADAME-OU CHANNA ENTRETIEN PARTIES COMMUNES 03/2024". May not be unique.
	Amount Amount    // Example: 1234567890, which means "1234567,90 €". Negative = credit, positive = debit.
	Date   time.Time // May not be unique. Example: "2024-07-01T21:59:59.000Z".

	// Only set when a document is attached, i.e., when HashFile or InvoiceID is
	// set. Example: "invoices/OU CHANNA - CT01037406 - 2024-10-01 - _27.pdf"
	FilePath string

	// Only set when a document is attached. To be used with GetDocumentURL.
	// Example: "66fbf2a9294cd8ed17d7ce9a"
	HashFile HashFile

	// Only set when a document is attached. Rarely useful since HashFile is
	// widely available, unlike InvoiceID. To be used with GetInvoiceURL.
	// Example: "64850e805e5793033297f476".
	//
	// Sometimes, both the InvoiceID and the HashFile are available. In that
	// case, the HashFile is the one to use (arbitrary choice) since both
	// GetInvoiceURL and GetDocumentURL return the same document.
	InvoiceID string

	Source Source

	AccountingKey AccountingKey
}

// Expenses can come from two different sources:
//
//	GetBuildingAccountingCurrent: "accounting"
//	GetBuildingAccountingRGDD:    "accounting"
//	GetBuildingAccountingRepairs: "repairs"
type Source string

const (
	SourceUnknown    Source = "unknown"
	SourceAccounting Source = "accounting"
	SourceRepairs    Source = "repairs"
)

// Each expense is grouped under two levels of grouping: the first group is
// 'allocation' ("Allocation") and the second 'expense type' ("Nature").
// Example:
//
//	allocations:
//	  - name: "CHARGES GENERALES"
//	    code: "001"
//	    expenseTypes:
//	      - name: "CONTRAT D'ENTRETIEN"
//	        code: "100"
//	        expenses:
//	          - invoiceId: "66d58ac6528cbab20fa41432"
//	            label: "2NRT-POMPES ENVIRONN - CONTRAT ENTRETIEN DE STATION DE RELEVAGE - 2024"
//
// Here is why we need to take both 'allocation' and 'expense type' into account
// when identifying an expense: the same invoice ID or hash file can be used in
// multiple allocations. For example, the following invoice of 820,97 € is split
// between the two buildings, but the invoice ID and hash file is the same:
//
//	allocations:
//	  - name: CHARGES ASCENSEUR D
//	    code: 601
//	    expenseTypes:
//	      - name: CONTRAT ETENDU ASCENSEUR
//	        code: 136
//	        expenses:
//	          - invoiceId: 6615521aac44b7c09440aeaa
//	            piece:
//	              hashFile: 6615521a0ee3bdcd450363fa
//	            label: TKE ENTRETIEN ASCENSEUR 2T2024
//	            date: 2024-04-09T14:35:07.357Z
//	            amount:
//	              value: 41049
//	              currency: EUR
//	              __typename: Debit
//	            isFromPreviousPeriod: true
//	  - name: CHARGES ASCENSEUR C
//	    code: 600
//	    expenseTypes:
//	      - name: CONTRAT ETENDU ASCENSEUR
//	        code: 136
//	        expenses:
//	          - invoiceId: 6615521aac44b7c09440aeaa
//	            piece:
//	              hashFile: 6615521a0ee3bdcd450363fa
//	            label: TKE ENTRETIEN ASCENSEUR 2T2024
//	            date: 2024-04-09T14:35:07.357Z
//	            amount:
//	              value: 41048
//	              currency: EUR
//	              __typename: Debit
//	            isFromPreviousPeriod: true
type AccountingKey struct {
	Allocation  string // Example: "CHARGES ASCENSEUR D"
	ExpenseType string // Example: "CONTRAT ETENDU ASCENSEUR"
}

func (a AccountingKey) String() string {
	return fmt.Sprintf("%s - %s", a.Allocation, a.ExpenseType)
}

type ExpenseDocumentID string

// Foncia's API doesn't return an ID for the expenses returned by
// getBuildingAccountingCurrent. Thus, I have to create my own ID. This isn't
// ideal since some expenses have the same tuple (invoiceId, label, hashFile,
// date, amount). The closest items I have found can be separated thanks to
// their date:
//
//	{
//	  "invoiceId": null,
//	  "piece": null,
//	  "label": "RELIQUAT DE REPARTITION",
//	  "date": "2024-06-30T22:00:00.000Z",
//	  "amount": {"value": 2},
//	  "isFromPreviousPeriod": false,
//	},
//	{
//	  "invoiceId": null,
//	  "piece": null,
//	  "label": "RELIQUAT DE REPARTITION",
//	  "date": "2023-06-30T22:00:00.000Z",
//	  "amount": {"value": 2},
//	  "isFromPreviousPeriod": true,
//	}
//
// Sometimes, there is a hash file but no invoice ID:
//
//	{
//	  "invoiceId": null,
//	  "piece": {
//	    "hashFile": "678f833860313bc2ff80e5b4",
//	    "__typename": "Document"
//	  },
//	  "label": "Honoraires Forfaitaires du 01/01/2025 au 31/01/2025",
//	  "date": "2025-01-21T11:21:24.342Z",
//	  "amount": {
//	    "value": 56480,
//	    "currency": "EUR",
//	    "__typename": "Debit"
//	  },
//	  "isFromPreviousPeriod": false,
//	}
//
// But I have never found a case where the invoice ID is set but not the hash
// file. Thus, I won't be using the invoice to identify the expenses; I will use
// the hashfile if it exists, and (label, date, amount) otherwise. Note that the
// hash file may appear later on, so the item should be updated in the database
// when the hash file starts appearing for a given (label, date, amount).
//
// What's weird is that getBuildingAccountingRGDD does return an ID for the
// expenses...
//
// Note that we may end up with duplicate expenses in the database when
// upserting, but that's a risk I'm willing to take.
//
// Note that an invoice ID or HashFile may be re-used across multiple items, so
// the label, date, and amount must always be used in the index. For example:
//
//	[
//	  {
//	    "invoiceId": null,
//	    "piece": {"hashFile": "65ae69fed44f299a134fee0f"},
//	    "label": "Honoraires Forfaitaires du 01/01/2024 au 09/01/2024",
//	    "date": "2024-01-22T13:13:21.524Z",
//	    "amount": { "value": 15618, "currency": "EUR", "__typename": "Debit" }
//	  },
//	  {
//	    "invoiceId": null,
//	    "piece": {"hashFile": "65ae69fed44f299a134fee0f"},
//	    "label": "Honoraires Forfaitaires du 10/01/2024 au 31/01/2024",
//	    "date": "2024-01-22T13:13:21.524Z",
//	    "amount": { "value": 39016, "currency": "EUR", "__typename": "Debit" }
//	  }
//	]
//
// The invoice ID or HashFile can also be re-used across multiple allocations:
//
//	allocations:
//	  - name: CHARGES ASCENSEUR D
//	    code: "601"
//	    expenseTypes:
//	      - name: CONTRAT ETENDU ASCENSEUR
//	        code: "136"
//	        expenses:
//	          - invoiceId: 6615521aac44b7c09440aeaa
//	            piece: { hashFile: 6615521a0ee3bdcd450363fa }
//	            label: TKE ENTRETIEN ASCENSEUR 2T2024
//	            date: 2024-04-09T14:35:07.357Z
//	            amount: { value: 41049, currency: EUR, __typename: Debit }
//	            isFromPreviousPeriod: true
//	  - name: CHARGES ASCENSEUR C
//	    code: "600"
//	    expenseTypes:
//	      - name: CONTRAT ETENDU ASCENSEUR
//	        code: "136"
//	        expenses:
//	          - invoiceId: 6615521aac44b7c09440aeaa
//	            piece: { hashFile: 6615521a0ee3bdcd450363fa }
//	            label: TKE ENTRETIEN ASCENSEUR 2T2024
//	            date: 2024-04-09T14:35:07.357Z
//	            amount: { value: 41048, currency: EUR, __typename: Debit }
//	            isFromPreviousPeriod: true
//
// Another problem I've seen is that some expenses have the same tuple (label,
// date, amount). In the below example, the only way to differentiate the two
// first expenses is to look at the hashFile:
//
//	allocations:
//	  - name: "CHARGES UNITAIRES C"
//	    code: "501"
//	    expenseTypes:
//	      - name: "CONTRAT EXTRACTEURS"
//	        code: "126"
//	        expenses:
//	          - invoiceId: null
//	            piece: { hashFile: 66dafe199f013b45ee991c96 }
//	            label: ELECO
//	            date: "2024-06-30T00:00:00.000Z"
//	            amount: { value: 79200, currency: EUR, __typename: Debit }
//	            isFromPreviousPeriod: true
//	          - invoiceId: null
//	            piece: { hashFile: 66e2b7bd424b4b0f0ab3954b }
//	            label: ELECO
//	            date: "2024-06-30T00:00:00.000Z"
//	            amount: { value: 79200, currency: EUR, __typename: Debit }
//	            isFromPreviousPeriod: true
//	  - name: "CHARGES UNITAIRES D"
//	    code: "502"
//	    expenseTypes:
//	      - name: "CONTRAT EXTRACTEURS"
//	        code: "126"
//	        expenses:
//	          - invoiceId: null
//	            piece: { hashFile: 66dafe459f013b45ee992188 }
//	            label: ELECO
//	            date: "2024-06-30T00:00:00.000Z"
//	            amount: { value: 79200, currency: EUR, __typename: Debit }
//	            isFromPreviousPeriod: true
//	          - invoiceId: null
//	            piece: { hashFile: 66dafd87d024fd1b510e1e37 }
//	            label: ELECO
//	            date: "2024-06-30T00:00:00.000Z"
//	            amount: { value: 79200, currency: EUR, __typename: Debit }
//	            isFromPreviousPeriod: true
type ExpenseDocumentsIndex struct {
	Elements                     []ExpenseDocumentDB
	ByLabelDateAmountKey         map[string]int
	ByLabelDateAmountKeyHashfile map[string]int
}

func NewExpenseDocumentsIndex(expenses []ExpenseDocumentDB) ExpenseDocumentsIndex {
	index := ExpenseDocumentsIndex{
		Elements:                     expenses,
		ByLabelDateAmountKey:         make(map[string]int),
		ByLabelDateAmountKeyHashfile: make(map[string]int),
	}
	for i, e := range expenses {
		if e.Label == "Honoraires Forfaitaires du 10/01/2024 au 31/01/2024" {
			logutil.Debugf("Honoraires Forfaitaires du 10/01/2024 au 31/01/2024")
		}
		index.ByLabelDateAmountKey[fmt.Sprintf("%s-%s-%d-%s", e.Label, e.Date.Format(time.RFC3339Nano), e.Amount, e.AccountingKey.String())] = i
	}
	for i, e := range expenses {
		if e.HashFile == "" {
			continue
		}
		index.ByLabelDateAmountKeyHashfile[fmt.Sprintf("%s-%s-%d-%s-%s", e.Label, e.Date.Format(time.RFC3339Nano), e.Amount, e.AccountingKey.String(), e.HashFile)] = i
	}
	return index
}

// Match returns a pointer to the original slice of expenses so that you can
// modify the original slice if you want to.
func (idx ExpenseDocumentsIndex) Match(partial ExpenseDocumentDB) (ExpenseDocumentDB, bool) {
	if partial.Label == "Honoraires Forfaitaires du 10/01/2024 au 31/01/2024" {
		logutil.Debugf("Honoraires Forfaitaires du 10/01/2024 au 31/01/2024")
	}
	if partial.HashFile != "" {
		i, ok := idx.ByLabelDateAmountKeyHashfile[fmt.Sprintf("%s-%s-%d-%s-%s", partial.Label, partial.Date.Format(time.RFC3339Nano), partial.Amount, partial.AccountingKey.String(), partial.HashFile)]
		if ok {
			return idx.Elements[i], true
		}
	}

	i, ok := idx.ByLabelDateAmountKey[fmt.Sprintf("%s-%s-%d-%s", partial.Label, partial.Date.Format(time.RFC3339Nano), partial.Amount, partial.AccountingKey.String())]
	if ok {
		return idx.Elements[i], true
	}

	return ExpenseDocumentDB{}, false
}

func (a ExpenseDocumentDB) Equal(b ExpenseDocumentDB) bool {
	// We ignore the file path, and compare the rest.
	a.FilePath = ""
	b.FilePath = ""
	return a == b
}

func Merge(oldFromDB, newFromAPI ExpenseDocumentDB) ExpenseDocumentDB {
	// Everything from the API is used except for the file path, since the file
	// path is only stored in DB.
	merged := newFromAPI
	merged.FilePath = oldFromDB.FilePath
	return merged
}

func (e ExpenseDocumentDB) Filename() string {
	// "OU CHANNA - CT01037406 - 2024-10-01 - _27.pdf"
	return filepath.Base(e.FilePath)
}

func GetExpensesByHashFileDB(ctx context.Context, db *sql.DB, hashFile string) ([]ExpenseDocumentDB, error) {
	var expenses []ExpenseDocumentDB
	rows, err := db.QueryContext(ctx, "SELECT invoice_id, label, amount, date, file_path, hash_file, source, accounting_allocation, accounting_expense_type FROM expenses WHERE hash_file = ?", hashFile)
	if err != nil {
		return nil, fmt.Errorf("while querying database: %w", err)
	}
	for rows.Next() {
		var e ExpenseDocumentDB
		var date string
		err = rows.Scan(&e.InvoiceID, &e.Label, &e.Amount, &date, &e.FilePath, &e.HashFile, &e.Source, &e.AccountingKey.Allocation, &e.AccountingKey.ExpenseType)
		if err != nil {
			return nil, fmt.Errorf("while scanning database row: %w", err)
		}

		e.Date, err = time.Parse(time.RFC3339Nano, date)

		if err != nil {
			return nil, fmt.Errorf("while parsing 'date': %w", err)
		}
		expenses = append(expenses, e)
	}

	return expenses, nil
}

func GetExpensesByInvoiceID(ctx context.Context, db *sql.DB, invoiceID string) ([]ExpenseDocumentDB, error) {
	rows, err := db.QueryContext(ctx, "SELECT invoice_id, label, amount, date, file_path, hash_file, source, accounting_allocation, accounting_expense_type FROM expenses WHERE invoice_id = ?", invoiceID)
	if err != nil {
		return nil, fmt.Errorf("while querying database: %w", err)
	}

	var expenses []ExpenseDocumentDB
	for rows.Next() {
		var e ExpenseDocumentDB
		var date string
		err = rows.Scan(&e.InvoiceID, &e.Label, &e.Amount, &date, &e.FilePath, &e.HashFile, &e.Source, &e.AccountingKey.Allocation, &e.AccountingKey.ExpenseType)
		if err != nil {
			return nil, fmt.Errorf("while scanning database row: %w", err)
		}

		e.Date, err = time.Parse(time.RFC3339Nano, date)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'date': %w", err)
		}

		expenses = append(expenses, e)
	}

	return expenses, nil
}

type AccountDocumentDB struct {
	ID        string           // Example: "64850e8057dcdd65a89cc462"
	HashFile  HashFile         // Example: "64850e8057dcdd65a89cc462" (same as ID)
	FilePath  string           // Example: "reports/CRvisite_0290-4661_202210131015.pdf"
	MimeType  string           // Example: "application/pdf"
	Category  DocumentCategory // Example: "reportVisit"
	CreatedAt time.Time
}

func (e AccountDocumentDB) Filename() string {
	// "VISITE_0290-4661_202210131015.pdf"
	return filepath.Base(e.FilePath)
}

func (e AccountDocumentDB) CategoryFrench() string {
	switch e.Category {
	case DocumentCategoryReportVisit:
		return "Rapport de visite"
	case DocumentCategoryInvoice:
		return "Facture"
	default:
		return "Inconnu"
	}
}

type DocumentCategory string

const (
	DocumentCategoryUnknown     DocumentCategory = "unknown" // Default.
	DocumentCategoryReportVisit DocumentCategory = "reportVisit"
	DocumentCategoryInvoice     DocumentCategory = "invoice"
)

func GetAccountDocumentByHashFileDB(ctx context.Context, db *sql.DB, hashFile string) (AccountDocumentDB, error) {
	var d AccountDocumentDB
	var createdAt string
	err := db.QueryRowContext(ctx, "SELECT id, hash_file, file_path, mime_type, category, created_at FROM account_documents WHERE hash_file = ?", hashFile).Scan(&d.ID, &d.HashFile, &d.FilePath, &d.MimeType, &d.Category, &createdAt)
	if err != nil {
		return AccountDocumentDB{}, fmt.Errorf("while querying database: %w", err)
	}

	d.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return AccountDocumentDB{}, fmt.Errorf("while parsing 'created_at': %w", err)
	}

	return d, nil
}

func GetAccountDocumentByCategoryDB(ctx context.Context, db *sql.DB, category DocumentCategory) ([]AccountDocumentDB, error) {
	rows, err := db.QueryContext(ctx, "SELECT id, hash_file, file_path, mime_type, category, created_at FROM account_documents WHERE category = ?", category)
	if err != nil {
		return nil, fmt.Errorf("while querying database: %w", err)
	}
	defer rows.Close()

	var documents []AccountDocumentDB
	for rows.Next() {
		var d AccountDocumentDB
		var createdAt string
		err = rows.Scan(&d.ID, &d.HashFile, &d.FilePath, &d.MimeType, &d.Category, &createdAt)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %w", err)
		}

		d.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'created_at': %w", err)
		}
		documents = append(documents, d)
	}

	return documents, nil
}

func GetAccountDocumentsDB(ctx context.Context, db *sql.DB) ([]AccountDocumentDB, error) {
	rows, err := db.QueryContext(ctx, "SELECT id, hash_file, file_path, mime_type, category, created_at FROM account_documents")
	if err != nil {
		return nil, fmt.Errorf("while querying database: %w", err)
	}
	defer rows.Close()

	var documents []AccountDocumentDB
	for rows.Next() {
		var d AccountDocumentDB
		var createdAt string
		err = rows.Scan(&d.ID, &d.HashFile, &d.FilePath, &d.MimeType, &d.Category, &createdAt)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %w", err)
		}

		d.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'created_at': %w", err)
		}
		documents = append(documents, d)
	}

	return documents, nil
}

func UpsertAccountDocumentsWithDB(ctx context.Context, db *sql.DB, documents []AccountDocumentDB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("while starting transaction: %w", err)
	}
	defer func() {
		err = tx.Rollback()
		if err != nil && err != sql.ErrTxDone {
			logutil.Errorf("while rolling back transaction: %w", err)
		}
	}()

	for _, d := range documents {
		req := "UPDATE account_documents SET file_path = ?, mime_type = ?, category = ?, created_at = ? WHERE hash_file = ?;"
		res, err := tx.ExecContext(ctx, req, d.FilePath, d.MimeType, d.Category, d.CreatedAt.Format(time.RFC3339Nano), d.HashFile)
		if err != nil {
			return fmt.Errorf("while updating account documents: %w", err)
		}

		// If no row was updated, insert a new one.
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("while getting rows affected: %w", err)
		}
		if n > 0 {
			logutil.Debugf("db: updated account document %q: %+v", d.ID, d)
		} else {
			req := "INSERT INTO account_documents (id, hash_file, file_path, mime_type, category, created_at) VALUES (?, ?, ?, ?, ?, ?);"
			_, err := tx.ExecContext(ctx, req, d.ID, d.HashFile, d.FilePath, d.MimeType, d.Category, d.CreatedAt.Format(time.RFC3339Nano))
			if err != nil {
				return fmt.Errorf("while inserting account documents: %w", err)
			}
			logutil.Debugf("db: added account document %q: %+v", d.ID, d)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("while committing transaction: %w", err)
	}
	return nil
}

func SaveWorkOrdersToDB(ctx context.Context, db *sql.DB, workOrders []WorkOrderDB) error {
	req := "INSERT INTO work_orders (id, mission_id, number, label, repair_date_start, repair_date_end, supplier_id, supplier_name, supplier_activity) VALUES "

	var values []interface{}
	for _, w := range workOrders {
		req += "(?, ?, ?, ?, ?, ?, ?, ?, ?),"
		values = append(values, w.ID, w.MissionID, w.Number, w.Label, w.RepairDateStart.Format(time.RFC3339Nano), w.RepairDateEnd.Format(time.RFC3339Nano), w.Supplier.ID, w.Supplier.Name, w.Supplier.Activity)
	}

	// No need to do anything if there are no work orders to insert.
	if len(values) == 0 {
		return nil
	}
	req = strings.TrimSuffix(req, ",")
	_, err := db.ExecContext(ctx, req, values...)

	logutil.Debugf("sql saveWorkOrdersToDB: %s with:%s", req, fprintfValues(values, ",", "\n", 9))
	if err != nil {
		return fmt.Errorf("while inserting work orders: %w", err)
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

func SaveMissionsToDB(ctx context.Context, db *sql.DB, missions ...MissionDB) error {
	req := "INSERT INTO missions (id, number, kind, label, status, started_at, description) VALUES "
	var values []interface{}
	for _, e := range missions {
		req += "(?, ?, ?, ?, ?, ?, ?),"
		values = append(values, e.ID, e.Number, e.Kind, e.Label, e.Status, e.StartedAt.Format(time.RFC3339Nano), e.Description)
	}
	req = strings.TrimSuffix(req, ",")
	_, err := db.ExecContext(ctx, req, values...)
	if err != nil {
		return fmt.Errorf("while inserting values: %w", err)
	}

	return nil
}

func GetMissionsDB(ctx context.Context, db *sql.DB) ([]MissionDB, error) {
	rows, err := db.QueryContext(ctx, "SELECT id, number, kind, label, status, started_at, description FROM missions ORDER BY started_at DESC")
	if err != nil {
		return nil, fmt.Errorf("while querying database: %w", err)
	}
	defer rows.Close()

	var missions []MissionDB
	for rows.Next() {
		var m MissionDB
		var startedAt string
		err = rows.Scan(&m.ID, &m.Number, &m.Kind, &m.Label, &m.Status, &startedAt, &m.Description)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %w", err)
		}

		m.StartedAt, err = time.Parse(time.RFC3339Nano, startedAt)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'started_at': %w", err)
		}
		missions = append(missions, m)
	}

	var missionIDs []string
	for i := range missions {
		missionIDs = append(missionIDs, missions[i].ID)
	}
	workOrderMap, err := getWorkOrdersDB(ctx, db, missionIDs...)
	if err != nil {
		return nil, fmt.Errorf("while getting work orders from DB: %w", err)
	}

	for i := range missions {
		workOrders, found := workOrderMap[missions[i].ID]
		if !found {
			continue
		}
		missions[i].WorkOrders = workOrders
	}
	return missions, nil
}

func getWorkOrdersDB(ctx context.Context, db *sql.DB, missionIDs ...string) (map[string][]WorkOrderDB, error) {
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
	// logutil.Debugf("sql getWorkOrdersDB: %s", req)

	rows, err := db.QueryContext(ctx, req, values...)
	if err != nil {
		return nil, fmt.Errorf("while querying database: %w", err)
	}
	defer rows.Close()

	workOrderMap := make(map[string][]WorkOrderDB)
	for rows.Next() {
		var wo WorkOrderDB
		var missionID, repairDateStart, repairDateEnd string
		var supplName, supplActivity sql.NullString
		var docID, docFilePath, docHashFile sql.NullString
		err = rows.Scan(
			&wo.ID, &missionID, &wo.Number, &wo.Label, &repairDateStart, &repairDateEnd, &wo.Supplier.ID,
			&supplName, &supplActivity,
			&docID, &docFilePath, &docHashFile,
		)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %w", err)
		}

		wo.Supplier.Name = supplName.String
		wo.Supplier.Activity = supplActivity.String

		wo.RepairDateStart, err = time.Parse(time.RFC3339Nano, repairDateStart)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'repair_date_start': %w", err)
		}
		wo.RepairDateEnd, err = time.Parse(time.RFC3339Nano, repairDateEnd)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'repair_date_end': %w", err)
		}

		workOrderMap[missionID] = append(workOrderMap[missionID], wo)
	}

	return workOrderMap, nil
}

func GetExpensesDB(ctx context.Context, db *sql.DB) ([]ExpenseDocumentDB, error) {
	rows, err := db.QueryContext(ctx, "SELECT invoice_id, label, amount, date, file_path, hash_file, source, accounting_allocation, accounting_expense_type FROM expenses")
	if err != nil {
		return nil, fmt.Errorf("while querying database: %w", err)
	}
	defer rows.Close()

	var expenses []ExpenseDocumentDB
	for rows.Next() {
		var e ExpenseDocumentDB
		var date string
		var source sql.NullString // The `source` field was added later on, so it may be NULL.
		err = rows.Scan(&e.InvoiceID, &e.Label, &e.Amount, &date, &e.FilePath, &e.HashFile, &source, &e.AccountingKey.Allocation, &e.AccountingKey.ExpenseType)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %w", err)
		}

		e.Source = Source(source.String)
		e.Date, err = time.Parse(time.RFC3339Nano, date)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'date': %w", err)
		}

		expenses = append(expenses, e)
	}

	return expenses, nil
}

func RmLastExpenseDB(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM expenses WHERE rowid = (SELECT max(rowid) FROM expenses);")
	if err != nil {
		return fmt.Errorf("while deleting last expense: %w", err)
	}
	return nil
}
func RmLastMissionDB(db *sql.DB) error {
	// First, remove the work orders associated with the last mission.
	_, err := db.Exec("DELETE FROM work_orders WHERE mission_id = (SELECT id FROM missions ORDER BY started_at DESC LIMIT 1);")
	if err != nil {
		return fmt.Errorf("while deleting work orders: %w", err)
	}

	_, err = db.Exec("DELETE FROM missions WHERE id = (SELECT id FROM missions ORDER BY started_at DESC LIMIT 1);")
	if err != nil {
		return fmt.Errorf("while deleting last mission: %w", err)
	}
	return nil
}

// We consider that the database is empty when there are no missions and no
// expenses.
func IsEmptyDB(ctx context.Context, db *sql.DB) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM missions;").Scan(&n)
	if err != nil {
		return false, fmt.Errorf("while querying database: %w", err)
	}

	if n > 0 {
		return false, nil
	}

	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM expenses;").Scan(&n)
	if err != nil {
		return false, fmt.Errorf("while querying database: %w", err)
	}

	if n > 0 {
		return false, nil
	}

	return true, nil
}

// Parse the mission number ("Ordre de service in French") from the subject.
// For example, given the subject:
//
//	"Ordre de service N° OSMIL805898844 – 2NRT POMPE ENVIRONNEMENT - 3 RUE BERTRAN 31200 TOULOUSE"
//
// we want to extract "OSMIL805898844".
func MissionNumber(s string) string {
	re := regexp.MustCompile(`N° ([A-Z0-9]+)`)
	m := re.FindStringSubmatch(s)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

// For example: getLastSyncForQuery(ctx, db, "getCouncilMissionSuppliers")
type LastSync struct {
	LastCursor string
	Date       time.Time
}

func GetLastSyncs(ctx context.Context, db *sql.DB) (map[string]LastSync, error) {
	var m map[string]LastSync

	req := "SELECT graphql_query_name, last_cursor, date FROM last_syncs;"
	rows, err := db.QueryContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("while querying database: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var l LastSync
		var queryName string
		err = rows.Scan(&queryName, &l.LastCursor, &l.Date)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %w", err)
		}
		m[queryName] = l
	}

	return m, nil
}

// For example: SetLastSyncForQuery(ctx, db, "getCouncilMissionSuppliers", "cursor")
func SetLastSyncForQuery(ctx context.Context, db *sql.DB, queryName, cursor string) error {
	_, err := db.ExecContext(ctx, "REPLACE INTO last_syncs (graphql_query_name, last_cursor, date) VALUES (?, ?, ?);", queryName, cursor, time.Now().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("while inserting into last_syncs: %w", err)
	}
	return nil
}
