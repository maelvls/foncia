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

const lastSyncTableSQL = `
	CREATE TABLE IF NOT EXISTS last_syncs (
		graphql_query_name TEXT PRIMARY KEY, -- Name of the GraphQL query that was last used to sync the database.
		last_cursor TEXT,                    -- Cursor of the last page of the last GraphQL query.
		date TEXT                            -- Date of the last sync. RFC3339.
	);`

type lastSync struct {
	graphqlQueryName string
	lastCursor       string
	date             time.Time
}

const missionsTableSQL = `
	CREATE TABLE IF NOT EXISTS missions (
		id TEXT UNIQUE,
		number TEXT,                 -- Foncia's ID for the intervention
		kind TEXT,
		label TEXT,
		status TEXT,
		started_at TEXT,             -- time.RFC3339
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
	StartedAt   time.Time // "2023-04-24T22:00:00.000Z" (time.RFC3339)
	Description string    // "BONJOUR,\n\nVEUILLEZ ENREGISTER LE C02\t\nMERCI CORDIALEMENT"
	WorkOrders  []WorkOrderDB
}

const workOrdersTableSQL = `
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
	);`

type WorkOrderDB struct {
	ID              string    // "64850e80df57eb4ade3cf63c"
	MissionID       string    // "64850e8019d5d64c415d13dd"
	Number          string    // "OSMIL802702875"
	Label           string    // "BOUVIER SECURITE INCENDIE - DEMANDE INTERVENTION P"
	RepairDateStart time.Time // "2022-10-18T22:00:00.000Z"
	RepairDateEnd   time.Time // "2022-10-18T22:00:00.000Z"
	Supplier        SupplierDB
}

const expensesTableSQL = `
	CREATE TABLE IF NOT EXISTS expenses (
		invoice_id TEXT,       -- May be "" if no invoice file
		label TEXT,
		amount INTEGER,
		date TEXT,             -- time.RFC3339
		file_path TEXT,        -- May be "" if no invoice file
		hash_file TEXT         -- May be "" if no invoice file
	);`

func InitSchemaDB(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, lastSyncTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create table 'last_sync': %w", err)
	}
	_, err = db.ExecContext(ctx, missionsTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create table 'missions': %w", err)
	}
	_, err = db.ExecContext(ctx, workOrdersTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create table 'work_orders': %w", err)
	}
	_, err = db.ExecContext(ctx, expensesTableSQL)
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
		return nil, fmt.Errorf("while querying database: %v", err)
	}
	defer rows.Close()

	var suppliers []SupplierDB
	for rows.Next() {
		var s SupplierDB
		err = rows.Scan(&s.ID, &s.Name, &s.Activity)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %v", err)
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
		return nil, fmt.Errorf("while querying database: %v", err)
	}
	defer rows.Close()

	var documents []SupplierContractDocumentDB
	for rows.Next() {
		var d SupplierContractDocumentDB
		err = rows.Scan(&d.ID, &d.FilePath, &d.HashFile, &d.SupplierID)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %v", err)
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
		return nil, fmt.Errorf("while querying database: %v", err)
	}
	defer rows.Close()

	var documents []SupplierContractDocumentDB
	for rows.Next() {
		var d SupplierContractDocumentDB
		err = rows.Scan(&d.ID, &d.FilePath, &d.HashFile, &d.SupplierID)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %v", err)
		}
		documents = append(documents, d)
	}

	return documents, nil
}

// Documents are merged using their IDs. O(N^2) but OK because N is small. When
// the previous value (e.g. filepath) was set the current value is empty, the
// previous value is kept.
func MergeSupplierContractDocsDB(previous, current []SupplierContractDocumentDB) (missing, updated, removed []SupplierContractDocumentDB) {
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
	for _, c := range current {
		for _, p := range previous {
			if c.ID != p.ID {
				continue
			}

			changed, hasChanged := MergeDoc(c, p)
			if !hasChanged {
				continue
			}
			changedDocs = append(changedDocs, changed)
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

// When the previous value (e.g. filepath) was wasn't empty but the current
// value is empty, the previous value is kept.
func MergeDoc(previous, current SupplierContractDocumentDB) (SupplierContractDocumentDB, bool) {
	var merged SupplierContractDocumentDB

	if current.FilePath == "" {
		merged.FilePath = previous.FilePath
	} else {
		merged.FilePath = current.FilePath
	}

	if current.HashFile == "" {
		merged.HashFile = previous.HashFile
	} else {
		merged.HashFile = current.HashFile
	}

	merged.ID = current.ID
	merged.SupplierID = current.SupplierID

	return current, DocumentHasChanged(current, merged)
}

func GetSupplierContractByHashFileDB(ctx context.Context, db *sql.DB, hashFile string) (SupplierContractDocumentDB, error) {
	var d SupplierContractDocumentDB
	err := db.QueryRowContext(ctx, "SELECT id, file_path, hash_file, supplier_id FROM contract_documents WHERE hash_file = ?", hashFile).Scan(&d.ID, &d.FilePath, &d.HashFile, &d.SupplierID)
	if err != nil {
		return SupplierContractDocumentDB{}, fmt.Errorf("while querying database: %v", err)
	}

	return d, nil
}

func UpsertSuppliersToDB(ctx context.Context, db *sql.DB, suppliers []SupplierDB) error {
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

	// Find the suppliers that are already in the database.
	req := "SELECT id, name, activity FROM suppliers;"
	rows, err := tx.QueryContext(ctx, req)
	if err != nil {
		return fmt.Errorf("while querying database: %v", err)
	}
	defer rows.Close()

	var suppliersInDB []SupplierDB
	for rows.Next() {
		var s SupplierDB
		err = rows.Scan(&s.ID, &s.Name, &s.Activity)
		if err != nil {
			return fmt.Errorf("while scanning row: %v", err)
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
			return fmt.Errorf("while inserting into suppliers: %v", err)
		}
		logutil.Debugf("db: added supplier %q: %+v", s.ID, s)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("while committing transaction: %v", err)
	}
	return nil
}

func DocumentHasChanged(live, d SupplierContractDocumentDB) bool {
	if live.HashFile != d.HashFile {
		return true
	}
	if live.FilePath != d.FilePath {
		return true
	}

	return false
}

func UpsertDocumentsWithDB(ctx context.Context, db *sql.DB, documents []SupplierContractDocumentDB) error {
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

	for _, e := range documents {
		req := "UPDATE contract_documents SET file_path = ?, hash_file = ? WHERE id = ?;"
		res, err := tx.ExecContext(ctx, req, e.FilePath, e.HashFile, e.ID)
		if err != nil {
			return fmt.Errorf("while updating contract documents: %v", err)
		}

		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("while getting rows affected: %v", err)
		}
		if n != 0 {
			logutil.Debugf("db: updated document %q: %+v", e.ID, e)
			continue
		}

		// No existing row was found: insert a new one.
		req = "INSERT INTO contract_documents (id, supplier_id, file_path, hash_file) VALUES (?, ?, ?, ?);"
		_, err = tx.ExecContext(ctx, req, e.ID, e.SupplierID, e.FilePath, e.HashFile)
		if err != nil {
			return fmt.Errorf("while inserting contract documents: %v", err)
		}
		logutil.Debugf("db: added document %q: %+v", e.ID, e)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("while committing transaction: %v", err)
	}
	return nil
}

// FilePath is the only field that ca be updated.
func UpsertExpensesWithDB(ctx context.Context, db *sql.DB, expense ...ExpenseDocumentDB) error {
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
		req := "UPDATE expenses SET file_path = ? where	invoice_id = ? and label = ? and hash_file = ? and date = ? and amount = ?;"
		values := []interface{}{e.FilePath, e.InvoiceID, e.Label, e.HashFile, e.Date.Format(time.RFC3339), e.Amount}
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
//	date TEXT,             -- time.RFC3339
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
type ExpenseDocumentDB struct {
	InvoiceID string    // Sometimes set. Not sure what it is for. E.g.: "64850e805e5793033297f476".
	Label     string    // Example: "MADAME-OU CHANNA ENTRETIEN PARTIES COMMUNES 03/2024". May not be unique.
	Amount    Amount    // Example: 1234567890, which means "1234567,90 €". Negative = credit, positive = debit.
	Date      time.Time // May not be unique.
	FilePath  string    // Only set when a document is attached. Example: "invoices/OU CHANNA - CT01037406 - 2024-10-01 - _27.pdf"
	HashFile  HashFile  // Only set when a document is attached. Example: "66fbf2a9294cd8ed17d7ce9a"
}

type ExpenseDocumentID string

// Foncia's API doesn't return an ID for the expenses returned by
// getBuildingAccountingCurrent. Thus, I have to create my own ID. This isn't
// ideal since some expenses have the same tuple (invoiceId, label, hashFile,
// date, amount). The closest items I have found can be separated thanks
// to their date:
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
// What's weird is that getBuildingAccountingRGDD does return an ID for the
// expenses...
//
// Note that we may end up with duplicate expenses in the database when
// upserting, but that's a risk I'm willing to take.
func (e ExpenseDocumentDB) ID() ExpenseDocumentID {
	return ExpenseDocumentID(fmt.Sprintf("%s-%s-%s-%s-%d", e.InvoiceID, e.Label, e.HashFile, e.Date.Format(time.RFC3339Nano), e.Amount))
}

func (a ExpenseDocumentDB) Equal(b ExpenseDocumentDB) bool {
	return a.InvoiceID == b.InvoiceID &&
		a.Label == b.Label &&
		a.Amount == b.Amount &&
		a.Date.Equal(b.Date) &&
		a.FilePath == b.FilePath &&
		a.HashFile == b.HashFile
}

func (e ExpenseDocumentDB) Filename() string {
	// "OU CHANNA - CT01037406 - 2024-10-01 - _27.pdf"
	return filepath.Base(e.FilePath)
}

// errors.Is(err, sql.NoRows) when not found.
func GetExpenseByHashFileDB(ctx context.Context, db *sql.DB, hashFile string) (ExpenseDocumentDB, error) {
	var e ExpenseDocumentDB
	var date string
	err := db.QueryRowContext(ctx, "SELECT invoice_id, label, amount, date, file_path, hash_file FROM expenses WHERE hash_file = ?", hashFile).Scan(&e.InvoiceID, &e.Label, &e.Amount, &date, &e.FilePath, &e.HashFile)
	if err != nil {
		return ExpenseDocumentDB{}, fmt.Errorf("while querying database: %w", err)
	}
	e.Date, err = time.Parse(time.RFC3339, date)
	if err != nil {
		return ExpenseDocumentDB{}, fmt.Errorf("while parsing 'date': %v", err)
	}

	return e, nil
}

type AccountDocumentDB struct {
	ID       string
	HashFile HashFile
	FilePath string
}

func GetAccountDocumentByHashFileDB(ctx context.Context, db *sql.DB, hashFile string) (AccountDocumentDB, error) {
	var d AccountDocumentDB
	err := db.QueryRowContext(ctx, "SELECT id, file_path, hash_file FROM account_documents WHERE hash_file = ?", hashFile).Scan(&d.ID, &d.FilePath, &d.HashFile)
	if err != nil {
		return AccountDocumentDB{}, fmt.Errorf("while querying database: %v", err)
	}

	return d, nil
}

func SaveWorkOrdersToDB(ctx context.Context, db *sql.DB, workOrders []WorkOrderDB) error {
	req := "INSERT INTO work_orders (id, mission_id, number, label, repair_date_start, repair_date_end, supplier_id, supplier_name, supplier_activity) VALUES "

	var values []interface{}
	for _, w := range workOrders {
		req += "(?, ?, ?, ?, ?, ?, ?, ?, ?),"
		values = append(values, w.ID, w.MissionID, w.Number, w.Label, w.RepairDateStart.Format(time.RFC3339), w.RepairDateEnd.Format(time.RFC3339), w.Supplier.ID, w.Supplier.Name, w.Supplier.Activity)
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

func SaveMissionsToDB(ctx context.Context, db *sql.DB, missions ...MissionDB) error {
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

func GetMissionsDB(ctx context.Context, db *sql.DB) ([]MissionDB, error) {
	rows, err := db.QueryContext(ctx, "SELECT id, number, kind, label, status, started_at, description FROM missions ORDER BY started_at DESC")
	if err != nil {
		return nil, fmt.Errorf("while querying database: %v", err)
	}
	defer rows.Close()

	var missions []MissionDB
	for rows.Next() {
		var m MissionDB
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
		return nil, fmt.Errorf("while querying database: %v", err)
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
			return nil, fmt.Errorf("while scanning row: %v", err)
		}

		wo.Supplier.Name = supplName.String
		wo.Supplier.Activity = supplActivity.String

		wo.RepairDateStart, err = time.Parse(time.RFC3339, repairDateStart)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'repair_date_start': %v", err)
		}
		wo.RepairDateEnd, err = time.Parse(time.RFC3339, repairDateEnd)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'repair_date_end': %v", err)
		}

		workOrderMap[missionID] = append(workOrderMap[missionID], wo)
	}

	return workOrderMap, nil
}

func GetExpensesDB(ctx context.Context, db *sql.DB) ([]ExpenseDocumentDB, error) {
	rows, err := db.QueryContext(ctx, "SELECT invoice_id, label, amount, date, file_path, hash_file FROM expenses ORDER BY date DESC")
	if err != nil {
		return nil, fmt.Errorf("while querying database: %v", err)
	}
	defer rows.Close()

	var expenses []ExpenseDocumentDB
	for rows.Next() {
		var e ExpenseDocumentDB
		var date string
		err = rows.Scan(&e.InvoiceID, &e.Label, &e.Amount, &date, &e.FilePath, &e.HashFile)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %v", err)
		}

		e.Date, err = time.Parse(time.RFC3339, date)
		if err != nil {
			return nil, fmt.Errorf("while parsing 'date': %v", err)
		}

		expenses = append(expenses, e)
	}

	return expenses, nil
}

func RmLastExpenseDB(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM expenses WHERE rowid = (SELECT max(rowid) FROM expenses);")
	if err != nil {
		return fmt.Errorf("while deleting last expense: %v", err)
	}
	return nil
}
func RmLastMissionDB(db *sql.DB) error {
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
func IsEmptyDB(ctx context.Context, db *sql.DB) (bool, error) {
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
		return nil, fmt.Errorf("while querying database: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var l LastSync
		var queryName string
		err = rows.Scan(&queryName, &l.LastCursor, &l.Date)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %v", err)
		}
		m[queryName] = l
	}

	return m, nil
}

// For example: SetLastSyncForQuery(ctx, db, "getCouncilMissionSuppliers", "cursor")
func SetLastSyncForQuery(ctx context.Context, db *sql.DB, queryName, cursor string) error {
	_, err := db.ExecContext(ctx, "REPLACE INTO last_syncs (graphql_query_name, last_cursor, date) VALUES (?, ?, ?);", queryName, cursor, time.Now().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("while inserting into last_syncs: %v", err)
	}
	return nil
}
