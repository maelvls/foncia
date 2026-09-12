package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/maelvls/foncia/logutil"
)

// -----------------------------------------------------------------------------
// Small helpers shared by the queries below.
// -----------------------------------------------------------------------------

// querier is implemented by both *sql.DB and *sql.Tx.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// queryAll runs the query and turns every row into a T using scan. It takes
// care of closing the rows and of checking rows.Err, which is easy to forget.
func queryAll[T any](ctx context.Context, q querier, query string, scan func(*sql.Rows) (T, error), args ...any) ([]T, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("while querying database: %w", err)
	}
	defer rows.Close()

	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("while scanning row: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("while iterating over rows: %w", err)
	}
	return out, nil
}

// inTx runs f in a transaction and commits it. The transaction is rolled back
// if f returns an error.
func inTx(ctx context.Context, db *sql.DB, f func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("while starting transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := f(tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("while committing transaction: %w", err)
	}
	return nil
}

// formatTime normalises the time to UTC before formatting it so that the
// RFC3339Nano text sorts chronologically (a "+02:00" offset would not).
func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(field, s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("while parsing %q: %w", field, err)
	}
	return t, nil
}

// placeholders returns "(?, ?, ?),(?, ?, ?)" for cols=3 and rows=2.
func placeholders(cols, rows int) string {
	one := "(" + strings.TrimSuffix(strings.Repeat("?, ", cols), ", ") + ")"
	return strings.TrimSuffix(strings.Repeat(one+",", rows), ",")
}

// maxRowsPerInsert keeps the number of bound parameters well below SQLite's
// limit (SQLITE_MAX_VARIABLE_NUMBER).
const maxRowsPerInsert = 50

// -----------------------------------------------------------------------------
// Missions and work orders.
// -----------------------------------------------------------------------------

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

const missionInsert = `INSERT INTO missions (id, number, kind, label, status, started_at, description) VALUES `

const missionOnConflict = ` ON CONFLICT(id) DO UPDATE SET
	number = excluded.number,
	kind = excluded.kind,
	label = excluded.label,
	status = excluded.status,
	started_at = excluded.started_at,
	description = excluded.description;`

// SaveMissionsToDB inserts the missions, updating the ones that already exist.
func SaveMissionsToDB(ctx context.Context, db *sql.DB, missions ...MissionDB) error {
	if len(missions) == 0 {
		return nil
	}

	return inTx(ctx, db, func(tx *sql.Tx) error {
		for chunk := range chunks(missions, maxRowsPerInsert) {
			var values []any
			for _, m := range chunk {
				values = append(values, m.ID, m.Number, m.Kind, m.Label, m.Status, formatTime(m.StartedAt), m.Description)
			}
			req := missionInsert + placeholders(7, len(chunk)) + missionOnConflict
			if _, err := tx.ExecContext(ctx, req, values...); err != nil {
				return fmt.Errorf("while upserting missions: %w", err)
			}
		}
		return nil
	})
}

const workOrderInsert = `INSERT INTO work_orders (id, mission_id, number, label, repair_date_start, repair_date_end, supplier_id, supplier_name, supplier_activity) VALUES `

const workOrderOnConflict = ` ON CONFLICT(id) DO UPDATE SET
	mission_id = excluded.mission_id,
	number = excluded.number,
	label = excluded.label,
	repair_date_start = excluded.repair_date_start,
	repair_date_end = excluded.repair_date_end,
	supplier_id = excluded.supplier_id,
	supplier_name = excluded.supplier_name,
	supplier_activity = excluded.supplier_activity;`

// SaveWorkOrdersToDB inserts the work orders, updating the ones that already
// exist.
func SaveWorkOrdersToDB(ctx context.Context, db *sql.DB, workOrders []WorkOrderDB) error {
	if len(workOrders) == 0 {
		return nil
	}

	return inTx(ctx, db, func(tx *sql.Tx) error {
		for chunk := range chunks(workOrders, maxRowsPerInsert) {
			var values []any
			for _, w := range chunk {
				values = append(values, w.ID, w.MissionID, w.Number, w.Label,
					formatTime(w.RepairDateStart), formatTime(w.RepairDateEnd),
					w.Supplier.ID, w.Supplier.Name, w.Supplier.Activity)
			}
			req := workOrderInsert + placeholders(9, len(chunk)) + workOrderOnConflict
			logutil.Debugf("sql SaveWorkOrdersToDB: %s with:%s", req, fprintfValues(values, ",", "\n", 9))
			if _, err := tx.ExecContext(ctx, req, values...); err != nil {
				return fmt.Errorf("while upserting work orders: %w", err)
			}
		}
		return nil
	})
}

func scanMission(rows *sql.Rows) (MissionDB, error) {
	var m MissionDB
	var startedAt string
	if err := rows.Scan(&m.ID, &m.Number, &m.Kind, &m.Label, &m.Status, &startedAt, &m.Description); err != nil {
		return MissionDB{}, err
	}
	var err error
	m.StartedAt, err = parseTime("started_at", startedAt)
	if err != nil {
		return MissionDB{}, err
	}
	return m, nil
}

func GetMissionsDB(ctx context.Context, db *sql.DB) ([]MissionDB, error) {
	missions, err := queryAll(ctx, db,
		"SELECT id, number, kind, label, status, started_at, description FROM missions ORDER BY started_at DESC",
		scanMission)
	if err != nil {
		return nil, err
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

// workOrderRow is a work order joined with its supplier and the supplier's
// contract documents. The mission ID is kept separately so that the caller can
// group the work orders by mission.
type workOrderRow struct {
	missionID string
	workOrder WorkOrderDB
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
			WHERE w.mission_id IN (` + strings.TrimSuffix(strings.Repeat("?,", len(missionIDs)), ",") + `);`

	var values []any
	for _, id := range missionIDs {
		values = append(values, id)
	}

	rows, err := queryAll(ctx, db, req, scanWorkOrderRow, values...)
	if err != nil {
		return nil, err
	}

	workOrderMap := make(map[string][]WorkOrderDB)
	for _, r := range rows {
		workOrderMap[r.missionID] = append(workOrderMap[r.missionID], r.workOrder)
	}
	return workOrderMap, nil
}

func scanWorkOrderRow(rows *sql.Rows) (workOrderRow, error) {
	var r workOrderRow
	var repairDateStart, repairDateEnd string
	// The LEFT JOINs mean these may legitimately be NULL.
	var supplName, supplActivity sql.NullString
	var docID, docFilePath, docHashFile sql.NullString
	err := rows.Scan(
		&r.workOrder.ID, &r.missionID, &r.workOrder.Number, &r.workOrder.Label,
		&repairDateStart, &repairDateEnd, &r.workOrder.Supplier.ID,
		&supplName, &supplActivity,
		&docID, &docFilePath, &docHashFile,
	)
	if err != nil {
		return workOrderRow{}, err
	}

	r.workOrder.Supplier.Name = supplName.String
	r.workOrder.Supplier.Activity = supplActivity.String

	r.workOrder.RepairDateStart, err = parseTime("repair_date_start", repairDateStart)
	if err != nil {
		return workOrderRow{}, err
	}
	r.workOrder.RepairDateEnd, err = parseTime("repair_date_end", repairDateEnd)
	if err != nil {
		return workOrderRow{}, err
	}
	return r, nil
}

// -----------------------------------------------------------------------------
// Suppliers and their contract documents.
// -----------------------------------------------------------------------------

type SupplierDB struct {
	ID        string
	Name      string // Examples: "2NRT-POMPES ENVIRONNEMENT"
	Activity  string // Examples: "PLOM", "ADBE", "ISOL"
	Documents []SupplierContractDocumentDB
}

type SupplierContractDocumentDB struct {
	ID         string   // The document's ID. Example: "64850e805e5793033297f476"
	HashFile   HashFile // Only set when a document is attached. Example: "64850e805e5793033297f476"
	FilePath   string   // Example: "invoices/2023-03-09_2apf.pdf". Empty when querying live.
	SupplierID string
}

func scanSupplier(rows *sql.Rows) (SupplierDB, error) {
	var s SupplierDB
	err := rows.Scan(&s.ID, &s.Name, &s.Activity)
	return s, err
}

func scanContractDoc(rows *sql.Rows) (SupplierContractDocumentDB, error) {
	var d SupplierContractDocumentDB
	err := rows.Scan(&d.ID, &d.FilePath, &d.HashFile, &d.SupplierID)
	return d, err
}

func GetSuppliersDB(ctx context.Context, db *sql.DB) ([]SupplierDB, error) {
	suppliers, err := queryAll(ctx, db, `SELECT id, name, activity FROM suppliers;`, scanSupplier)
	if err != nil {
		return nil, err
	}

	// Then, get the documents for each supplier.
	for i := range suppliers {
		docs, err := GetSupplierContractBySupplierIDDB(ctx, db, suppliers[i].ID)
		if err != nil {
			return nil, fmt.Errorf("while getting documents for supplier %q: %w", suppliers[i].ID, err)
		}
		suppliers[i].Documents = docs
	}

	return suppliers, nil
}

func GetSupplierContractBySupplierIDDB(ctx context.Context, db *sql.DB, supplierID string) ([]SupplierContractDocumentDB, error) {
	return queryAll(ctx, db,
		`SELECT id, file_path, hash_file, supplier_id FROM contract_documents WHERE supplier_id = ?;`,
		scanContractDoc, supplierID)
}

func GetSupplierContractDocsDB(ctx context.Context, db *sql.DB) ([]SupplierContractDocumentDB, error) {
	return queryAll(ctx, db,
		`SELECT id, file_path, hash_file, supplier_id FROM contract_documents;`,
		scanContractDoc)
}

func GetSupplierContractByHashFileDB(ctx context.Context, db *sql.DB, hashFile string) (SupplierContractDocumentDB, error) {
	var d SupplierContractDocumentDB
	err := db.QueryRowContext(ctx, "SELECT id, file_path, hash_file, supplier_id FROM contract_documents WHERE hash_file = ?", hashFile).
		Scan(&d.ID, &d.FilePath, &d.HashFile, &d.SupplierID)
	if err != nil {
		return SupplierContractDocumentDB{}, fmt.Errorf("while querying database: %w", err)
	}
	return d, nil
}

// UpsertSuppliersToDB inserts the suppliers, and updates the name and activity
// of the ones that already exist.
func UpsertSuppliersToDB(ctx context.Context, db *sql.DB, suppliers []SupplierDB) error {
	if len(suppliers) == 0 {
		return nil
	}

	const req = `INSERT INTO suppliers (id, name, activity) VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name = excluded.name, activity = excluded.activity;`

	return inTx(ctx, db, func(tx *sql.Tx) error {
		for _, s := range suppliers {
			if _, err := tx.ExecContext(ctx, req, s.ID, s.Name, s.Activity); err != nil {
				return fmt.Errorf("db: while upserting supplier %q: %w", s.ID, err)
			}
			logutil.Debugf("db: upserted supplier %q: %+v", s.ID, s)
		}
		return nil
	})
}

func UpsertContractDocumentsWithDB(ctx context.Context, db *sql.DB, documents []SupplierContractDocumentDB) error {
	if len(documents) == 0 {
		return nil
	}

	const req = `INSERT INTO contract_documents (id, supplier_id, file_path, hash_file) VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			supplier_id = excluded.supplier_id,
			file_path = excluded.file_path,
			hash_file = excluded.hash_file;`

	return inTx(ctx, db, func(tx *sql.Tx) error {
		for _, d := range documents {
			if _, err := tx.ExecContext(ctx, req, d.ID, d.SupplierID, d.FilePath, d.HashFile); err != nil {
				return fmt.Errorf("while upserting contract document %q: %w", d.ID, err)
			}
			logutil.Debugf("db: upserted contract document %q: %+v", d.ID, d)
		}
		return nil
	})
}

// -----------------------------------------------------------------------------
// Merging documents coming from the API with the ones already in the database.
// -----------------------------------------------------------------------------

// mergeByID compares the documents already in the database (previous) with the
// ones just fetched from the API (current). It returns the documents that are
// missing from the database, the ones that have changed (already merged with
// their previous version), and the ones that have disappeared from the API.
func mergeByID[T any](
	previous, current []T,
	id func(T) string,
	equal func(a, b T) bool,
	merge func(previous, current T) T,
) (missing, updated, removed []T) {
	prevByID := make(map[string]T, len(previous))
	for _, p := range previous {
		prevByID[id(p)] = p
	}
	curByID := make(map[string]T, len(current))
	for _, c := range current {
		curByID[id(c)] = c
	}

	for _, c := range current {
		prev, found := prevByID[id(c)]
		switch {
		case !found:
			missing = append(missing, c)
		case !equal(prev, c):
			updated = append(updated, merge(prev, c))
		}
	}

	for _, p := range previous {
		if _, found := curByID[id(p)]; !found {
			removed = append(removed, p)
		}
	}

	return missing, updated, removed
}

// MergeSupplierContractDocs merges documents using their IDs. When the previous
// value (e.g. the file path) was set and the current value is empty, the
// previous value is kept.
func MergeSupplierContractDocs(previous, current []SupplierContractDocumentDB) (missing, updated, removed []SupplierContractDocumentDB) {
	return mergeByID(previous, current,
		func(d SupplierContractDocumentDB) string { return d.ID },
		EqualSupplierDocs,
		MergeSupplierDoc,
	)
}

// MergeAccountDocumentsDB merges documents using their IDs. Regarding the
// FilePath: when the previous value was set and the current value is empty, the
// previous value is kept.
func MergeAccountDocumentsDB(previous, current []AccountDocumentDB) (missing, updated, removed []AccountDocumentDB) {
	return mergeByID(previous, current,
		func(d AccountDocumentDB) string { return d.ID },
		EqualAccountDocs,
		MergeAccountDoc,
	)
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

// -----------------------------------------------------------------------------
// Expenses.
// -----------------------------------------------------------------------------

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

// An expense is one line of the building's accounts, or of a "compte travaux".
// It is keyed on Foncia's own id for the line (see ID); every other field may
// change from one sync to the next and is updated in place.
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
// Also, an invoiceID and HashFile may be re-used across multiple items. See
// AccountingKey for an example.
type ExpenseDocumentDB struct {
	// Primary key. Foncia's own id for the expense line, e.g.
	// "6aa37115444a8644bdf6434d": unique per line (an invoice split across two
	// allocations is two lines with two ids), stable across calls, and
	// returned by getBuildingAccountingRGDD and getRepairBudgetDetails.
	//
	// Rows written before Foncia's id was used carry a legacy id instead, a
	// 64-character hash of their contents (see LegacyExpenseID). The sync
	// re-keys such a row to its Foncia id the first time it sees the expense
	// again; a row Foncia no longer returns keeps its legacy id forever.
	ID string

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

func (e ExpenseDocumentDB) Filename() string {
	// "OU CHANNA - CT01037406 - 2024-10-01 - _27.pdf"
	return filepath.Base(e.FilePath)
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

// Expenses can come from two different sources:
//
//	GetBuildingAccountingRGDD: "accounting" (one call per accounting period)
//	GetRepairBudgetDetails:    "repairs"    (one call per "compte travaux")
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

// legacyExpenseKey is the tuple that used to identify an expense before Foncia's
// own id was used, ignoring the hash file. The separator is a NUL byte so that
// it can't appear in any of the fields. Only LegacyExpenseID needs it.
func legacyExpenseKey(e ExpenseDocumentDB) string {
	return strings.Join([]string{
		e.Label,
		formatTime(e.Date),
		fmt.Sprintf("%d", int(e.Amount)),
		e.AccountingKey.Allocation,
		e.AccountingKey.ExpenseType,
	}, "\x00")
}

// LegacyExpenseID is the primary key that expenses had before Foncia's own id
// was used (see ExpenseDocumentDB.ID): a hash of (label, date, amount,
// allocation, expense type, hash file), derived in Go because the API query in
// use at the time had no id. Migration 2 backfilled it on every row, so it is
// still the id of every row that has not been re-keyed since.
//
// It is kept for two reasons: migration 2 must keep deriving exactly the same
// ids forever, and the sync uses it to recognise a row stored under the old
// scheme so that it can give it its Foncia id instead of inserting a copy (see
// RekeyExpense). A row that Foncia no longer returns keeps its legacy id for
// good; the two kinds are easy to tell apart, a legacy id is 64 hex characters
// and a Foncia id 24.
//
// The hash file is part of it because, before Foncia's id was used, two
// otherwise identical expenses could only be told apart by their hash file:
//
//   - piece: {hashFile: 66dafe199f013b45ee991c96}
//     label: ELECO
//     date: "2024-06-30T00:00:00.000Z"
//     amount: {value: 79200}
//   - piece: {hashFile: 66e2b7bd424b4b0f0ab3954b}
//     label: ELECO
//     date: "2024-06-30T00:00:00.000Z"
//     amount: {value: 79200}
//
// A row stored before its hash file showed up has the id derived WITHOUT the
// hash file, so a caller looking for the legacy row of an expense that has a
// hash file must try both, see LegacyExpenseIDs.
func LegacyExpenseID(e ExpenseDocumentDB) string {
	sum := sha256.Sum256([]byte(legacyExpenseKey(e) + "\x00" + string(e.HashFile)))
	return hex.EncodeToString(sum[:])
}

// LegacyExpenseIDs returns the legacy ids under which the given expense may
// have been stored: with its hash file, and, when it has one, without it (the
// row may predate the hash file showing up on the API).
func LegacyExpenseIDs(e ExpenseDocumentDB) []string {
	ids := []string{LegacyExpenseID(e)}
	if e.HashFile != "" {
		withoutHash := e
		withoutHash.HashFile = ""
		ids = append(ids, LegacyExpenseID(withoutHash))
	}
	return ids
}

const expenseColumns = "id, invoice_id, label, amount, date, file_path, hash_file, source, accounting_allocation, accounting_expense_type"

func scanExpense(rows *sql.Rows) (ExpenseDocumentDB, error) {
	var e ExpenseDocumentDB
	var date string
	err := rows.Scan(&e.ID, &e.InvoiceID, &e.Label, &e.Amount, &date, &e.FilePath, &e.HashFile,
		&e.Source, &e.AccountingKey.Allocation, &e.AccountingKey.ExpenseType)
	if err != nil {
		return ExpenseDocumentDB{}, err
	}
	e.Date, err = parseTime("date", date)
	if err != nil {
		return ExpenseDocumentDB{}, err
	}
	return e, nil
}

func GetExpensesDB(ctx context.Context, db *sql.DB) ([]ExpenseDocumentDB, error) {
	return queryAll(ctx, db, "SELECT "+expenseColumns+" FROM expenses", scanExpense)
}

func GetExpensesByHashFileDB(ctx context.Context, db *sql.DB, hashFile string) ([]ExpenseDocumentDB, error) {
	return queryAll(ctx, db, "SELECT "+expenseColumns+" FROM expenses WHERE hash_file = ?", scanExpense, hashFile)
}

func GetExpensesByInvoiceID(ctx context.Context, db *sql.DB, invoiceID string) ([]ExpenseDocumentDB, error) {
	return queryAll(ctx, db, "SELECT "+expenseColumns+" FROM expenses WHERE invoice_id = ?", scanExpense, invoiceID)
}

// Every column but the id can change: Foncia relabels, re-dates and reallocates
// lines after the fact, and a hash file typically shows up a couple of weeks
// after the line. Keying on Foncia's id is what lets those changes update the
// row instead of creating a second one.
const upsertExpense = `INSERT INTO expenses (id, invoice_id, label, amount, date, file_path, hash_file, source, accounting_allocation, accounting_expense_type)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		invoice_id = excluded.invoice_id,
		label = excluded.label,
		amount = excluded.amount,
		date = excluded.date,
		file_path = excluded.file_path,
		hash_file = excluded.hash_file,
		source = excluded.source,
		accounting_allocation = excluded.accounting_allocation,
		accounting_expense_type = excluded.accounting_expense_type;`

// UpsertExpensesWithDB inserts the expenses, and updates in place the ones whose
// id already exists. The id must be set; the sync gets it from Foncia (see
// ExpenseDocumentDB.ID).
func UpsertExpensesWithDB(ctx context.Context, db *sql.DB, expense ...ExpenseDocumentDB) error {
	if len(expense) == 0 {
		return nil
	}

	return inTx(ctx, db, func(tx *sql.Tx) error {
		for _, e := range expense {
			if e.ID == "" {
				return fmt.Errorf("expense %q (%s) has no id", e.Label, formatTime(e.Date))
			}
			_, err := tx.ExecContext(ctx, upsertExpense,
				e.ID, e.InvoiceID, e.Label, int(e.Amount), formatTime(e.Date),
				e.FilePath, e.HashFile, e.Source, e.AccountingKey.Allocation, e.AccountingKey.ExpenseType)
			if err != nil {
				return fmt.Errorf("while upserting expense %q: %w", e.Label, err)
			}
			logutil.Debugf("db: upserted expense %q: %+v", e.Date, e)
		}
		return nil
	})
}

// RekeyExpense changes the primary key of one expense row. It is how a row
// stored under a legacy id (see LegacyExpenseID) gets its Foncia id the first
// time the sync sees that expense with an id, so that the upsert that follows
// updates the row instead of inserting a second copy.
//
// It reports whether a row was actually re-keyed. Nothing happens when no row
// has the old id, or when a row already has the new one (the legacy row is then
// left alone rather than colliding with it).
func RekeyExpense(ctx context.Context, db *sql.DB, oldID, newID string) (bool, error) {
	if oldID == "" || newID == "" {
		return false, fmt.Errorf("re-keying expense %q to %q: both ids must be set", oldID, newID)
	}
	res, err := db.ExecContext(ctx, `UPDATE OR IGNORE expenses SET id = ? WHERE id = ?;`, newID, oldID)
	if err != nil {
		return false, fmt.Errorf("while re-keying expense %s to %s: %w", oldID, newID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// -----------------------------------------------------------------------------
// Account documents.
// -----------------------------------------------------------------------------

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
	case DocumentCategoryConvocation:
		return "Convocation d'assemblée générale"
	case DocumentCategoryMinutesSigned:
		return "Procès-verbal d'assemblée générale"
	case DocumentCategoryGeneralAssembly:
		return "Document d'assemblée générale"
	default:
		return "Inconnu"
	}
}

// IsGeneralAssembly tells whether the document is one of the documents attached
// to a general assembly ("assemblée générale"): the convocation, the signed
// minutes, or one of the annexes (accounts, water meter readings, etc.).
func (e AccountDocumentDB) IsGeneralAssembly() bool {
	switch e.Category {
	case DocumentCategoryConvocation, DocumentCategoryMinutesSigned, DocumentCategoryGeneralAssembly:
		return true
	default:
		return false
	}
}

type DocumentCategory string

const (
	DocumentCategoryUnknown     DocumentCategory = "unknown" // Default.
	DocumentCategoryReportVisit DocumentCategory = "reportVisit"
	DocumentCategoryInvoice     DocumentCategory = "invoice"

	// The three categories below are the ones returned by the API for the
	// documents of a general assembly. They are all fetched at once by passing
	// the "portal category" DocumentCategoryGeneralAssembly to
	// api.GetAccountDocuments; each document then carries the finer-grained
	// category below.
	//
	//  DocumentCategoryConvocation:     "Convocation.AGO.10.12.2025.pdf"
	//  DocumentCategoryMinutesSigned:   "PV.AGO.10.12.2025.pdf"
	//  DocumentCategoryGeneralAssembly: "CC_20210701_Annexe_6-2022.pdf"
	DocumentCategoryGeneralAssembly DocumentCategory = "generalAssembly"
	DocumentCategoryConvocation     DocumentCategory = "convocation"
	DocumentCategoryMinutesSigned   DocumentCategory = "minutesSigned"
)

// GeneralAssemblyCategories are the categories of the documents attached to a
// general assembly.
var GeneralAssemblyCategories = []DocumentCategory{
	DocumentCategoryConvocation,
	DocumentCategoryMinutesSigned,
	DocumentCategoryGeneralAssembly,
}

const accountDocumentColumns = "id, hash_file, file_path, mime_type, category, created_at"

func scanAccountDocument(rows *sql.Rows) (AccountDocumentDB, error) {
	var d AccountDocumentDB
	var createdAt string
	err := rows.Scan(&d.ID, &d.HashFile, &d.FilePath, &d.MimeType, &d.Category, &createdAt)
	if err != nil {
		return AccountDocumentDB{}, err
	}
	d.CreatedAt, err = parseTime("created_at", createdAt)
	if err != nil {
		return AccountDocumentDB{}, err
	}
	return d, nil
}

func GetAccountDocumentByHashFileDB(ctx context.Context, db *sql.DB, hashFile string) (AccountDocumentDB, error) {
	var d AccountDocumentDB
	var createdAt string
	err := db.QueryRowContext(ctx, "SELECT "+accountDocumentColumns+" FROM account_documents WHERE hash_file = ?", hashFile).
		Scan(&d.ID, &d.HashFile, &d.FilePath, &d.MimeType, &d.Category, &createdAt)
	if err != nil {
		return AccountDocumentDB{}, fmt.Errorf("while querying database: %w", err)
	}

	d.CreatedAt, err = parseTime("created_at", createdAt)
	if err != nil {
		return AccountDocumentDB{}, err
	}
	return d, nil
}

func GetAccountDocumentByCategoryDB(ctx context.Context, db *sql.DB, category DocumentCategory) ([]AccountDocumentDB, error) {
	return queryAll(ctx, db,
		"SELECT "+accountDocumentColumns+" FROM account_documents WHERE category = ?",
		scanAccountDocument, category)
}

func GetAccountDocumentsDB(ctx context.Context, db *sql.DB) ([]AccountDocumentDB, error) {
	return queryAll(ctx, db, "SELECT "+accountDocumentColumns+" FROM account_documents", scanAccountDocument)
}

func UpsertAccountDocumentsWithDB(ctx context.Context, db *sql.DB, documents []AccountDocumentDB) error {
	if len(documents) == 0 {
		return nil
	}

	const req = `INSERT INTO account_documents (id, hash_file, file_path, mime_type, category, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			hash_file = excluded.hash_file,
			file_path = excluded.file_path,
			mime_type = excluded.mime_type,
			category = excluded.category,
			created_at = excluded.created_at;`

	return inTx(ctx, db, func(tx *sql.Tx) error {
		for _, d := range documents {
			_, err := tx.ExecContext(ctx, req, d.ID, d.HashFile, d.FilePath, d.MimeType, d.Category, formatTime(d.CreatedAt))
			if err != nil {
				return fmt.Errorf("while upserting account document %q: %w", d.ID, err)
			}
			logutil.Debugf("db: upserted account document %q: %+v", d.ID, d)
		}
		return nil
	})
}

// -----------------------------------------------------------------------------
// Misc.
// -----------------------------------------------------------------------------

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

var missionNumberRE = regexp.MustCompile(`N° ([A-Z0-9]+)`)

// MissionNumber parses the mission number ("Ordre de service" in French) from
// the subject. For example, given the subject:
//
//	"Ordre de service N° OSMIL805898844 – 2NRT POMPE ENVIRONNEMENT - 3 RUE BERTRAN 31200 TOULOUSE"
//
// we want to extract "OSMIL805898844".
func MissionNumber(s string) string {
	m := missionNumberRE.FindStringSubmatch(s)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

// chunks yields successive slices of at most n elements.
func chunks[T any](s []T, n int) func(func([]T) bool) {
	return func(yield func([]T) bool) {
		for i := 0; i < len(s); i += n {
			end := min(i+n, len(s))
			if !yield(s[i:end]) {
				return
			}
		}
	}
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
func fprintfValues(values []any, sep, entrySep string, valuesPerEntry int) string {
	var b strings.Builder
	for i, v := range values {
		if i%valuesPerEntry == 0 {
			b.WriteString(entrySep)
		}
		b.WriteString(fmt.Sprintf("%v%s", v, sep))
	}
	return b.String()
}
