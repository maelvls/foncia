-- Rebuild every table into its final, strict shape:
--
--   * a `TEXT PRIMARY KEY NOT NULL` id instead of `TEXT UNIQUE` (a UNIQUE
--     column still accepts an unlimited number of NULLs, so it is not a key),
--   * every column NOT NULL, because the Go code scans into plain string/int
--     fields and a NULL would fail Scan,
--   * STRICT, so that a string can never sneak into `amount` and an integer can
--     never sneak into a text column,
--   * the indexes the queries in db.go actually use.
--
-- This is the standard SQLite table rebuild: create under a temporary name,
-- INSERT INTO ... SELECT, drop the old table, rename. It must run with
-- `PRAGMA foreign_keys=OFF` (see migrate.go), otherwise dropping `missions`
-- while `work_orders` still points at it fails.
--
-- COALESCE everywhere: production has no NULL today, but a NULL that shows up
-- in a database that has not been migrated yet must not abort the migration.
-- CAST on `amount` for the same reason: STRICT rejects a text value.
--
-- The Go half of this migration (migrate.go, migration 2) runs *before* this
-- file: it normalises the timestamps in place and fills the `id` column that it
-- adds to the old `expenses` table. The SELECTs below therefore read columns
-- that are already in their final form.

-- Suppliers first: nothing references anything yet.
CREATE TABLE suppliers_new (
    id       TEXT PRIMARY KEY NOT NULL,
    name     TEXT NOT NULL, -- "2NRT-POMPES ENVIRONNEMENT"
    activity TEXT NOT NULL  -- "PLOM", "ADBE", "ISOL"
) STRICT;

INSERT OR IGNORE INTO suppliers_new (id, name, activity)
SELECT COALESCE(id, ''), COALESCE(name, ''), COALESCE(activity, '')
FROM suppliers;

DROP TABLE suppliers;
ALTER TABLE suppliers_new RENAME TO suppliers;

-- Missions.
CREATE TABLE missions_new (
    id          TEXT PRIMARY KEY NOT NULL, -- "64850e8019d5d64c415d13dd"
    number      TEXT NOT NULL,             -- Foncia's ID for the intervention
    kind        TEXT NOT NULL,             -- "Incident" | "Repair"
    label       TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  TEXT NOT NULL,             -- time.RFC3339Nano, UTC
    description TEXT NOT NULL
) STRICT;

INSERT OR IGNORE INTO missions_new (id, number, kind, label, status, started_at, description)
SELECT COALESCE(id, ''), COALESCE(number, ''), COALESCE(kind, ''), COALESCE(label, ''),
       COALESCE(status, ''), COALESCE(started_at, ''), COALESCE(description, '')
FROM missions;

-- `idx_entries_started_at` is the old, misleading name; it is dropped with the
-- table anyway, but an explicit DROP keeps the intent visible.
DROP INDEX IF EXISTS idx_entries_started_at;
DROP TABLE missions;
ALTER TABLE missions_new RENAME TO missions;

CREATE INDEX idx_missions_started_at ON missions (started_at);

-- Work orders. The foreign key on mission_id has zero orphans in production, so
-- it is kept.
CREATE TABLE work_orders_new (
    id                TEXT PRIMARY KEY NOT NULL,
    mission_id        TEXT NOT NULL,
    number            TEXT NOT NULL,
    label             TEXT NOT NULL,
    repair_date_start TEXT NOT NULL, -- time.RFC3339Nano, UTC
    repair_date_end   TEXT NOT NULL, -- time.RFC3339Nano, UTC
    supplier_id       TEXT NOT NULL,
    supplier_name     TEXT NOT NULL,
    supplier_activity TEXT NOT NULL,
    FOREIGN KEY (mission_id) REFERENCES missions (id)
) STRICT;

INSERT OR IGNORE INTO work_orders_new (id, mission_id, number, label, repair_date_start,
                                       repair_date_end, supplier_id, supplier_name, supplier_activity)
SELECT COALESCE(id, ''), COALESCE(mission_id, ''), COALESCE(number, ''), COALESCE(label, ''),
       COALESCE(repair_date_start, ''), COALESCE(repair_date_end, ''), COALESCE(supplier_id, ''),
       COALESCE(supplier_name, ''), COALESCE(supplier_activity, '')
FROM work_orders;

DROP TABLE work_orders;
ALTER TABLE work_orders_new RENAME TO work_orders;

CREATE INDEX idx_work_orders_mission_id ON work_orders (mission_id);
CREATE INDEX idx_work_orders_supplier_id ON work_orders (supplier_id);

-- Contract documents. No FOREIGN KEY on supplier_id: every single one of the 25
-- rows in production is an orphan. The supplier ids are legitimate Foncia ids,
-- they are simply not among the suppliers the API still returns. Declaring the
-- constraint would mean either losing those rows or failing the migration, and
-- these documents are the only remaining record of those contracts.
CREATE TABLE contract_documents_new (
    id          TEXT PRIMARY KEY NOT NULL,
    supplier_id TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    hash_file   TEXT NOT NULL
) STRICT;

INSERT OR IGNORE INTO contract_documents_new (id, supplier_id, file_path, hash_file)
SELECT COALESCE(id, ''), COALESCE(supplier_id, ''), COALESCE(file_path, ''), COALESCE(hash_file, '')
FROM contract_documents;

DROP TABLE contract_documents;
ALTER TABLE contract_documents_new RENAME TO contract_documents;

CREATE INDEX idx_contract_documents_supplier_id ON contract_documents (supplier_id);
CREATE INDEX idx_contract_documents_hash_file ON contract_documents (hash_file);

-- Account documents.
CREATE TABLE account_documents_new (
    id         TEXT PRIMARY KEY NOT NULL,
    hash_file  TEXT NOT NULL,
    file_path  TEXT NOT NULL,
    mime_type  TEXT NOT NULL,
    category   TEXT NOT NULL,
    created_at TEXT NOT NULL -- time.RFC3339Nano, UTC
) STRICT;

INSERT OR IGNORE INTO account_documents_new (id, hash_file, file_path, mime_type, category, created_at)
SELECT COALESCE(id, ''), COALESCE(hash_file, ''), COALESCE(file_path, ''),
       COALESCE(mime_type, ''), COALESCE(category, ''), COALESCE(created_at, '')
FROM account_documents;

DROP TABLE account_documents;
ALTER TABLE account_documents_new RENAME TO account_documents;

CREATE INDEX idx_account_documents_hash_file ON account_documents (hash_file);
CREATE INDEX idx_account_documents_category ON account_documents (category);

-- Expenses. Foncia's API does not return an ID for the expenses returned by
-- getBuildingAccountingCurrent, so `id` is derived in Go from the identifying
-- tuple (label, date, amount, allocation, expense type, hash file). See
-- expenseID in db.go; the Go half of this migration has already written it into
-- the old table.
--
-- INSERT OR IGNORE, not INSERT: two rows deriving the same id would otherwise
-- abort the whole migration. The first one wins and the Go half logs the
-- collision.
CREATE TABLE expenses_new (
    id                      TEXT PRIMARY KEY NOT NULL,
    invoice_id              TEXT NOT NULL,    -- "" when no invoice file
    label                   TEXT NOT NULL,
    amount                  INTEGER NOT NULL, -- cents; negative = credit
    date                    TEXT NOT NULL,    -- time.RFC3339Nano, UTC
    file_path               TEXT NOT NULL,    -- "" when not downloaded yet
    hash_file               TEXT NOT NULL,    -- "" when no invoice file
    source                  TEXT NOT NULL,    -- "unknown" | "accounting" | "repairs"
    accounting_allocation   TEXT NOT NULL,
    accounting_expense_type TEXT NOT NULL
) STRICT;

INSERT OR IGNORE INTO expenses_new (id, invoice_id, label, amount, date, file_path,
                                    hash_file, source, accounting_allocation, accounting_expense_type)
SELECT COALESCE(id, ''), COALESCE(invoice_id, ''), COALESCE(label, ''),
       CAST(COALESCE(amount, 0) AS INTEGER), COALESCE(date, ''), COALESCE(file_path, ''),
       COALESCE(hash_file, ''), COALESCE(source, ''), COALESCE(accounting_allocation, ''),
       COALESCE(accounting_expense_type, '')
FROM expenses;

DROP TABLE expenses;
ALTER TABLE expenses_new RENAME TO expenses;

CREATE INDEX idx_expenses_hash_file ON expenses (hash_file);
CREATE INDEX idx_expenses_invoice_id ON expenses (invoice_id);
