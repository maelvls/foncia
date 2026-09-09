-- Schema for the SQLite database. It is embedded in the binary (see open.go)
-- and executed every time the database is opened.
--
-- Backward compatibility is not a concern: the database is a cache of Foncia's
-- API and can be deleted and re-synced from scratch at any time. That is why
-- there is no migration machinery here; just CREATE TABLE IF NOT EXISTS.
--
-- Conventions:
--   * every table has a PRIMARY KEY,
--   * every column is NOT NULL (the Go code scans into plain strings/ints, so a
--     NULL would break Scan),
--   * every time is stored as UTC text in the time.RFC3339Nano layout, which
--     sorts chronologically as text.

CREATE TABLE IF NOT EXISTS missions (
    id          TEXT PRIMARY KEY NOT NULL, -- "64850e8019d5d64c415d13dd"
    number      TEXT NOT NULL,             -- Foncia's ID for the intervention
    kind        TEXT NOT NULL,             -- "Incident" | "Repair"
    label       TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  TEXT NOT NULL,             -- time.RFC3339Nano, UTC
    description TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_missions_started_at ON missions (started_at);

CREATE TABLE IF NOT EXISTS suppliers (
    id       TEXT PRIMARY KEY NOT NULL,
    name     TEXT NOT NULL, -- "2NRT-POMPES ENVIRONNEMENT"
    activity TEXT NOT NULL  -- "PLOM", "ADBE", "ISOL"
) STRICT;

CREATE TABLE IF NOT EXISTS work_orders (
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

CREATE INDEX IF NOT EXISTS idx_work_orders_mission_id ON work_orders (mission_id);
CREATE INDEX IF NOT EXISTS idx_work_orders_supplier_id ON work_orders (supplier_id);

-- Foncia's API does not return an ID for the expenses returned by
-- getBuildingAccountingCurrent, so `id` is derived in Go from the identifying
-- tuple (label, date, amount, allocation, expense type, hash file). See
-- expenseID in db.go.
CREATE TABLE IF NOT EXISTS expenses (
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

CREATE INDEX IF NOT EXISTS idx_expenses_hash_file ON expenses (hash_file);
CREATE INDEX IF NOT EXISTS idx_expenses_invoice_id ON expenses (invoice_id);

CREATE TABLE IF NOT EXISTS contract_documents (
    id          TEXT PRIMARY KEY NOT NULL,
    supplier_id TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    hash_file   TEXT NOT NULL,
    FOREIGN KEY (supplier_id) REFERENCES suppliers (id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_contract_documents_supplier_id ON contract_documents (supplier_id);
CREATE INDEX IF NOT EXISTS idx_contract_documents_hash_file ON contract_documents (hash_file);

CREATE TABLE IF NOT EXISTS account_documents (
    id         TEXT PRIMARY KEY NOT NULL,
    hash_file  TEXT NOT NULL,
    file_path  TEXT NOT NULL,
    mime_type  TEXT NOT NULL,
    category   TEXT NOT NULL,
    created_at TEXT NOT NULL -- time.RFC3339Nano, UTC
) STRICT;

CREATE INDEX IF NOT EXISTS idx_account_documents_hash_file ON account_documents (hash_file);
CREATE INDEX IF NOT EXISTS idx_account_documents_category ON account_documents (category);
