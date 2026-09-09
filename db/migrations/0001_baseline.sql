-- Baseline: the schema as it was before any migration machinery existed.
--
-- This migration exists so that a database created by an older version of this
-- program (which had no `user_version` and applied `db/schema.sql` with CREATE
-- TABLE IF NOT EXISTS on every open) and a brand new empty database both end up
-- in the same known state before migration 0002 transforms them.
--
-- On an existing database every statement below is a no-op; on a fresh one it
-- creates the old shape, which 0002 immediately rebuilds. That is deliberate:
-- migrations are replayed from 0001 on every database, so the sequence has to
-- start from the historical shape, not from today's.
--
-- Do not "fix" anything here: nullable columns, the `idx_entries_started_at`
-- misnomer and the missing `expenses.id` are all faithful reproductions of what
-- production actually contains.

CREATE TABLE IF NOT EXISTS missions (
    id          TEXT UNIQUE,
    number      TEXT,
    kind        TEXT,
    label       TEXT,
    status      TEXT,
    started_at  TEXT,
    description TEXT
);

CREATE INDEX IF NOT EXISTS idx_entries_started_at ON missions (started_at);

CREATE TABLE IF NOT EXISTS suppliers (
    id       TEXT UNIQUE,
    name     TEXT,
    activity TEXT
);

CREATE TABLE IF NOT EXISTS work_orders (
    id                TEXT UNIQUE,
    mission_id        TEXT NOT NULL,
    number            TEXT,
    label             TEXT,
    repair_date_start TEXT,
    repair_date_end   TEXT,
    supplier_id       TEXT,
    supplier_name     TEXT,
    supplier_activity TEXT,
    FOREIGN KEY (mission_id) REFERENCES missions (id)
);

CREATE TABLE IF NOT EXISTS contract_documents (
    id          TEXT UNIQUE,
    supplier_id TEXT NOT NULL,
    file_path   TEXT,
    hash_file   TEXT,
    FOREIGN KEY (supplier_id) REFERENCES suppliers (id)
);

CREATE TABLE IF NOT EXISTS account_documents (
    id         TEXT UNIQUE,
    file_path  TEXT,
    hash_file  TEXT,
    category   TEXT NOT NULL DEFAULT 'unknown',
    mime_type  TEXT NOT NULL DEFAULT 'application/pdf',
    created_at TEXT NOT NULL DEFAULT '0001-01-01 00:00:00 +0000 UTC'
);

CREATE TABLE IF NOT EXISTS expenses (
    invoice_id              TEXT,
    label                   TEXT,
    amount                  INT,
    date                    TEXT,
    file_path               TEXT,
    hash_file               TEXT,
    source                  TEXT,
    accounting_allocation   TEXT,
    accounting_expense_type TEXT
);
