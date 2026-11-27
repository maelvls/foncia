-- The journal of what changed in the mirror of Foncia, for whoever follows it
-- (GET /api/v1/changements): one row per mission, work order, expense, account
-- document or contract document that appeared or changed, numbered in the
-- order it happened. A reader keeps the last number it has seen, its cursor,
-- and asks for what came after it; a reader that was down for a night gets
-- the night back.
--
-- The rows are written by triggers, not by the sync: every way a row is
-- written (the sync, the downloads on the first click, a migration) lands
-- here, and the sync's code doesn't change. The upserts of the sync run every
-- 10 minutes on rows that most of the time haven't changed, so the UPDATE
-- triggers only write when a column did change.
--
-- What is already there goes in first, oldest first, as "existant": a reader
-- that starts from 0 replays the whole history.

CREATE TABLE changements (
    seq    INTEGER PRIMARY KEY AUTOINCREMENT,
    at     TEXT NOT NULL, -- time.RFC3339Nano, UTC; for "existant", the date of the thing itself
    kind   TEXT NOT NULL, -- "mission" | "work_order" | "expense" | "account_document" | "contract_document"
    ref    TEXT NOT NULL, -- the id of the row in its table
    action TEXT NOT NULL  -- "existant" | "nouveau" | "modifie"
) STRICT;

CREATE INDEX idx_changements_kind_ref ON changements (kind, ref);

-- What is already there.
INSERT INTO changements (at, kind, ref, action)
SELECT at, kind, ref, 'existant' FROM (
    SELECT started_at AS at, 'mission' AS kind, id AS ref FROM missions
    UNION ALL
    SELECT repair_date_start, 'work_order', id FROM work_orders
    UNION ALL
    SELECT date, 'expense', id FROM expenses
    UNION ALL
    SELECT created_at, 'account_document', id FROM account_documents
    UNION ALL
    -- A contract has no date: "at" is empty, and they come first.
    SELECT '', 'contract_document', id FROM contract_documents
)
ORDER BY at, kind, ref;

-- strftime('%Y-%m-%dT%H:%M:%fZ') is RFC 3339 with milliseconds, which
-- time.RFC3339Nano parses.

CREATE TRIGGER changements_missions_insert AFTER INSERT ON missions BEGIN
    INSERT INTO changements (at, kind, ref, action) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ'), 'mission', NEW.id, 'nouveau');
END;
CREATE TRIGGER changements_missions_update AFTER UPDATE ON missions
WHEN (OLD.id, OLD.number, OLD.kind, OLD.label, OLD.status, OLD.started_at, OLD.description)
     IS NOT (NEW.id, NEW.number, NEW.kind, NEW.label, NEW.status, NEW.started_at, NEW.description)
BEGIN
    INSERT INTO changements (at, kind, ref, action) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ'), 'mission', NEW.id, 'modifie');
END;

CREATE TRIGGER changements_work_orders_insert AFTER INSERT ON work_orders BEGIN
    INSERT INTO changements (at, kind, ref, action) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ'), 'work_order', NEW.id, 'nouveau');
END;
CREATE TRIGGER changements_work_orders_update AFTER UPDATE ON work_orders
WHEN (OLD.id, OLD.mission_id, OLD.number, OLD.label, OLD.repair_date_start, OLD.repair_date_end, OLD.supplier_id, OLD.supplier_name, OLD.supplier_activity)
     IS NOT (NEW.id, NEW.mission_id, NEW.number, NEW.label, NEW.repair_date_start, NEW.repair_date_end, NEW.supplier_id, NEW.supplier_name, NEW.supplier_activity)
BEGIN
    INSERT INTO changements (at, kind, ref, action) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ'), 'work_order', NEW.id, 'modifie');
END;

-- An expense whose PDF has just been downloaded changes its file_path: that
-- is a "modifie", and the reader can now fetch the PDF.
CREATE TRIGGER changements_expenses_insert AFTER INSERT ON expenses BEGIN
    INSERT INTO changements (at, kind, ref, action) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ'), 'expense', NEW.id, 'nouveau');
END;
CREATE TRIGGER changements_expenses_update AFTER UPDATE ON expenses
WHEN (OLD.id, OLD.invoice_id, OLD.label, OLD.amount, OLD.date, OLD.file_path, OLD.hash_file, OLD.source, OLD.accounting_allocation, OLD.accounting_expense_type)
     IS NOT (NEW.id, NEW.invoice_id, NEW.label, NEW.amount, NEW.date, NEW.file_path, NEW.hash_file, NEW.source, NEW.accounting_allocation, NEW.accounting_expense_type)
BEGIN
    INSERT INTO changements (at, kind, ref, action) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ'), 'expense', NEW.id, 'modifie');
END;

CREATE TRIGGER changements_account_documents_insert AFTER INSERT ON account_documents BEGIN
    INSERT INTO changements (at, kind, ref, action) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ'), 'account_document', NEW.id, 'nouveau');
END;
CREATE TRIGGER changements_account_documents_update AFTER UPDATE ON account_documents
WHEN (OLD.id, OLD.hash_file, OLD.file_path, OLD.mime_type, OLD.category, OLD.created_at)
     IS NOT (NEW.id, NEW.hash_file, NEW.file_path, NEW.mime_type, NEW.category, NEW.created_at)
BEGIN
    INSERT INTO changements (at, kind, ref, action) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ'), 'account_document', NEW.id, 'modifie');
END;

CREATE TRIGGER changements_contract_documents_insert AFTER INSERT ON contract_documents BEGIN
    INSERT INTO changements (at, kind, ref, action) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ'), 'contract_document', NEW.id, 'nouveau');
END;
CREATE TRIGGER changements_contract_documents_update AFTER UPDATE ON contract_documents
WHEN (OLD.id, OLD.supplier_id, OLD.file_path, OLD.hash_file)
     IS NOT (NEW.id, NEW.supplier_id, NEW.file_path, NEW.hash_file)
BEGIN
    INSERT INTO changements (at, kind, ref, action) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ'), 'contract_document', NEW.id, 'modifie');
END;
