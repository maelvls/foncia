package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/maelvls/foncia/logutil"
)

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
