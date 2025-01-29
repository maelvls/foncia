package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/google/go-cmp/cmp"
	"github.com/maelvls/foncia/api"
	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

// Returns the new items.
func syncLiveMissionsWithDB(ctx context.Context, client *http.Client, sqlDB *sql.DB, uuid string) ([]db.MissionDB, error) {
	missions, _, err := api.GetMissionsAPI(client, uuid, "")
	if err != nil {
		return nil, fmt.Errorf("while getting interventions: %v", err)
	}

	missionsInDB, err := db.GetMissionsDB(ctx, sqlDB)
	if err != nil {
		return nil, fmt.Errorf("while getting existing missions: %v", err)
	}
	existsInDB := make(map[string]struct{})
	for _, item := range missionsInDB {
		existsInDB[item.ID] = struct{}{}
	}
	var newMissions []db.MissionDB
	for _, m := range missions {
		_, already := existsInDB[m.ID]
		if already {
			continue
		}
		newMissions = append(newMissions, MissionAPIToDB(m))
		logutil.Debugf("found new mission: %+v", m)
	}

	// Since HTTP request per new mission is made, and there may be 200-300
	// missions, let's do them in batches of 20 so that we can save to DB in
	// regularly so we don't lose all the work if the program crashes (takes a
	// lot of time partly because Synology's disk is slow, partly because there
	// are 200-300 HTTP calls to be made).
	batchSize := 1
	i := 0
	err = DoInBatches(batchSize, newMissions, func(batchMissions []db.MissionDB) error {
		i++
		logutil.Debugf("batch %d", i)

		var batchWorkOrders []db.WorkOrderDB

		// Let's update each mission with its work orders.
		for i, mission := range batchMissions {
			orders, err := api.GetWorkOrdersAPI(client, uuid, mission.ID)
			if err != nil {
				return fmt.Errorf("while getting work orders from API: %v", err)
			}

			var missionWorkOrders []db.WorkOrderDB
			for _, wo := range orders {
				missionWorkOrders = append(missionWorkOrders, WorkOrderAPIToDB(wo, mission.ID))
			}
			batchMissions[i].WorkOrders = missionWorkOrders

			batchWorkOrders = append(batchWorkOrders, missionWorkOrders...)
		}

		logutil.Debugf("saving work orders for %d missions to DB", len(batchMissions))
		err = db.SaveWorkOrdersToDB(ctx, sqlDB, batchWorkOrders)
		if err != nil {
			return fmt.Errorf("while saving work orders: %v", err)
		}

		logutil.Debugf("saving %d missions to DB", batchMissions)

		err = db.SaveMissionsToDB(ctx, sqlDB, batchMissions...)
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
func syncExpensesWithDB(ctx context.Context, client *http.Client, sqlDB *sql.DB, uuid, invoicesDir string) ([]db.ExpenseDocumentDB, error) {
	// Unauthenticated client just used for downloading files from AWS.
	downloadClient := &http.Client{}
	api.EnableDebugCurlLogs(downloadClient)

	// Create dir if missing.
	err := os.MkdirAll(invoicesDir, 0755)
	if err != nil {
		return nil, fmt.Errorf("while creating directory: %v", err)
	}

	// For now, the fetched expenses won't contain the FilePath field. It will
	// be set later on.
	var expensesLive []db.ExpenseDocumentDB
	expensesFromAPI, err := api.GetExpensesCurrentAPI(client, uuid)
	if err != nil {
		return nil, fmt.Errorf("while getting expenses: %v", err)
	}
	for _, e := range expensesFromAPI {
		expensesLive = append(expensesLive, ExpenseDocumentAPIToDB(e))
	}
	periods, err := api.GetAccountingPeriodsLive(client, uuid)
	if err != nil {
		return nil, fmt.Errorf("while getting accounting periods: %v", err)
	}
	for _, period := range periods {
		cur, err := api.GetBuildingAccountingRGDDLive(client, uuid, period.ID)
		if err != nil {
			return nil, fmt.Errorf("while getting building accounting RGDD: %v", err)
		}
		for _, e := range cur {
			expensesLive = append(expensesLive, ExpenseDocumentAPIToDB(e))
		}
	}

	expensesInDB, err := db.GetExpensesDB(ctx, sqlDB)
	if err != nil {
		return nil, fmt.Errorf("while getting existing expenses: %v", err)
	}

	mapExpensesInDB := make(map[db.ExpenseDocumentID]db.ExpenseDocumentDB) // expense.ID() -> expense
	for _, item := range expensesInDB {
		mapExpensesInDB[item.ID()] = item
	}

	var newExpensesDB []db.ExpenseDocumentDB
	// Save the invoice PDFs to disk. By "live", I mean that it's the expenses
	// that were fetched from the API.
	err = DoInBatches(1, expensesLive, func(liveExpenses []db.ExpenseDocumentDB) error {
		for i, e := range liveExpenses {
			// I noticed that certain expenses have an invoiceID but no PDF
			// document attached, and that appears to be the case when the
			// hashFile is empty. So I skip downloading when there is no
			// invoiceID or when the hashFile is empty.
			if e.InvoiceID == "" || e.HashFile == "" {
				continue
			}

			// No need to download if it is already present on disk.
			eDB, found := mapExpensesInDB[e.ID()]
			if found && fileExists(eDB.FilePath) {
				continue
			}
			if !found {
				logutil.Debugf("expense %s not found in DB", e.ID())
			}
			if found && !fileExists(eDB.FilePath) {
				logutil.Debugf("file %q not found, downloading invoice %q", eDB.FilePath, e.InvoiceID)
			}

			// I found that the graphql query 'getInvoiceURL' returns an empty
			// URL if the invoiceID exists but the hashFile is empty.
			if e.HashFile == "" {
				logutil.Infof("no hash file found for expense %s, skipping download", e.ID())
				continue
			}

			filename, invoiceURL, err := api.GetInvoiceURL(client, e.InvoiceID)
			if err != nil {
				return fmt.Errorf("while getting invoice URL: %v", err)
			}
			if invoiceURL == "" {
				logutil.Infof("no invoice URL found for invoice ID %q, skipping download. Expense: %+v", e.InvoiceID, e)
				continue
			}
			filePath := path.Join(invoicesDir, filename)
			if fileExists(filePath) {
				continue
			}

			err = api.Download(downloadClient, invoiceURL, filePath)
			if err != nil {
				return fmt.Errorf("while downloading invoice for expense %s: %v", invoiceURL, err)
			}

			liveExpenses[i].FilePath = filePath
		}

		var newExpenses, changedExpences []db.ExpenseDocumentDB
		for _, expLive := range liveExpenses {
			expDB, found := mapExpensesInDB[expLive.ID()]
			if !found {
				logutil.Debugf("found new expense %s (%s)", expLive.Label, expLive.Date)
				newExpenses = append(newExpenses, expLive)
				continue
			}

			// Many expenses don't have an invoice PDF attached for a couple of
			// weeks. That's why we want to update the invoice_id if we found
			// that it changed. Note that some fields are unique to the database
			// Expense (Filename, FilePath), that's why we don't compare them.
			// The date and label are used as keys, so they are not compared.
			//
			// Note that the FilePath is the only value that can be updated,
			// since it is the only value that does not participate to the ID()
			// func.
			if !expDB.Equal(expLive) {
				diff := cmp.Diff(expDB, expLive)
				logutil.Debugf("found changed expense %q: %s, diff: %s", expLive.Date, expLive.Label, diff)
				changedExpences = append(changedExpences, expLive)
			}
		}

		newExpensesDB = append(newExpensesDB, newExpenses...)

		newOrChanged := append(newExpenses, changedExpences...)
		err = db.UpsertExpensesWithDB(ctx, sqlDB, newOrChanged...)
		if err != nil {
			return fmt.Errorf("while saving expenses: %v", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return newExpensesDB, nil
}

func syncSuppliersWithDB(ctx context.Context, client *http.Client, sqlDB *sql.DB, uuid, invoicesDir string) error {
	// Unauthenticated client just used for downloading files from AWS.
	downloadClient := &http.Client{}
	api.EnableDebugCurlLogs(downloadClient)

	supplierContractsLive, err := api.GetCouncilMissionSuppliersAPI(client, uuid)
	if err != nil {
		return fmt.Errorf("while getting suppliers: %v", err)
	}

	var suppliersLive []db.SupplierDB
	for _, c := range supplierContractsLive {
		suppliersLive = append(suppliersLive, SupplierAPIToDB(c.Supplier))
	}
	err = db.UpsertSuppliersToDB(ctx, sqlDB, suppliersLive)
	if err != nil {
		return fmt.Errorf("while saving suppliers: %v", err)
	}

	// Now, the contract documents. For now, the FilePath value isn't checked,
	// we will do that at a later stage.
	var docsLive []db.SupplierContractDocumentDB
	for _, d := range supplierContractsLive {
		docsLive = append(docsLive, SupplierContractAPIToDB(d)...)
	}

	// Let's keep all documents in DB, just in case Foncia decides to remove
	// some documents from the API.
	docsInDB, err := db.GetSupplierContractDocsDB(ctx, sqlDB)
	if err != nil {
		return fmt.Errorf("while getting existing documents: %v", err)
	}
	docsToBeAdded, docsToBeUpdated, _ := db.MergeSupplierContractDocsDB(docsInDB, docsLive)

	// Since we use upsert, let's combine the two slices.
	docs := append(docsToBeAdded, docsToBeUpdated...)

	// Let's set the FilePath for each document.
	for i, doc := range docs {
		// No need to download if it is already present on disk.
		if fileExists(doc.FilePath) {
			continue
		}

		// I found that the graphql query 'getDocumentURL' returns an empty URL
		// if the hashFile is empty.
		if doc.HashFile == "" {
			logutil.Infof("no hash file found for document %s, skipping download", doc.ID)
			continue
		}

		filename, fileURL, err := api.GetDocumentURL(client, string(doc.HashFile))
		if err != nil {
			return fmt.Errorf("while getting document URL: %v", err)
		}

		filePath := path.Join(invoicesDir, filename)
		docs[i].FilePath = filePath
		if fileExists(filePath) {
			continue
		}

		err = api.Download(downloadClient, fileURL, filePath)
		if err != nil {
			return fmt.Errorf("while downloading document: %v", err)
		}
	}

	err = db.UpsertDocumentsWithDB(ctx, sqlDB, docs)
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
