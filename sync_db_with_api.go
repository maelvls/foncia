package main

import (
	"context"
	"database/sql"
	"errors"
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
func syncLiveMissionsWithDB(ctx context.Context, client *http.Client, sqlDB *sql.DB, graphqlURL, uuid string) ([]db.MissionDB, error) {
	missions, _, err := api.GetMissionsAPI(client, graphqlURL, uuid, "")
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
		var batchWorkOrders []db.WorkOrderDB

		// Let's update each mission with its work orders.
		for i, mission := range batchMissions {
			orders, err := api.GetWorkOrdersAPI(client, graphqlURL, uuid, mission.ID)
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
func syncExpensesWithDB(ctx context.Context, client *http.Client, sqlDB *sql.DB, graphqlURL, uuid, invoicesDir string) ([]db.ExpenseDocumentDB, error) {
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
	expensesFromAPI, err := api.GetBuildingAccountingCurrent(client, graphqlURL, uuid)
	if err != nil {
		return nil, fmt.Errorf("while getting expenses: %v", err)
	}
	for _, e := range expensesFromAPI {
		expensesLive = append(expensesLive, ExpenseDocumentAPIToDB(e, db.SourceAccounting))
	}
	periods, err := api.GetAccountingPeriodsLive(client, graphqlURL, uuid)
	if err != nil {
		return nil, fmt.Errorf("while getting accounting periods: %v", err)
	}
	for _, period := range periods {
		cur, err := api.GetBuildingAccountingRGDDLive(client, graphqlURL, uuid, period.ID)
		if err != nil {
			return nil, fmt.Errorf("while getting building accounting RGDD: %v", err)
		}
		for _, e := range cur {
			expensesLive = append(expensesLive, ExpenseDocumentAPIToDB(e, db.SourceAccounting))
		}
	}

	ids, err := api.GetRepairBudgets(client, graphqlURL, uuid)
	if err != nil {
		return nil, fmt.Errorf("while getting repair IDs: %v", err)
	}
	for _, id := range ids {
		got, err := api.GetRepairBudgetDetailsAPI(client, graphqlURL, uuid, id)
		if err != nil {
			return nil, fmt.Errorf("while getting repair budget details: %v", err)
		}
		for _, e := range got {
			expensesLive = append(expensesLive, ExpenseDocumentAPIToDB(e, db.SourceRepairs))
		}
	}

	expensesInDB, err := db.GetExpensesDB(ctx, sqlDB)
	if err != nil {
		return nil, fmt.Errorf("while getting existing expenses: %v", err)
	}
	expensesInDBIndex := db.NewExpenseDocumentsIndex(expensesInDB)

	var newExpensesDB []db.ExpenseDocumentDB
	// Save the invoice PDFs to disk. By "live", I mean that it's the expenses
	// that were fetched from the API.
	err = DoInBatches(1, expensesLive, func(liveExpenses []db.ExpenseDocumentDB) error {
		for i := range liveExpenses {
			e := &liveExpenses[i]

			if eDB, found := expensesInDBIndex.Match(*e); found {
				*e = db.Merge(eDB, *e)
			}

			// The PDF URL can either be fetched using the InvoiceID or the
			// HashFile.
			if e.HashFile == "" && e.InvoiceID == "" {
				continue
			}

			if fileExists(e.FilePath) {
				continue
			} else if e.FilePath != "" {
				logutil.Debugf("file needs to be downloaded for '%s' (%s, %d)", e.FilePath, e.Label, e.Date, e.Amount)
			}

			// First try using the HashFile, then the InvoiceID.
			var fileURL, filename string
			if e.HashFile != "" {
				filename, fileURL, err = api.GetDocumentURL(client, graphqlURL, e.HashFile)
				switch {
				case errors.Is(err, api.ErrEmptyURL):
					logutil.Debugf("no document URL found for hash file '%s', skipping download. Expense: %+v", e.HashFile, e)
					continue
				case err != nil:
					return fmt.Errorf("while getting document URL from hash file %s: %w", e.HashFile, err)
				}
			} else if e.InvoiceID != "" {
				// I found that the graphql query 'getInvoiceURL' returns an empty
				// URL if the invoiceID exists but the hashFile is empty.
				filename, fileURL, err = api.GetInvoiceURL(client, graphqlURL, e.InvoiceID)
				switch {
				case errors.Is(err, api.ErrEmptyURL):
					logutil.Debugf("no invoice URL found for invoice ID '%s', skipping download. Expense: %+v", e.InvoiceID, e)
					continue
				case err != nil:
					return fmt.Errorf("while getting invoice URL from invoice ID %v: %w", e.InvoiceID, err)
				}
			} else {
				panic("programmer mistake: either HashFile or InvoiceID should be set")
			}
			e.FilePath = path.Join(invoicesDir, filename)

			if fileExists(e.FilePath) {
				logutil.Debugf("file %q already exists, skipping download", e.FilePath)
				continue
			}

			err = api.Download(downloadClient, fileURL, e.FilePath)
			if err != nil {
				return fmt.Errorf("while downloading invoice for expense %s: %v", fileURL, err)
			}
		}

		var newExpenses, changedExpences []db.ExpenseDocumentDB
		for _, expLive := range liveExpenses {
			expDB, found := expensesInDBIndex.Match(expLive)
			if !found {
				logutil.Debugf("found new expense %s (%s)", expLive.Label, expLive.Date)
				newExpenses = append(newExpenses, expLive)
				continue
			}

			// Many expenses don't have a PDF attached (= no HashFile) for a
			// couple of weeks. That's why we want to update the HashFile if we
			// found that it has changed.
			//
			// Due to a change in date formats in DB (from RFC3339 to
			// RFC3339Nano), the date may also change as long as the HashFile is
			// present.
			//
			// The Invoice ID may also change if it is set on the live API.
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

func syncSuppliersWithDB(ctx context.Context, client *http.Client, sqlDB *sql.DB, graphqlURL, uuid, invoicesDir string) error {
	// Unauthenticated client just used for downloading files from AWS.
	downloadClient := &http.Client{}
	api.EnableDebugCurlLogs(downloadClient)

	supplierContractsLive, err := api.GetCouncilMissionSuppliersAPI(client, graphqlURL, uuid)
	if err != nil {
		return fmt.Errorf("while getting suppliers: %v", err)
	}

	suppliersLive := ExtractSuppliersFromContracts(supplierContractsLive)

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
	mapDocsInDB := make(map[string]db.SupplierContractDocumentDB)
	for i := range docsInDB {
		mapDocsInDB[docsInDB[i].ID] = docsInDB[i]
	}

	// Let's set the FilePath for each document.
	for i := range docsLive {
		doc := &docsLive[i]

		docDB, found := mapDocsInDB[doc.ID]
		if found {
			*doc = db.MergeSupplierDoc(docDB, *doc)
		}

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

		filename, fileURL, err := api.GetDocumentURL(client, graphqlURL, doc.HashFile)
		if err != nil {
			return fmt.Errorf("while getting document URL: %v", err)
		}
		doc.FilePath = path.Join(invoicesDir, filename)

		if fileExists(doc.FilePath) {
			continue
		}

		err = api.Download(downloadClient, fileURL, doc.FilePath)
		if err != nil {
			return fmt.Errorf("while downloading document: %v", err)
		}
	}

	docsToBeAdded, docsToBeUpdated, deleted := db.MergeSupplierContractDocs(docsInDB, docsLive)
	if len(deleted) > 0 {
		logutil.Errorf("found that %d supplier documents were deleted from the API, not deleting them", len(deleted))
	}

	// Since we use upsert, let's combine the two slices.
	docs := append(docsToBeAdded, docsToBeUpdated...)

	err = db.UpsertContractDocumentsWithDB(ctx, sqlDB, docs)
	if err != nil {
		return fmt.Errorf("while saving documents: %v", err)
	}

	return nil
}

func syncAccountDocumentsWithDB(ctx context.Context, client *http.Client, sqlDB *sql.DB, graphqlURL, uuid, invoicesDir string) error {
	// Unauthenticated client just used for downloading files from AWS.
	downloadClient := &http.Client{}
	api.EnableDebugCurlLogs(downloadClient)

	accountDocumentsLive, err := api.GetAccountDocuments(client, graphqlURL, uuid, db.DocumentCategoryReportVisit)
	if err != nil {
		return fmt.Errorf("while getting account documents: %v", err)
	}

	var docsLive []db.AccountDocumentDB
	for _, d := range accountDocumentsLive {
		docsLive = append(docsLive, AccountDocumentAPIToDB(d))
	}

	docsInDB, err := db.GetAccountDocumentsDB(ctx, sqlDB)
	if err != nil {
		return fmt.Errorf("while getting existing documents: %v", err)
	}
	mapDocsInDB := make(map[string]db.AccountDocumentDB)
	for i := range docsInDB {
		mapDocsInDB[docsInDB[i].ID] = docsInDB[i]
	}

	// Let's set the FilePath for each document. Document are edited in place.
	for i := range docsLive {
		doc := &docsLive[i]

		docDB, found := mapDocsInDB[doc.ID]
		if found {
			*doc = db.MergeAccountDoc(docDB, *doc)
		}

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

		filename, fileURL, err := api.GetDocumentURL(client, graphqlURL, doc.HashFile)
		if err != nil {
			return fmt.Errorf("while getting document URL: %v", err)
		}
		doc.FilePath = path.Join(invoicesDir, filename)

		if fileExists(doc.FilePath) {
			continue
		}

		err = api.Download(downloadClient, fileURL, doc.FilePath)
		if err != nil {
			return fmt.Errorf("while downloading document: %v", err)
		}
	}

	docsToBeAdded, docsToBeUpdated, deleted := db.MergeAccountDocumentsDB(docsInDB, docsLive)
	if len(deleted) > 0 {
		logutil.Errorf("found that %d account documents were deleted from the API, not deleting them", len(deleted))
	}

	// Since we use upsert, let's combine the two slices.
	docs := append(docsToBeAdded, docsToBeUpdated...)

	// Show a diff in debug mode.
	for _, doc := range docs {
		docDB, found := mapDocsInDB[doc.ID]
		if found {
			diff := cmp.Diff(docDB, doc)
			logutil.Debugf("diff for account document %s: %s", doc.ID, diff)
		}
	}

	err = db.UpsertAccountDocumentsWithDB(ctx, sqlDB, docs)
	if err != nil {
		return fmt.Errorf("while saving account documents: %v", err)
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

// The `Expenses` table is a bit special because it doesn't have a unique ID I
// can use. Some items have an `hashFile` that can be used as a unique ID, so we
// first use this. If the `hashFile` is empty, we use the rest of the fields to
// (date, amount, label) to identify the expense.
type Indexer[T any] struct {
	Index map[string]T
}

func NewIndexer[T any](elmts []T, key func(T) string) Indexer[T] {
	index := make(map[string]T)
	for _, e := range elmts {
		index[key(e)] = e
	}
	return Indexer[T]{Index: index}
}

func (i Indexer[T]) Get(key string) (T, bool) {
	e, found := i.Index[key]
	return e, found
}

func (i Indexer[T]) Keys() []string {
	var keys []string
	for k := range i.Index {
		keys = append(keys, k)
	}
	return keys
}
