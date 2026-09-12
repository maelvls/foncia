package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/maelvls/foncia/api"
	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

// Returns the new items.
func syncLiveMissionsWithDB(ctx context.Context, client *http.Client, sqlDB *sql.DB, graphqlURL, uuid string) ([]db.MissionDB, error) {
	missions, _, err := api.GetMissionsAPI(ctx, client, graphqlURL, uuid, api.MissionsCursor{})
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
	// missions, let's do them in small batches so that we can save to DB
	// regularly so we don't lose all the work if the program crashes (takes a
	// lot of time partly because the Raspberry Pi's disk is slow, partly because
	// there are 200-300 HTTP calls to be made).
	batchSize := 1
	i := 0
	var savedMissions []db.MissionDB
	err = DoInBatches(batchSize, newMissions, func(batchMissions []db.MissionDB) error {
		i++
		var batchWorkOrders []db.WorkOrderDB

		// Let's update each mission with its work orders.
		for i, mission := range batchMissions {
			orders, err := api.GetWorkOrdersAPI(ctx, client, graphqlURL, uuid, mission.ID)
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

		// Missions first: work_orders.mission_id is a foreign key onto
		// missions.id, and foreign keys are enforced now, so inserting the work
		// orders first would be rejected.
		logutil.Debugf("saving %d missions to DB", len(batchMissions))
		err = db.SaveMissionsToDB(ctx, sqlDB, batchMissions...)
		if err != nil {
			return fmt.Errorf("while saving missions: %v", err)
		}

		logutil.Debugf("saving work orders for %d missions to DB", len(batchMissions))
		err = db.SaveWorkOrdersToDB(ctx, sqlDB, batchWorkOrders)
		if err != nil {
			return fmt.Errorf("while saving work orders: %v", err)
		}

		savedMissions = append(savedMissions, batchMissions...)
		return nil
	})
	if err != nil {
		// The batches before the failing one are already in the database.
		// Hand them back so that the caller can still notify about them.
		return savedMissions, err
	}

	return savedMissions, nil
}

// Returns new expenses.
//
// The expenses come from two places: the building's accounts, one accounting
// period at a time through getBuildingAccountingRGDD (including the open
// periods: the "current" accounts are just the union of the two open periods),
// and the "comptes travaux" through getRepairBudgetDetails. Both give every line
// Foncia's own id, which is the primary key of the expenses table, so a line
// that Foncia relabels, re-dates or reallocates is updated in place rather than
// stored a second time.
func syncExpensesWithDB(ctx context.Context, client *http.Client, sqlDB *sql.DB, graphqlURL, uuid, invoicesDir string) ([]db.ExpenseDocumentDB, error) {
	// Unauthenticated client just used for downloading files from AWS.
	downloadClient := &http.Client{Timeout: 5 * time.Minute}
	api.EnableDebugCurlLogs(downloadClient)

	// Create dir if missing.
	err := os.MkdirAll(invoicesDir, 0755)
	if err != nil {
		return nil, fmt.Errorf("while creating directory: %v", err)
	}

	// For now, the fetched expenses won't contain the FilePath field. It will
	// be set later on.
	var expensesLive []db.ExpenseDocumentDB
	periods, err := api.GetAccountingPeriods(ctx, client, graphqlURL, uuid)
	if err != nil {
		return nil, fmt.Errorf("while getting accounting periods: %v", err)
	}
	for _, period := range periods {
		cur, err := api.GetBuildingAccountingRGDD(ctx, client, graphqlURL, uuid, period.ID)
		if err != nil {
			return nil, fmt.Errorf("while getting building accounting RGDD: %v", err)
		}
		for _, e := range cur {
			expensesLive = append(expensesLive, ExpenseDocumentAPIToDB(e, db.SourceAccounting))
		}
	}

	budgets, err := api.GetRepairBudgets(ctx, client, graphqlURL, uuid)
	if err != nil {
		return nil, fmt.Errorf("while getting repair IDs: %v", err)
	}
	for _, budget := range budgets {
		got, err := api.GetRepairBudgetDetails(ctx, client, graphqlURL, uuid, budget.ID)
		if err != nil {
			return nil, fmt.Errorf("while getting repair budget details: %v", err)
		}
		for _, e := range got {
			expensesLive = append(expensesLive, ExpenseDocumentAPIToDB(e, db.SourceRepairs))
		}
	}

	// The accounting periods don't overlap, and the API layer refuses an
	// expense without an id, so this is only a safety net: should the same id
	// ever be returned twice, the second copy is dropped rather than counted
	// as new twice.
	expensesLive = deduplicateByID(expensesLive)

	expensesInDB, err := db.GetExpensesDB(ctx, sqlDB)
	if err != nil {
		return nil, fmt.Errorf("while getting existing expenses: %v", err)
	}
	expensesInDBByID := make(map[string]db.ExpenseDocumentDB, len(expensesInDB))
	for _, e := range expensesInDB {
		expensesInDBByID[e.ID] = e
	}

	// Rows written before Foncia's id was used carry a legacy id derived from
	// their contents. The first time such a row is seen again with its Foncia
	// id, it is re-keyed so that the upsert below updates it instead of
	// inserting a second copy. Once every row Foncia still returns has been
	// re-keyed, this loop never re-keys anything again; the rows that Foncia
	// no longer returns keep their legacy id.
	for i := range expensesLive {
		e := &expensesLive[i]
		if _, found := expensesInDBByID[e.ID]; found {
			continue
		}
		for _, legacyID := range db.LegacyExpenseIDs(*e) {
			eDB, found := expensesInDBByID[legacyID]
			if !found {
				continue
			}
			rekeyed, err := db.RekeyExpense(ctx, sqlDB, legacyID, e.ID)
			if err != nil {
				return nil, err
			}
			if !rekeyed {
				// Can only happen when a row already has the new id, which
				// the map lookup above rules out; log it rather than guess.
				logutil.Errorf("expense %q (%s) could not be re-keyed from %s to %s", e.Label, e.Date.Format(time.RFC3339), legacyID, e.ID)
				continue
			}
			logutil.Infof("expense %q (%s) re-keyed from legacy id %s to Foncia id %s", e.Label, e.Date.Format(time.RFC3339), legacyID, e.ID)
			eDB.ID = e.ID
			delete(expensesInDBByID, legacyID)
			expensesInDBByID[e.ID] = eDB
			break
		}
	}

	var newExpensesDB []db.ExpenseDocumentDB
	// Save the invoice PDFs to disk. By "live", I mean that it's the expenses
	// that were fetched from the API.
	err = DoInBatches(1, expensesLive, func(liveExpenses []db.ExpenseDocumentDB) error {
		for i := range liveExpenses {
			e := &liveExpenses[i]

			if eDB, found := expensesInDBByID[e.ID]; found {
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
				logutil.Debugf("file needs to be downloaded for %q (%s, %s, %s)", e.FilePath, e.Label, e.Date.Format(time.RFC3339), e.Amount)
			}

			// First try using the HashFile, then the InvoiceID.
			var fileURL, filename string
			if e.HashFile != "" {
				filename, fileURL, err = api.GetDocumentURL(ctx, client, graphqlURL, e.HashFile)
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
				filename, fileURL, err = api.GetInvoiceURL(ctx, client, graphqlURL, e.InvoiceID)
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

			err = api.Download(ctx, downloadClient, fileURL, e.FilePath)
			if err != nil {
				return fmt.Errorf("while downloading invoice for expense %s: %v", fileURL, err)
			}
		}

		var newExpenses, changedExpenses []db.ExpenseDocumentDB
		for _, expLive := range liveExpenses {
			expDB, found := expensesInDBByID[expLive.ID]
			if !found {
				logutil.Debugf("found new expense %s (%s)", expLive.Label, expLive.Date)
				newExpenses = append(newExpenses, expLive)
				continue
			}

			// Anything but the id can change: many expenses don't have a PDF
			// attached (= no HashFile) for a couple of weeks, and Foncia
			// sometimes relabels or re-dates a line after the fact. The row is
			// updated in place, and the change is logged so that it can be
			// traced back.
			if !expDB.Equal(expLive) {
				diff := cmp.Diff(expDB, expLive)
				logutil.Infof("expense %s changed (%q, %s): %s", expLive.ID, expLive.Label, expLive.Date.Format(time.RFC3339), diff)
				changedExpenses = append(changedExpenses, expLive)
			}
		}

		newOrChanged := append(newExpenses, changedExpenses...)
		err = db.UpsertExpensesWithDB(ctx, sqlDB, newOrChanged...)
		if err != nil {
			return fmt.Errorf("while saving expenses: %v", err)
		}

		// Only count them as new once they are actually persisted.
		newExpensesDB = append(newExpensesDB, newExpenses...)
		return nil
	})
	if err != nil {
		// Same as for the missions: the earlier batches are saved, so report
		// them rather than dropping them on the floor.
		return newExpensesDB, err
	}

	return newExpensesDB, nil
}

// deduplicateByID keeps the first expense of each id, preserving the order.
func deduplicateByID(expenses []db.ExpenseDocumentDB) []db.ExpenseDocumentDB {
	seen := make(map[string]struct{}, len(expenses))
	deduped := make([]db.ExpenseDocumentDB, 0, len(expenses))
	for _, e := range expenses {
		if _, found := seen[e.ID]; found {
			logutil.Errorf("expense %s (%q, %s) was returned twice by the API, keeping the first one", e.ID, e.Label, e.Date.Format(time.RFC3339))
			continue
		}
		seen[e.ID] = struct{}{}
		deduped = append(deduped, e)
	}
	return deduped
}

func syncSuppliersWithDB(ctx context.Context, client *http.Client, sqlDB *sql.DB, graphqlURL, uuid, invoicesDir string) error {
	// Unauthenticated client just used for downloading files from AWS.
	downloadClient := &http.Client{Timeout: 5 * time.Minute}
	api.EnableDebugCurlLogs(downloadClient)

	supplierContractsLive, err := api.GetCouncilMissionSuppliersAPI(ctx, client, graphqlURL, uuid)
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

		filename, fileURL, err := api.GetDocumentURL(ctx, client, graphqlURL, doc.HashFile)
		if err != nil {
			return fmt.Errorf("while getting document URL: %v", err)
		}
		doc.FilePath = path.Join(invoicesDir, filename)

		if fileExists(doc.FilePath) {
			continue
		}

		err = api.Download(ctx, downloadClient, fileURL, doc.FilePath)
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

// The general assembly documents are always indexed so that they show up in the
// UI, but they are only downloaded when `downloadAGDocs` is set: there are more
// than a hundred of them, and some of the convocations weigh tens of megabytes.
// When they aren't on disk, the HTTP server redirects to the Foncia URL.
func syncAccountDocumentsWithDB(ctx context.Context, client *http.Client, sqlDB *sql.DB, graphqlURL, uuid, invoicesDir string, downloadAGDocs bool) error {
	// Unauthenticated client just used for downloading files from AWS.
	downloadClient := &http.Client{Timeout: 5 * time.Minute}
	api.EnableDebugCurlLogs(downloadClient)

	// The general assembly documents (convocations, procès-verbaux, and the
	// annexes) are fetched under a single "portal category"; each document then
	// carries its own finer-grained category.
	portalCategories := []db.DocumentCategory{
		db.DocumentCategoryReportVisit,
		db.DocumentCategoryGeneralAssembly,
	}

	var docsLive []db.AccountDocumentDB
	for _, portalCategory := range portalCategories {
		accountDocumentsLive, err := api.GetAccountDocuments(ctx, client, graphqlURL, uuid, portalCategory)
		if err != nil {
			return fmt.Errorf("while getting the %q account documents: %v", portalCategory, err)
		}
		for _, d := range accountDocumentsLive {
			docsLive = append(docsLive, AccountDocumentAPIToDB(d))
		}
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

		// The general assembly documents are only indexed, not downloaded,
		// unless asked otherwise. The HTTP server redirects to the Foncia URL
		// for the ones that aren't on disk.
		if doc.IsGeneralAssembly() && !downloadAGDocs {
			continue
		}

		// I found that the graphql query 'getDocumentURL' returns an empty URL
		// if the hashFile is empty.
		if doc.HashFile == "" {
			logutil.Infof("no hash file found for document %s, skipping download", doc.ID)
			continue
		}

		filename, fileURL, err := api.GetDocumentURL(ctx, client, graphqlURL, doc.HashFile)
		if err != nil {
			return fmt.Errorf("while getting document URL: %v", err)
		}
		doc.FilePath = path.Join(invoicesDir, filename)

		if fileExists(doc.FilePath) {
			continue
		}

		err = api.Download(ctx, downloadClient, fileURL, doc.FilePath)
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
