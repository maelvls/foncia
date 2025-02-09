package main

import (
	"github.com/maelvls/foncia/api"
	"github.com/maelvls/foncia/db"
)

func MissionAPIToDB(m api.MissionAPI) db.MissionDB {
	return db.MissionDB{
		ID:          m.ID,
		StartedAt:   m.StartedAt,
		Kind:        string(m.Kind),
		Number:      m.Number,
		Label:       m.Label,
		Description: m.Description,
		Status:      m.Status,
	}
}

// WARNING: the `Documents` field is not set by this function. You need to set
// it manually afterwards.
func SupplierAPIToDB(s api.SupplierAPI) db.SupplierDB {
	return db.SupplierDB{
		ID:       s.ID,
		Name:     s.Name,
		Activity: s.Activity,
	}
}

func ExtractSuppliersFromContracts(contracts []api.SupplierContractAPI) []db.SupplierDB {
	// There might be multiple contracts with the same supplier, so we need to
	// de-duplicate.
	exists := make(map[string]struct{})

	var suppliers []db.SupplierDB
	for _, c := range contracts {
		_, already := exists[c.Supplier.ID]
		if already {
			continue
		}
		exists[c.Supplier.ID] = struct{}{}
		suppliers = append(suppliers, SupplierAPIToDB(c.Supplier))
	}
	return suppliers
}

// WARNING: the `FilePath` field is not set by this function. You need to set it
// manually afterwards.
func ExpenseDocumentAPIToDB(e api.ExpenseDocumentAPI, src db.Source) db.ExpenseDocumentDB {
	return db.ExpenseDocumentDB{
		Label:     e.Label,
		Date:      e.Date,
		Amount:    e.Amount,
		InvoiceID: e.InvoiceID,
		HashFile:  e.HashFile,
		FilePath:  "", // Remember to set this later on.
		Source:    src,
		AccountingKey: db.AccountingKey{
			Allocation:  e.AccountingAllocation,
			ExpenseType: e.AccountingExpenseType,
		},
	}
}

// WARNING: the `FilePath` field is not set by this function. You need to set it
// manually afterwards.
func AccountDocumentAPIToDB(a api.AccountDocumentAPI) db.AccountDocumentDB {
	return db.AccountDocumentDB{
		ID:        a.ID,
		HashFile:  a.HashFile,
		FilePath:  "", // Remember to set this later on.
		MimeType:  a.MimeType,
		Category:  a.Category,
		CreatedAt: a.CreatedAt,
	}
}

// The FilePath is left empty. You have to set it later on.
func SupplierContractAPIToDB(c api.SupplierContractAPI) []db.SupplierContractDocumentDB {
	var docs []db.SupplierContractDocumentDB
	for _, doc := range c.Documents {
		docs = append(docs, db.SupplierContractDocumentDB{
			ID:         doc.ID,
			HashFile:   doc.HashFile,
			FilePath:   "", // Remember to set this later on.
			SupplierID: c.ID,
		})
	}
	return docs
}

func WorkOrderAPIToDB(w api.WorkOrderAPI, missionID string) db.WorkOrderDB {
	return db.WorkOrderDB{
		ID:              w.ID,
		MissionID:       missionID,
		Number:          w.Number,
		Label:           w.Label,
		RepairDateStart: w.RepairDateStart,
		RepairDateEnd:   w.RepairDateEnd,
		Supplier:        SupplierAPIToDB(w.Supplier),
	}
}
