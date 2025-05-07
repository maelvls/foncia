package search

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/blevesearch/bleve/v2"
	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

const (
	indexDirectoryName = "expenses.bleve"
)

// OpenIndex opens the index at the given path, creating it if it doesn't exist.
func OpenIndex(dataDir string) (bleve.Index, error) {
	indexPath := filepath.Join(dataDir, indexDirectoryName)

	// If the index doesn't exist, create it.
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		logutil.Infof("creating bleve index at %s", indexPath)
		mapping := bleve.NewIndexMapping()
		index, err := bleve.New(indexPath, mapping)
		if err != nil {
			return nil, fmt.Errorf("couldn't create index: %w", err)
		}
		return index, nil
	}

	// Open the existing index.
	index, err := bleve.Open(indexPath)
	if err != nil {
		return nil, fmt.Errorf("couldn't open index: %w", err)
	}
	return index, nil
}

// IndexExpense adds or updates an expense in the index.
func IndexExpense(index bleve.Index, expense db.ExpenseDocumentDB) error {
	err := index.Index(expense.HashFile, expense)
	if err != nil {
		return fmt.Errorf("couldn't index expense: %w", err)
	}
	return nil
}

// SearchExpenses searches the index for expenses matching the given query.
func SearchExpenses(index bleve.Index, query string) (*bleve.SearchResult, error) {
	bleveQuery := bleve.NewQueryStringQuery(query)
	searchRequest := bleve.NewSearchRequest(bleveQuery)
	searchResult, err := index.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("couldn't search index: %w", err)
	}
	return searchResult, nil
}
