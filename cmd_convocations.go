package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/maelvls/foncia/api"
	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

// ConvocationsCmd lists the convocations of the general assemblies. With
// `withAll`, the procès-verbaux and the annexes of the general assemblies are
// listed too. With `outDir` set, the PDFs are downloaded there instead of being
// listed.
//
// `search` is an optional case-insensitive fragment of the file name, e.g.
// "2025".
func ConvocationsCmd(ctx context.Context, username string, password api.Password, search, outDir string, withAll, asJSON bool) {
	client, err := api.AuthenticatedClient(&http.Client{}, graphqlURL, username, password)
	if err != nil {
		logutil.Errorf("while authenticating: %v", err)
		os.Exit(1)
	}

	accUUID, err := api.GetAccountUUID(ctx, client, graphqlURL)
	if err != nil {
		logutil.Errorf("while getting account UUID: %v", err)
		os.Exit(1)
	}

	// The convocations, the procès-verbaux, and the annexes all live under the
	// "generalAssembly" portal category; each document then carries its own
	// finer-grained category.
	docs, err := api.GetAccountDocuments(ctx, client, graphqlURL, accUUID, db.DocumentCategoryGeneralAssembly)
	if err != nil {
		logutil.Errorf("while getting the general assembly documents: %v", err)
		os.Exit(1)
	}

	var kept []api.AccountDocumentAPI
	for _, doc := range docs {
		if !withAll && doc.Category != db.DocumentCategoryConvocation {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(doc.OriginalFilename), strings.ToLower(search)) {
			continue
		}
		kept = append(kept, doc)
	}

	// Most recent first.
	sort.Slice(kept, func(i, j int) bool {
		return kept[i].CreatedAt.After(kept[j].CreatedAt)
	})

	if len(kept) == 0 {
		logutil.Errorf("no document found")
		os.Exit(1)
	}

	if asJSON {
		printJSON(kept)
		return
	}

	if outDir == "" {
		for _, doc := range kept {
			fmt.Printf("%s  %s  %s\n",
				logutil.Gray(doc.CreatedAt.Format("02 Jan 2006")),
				logutil.Yel(fmt.Sprintf("%-15s", categoryShortFrench(doc.Category))),
				doc.OriginalFilename,
			)
		}
		return
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		logutil.Errorf("while creating the output directory: %v", err)
		os.Exit(1)
	}

	// The download URLs are pre-signed S3 URLs, so they must be fetched with a
	// client that doesn't send the Foncia Authorization header.
	// Convocation PDFs can weigh tens of megabytes, so the timeout is generous.
	downloadClient := &http.Client{Timeout: 5 * time.Minute}
	if *debugFlag {
		api.EnableDebugCurlLogs(downloadClient)
	}

	for _, doc := range kept {
		if doc.HashFile == "" {
			logutil.Infof("no hash file for %q, skipping", doc.OriginalFilename)
			continue
		}

		filename, fileURL, err := api.GetDocumentURL(ctx, client, graphqlURL, doc.HashFile)
		if errors.Is(err, api.ErrEmptyURL) {
			logutil.Infof("no PDF available for %q, skipping", doc.OriginalFilename)
			continue
		}
		if err != nil {
			logutil.Errorf("while getting the URL of %q: %v", doc.OriginalFilename, err)
			os.Exit(1)
		}

		filePath := filepath.Join(outDir, filename)
		if fileExists(filePath) {
			fmt.Printf("%s %s\n", logutil.Gray("déjà présent:"), filePath)
			continue
		}

		err = api.Download(ctx, downloadClient, fileURL, filePath)
		if err != nil {
			logutil.Errorf("while downloading %q: %v", doc.OriginalFilename, err)
			os.Exit(1)
		}
		fmt.Printf("%s %s\n", logutil.Green("téléchargé:"), filePath)
	}
}

func categoryShortFrench(c db.DocumentCategory) string {
	switch c {
	case db.DocumentCategoryConvocation:
		return "Convocation"
	case db.DocumentCategoryMinutesSigned:
		return "Procès-verbal"
	case db.DocumentCategoryGeneralAssembly:
		return "Annexe"
	default:
		return string(c)
	}
}
