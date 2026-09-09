package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/maelvls/foncia/api"
	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

// ComptesTravauxCmd lists the "comptes travaux" of the building, i.e., the
// works budgets voted at the general assemblies. When `search` isn't empty, the
// matching "compte travaux" is shown in detail: its expenses grouped by
// accounting allocation and expense type.
//
// The `search` argument can either be the ID of a "compte travaux", or a
// case-insensitive fragment of its label, e.g. "ascenseur".
func ComptesTravauxCmd(ctx context.Context, username string, password api.Password, search string, asJSON, withTotals bool) {
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

	budgets, err := api.GetRepairBudgets(ctx, client, graphqlURL, accUUID)
	if err != nil {
		logutil.Errorf("while getting the comptes travaux: %v", err)
		os.Exit(1)
	}

	if search != "" {
		budget, err := findRepairBudget(budgets, search)
		if err != nil {
			logutil.Errorf("%v", err)
			os.Exit(1)
		}
		details, err := api.GetRepairBudgetDetailsFull(ctx, client, graphqlURL, accUUID, budget.ID)
		if err != nil {
			logutil.Errorf("while getting the details of the compte travaux %q: %v", budget.Label, err)
			os.Exit(1)
		}
		if asJSON {
			printJSON(struct {
				api.RepairBudgetAPI
				Details api.RepairBudgetDetailsAPI
			}{RepairBudgetAPI: budget, Details: details})
			return
		}
		printRepairBudgetDetails(budget, details)
		return
	}

	// Without a search term, we list all the "comptes travaux". Fetching the
	// balance of each of them takes one extra HTTP call per "compte travaux",
	// which is why it is behind --totals.
	type budgetWithTotal struct {
		api.RepairBudgetAPI
		Balance   db.Amount `json:",omitempty"`
		hasTotals bool
	}
	rows := make([]budgetWithTotal, 0, len(budgets))
	for _, budget := range budgets {
		row := budgetWithTotal{RepairBudgetAPI: budget}
		if withTotals {
			details, err := api.GetRepairBudgetDetailsFull(ctx, client, graphqlURL, accUUID, budget.ID)
			if err != nil {
				logutil.Errorf("while getting the details of the compte travaux %q: %v", budget.Label, err)
				os.Exit(1)
			}
			row.Balance = details.TotalToAllocate
			row.hasTotals = true
		}
		rows = append(rows, row)
	}

	if asJSON {
		printJSON(rows)
		return
	}

	labelWidth := 0
	for _, row := range rows {
		if len(row.Label) > labelWidth {
			labelWidth = len(row.Label)
		}
	}
	for _, row := range rows {
		line := fmt.Sprintf("%s  %s  %s",
			logutil.Gray(row.ID),
			logutil.Yel(fmt.Sprintf("%-*s", labelWidth, row.Label)),
			alignRight(row.ValidatedAmount.String(), 14),
		)
		if row.hasTotals {
			line += "  " + logutil.Gray("solde: ") + coloredAmount(row.Balance)
		}
		fmt.Println(line)
	}
}

// findRepairBudget looks for a "compte travaux" by ID, or by a
// case-insensitive fragment of its label.
func findRepairBudget(budgets []api.RepairBudgetAPI, search string) (api.RepairBudgetAPI, error) {
	for _, budget := range budgets {
		if budget.ID == search {
			return budget, nil
		}
	}

	var matches []api.RepairBudgetAPI
	for _, budget := range budgets {
		if strings.Contains(strings.ToLower(budget.Label), strings.ToLower(search)) {
			matches = append(matches, budget)
		}
	}
	switch len(matches) {
	case 0:
		return api.RepairBudgetAPI{}, fmt.Errorf("no compte travaux matches %q", search)
	case 1:
		return matches[0], nil
	default:
		var labels []string
		for _, m := range matches {
			labels = append(labels, fmt.Sprintf("%s (%s)", m.Label, m.ID))
		}
		return api.RepairBudgetAPI{}, fmt.Errorf("%d comptes travaux match %q, be more specific: %s",
			len(matches), search, strings.Join(labels, ", "))
	}
}

func printRepairBudgetDetails(budget api.RepairBudgetAPI, details api.RepairBudgetDetailsAPI) {
	fmt.Printf("%s %s\n", logutil.Bold(budget.Label), logutil.Gray("("+budget.ID+")"))
	fmt.Printf("  Montant voté: %s\n", budget.ValidatedAmount)
	fmt.Printf("  Solde:        %s\n", coloredAmount(details.TotalToAllocate))
	fmt.Printf("  Dont TVA:     %s\n", details.TotalVat)
	fmt.Printf("  Récupérable:  %s\n", details.TotalRecoverable)

	for _, allocation := range details.Allocations {
		fmt.Printf("\n  %s %s %s\n",
			logutil.Bold(allocation.Name),
			logutil.Gray("["+allocation.Code+"]"),
			coloredAmount(allocation.ToAllocate),
		)
		for _, expenseType := range allocation.ExpenseTypes {
			fmt.Printf("    %s %s %s\n",
				logutil.Yel(expenseType.Name),
				logutil.Gray("["+expenseType.Code+"]"),
				coloredAmount(expenseType.ToAllocate),
			)
			for _, expense := range expenseType.Expenses {
				fmt.Printf("      %s %s %s\n",
					logutil.Gray(expense.Date.Format("02 Jan 2006")),
					alignRight(expense.ToAllocate.String(), 14),
					expense.Label,
				)
			}
		}
	}
}

// A "compte travaux" balance is a debit when positive (money still to be paid
// by the co-owners) and a credit when negative.
func coloredAmount(a db.Amount) string {
	if a > 0 {
		return logutil.Red(a.String())
	}
	return logutil.Green(a.String())
}

// Amounts contain a "€", which is 3 bytes long in UTF-8, so we can't use len().
func alignRight(s string, width int) string {
	n := utf8.RuneCountInString(s)
	if n >= width {
		return s
	}
	return strings.Repeat(" ", width-n) + s
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		logutil.Errorf("while printing JSON: %v", err)
		os.Exit(1)
	}
}
