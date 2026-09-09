package main

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"

	"github.com/maelvls/foncia/api"
	"github.com/maelvls/foncia/logutil"
)

func coownersEndpoint(client *http.Client, uuid string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		coowners, err := api.GetCouncilCoowners(r.Context(), client, graphqlURL, uuid)
		if err != nil {
			logutil.Errorf("while getting coowners: %v", err)
			http.Error(w, "erreur interne, voir les logs du serveur", http.StatusInternalServerError)
			return
		}

		var coownersData []coownerRow
		for _, coowner := range coowners {
			apartment := ""
			parking := []string{}
			for _, lot := range coowner.Units {
				m, found := lotByNumber[lot]
				if !found {
					logutil.Errorf("unknown lot %d for coowner %s", lot, coowner.DisplayName)
					continue
				}

				switch {
				case strings.HasPrefix(m.Type, "T"):
					apartment = m.Description
				case strings.HasPrefix(m.Type, "Parking"):
					parking = append(parking, m.Description)
				default:
					logutil.Errorf("unknown lot type %s for lot %d", m.Type, m.Lot)
				}
			}

			coownersData = append(coownersData, coownerRow{
				Name:      coowner.DisplayName,
				Address:   fmt.Sprintf("%s %s %s %s", coowner.Address1, coowner.Address2, coowner.ZipCode, coowner.City),
				Apartment: apartment,
				Parking:   parking,
			})
		}

		// Sort by Apartment before rendering.
		sort.Slice(coownersData, func(i, j int) bool {
			return coownersData[i].Apartment < coownersData[j].Apartment
		})

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		err = coownersTmpl.Execute(w, coownersData)
		if err != nil {
			logutil.Errorf("executing template: %v", err)
			return
		}
	}
}

type coownerRow struct {
	Name      string
	Address   string
	Apartment string
	Parking   []string
}

var coownersTmpl = template.Must(template.New("coowners").Parse(coownersHTML))

var lotMapping = []struct {
	Lot         int
	Description string
	Type        string
}{
	// Extracted from the 'Reglement de copropriété' document.
	{Lot: 1, Description: "C01", Type: "T4"},
	{Lot: 2, Description: "C02", Type: "T4"},
	{Lot: 3, Description: "C03", Type: "T4"},
	{Lot: 4, Description: "C04", Type: "T2"},
	{Lot: 5, Description: "C05", Type: "T3"},
	{Lot: 6, Description: "C06", Type: "T3"},
	{Lot: 7, Description: "C07", Type: "T2"},
	{Lot: 8, Description: "C08", Type: "T2"},
	{Lot: 9, Description: "C09", Type: "T3"},
	{Lot: 10, Description: "C10", Type: "T2"},
	{Lot: 11, Description: "C11", Type: "T3"},
	{Lot: 12, Description: "C12", Type: "T2"},
	{Lot: 13, Description: "C13", Type: "T3"},
	{Lot: 14, Description: "C14", Type: "T3"},
	{Lot: 15, Description: "D01", Type: "T4"},
	{Lot: 16, Description: "D02", Type: "T4"},
	{Lot: 17, Description: "D03", Type: "T3"},
	{Lot: 18, Description: "D04", Type: "T3"},
	{Lot: 19, Description: "D05", Type: "T3"},
	{Lot: 20, Description: "D06", Type: "T2"},
	{Lot: 21, Description: "D07", Type: "T2"},
	{Lot: 22, Description: "D08", Type: "T3"},
	{Lot: 23, Description: "D09", Type: "T3"},
	{Lot: 24, Description: "D10", Type: "T2"},
	{Lot: 25, Description: "D11", Type: "T3"},
	{Lot: 26, Description: "D12", Type: "T3"},
	{Lot: 27, Description: "D13", Type: "T2"},
	{Lot: 28, Description: "44", Type: "Parking"},
	{Lot: 29, Description: "45", Type: "Parking"},
	{Lot: 30, Description: "46", Type: "Parking"},
	{Lot: 31, Description: "47", Type: "Parking"},
	{Lot: 32, Description: "48", Type: "Parking"},
	{Lot: 33, Description: "49", Type: "Parking"},
	{Lot: 34, Description: "50", Type: "Parking"},
	{Lot: 35, Description: "51", Type: "Parking"},
	{Lot: 36, Description: "52", Type: "Parking"},
	{Lot: 37, Description: "53", Type: "Parking"},
	{Lot: 38, Description: "54", Type: "Parking"},
	{Lot: 39, Description: "55", Type: "Parking"},
	{Lot: 40, Description: "56", Type: "Parking"},
	{Lot: 41, Description: "57", Type: "Parking"},
	{Lot: 42, Description: "58", Type: "Parking"},
	{Lot: 43, Description: "59", Type: "Parking"},
	{Lot: 44, Description: "60", Type: "Parking"},
	{Lot: 45, Description: "61", Type: "Parking"},
	{Lot: 46, Description: "62", Type: "Parking"},
	{Lot: 47, Description: "63", Type: "Parking"},
	{Lot: 48, Description: "64", Type: "Parking"},
	{Lot: 49, Description: "65", Type: "Parking"},
	{Lot: 50, Description: "66", Type: "Parking"},
	{Lot: 51, Description: "67", Type: "Parking"},
	{Lot: 52, Description: "68", Type: "Parking"},
	{Lot: 53, Description: "69", Type: "Parking"},
	{Lot: 54, Description: "70", Type: "Parking"},
	{Lot: 55, Description: "71", Type: "Parking"},
	{Lot: 56, Description: "72", Type: "Parking"},
	{Lot: 57, Description: "73", Type: "Parking"},
	{Lot: 58, Description: "74", Type: "Parking"},
}

// lotByNumber indexes lotMapping so that resolving a coowner's lots is a map
// lookup instead of a scan over all 58 entries per lot per request.
var lotByNumber = func() map[int]struct {
	Lot         int
	Description string
	Type        string
} {
	m := make(map[int]struct {
		Lot         int
		Description string
		Type        string
	}, len(lotMapping))
	for _, l := range lotMapping {
		m[l.Lot] = l
	}
	return m
}()
