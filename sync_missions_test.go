package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maelvls/foncia/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeFoncia serves the missions and their work orders, and counts the
// getWorkOrders calls per mission: that is the expensive call the sync has to
// be careful with.
type fakeFoncia struct {
	mu         sync.Mutex
	missions   []fakeMission
	workOrders map[string][]string // Mission ID -> work order IDs.
	woCalls    map[string]int      // Mission ID -> number of getWorkOrders calls.
}

type fakeMission struct{ id, label, status string }

func (f *fakeFoncia) calls() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]int, len(f.woCalls))
	for k, v := range f.woCalls {
		out[k] = v
	}
	return out
}

func (f *fakeFoncia) resetCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.woCalls = map[string]int{}
}

func (f *fakeFoncia) serve(t *testing.T) *httptest.Server {
	t.Helper()
	f.woCalls = map[string]int{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		f.mu.Lock()
		defer f.mu.Unlock()

		switch {
		case strings.Contains(req.Query, "missionIncidents"):
			var edges []string
			for i, m := range f.missions {
				edges = append(edges, fmt.Sprintf(
					`{"node":{"id":%q,"number":%q,"label":%q,"status":%q,"description":"d","startedAt":"2024-01-%02dT00:00:00.000Z"}}`,
					m.id, "N-"+m.id, m.label, m.status, i+1))
			}
			fmt.Fprintf(w, `{"data":{"coownerAccount":{"uuid":"u","trusteeCouncil":{"missionIncidents":{"totalCount":%d,"pageInfo":{"endCursor":"end","hasNextPage":false},"edges":[%s]}}}}}`,
				len(edges), strings.Join(edges, ","))
		case strings.Contains(req.Query, "missionRepairs"):
			fmt.Fprint(w, `{"data":{"coownerAccount":{"uuid":"u","trusteeCouncil":{"missionRepairs":{"totalCount":0,"pageInfo":{"endCursor":"","hasNextPage":false},"edges":[]}}}}}`)
		case strings.Contains(req.Query, "query getWorkOrders"):
			id, _ := req.Variables["missionId"].(string)
			f.woCalls[id]++
			var edges []string
			for _, wo := range f.workOrders[id] {
				edges = append(edges, fmt.Sprintf(
					`{"node":{"id":%q,"number":%q,"label":"DEMANDE INTERVENTION","repairDate":{"start":"2024-02-01T00:00:00.000Z","end":"2024-02-02T00:00:00.000Z"},"supplier":null}}`,
					wo, "OS-"+wo))
			}
			fmt.Fprintf(w, `{"data":{"workOrders":{"edges":[%s]}}}`, strings.Join(edges, ","))
		default:
			t.Errorf("unexpected query: %s", req.Query)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func workOrderIDs(t *testing.T, missions []db.MissionDB, missionID string) []string {
	t.Helper()
	for _, m := range missions {
		if m.ID != missionID {
			continue
		}
		var ids []string
		for _, wo := range m.WorkOrders {
			ids = append(ids, wo.ID)
		}
		return ids
	}
	t.Fatalf("mission %s not found", missionID)
	return nil
}

func TestSyncLiveMissionsWithDB(t *testing.T) {
	t.Run("a new mission is saved with its work orders and reported once", func(t *testing.T) {
		f := &fakeFoncia{
			missions:   []fakeMission{{"m1", "FUITE PARKING", "OPEN"}},
			workOrders: map[string][]string{"m1": {"wo1"}},
		}
		srv := f.serve(t)
		sqlDB := withRealDB(t)

		newMissions, err := syncLiveMissionsWithDB(t.Context(), srv.Client(), sqlDB, srv.URL, "uuid", 0)
		require.NoError(t, err)
		require.Len(t, newMissions, 1)
		assert.Equal(t, "m1", newMissions[0].ID)
		assert.Len(t, newMissions[0].WorkOrders, 1, "the notification needs the work orders")

		newMissions, err = syncLiveMissionsWithDB(t.Context(), srv.Client(), sqlDB, srv.URL, "uuid", 0)
		require.NoError(t, err)
		assert.Empty(t, newMissions)
		assert.Equal(t, map[string]int{"m1": 1}, f.calls(), "with no budget, an unchanged mission costs no call")

		got, err := db.GetMissionsDB(t.Context(), sqlDB)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []string{"wo1"}, workOrderIDs(t, got, "m1"))
	})

	t.Run("a status or label change updates the mission and refetches its work orders", func(t *testing.T) {
		// This is the bug being fixed: a known mission used to be skipped for
		// good, so it stayed OPEN in the database forever.
		f := &fakeFoncia{
			missions:   []fakeMission{{"m1", "RBST M VALAIS FLUIDE COLPORTEUR", "OPEN"}, {"m2", "GSM BAT C", "FINISHED"}},
			workOrders: map[string][]string{"m1": {"wo1"}},
		}
		srv := f.serve(t)
		sqlDB := withRealDB(t)
		_, err := syncLiveMissionsWithDB(t.Context(), srv.Client(), sqlDB, srv.URL, "uuid", 0)
		require.NoError(t, err)

		f.mu.Lock()
		f.missions[0] = fakeMission{"m1", "RBST M VALAIS FLUIDE CALOPORTEUR", "FINISHED"}
		f.workOrders["m1"] = []string{"wo1", "wo2"}
		f.mu.Unlock()
		f.resetCalls()

		newMissions, err := syncLiveMissionsWithDB(t.Context(), srv.Client(), sqlDB, srv.URL, "uuid", 0)
		require.NoError(t, err)
		assert.Empty(t, newMissions, "a changed mission is not a new mission")
		assert.Equal(t, map[string]int{"m1": 1}, f.calls(), "only the changed mission is refetched")

		got, err := db.GetMissionsDB(t.Context(), sqlDB)
		require.NoError(t, err)
		require.Len(t, got, 2)
		for _, m := range got {
			if m.ID == "m1" {
				assert.Equal(t, "FINISHED", m.Status)
				assert.Equal(t, "RBST M VALAIS FLUIDE CALOPORTEUR", m.Label)
			}
		}
		assert.ElementsMatch(t, []string{"wo1", "wo2"}, workOrderIDs(t, got, "m1"))
	})

	t.Run("the budget refreshes the open missions in turn, the stalest first", func(t *testing.T) {
		f := &fakeFoncia{
			missions: []fakeMission{
				{"m1", "a", "OPEN"}, {"m2", "b", "WORK_IN_PROGRESS"}, {"m3", "c", "OPEN"},
				{"m4", "d", "FINISHED"}, {"m5", "e", "CLOSE"},
			},
			workOrders: map[string][]string{},
		}
		srv := f.serve(t)
		sqlDB := withRealDB(t)
		_, err := syncLiveMissionsWithDB(t.Context(), srv.Client(), sqlDB, srv.URL, "uuid", 2)
		require.NoError(t, err)
		assert.Equal(t, map[string]int{"m1": 1, "m2": 1, "m3": 1, "m4": 1, "m5": 1}, f.calls(),
			"new missions are all fetched, and don't also eat the budget")

		// A work order shows up on m3, which does not change otherwise: the
		// common case, and the one the old sync never saw.
		f.mu.Lock()
		f.workOrders["m3"] = []string{"wo-late"}
		f.mu.Unlock()

		// Make the staleness order unambiguous rather than rely on the clock.
		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		for i, id := range []string{"m1", "m2", "m3", "m4", "m5"} {
			require.NoError(t, db.MarkWorkOrdersSynced(t.Context(), sqlDB, base.Add(time.Duration(i)*time.Hour), id))
		}

		f.resetCalls()
		_, err = syncLiveMissionsWithDB(t.Context(), srv.Client(), sqlDB, srv.URL, "uuid", 2)
		require.NoError(t, err)
		assert.Equal(t, map[string]int{"m1": 1, "m2": 1}, f.calls(), "the two stalest open missions")

		f.resetCalls()
		_, err = syncLiveMissionsWithDB(t.Context(), srv.Client(), sqlDB, srv.URL, "uuid", 2)
		require.NoError(t, err)
		assert.Equal(t, map[string]int{"m3": 1, "m1": 1}, f.calls(),
			"then the next one, and round again; FINISHED and CLOSE missions are never part of it")

		got, err := db.GetMissionsDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Equal(t, []string{"wo-late"}, workOrderIDs(t, got, "m3"))
	})

	t.Run("a mission or a work order that Foncia drops is kept", func(t *testing.T) {
		f := &fakeFoncia{
			missions:   []fakeMission{{"m1", "a", "OPEN"}, {"m2", "b", "OPEN"}},
			workOrders: map[string][]string{"m1": {"wo1", "wo2"}},
		}
		srv := f.serve(t)
		sqlDB := withRealDB(t)
		_, err := syncLiveMissionsWithDB(t.Context(), srv.Client(), sqlDB, srv.URL, "uuid", 10)
		require.NoError(t, err)

		f.mu.Lock()
		f.missions = f.missions[:1]          // m2 is gone.
		f.workOrders["m1"] = []string{"wo1"} // wo2 is gone.
		f.mu.Unlock()
		f.resetCalls()

		_, err = syncLiveMissionsWithDB(t.Context(), srv.Client(), sqlDB, srv.URL, "uuid", 10)
		require.NoError(t, err)
		assert.Equal(t, map[string]int{"m1": 1}, f.calls(), "a mission that is gone is not asked about")

		got, err := db.GetMissionsDB(t.Context(), sqlDB)
		require.NoError(t, err)
		assert.Len(t, got, 2)
		assert.ElementsMatch(t, []string{"wo1", "wo2"}, workOrderIDs(t, got, "m1"))
	})
}
