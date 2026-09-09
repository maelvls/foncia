package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"

	"github.com/maelvls/foncia/api"
	"github.com/maelvls/foncia/logutil"
)

func ListCmd(ctx context.Context, username string, password api.Password) {
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

	missions, _, err := api.GetMissionsAPI(ctx, client, graphqlURL, accUUID, api.MissionsCursor{})
	if err != nil {
		logutil.Errorf("getting interventions: %v", err)
		os.Exit(1)
	}

	// Print the items starting with the oldest one.
	for _, mission := range slices.Backward(missions) {
		fmt.Printf("%s %s %s %s %s\n",
			mission.StartedAt.Format("02 Jan 2006"),
			logutil.Bold(string(mission.Kind)),
			logutil.Yel(mission.Label),
			func() string {
				if mission.Status == "WORK_IN_PROGRESS" {
					return logutil.Red(mission.Status)
				} else {
					return logutil.Green(mission.Status)
				}
			}(),
			logutil.Gray(mission.Description),
		)
	}
}
