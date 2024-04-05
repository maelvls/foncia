package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/glebarez/go-sqlite"
)

func TestDoInBatches(t *testing.T) {
	tests := []struct {
		name           string
		givenbatchSize int
		givenElmts     []int
		wantBatches    [][]int
		wantErr        error
	}{
		{
			name:           "when each batch is full, only two batches are needed, not three",
			givenbatchSize: 5,
			givenElmts:     []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			wantBatches:    [][]int{{1, 2, 3, 4, 5}, {6, 7, 8, 9, 10}},
		},
		{
			name:           "when the last batch is not full, it is processed",
			givenbatchSize: 5,
			givenElmts:     []int{1, 2, 3, 4, 5, 6, 7, 8},
			wantBatches:    [][]int{{1, 2, 3, 4, 5}, {6, 7, 8}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotBatches [][]int
			err := DoInBatches(tt.givenbatchSize, tt.givenElmts, func(elmts []int) error {
				gotBatches = append(gotBatches, elmts)
				return nil
			})
			if tt.wantErr != nil {
				require.EqualError(t, tt.wantErr, err.Error())
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantBatches, gotBatches)
		})
	}
}
