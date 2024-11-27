package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAmount(t *testing.T) {
	t.Run("when the amount is negative", func(t *testing.T) {
		assert.Equal(t, "-1.00 €", Amount(-100).String())
		assert.Equal(t, "1.00 €", Amount(100).String())
		assert.Equal(t, "1.00 €", Amount(100).String())
	})
}
