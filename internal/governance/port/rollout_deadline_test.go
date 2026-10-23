package port

import (
	"errors"
	"testing"
)

func TestRolloutDeadlineBatchBounds(t *testing.T) {
	for _, n := range []int{-1, 0, MaxRolloutDeadlineBatch + 1} {
		if !errors.Is(ValidateRolloutDeadlineBatch(n), ErrInvalidDeadlineBatch) {
			t.Fatalf("accepted batch %d", n)
		}
	}
	for _, n := range []int{1, MaxRolloutDeadlineBatch} {
		if err := ValidateRolloutDeadlineBatch(n); err != nil {
			t.Fatal(err)
		}
	}
}
