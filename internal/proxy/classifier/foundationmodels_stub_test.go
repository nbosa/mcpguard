//go:build !foundationmodels || !darwin || !cgo

package classifier

import (
	"context"
	"testing"
)

func TestFoundationModelsStubRegistered(t *testing.T) {
	c, err := Default().Get(foundationModelsName)
	if err != nil {
		t.Fatalf("expected stub classifier to be registered: %v", err)
	}
	if c.Name() != foundationModelsName {
		t.Fatalf("unexpected name: %s", c.Name())
	}
	if err := c.Available(); err == nil {
		t.Fatal("expected stub Available() to return error")
	}
	if _, err := c.Classify(context.Background(), ThreatPromptInjection, "hello", "loc"); err == nil {
		t.Fatal("expected stub Classify() to return error")
	}
}
