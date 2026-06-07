//go:build !foundationmodels || !darwin || !cgo

// Stub Foundation Models classifier: registers the plugin name so users get a
// clear "not built with this tag" error via Available() instead of a
// confusing "classifier not found".
package classifier

import (
	"context"
	"errors"
)

const foundationModelsName = "foundation-models"

// ErrFoundationModelsUnavailable is returned by Available() and Classify()
// when the binary was not built with the foundationmodels build tag.
var ErrFoundationModelsUnavailable = errors.New(
	"foundation models classifier unavailable: rebuild on macOS with CGO_ENABLED=1 and -tags foundationmodels",
)

type foundationModelsStub struct{}

// NewFoundationModelsClassifier returns a stub that always reports unavailability.
func NewFoundationModelsClassifier() (Classifier, error) {
	return &foundationModelsStub{}, nil
}

func (c *foundationModelsStub) Name() string { return foundationModelsName }
func (c *foundationModelsStub) Description() string {
	return "Local Apple Foundation Models classifier (requires macOS + -tags foundationmodels build)."
}

func (c *foundationModelsStub) Available() error { return ErrFoundationModelsUnavailable }

func (c *foundationModelsStub) Classify(ctx context.Context, threat ThreatType, text, location string) (*Finding, error) {
	return nil, ErrFoundationModelsUnavailable
}

func init() {
	c, err := NewFoundationModelsClassifier()
	if err == nil {
		Default().MustRegister(c)
	}
}
