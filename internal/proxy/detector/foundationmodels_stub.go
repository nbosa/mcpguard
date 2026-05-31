//go:build !foundationmodels || !darwin || !cgo

package detector

import "errors"

var ErrFoundationModelsUnavailable = errors.New("foundation models detector is unavailable; build on macOS with -tags foundationmodels and CGO enabled")

// NewFoundationModelsClassifier returns an unavailable error unless built with the foundationmodels tag on macOS.
func NewFoundationModelsClassifier() (ModelClassifier, error) {
	return nil, ErrFoundationModelsUnavailable
}
