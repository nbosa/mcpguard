package classifier

import (
	"context"
	"errors"
	"testing"
)

type fakeClassifier struct {
	name        string
	available   error
	threat      ThreatType
	matchText   string
	skipOnEmpty bool
	calls       int
}

func (f *fakeClassifier) Name() string        { return f.name }
func (f *fakeClassifier) Description() string { return "fake " + f.name }
func (f *fakeClassifier) Available() error    { return f.available }
func (f *fakeClassifier) Classify(ctx context.Context, threat ThreatType, text, location string) (*Finding, error) {
	f.calls++
	if f.skipOnEmpty && text == "" {
		return nil, nil
	}
	if threat != f.threat {
		return nil, nil
	}
	if f.matchText != "" && text != f.matchText {
		return nil, nil
	}
	return &Finding{Type: threat, Severity: SeverityHigh, Reason: "fake match", Classifier: f.name}, nil
}

func TestRegistryRegisterAndGet(t *testing.T) {
	r := NewRegistry()
	c := &fakeClassifier{name: "alpha"}
	if err := r.Register(c); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := r.Get("alpha")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name() != "alpha" {
		t.Fatalf("unexpected classifier: %s", got.Name())
	}
}

func TestRegistryRejectsDuplicate(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(&fakeClassifier{name: "dup"})
	if err := r.Register(&fakeClassifier{name: "dup"}); err == nil {
		t.Fatal("expected duplicate registration to fail")
	}
}

func TestRegistryRejectsEmptyName(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(&fakeClassifier{name: ""}); err == nil {
		t.Fatal("expected empty name registration to fail")
	}
}

func TestRegistryRejectsNil(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(nil); err == nil {
		t.Fatal("expected nil registration to fail")
	}
}

func TestRegistryNamesSorted(t *testing.T) {
	r := NewRegistry()
	for _, n := range []string{"charlie", "alpha", "bravo"} {
		_ = r.Register(&fakeClassifier{name: n})
	}
	names := r.Names()
	want := []string{"alpha", "bravo", "charlie"}
	if len(names) != len(want) {
		t.Fatalf("expected %v, got %v", want, names)
	}
	for i, n := range want {
		if names[i] != n {
			t.Fatalf("expected %v, got %v", want, names)
		}
	}
}

func TestRegistryGetMissing(t *testing.T) {
	r := NewRegistry()
	_, err := r.Get("nope")
	if err == nil {
		t.Fatal("expected error for missing classifier")
	}
}

func TestRegistryAllDeterministic(t *testing.T) {
	r := NewRegistry()
	for _, n := range []string{"z", "a", "m"} {
		_ = r.Register(&fakeClassifier{name: n})
	}
	all := r.All()
	if len(all) != 3 || all[0].Name() != "a" || all[1].Name() != "m" || all[2].Name() != "z" {
		t.Fatalf("unexpected order: %v", allNames(all))
	}
}

func TestMustRegisterPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	r := NewRegistry()
	r.MustRegister(nil)
}

func TestAnalyzeRunsAll(t *testing.T) {
	a := &fakeClassifier{name: "a", threat: ThreatPromptInjection, matchText: "boom"}
	b := &fakeClassifier{name: "b", threat: ThreatPromptInjection, matchText: "boom"}
	ctx := context.Background()
	findings := Analyze(ctx, []Classifier{a, b}, ThreatPromptInjection, "boom", "loc")
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Classifier != "a" || findings[1].Classifier != "b" {
		t.Fatalf("unexpected classifier order/tags: %+v", findings)
	}
}

func TestAnalyzeEmptyText(t *testing.T) {
	a := &fakeClassifier{name: "a", threat: ThreatPromptInjection, matchText: "x"}
	if findings := Analyze(context.Background(), []Classifier{a}, ThreatPromptInjection, "", "loc"); findings != nil {
		t.Fatalf("expected nil findings, got %v", findings)
	}
}

func TestAnalyzeSkipsErrors(t *testing.T) {
	good := &fakeClassifier{name: "good", threat: ThreatPromptInjection, matchText: "x"}
	bad := &erroringClassifier{err: errors.New("boom")}
	findings := Analyze(context.Background(), []Classifier{good, bad}, ThreatPromptInjection, "x", "loc")
	if len(findings) != 1 || findings[0].Classifier != "good" {
		t.Fatalf("expected only good to fire, got %+v", findings)
	}
}

type erroringClassifier struct{ err error }

func (e *erroringClassifier) Name() string        { return "bad" }
func (e *erroringClassifier) Description() string { return "errors" }
func (e *erroringClassifier) Available() error    { return e.err }
func (e *erroringClassifier) Classify(ctx context.Context, threat ThreatType, text, location string) (*Finding, error) {
	return nil, e.err
}

func allNames(cs []Classifier) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Name()
	}
	return out
}
