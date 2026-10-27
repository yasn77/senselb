package provider_test

import (
	"errors"
	"testing"

	"github.com/yasn77/senselb/pkg/haproxy"
	"github.com/yasn77/senselb/pkg/provider"
)

// Compile-time assertions: the mock satisfies the full contract plus the
// optional rollback capability, and both error types satisfy error.
var (
	_ provider.Provider   = (*mockProvider)(nil)
	_ provider.Rollbacker = (*mockProvider)(nil)
	_ error               = (*provider.ErrConfigTest)(nil)
	_ error               = (*provider.ErrOwnershipConflict)(nil)
)

// mockProvider is an in-memory Provider used only to pin the interface shapes.
type mockProvider struct {
	model      *haproxy.Model
	applied    []haproxy.Plan
	validated  int
	reloaded   int
	rolledBack int
}

func (m *mockProvider) Get() (*haproxy.Model, error) { return m.model, nil }

func (m *mockProvider) Apply(plan haproxy.Plan) error {
	m.applied = append(m.applied, plan)
	return nil
}

func (m *mockProvider) Validate() error {
	m.validated++
	return nil
}

func (m *mockProvider) Reload() error {
	m.reloaded++
	return nil
}

func (m *mockProvider) Rollback() error {
	m.rolledBack++
	return nil
}

func TestMockProviderSatisfiesContract(t *testing.T) {
	t.Parallel()

	model := &haproxy.Model{}
	plan := haproxy.Plan{Ordered: true}
	mock := &mockProvider{model: model}

	var backend provider.Provider = mock

	got, err := backend.Get()
	if err != nil || got != model {
		t.Fatalf("Get() = (%v, %v), want (%v, nil)", got, err, model)
	}
	if err := backend.Apply(plan); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	if err := backend.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if err := backend.Reload(); err != nil {
		t.Fatalf("Reload() = %v, want nil", err)
	}

	if len(mock.applied) != 1 || mock.applied[0].Ordered != plan.Ordered {
		t.Fatalf("applied = %+v, want the submitted plan once", mock.applied)
	}
	if mock.validated != 1 || mock.reloaded != 1 {
		t.Fatalf("validated = %d, reloaded = %d, want 1 each", mock.validated, mock.reloaded)
	}

	rollbacker, ok := backend.(provider.Rollbacker)
	if !ok {
		t.Fatal("mock does not satisfy provider.Rollbacker")
	}
	if err := rollbacker.Rollback(); err != nil {
		t.Fatalf("Rollback() = %v, want nil", err)
	}
	if mock.rolledBack != 1 {
		t.Fatalf("rolledBack = %d, want 1", mock.rolledBack)
	}
}

func TestErrConfigTest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  *provider.ErrConfigTest
		want string
	}{
		{name: "with message", err: &provider.ErrConfigTest{Message: `unexpected token 'foo'`}, want: `configtest failed: unexpected token 'foo'`},
		{name: "without message", err: &provider.ErrConfigTest{}, want: "configtest failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrOwnershipConflict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  *provider.ErrOwnershipConflict
		want string
	}{
		{
			name: "single object",
			err:  &provider.ErrOwnershipConflict{Refs: []string{"frontend ingress-HTTPS"}},
			want: "ownership conflict: frontend ingress-HTTPS",
		},
		{
			name: "several objects",
			err:  &provider.ErrOwnershipConflict{Refs: []string{"frontend ingress-HTTPS", "backend k8s-ingress-HTTPS"}},
			want: "ownership conflict: frontend ingress-HTTPS, backend k8s-ingress-HTTPS",
		},
		{
			name: "no objects",
			err:  &provider.ErrOwnershipConflict{},
			want: "ownership conflict",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrorsAsFindsTypedErrors(t *testing.T) {
	t.Parallel()

	configErr := &provider.ErrConfigTest{Message: "boom"}
	if !errors.As(configErr, new(*provider.ErrConfigTest)) {
		t.Error("errors.As did not match *ErrConfigTest")
	}

	conflictErr := &provider.ErrOwnershipConflict{Refs: []string{"frontend ingress-HTTPS"}}
	if !errors.As(conflictErr, new(*provider.ErrOwnershipConflict)) {
		t.Error("errors.As did not match *ErrOwnershipConflict")
	}

	if errors.As(configErr, new(*provider.ErrOwnershipConflict)) {
		t.Error("errors.As matched the wrong error type")
	}
}
