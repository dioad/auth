package auth

import "context"

// MockPrincipalSource is a test implementation of PrincipalSource.
type MockPrincipalSource struct {
	MockName      string
	MockPrincipal string
	MockError     error
	MockClaims    map[string]any
	MockRoles     []string
	MockIsService bool
}

func (m *MockPrincipalSource) Extract(_ context.Context) (string, error) {
	return m.MockPrincipal, m.MockError
}

func (m *MockPrincipalSource) Name() string {
	if m.MockName == "" {
		return "mock"
	}
	return m.MockName
}

func (m *MockPrincipalSource) Claims(_ context.Context) map[string]any {
	return m.MockClaims
}

func (m *MockPrincipalSource) Roles(_ context.Context) []string {
	return m.MockRoles
}

func (m *MockPrincipalSource) IsService(_ context.Context) bool { return m.MockIsService }
