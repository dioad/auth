package auth_test

import (
	"context"
	"fmt"

	"github.com/dioad/auth"
)

// ExamplePrincipalContext_IsAllowAll shows how to avoid recording the
// anonymous allow-all principal as a caller's identity.
func ExamplePrincipalContext_IsAllowAll() {
	pc, _ := auth.NewAllowAllPrincipalExtractor().ExtractPrincipal(context.Background())

	if pc.IsAllowAll() {
		fmt.Println("anonymous principal: do not record", pc.ID)
	}
	// Output:
	// anonymous principal: do not record unauthenticated
}
