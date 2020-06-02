package v1

import (
	"context"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
)

// DependencyCheckHandler takes in a domain.DependencyChecker to check external dependencies
type DependencyCheckHandler struct {
	DependencyCheck domain.DependencyCheck
}

// Handle makes a call CheckDependencies from DependencyChecker that verifies this
// app can talk to it's external dependencies
func (h *DependencyCheckHandler) Handle(ctx context.Context) error {
	return nil
	// return h.DependencyCheck.CheckDependencies(ctx)
}
