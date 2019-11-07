package domain

import (
	"context"
)

// DependencyCheck represents the interface you can use to check whether an implementation
// can talk to its dependencies
type DependencyCheck interface {
	CheckDependencies(ctx context.Context) error
}
