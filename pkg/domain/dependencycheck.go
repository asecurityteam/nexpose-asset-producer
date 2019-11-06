package domain

import "context"

// DependencyChecker represents an interface for hydrating an Asset with vulnerability details
type DependencyChecker interface {
	CheckDependencies(context.Context) error
}
