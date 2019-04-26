package domain

import "context"

// The Producer interface is used to produce assets onto a queue
type Producer interface {
	Produce(ctx context.Context, asset Asset) error
}
