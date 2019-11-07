package domain

import (
	"context"
)

// AssetFetcher represents the interface you can use to fetch scanned assets for a given site
type AssetFetcher interface {
	FetchAssets(ctx context.Context, siteID string) (<-chan AssetEvent, <-chan error)
	CheckDependencies(ctx context.Context) error
}
