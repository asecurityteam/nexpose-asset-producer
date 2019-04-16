package domain

import (
	"context"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain/nexpose"
)

// AssetFetcher represents the interface you can use to fetch scanned assets for a given site
type AssetFetcher interface {
	FetchAssets(ctx context.Context, siteID string) (<-chan nexpose.Asset, <-chan error)
}
