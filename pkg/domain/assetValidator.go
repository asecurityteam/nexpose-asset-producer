package domain

import (
	"context"

	"github.com/asecurityteam/runhttp"
)

// AssetValidator represents the interface you can use to validate all Assets. It returns
// a list of valid assets and a list of errors that reflect invalid assets
type AssetValidator interface {
	ValidateAssets(ctx context.Context, assets []Asset, scanID string, siteID string, logger runhttp.Logger) ([]AssetEvent, []error)
}
