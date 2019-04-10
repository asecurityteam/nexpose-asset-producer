package domain

import (
	"context"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain/nexpose"
)

type AssetFetcher interface {
	FetchAssets(ctx context.Context, siteID string, nexposeHost string, nexposeAssetPageSize int32) <- chan []nexpose.Asset
}