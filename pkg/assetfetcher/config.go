package assetfetcher

import (
	"context"
	"net/url"

	"github.com/asecurityteam/runhttp"
)

// AssetFetcherConfig holds configuration to connect to Nexpose
// and make a call to the fetch assets API
type AssetFetcherConfig struct {
	Host     string `description:"The scheme and host of a Nexpose instance."`
	PageSize int    `description:"The number of assets that should be returned from the Nexpose API at one time."`
}

// Name is used by the settings library and will add a "NEXPOSE_"
// prefix to AssetFetcherConfig environment variables
func (c *AssetFetcherConfig) Name() string {
	return "Nexpose"
}

// AssetFetcherConfigComponent satisfies the settings library Component
// API, and may be used by the settings.NewComponent function.
type AssetFetcherConfigComponent struct{}

// Settings can be used to populate default values if there are any
func (*AssetFetcherConfigComponent) Settings() *AssetFetcherConfig {
	return &AssetFetcherConfig{
		PageSize: 100,
	}
}

// New constructs a NexposeAssetFetcher from a config.
func (*AssetFetcherConfigComponent) New(_ context.Context, c *AssetFetcherConfig) (*NexposeAssetFetcher, error) {
	host, err := url.Parse(c.Host)
	if err != nil {
		return nil, err
	}

	return &NexposeAssetFetcher{
		Host:     host,
		PageSize: c.PageSize,
		StatFn:   runhttp.StatFromContext,
	}, nil
}
