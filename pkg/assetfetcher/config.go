package assetfetcher

import "context"

// AssetFetcherConfig holds configuration to connect to Nexpose
// and make a call to the fetch assets API
type AssetFetcherConfig struct {
	Host                 string
	Username             string
	Password             string
	AssetFetcherPageSize int
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
func (*AssetFetcherConfigComponent) Settings() *AssetFetcherConfig { return &AssetFetcherConfig{} }

// New constructs a NexposeAssetFetcher from a config.
func (*AssetFetcherConfigComponent) New(_ context.Context, c *AssetFetcherConfig) (*NexposeAssetFetcher, error) {
	return &NexposeAssetFetcher{
		Host:     c.Host,
		Username: c.Username,
		Password: c.Password,
		PageSize: c.AssetFetcherPageSize,
	}, nil
}
