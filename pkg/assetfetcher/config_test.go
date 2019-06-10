package assetfetcher

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestName(t *testing.T) {
	assetFetcherConfig := AssetFetcherConfig{}
	assert.Equal(t, "Nexpose", assetFetcherConfig.Name())
}

func TestAssetComponentDefaultConfig(t *testing.T) {
	component := &AssetFetcherConfigComponent{}
	config := component.Settings()
	assert.Empty(t, config.Host)
	assert.Equal(t, config.PageSize, 100)
}

func TestAssetFetcherConfigWithValues(t *testing.T) {
	assetFetcherComponent := AssetFetcherConfigComponent{}
	config := &AssetFetcherConfig{
		Host:     "http://localhost",
		PageSize: 5,
	}
	assetFetcher, err := assetFetcherComponent.New(context.Background(), config)

	assert.Equal(t, "http://localhost", assetFetcher.Host.String())
	assert.Equal(t, 5, assetFetcher.PageSize)
	assert.Nil(t, err)
}

func TestAssetFetcherConfigWithInvalidHost(t *testing.T) {
	assetFetcherComponent := AssetFetcherConfigComponent{}
	config := &AssetFetcherConfig{Host: "~!@#$%^&*()_+:?><!@#$%^&*())_:"}
	_, err := assetFetcherComponent.New(context.Background(), config)

	assert.Error(t, err)
}
