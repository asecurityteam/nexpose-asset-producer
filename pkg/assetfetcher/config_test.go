package assetfetcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestName(t *testing.T) {
	assetFetcherConfig := AssetFetcherConfig{}
	assert.Equal(t, "Nexpose", assetFetcherConfig.Name())
}
