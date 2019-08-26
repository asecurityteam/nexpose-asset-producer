package assetfetcher

import (
	"testing"
	"time"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	"github.com/stretchr/testify/assert"
)

func TestLastAssessedForVulnerabilities(t *testing.T) {
	tests := []struct {
		name     string
		history  assetHistoryEvents
		expected time.Time
	}{
		{
			"single event",
			assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"}},
			time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
		},
		{
			"multiple events in chronological order",
			assetHistoryEvents{
				AssetHistory{Type: "SCAN", Date: "2018-04-22T15:02:44.000Z"},
				AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"},
			},
			time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
		},
		{
			"multiple events in non-chronological order",
			assetHistoryEvents{
				AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"},
				AssetHistory{Type: "SCAN", Date: "2018-04-22T15:02:44.000Z"},
			},
			time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
		},
		{
			"invalid date",
			assetHistoryEvents{
				AssetHistory{Type: "SCAN", Date: "iamnotadate"},
			},
			time.Time{},
		},
		{
			"invalid time signature",
			assetHistoryEvents{
				AssetHistory{Type: "SCAN", Date: "2018-02-05 01:02:03 +1234 UTC"},
			},
			time.Time{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			lastAssessed := test.history.verifyAndGetLastScanned()
			assert.Equal(t, test.expected, lastAssessed)
		})
	}

}

func TestAssetPayloadToAssetEventSuccess(t *testing.T) {
	date := time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC)
	asset := Asset{
		ID:      1,
		IP:      "127.0.0.1",
		History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"}},
	}
	expectedAssetEvent := domain.AssetEvent{
		ID:          1,
		IP:          "127.0.0.1",
		LastScanned: date,
	}

	assetEvent, err := asset.AssetPayloadToAssetEvent()
	assert.NoError(t, err)
	assert.Equal(t, expectedAssetEvent, assetEvent)
}

func TestAssetPayloadToAssetEventError(t *testing.T) {
	tests := []struct {
		name                     string
		asset                    Asset
		expectedDomainAssetEvent domain.AssetEvent
		expectedError            bool
	}{
		{
			"No ID",
			Asset{
				IP:      "127.0.0.1",
				History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"}},
			},
			domain.AssetEvent{},
			true,
		},
		{
			"No IP or Hostname",
			Asset{
				History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"}},
			},
			domain.AssetEvent{},
			true,
		},
		{
			"No LastScanned",
			Asset{
				ID:      1,
				IP:      "127.0.0.1",
				History: assetHistoryEvents{AssetHistory{Type: "CREATE", Date: "2019-04-22T15:02:44.000Z"}},
			},
			domain.AssetEvent{},
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			assetEvent, err := test.asset.AssetPayloadToAssetEvent()
			assert.Equal(t, test.expectedDomainAssetEvent, assetEvent)
			assert.Equal(t, test.expectedError, err != nil)
		})
	}
}

// check if we do indeed receive a asset history with an invalid history
// AssetPayloadToAssetEvent never should receive an invalid asset history,
// this test is more so to have coverage, and make sure we do catch this in the event
func TestAssetPayloadToAssetEventLastScannedError(t *testing.T) {
	tests := []struct {
		name  string
		asset Asset
	}{
		{
			"No ID",
			Asset{
				IP:      "127.0.0.1",
				History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "invalid date time stamp"}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			assetEvent, err := test.asset.AssetPayloadToAssetEvent()
			assert.Equal(t, domain.AssetEvent{}, assetEvent)
			assert.NotNil(t, err)

		})
	}
}
