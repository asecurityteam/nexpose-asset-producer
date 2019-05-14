package assetfetcher

import (
	"testing"
	"time"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	"github.com/stretchr/testify/assert"
)

func TestLastAssessedForVulnerabilities(t *testing.T) {
	tests := []struct {
		name        string
		history     assetHistoryEvents
		expected    time.Time
		expectedErr bool
	}{
		{
			"single event",
			assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"}},
			time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
			false,
		},
		{
			"multiple events in chronological order",
			assetHistoryEvents{
				AssetHistory{Type: "SCAN", Date: "2018-04-22T15:02:44.000Z"},
				AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"},
			},
			time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
			false,
		},
		{
			"multiple events in non-chronological order",
			assetHistoryEvents{
				AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"},
				AssetHistory{Type: "SCAN", Date: "2018-04-22T15:02:44.000Z"},
			},
			time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
			false,
		},
		{
			"invalid date",
			assetHistoryEvents{
				AssetHistory{Type: "SCAN", Date: "iamnotadate"},
			},
			time.Time{},
			true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			lastAssessed, err := test.history.lastScannedTimestamp()
			assert.Equal(t, test.expected, lastAssessed)
			assert.Equal(t, test.expectedErr, err != nil)
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
		name  string
		asset Asset
	}{
		{
			"No ID",
			Asset{
				IP:      "127.0.0.1",
				History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"}},
			},
		},
		{
			"No IP",
			Asset{
				ID:      1,
				History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"}},
			},
		},
		{
			"No LastScanned",
			Asset{
				ID: 1,
				IP: "127.0.0.1",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			_, err := test.asset.AssetPayloadToAssetEvent()
			lastScanned, _ := test.asset.History.lastScannedTimestamp()
			assert.Equal(t, &MissingRequiredFields{test.asset.ID, test.asset.IP, lastScanned}, err)

		})
	}
}
