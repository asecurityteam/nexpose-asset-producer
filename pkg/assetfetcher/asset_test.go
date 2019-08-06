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
		{
			"empty timestamp field",
			assetHistoryEvents{
				AssetHistory{Type: "SCAN", Date: ""},
			},
			time.Time{},
			true,
		},
		{
			"0 timestamp field",
			assetHistoryEvents{
				AssetHistory{Type: "SCAN", Date: "0001-01-01T00:00:00Z"},
			},
			time.Time{},
			false,
		},
		{
			"invalid time signature",
			assetHistoryEvents{
				AssetHistory{Type: "SCAN", Date: "2018-02-05 01:02:03 +1234 UTC"},
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
			"No IP or Hostname",
			Asset{
				History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			_, err := test.asset.AssetPayloadToAssetEvent()
			lastScanned, _ := test.asset.History.lastScannedTimestamp()
			assert.Equal(t, &MissingRequiredFields{test.asset.ID, test.asset.IP, test.asset.HostName, lastScanned}, err)

		})
	}
}

func TestAssetPayloadToAssetEventErrorNeverBeenScanned(t *testing.T) {
	tests := []struct {
		name  string
		asset Asset
	}{
		{
			"No LastScanned",
			Asset{
				ID: 1,
				IP: "127.0.0.1",
			},
		},
		{
			"Never been scanned",
			Asset{
				ID:      1,
				IP:      "127.0.0.1",
				History: assetHistoryEvents{AssetHistory{Type: "ASSET-IMPORT", Date: "2019-04-22T15:02:44.000Z"}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			// per the AssetPayloadToAssetEvent docs, callers should only call the function
			// when the Asset can be cleanly mapped.  The two test structs cannot, but this
			// test remains to ensure the function handles such a case appropriately
			_, err := test.asset.AssetPayloadToAssetEvent()
			var lastScanned time.Time // intentionally empty
			assert.Equal(t, &MissingRequiredFields{test.asset.ID, test.asset.IP, test.asset.HostName, lastScanned}, err)
		})
	}
}
