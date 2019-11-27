package assetfetcher

import (
	"errors"
	"testing"
	"time"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	"github.com/stretchr/testify/assert"
)

func TestGetScanTime(t *testing.T) {
	tests := []struct {
		name          string
		asset         Asset
		expectedTime  time.Time
		expectedError error
	}{
		{
			"single event",
			Asset{ID: 1, IP: "127.0.0.1", History: assetHistoryEvents{AssetHistory{Type: "SCAN", ScanID: "1", Date: "2019-04-22T15:02:44.000Z"}}},
			time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
			nil,
		},
		{
			"multiple events with different ScanIDs",
			Asset{ID: 1, IP: "127.0.0.1", History: assetHistoryEvents{
				AssetHistory{Type: "SCAN", ScanID: "2", Date: "2018-04-22T15:02:44.000Z"},
				AssetHistory{Type: "SCAN", ScanID: "1", Date: "2019-04-22T15:02:44.000Z"},
			}},
			time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
			nil,
		},
		{
			"multiple events same ScanIDs different scan times",
			Asset{ID: 1, IP: "127.0.0.1", History: assetHistoryEvents{
				AssetHistory{Type: "SCAN", ScanID: "1", Date: "2019-04-22T15:02:44.000Z"},
				AssetHistory{Type: "SCAN", ScanID: "1", Date: "2018-04-22T15:02:44.000Z"},
			}},
			time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
			nil,
		},
		{
			"invalid date",
			Asset{ID: 1, IP: "127.0.0.1", History: assetHistoryEvents{
				AssetHistory{Type: "SCAN", ScanID: "1", Date: "iamnotadate"},
			}},
			time.Time{},
			&InvalidScanTime{ScanID: "1", ScanTime: time.Time{}, AssetID: 1, AssetIP: "127.0.0.1", AssetHostname: "", Inner: &time.ParseError{Value: "iamnotadate", Layout: time.RFC3339, ValueElem: "iamnotadate", LayoutElem: "2006"}}, //errors.New("parsing time \"iamnotadate\" as " + time.RFC3339 + ": cannot parse \"iamnotadate\" as \"2006\"")},
		},
		{
			"invalid time signature",
			Asset{ID: 1, IP: "127.0.0.1", History: assetHistoryEvents{
				AssetHistory{Type: "SCAN", ScanID: "1", Date: "2018-02-05 01:02:03 +1234 UTC"},
			}},
			time.Time{},
			&InvalidScanTime{ScanID: "1", ScanTime: time.Time{}, AssetID: 1, AssetIP: "127.0.0.1", AssetHostname: "", Inner: &time.ParseError{Value: "2018-02-05 01:02:03 +1234 UTC", Layout: time.RFC3339, ValueElem: " 01:02:03 +1234 UTC", LayoutElem: "T"}}, //errors.New("parsing time \"2018-02-05 01:02:03 +1234 UTC\" as " + time.RFC3339 + ": cannot parse \" 01:02:03 +1234 UTC\" as \"T\"")},
		},
		{
			"zero scan time",
			Asset{ID: 1, IP: "127.0.0.1", History: assetHistoryEvents{
				AssetHistory{Type: "SCAN", ScanID: "1", Date: "0001-01-01T00:00:00.000Z"},
			}},
			time.Time{},
			&InvalidScanTime{ScanID: "1", ScanTime: time.Time{}, AssetID: 1, AssetIP: "127.0.0.1", AssetHostname: "", Inner: errors.New("scan time is zero")},
		},
		{
			"non-scan type",
			Asset{ID: 1, IP: "127.0.0.1", History: assetHistoryEvents{AssetHistory{Type: "CREATE", ScanID: "1", Date: "2019-04-22T15:02:44.000Z"}}},
			time.Time{},
			&ScanIDForLastScanNotInAssetHistory{ScanID: "1", AssetID: 1, AssetIP: "127.0.0.1", AssetHostname: ""},
		},
		{
			"no matching ScanID",
			Asset{ID: 1, IP: "127.0.0.1", History: assetHistoryEvents{AssetHistory{Type: "SCAN", ScanID: "3", Date: "2019-04-22T15:02:44.000Z"}}},
			time.Time{},
			&ScanIDForLastScanNotInAssetHistory{ScanID: "1", AssetID: 1, AssetIP: "127.0.0.1", AssetHostname: ""},
		},
		{
			"no ScanID",
			Asset{ID: 1, IP: "127.0.0.1", History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"}}},
			time.Time{},
			&ScanIDForLastScanNotInAssetHistory{ScanID: "1", AssetID: 1, AssetIP: "127.0.0.1", AssetHostname: ""},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			scanTime, err := test.asset.GetScanTime("1")
			if err != nil {
				assert.Equal(t, test.expectedError.Error(), err.Error())
			}
			assert.Equal(t, test.expectedTime, scanTime)
		})
	}

}

func TestAssetPayloadToAssetEventError(t *testing.T) {
	tests := []struct {
		name                     string
		asset                    Asset
		expectedDomainAssetEvent domain.AssetEvent
		expectedError            bool
	}{
		{
			"success case",
			Asset{
				ID:       1,
				IP:       "127.0.0.1",
				HostName: "ec2-something-my-test-instance.com",
				History:  assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"}},
			},
			domain.AssetEvent{
				ID:       1,
				IP:       "127.0.0.1",
				Hostname: "ec2-something-my-test-instance.com",
				ScanTime: time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
			},
			false,
		},
		{
			"IP only",
			Asset{
				ID:      1,
				IP:      "127.0.0.1",
				History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"}},
			},
			domain.AssetEvent{
				ID:       1,
				IP:       "127.0.0.1",
				ScanTime: time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
			},
			false,
		},
		{
			"Hostname only",
			Asset{
				ID:       1,
				HostName: "ec2-something-my-test-instance.com",
				History:  assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-04-22T15:02:44.000Z"}},
			},
			domain.AssetEvent{
				ID:       1,
				Hostname: "ec2-something-my-test-instance.com",
				ScanTime: time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
			},
			false,
		},
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
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			assetEvent, err := test.asset.AssetPayloadToAssetEvent(time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC))
			assert.Equal(t, test.expectedDomainAssetEvent, assetEvent)
			assert.Equal(t, test.expectedError, err != nil)
		})
	}
}
