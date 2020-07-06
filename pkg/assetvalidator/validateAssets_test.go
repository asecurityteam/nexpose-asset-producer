package assetvalidator

import (
	"context"
	"testing"
	"time"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	"github.com/stretchr/testify/assert"
)

func TestAssetValidation(t *testing.T) {

	nowish, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	tests := []struct {
		name                         string
		assetList                    []domain.Asset
		expectedDomainAssetEventList []domain.AssetEvent
		expectedErrorList            []error
	}{
		{
			"success case",
			[]domain.Asset{
				{
					ID:       1,
					IP:       "127.0.0.1",
					HostName: "ec2-something-my-test-instance.com",
					History:  domain.AssetHistoryEvents{domain.AssetHistory{Type: "SCAN", ScanID: 6, Date: "2019-04-22T15:02:44.000Z"}},
				},
				{
					ID:       2,
					IP:       "127.0.0.2",
					HostName: "ec2-something-my-test-instance2.com",
					History:  domain.AssetHistoryEvents{domain.AssetHistory{Type: "SCAN", ScanID: 6, Date: "2019-04-22T15:02:44.000Z"}},
				},
			},
			[]domain.AssetEvent{
				{
					ID:       1,
					IP:       "127.0.0.1",
					Hostname: "ec2-something-my-test-instance.com",
					ScanTime: time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
					ScanType: "remote",
				},
				{
					ID:       2,
					IP:       "127.0.0.2",
					Hostname: "ec2-something-my-test-instance2.com",
					ScanTime: time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
					ScanType: "remote",
				},
			},
			[]error{},
		},
		{
			"IP only case",
			[]domain.Asset{
				{
					ID:      1,
					IP:      "127.0.0.1",
					History: domain.AssetHistoryEvents{domain.AssetHistory{Type: "SCAN", ScanID: 6, Date: "2019-04-22T15:02:44.000Z"}},
				},
				{
					ID:      2,
					IP:      "127.0.0.2",
					History: domain.AssetHistoryEvents{domain.AssetHistory{Type: "SCAN", ScanID: 6, Date: "2019-04-22T15:02:44.000Z"}},
				},
			},
			[]domain.AssetEvent{
				{
					ID:       1,
					IP:       "127.0.0.1",
					ScanTime: time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
					ScanType: "remote",
				},
				{
					ID:       2,
					IP:       "127.0.0.2",
					ScanTime: time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
					ScanType: "remote",
				},
			},
			[]error{},
		},
		{
			"Hostname only case",
			[]domain.Asset{
				{
					ID:       1,
					HostName: "ec2-something-my-test-instance.com",
					History:  domain.AssetHistoryEvents{domain.AssetHistory{Type: "SCAN", ScanID: 6, Date: "2019-04-22T15:02:44.000Z"}},
				},
				{
					ID:       2,
					HostName: "ec2-something-my-test-instance2.com",
					History:  domain.AssetHistoryEvents{domain.AssetHistory{Type: "SCAN", ScanID: 6, Date: "2019-04-22T15:02:44.000Z"}},
				},
			},
			[]domain.AssetEvent{
				{
					ID:       1,
					Hostname: "ec2-something-my-test-instance.com",
					ScanTime: time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
					ScanType: "remote",
				},
				{
					ID:       2,
					Hostname: "ec2-something-my-test-instance2.com",
					ScanTime: time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
					ScanType: "remote",
				},
			},
			[]error{},
		},
		{
			"No ID or no Host and IP",
			[]domain.Asset{
				{
					History: domain.AssetHistoryEvents{domain.AssetHistory{Type: "SCAN", ScanID: 6, Date: "2019-04-22T15:02:44.000Z"}},
				},
				{
					ID:      2,
					History: domain.AssetHistoryEvents{domain.AssetHistory{Type: "SCAN", ScanID: 6, Date: "2019-04-22T15:02:44.000Z"}},
				},
			},
			[]domain.AssetEvent{},
			[]error{
				&domain.MissingRequiredInformation{
					AssetID:       0,
					AssetIP:       "",
					AssetHostname: "",
				},
				&domain.MissingRequiredInformation{
					AssetID:       2,
					AssetIP:       "",
					AssetHostname: "",
				},
			},
		},

		{
			"no scan type case",
			[]domain.Asset{
				{
					ID:       1,
					IP:       "127.0.0.1",
					HostName: "ec2-something-my-test-instance.com",
					History:  domain.AssetHistoryEvents{domain.AssetHistory{Type: "CREATE", ScanID: 6, Date: "2019-04-22T15:02:44.000Z"}},
				},
			},
			[]domain.AssetEvent{},
			[]error{
				&domain.ScanIDForLastScanNotInAssetHistory{
					AssetID:       1,
					ScanID:        "6",
					AssetIP:       "127.0.0.1",
					AssetHostname: "ec2-something-my-test-instance.com",
				},
			},
		},
		{
			"agent scan success case",
			[]domain.Asset{
				{
					ID:       1,
					IP:       "127.0.0.1",
					HostName: "ec2-something-my-test-instance.com",
					History:  domain.AssetHistoryEvents{domain.AssetHistory{Type: "SCAN", ScanID: 6, Date: "2019-04-22T15:02:44.000Z"}},
				},
				{
					ID:       2,
					IP:       "127.0.0.2",
					HostName: "ec2-something-my-test-instance2.com",
					History:  domain.AssetHistoryEvents{domain.AssetHistory{Type: "AGENT-IMPORT", ScanID: 6, Date: nowish.Format(time.RFC3339)}},
				},
			},
			[]domain.AssetEvent{
				{
					ID:       1,
					IP:       "127.0.0.1",
					Hostname: "ec2-something-my-test-instance.com",
					ScanTime: time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
					ScanType: "remote",
				},
				{
					ID:       2,
					IP:       "127.0.0.2",
					Hostname: "ec2-something-my-test-instance2.com",
					ScanTime: nowish,
					ScanType: "local",
				},
			},
			[]error{},
		},
		{
			"agent scan failure case",
			[]domain.Asset{
				{
					ID:       1,
					IP:       "127.0.0.1",
					HostName: "ec2-something-my-test-instance.com",
					History:  domain.AssetHistoryEvents{domain.AssetHistory{Type: "SCAN", ScanID: 6, Date: "2019-04-22T15:02:44.000Z"}},
				},
				{
					ID:       2,
					IP:       "127.0.0.2",
					HostName: "ec2-something-my-test-instance2.com",
					History:  domain.AssetHistoryEvents{domain.AssetHistory{Type: "AGENT-IMPORT", ScanID: 6, Date: "2019-04-22T15:02:44.000Z"}},
				},
			},
			[]domain.AssetEvent{
				{
					ID:       1,
					IP:       "127.0.0.1",
					Hostname: "ec2-something-my-test-instance.com",
					ScanTime: time.Date(2019, time.April, 22, 15, 2, 44, 0, time.UTC),
					ScanType: "remote",
				},
			},
			[]error{
				&domain.ScanIDForLastScanNotInAssetHistory{
					AssetID:       2,
					ScanID:        "6",
					AssetIP:       "127.0.0.2",
					AssetHostname: "ec2-something-my-test-instance2.com",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			validator := NexposeAssetValidator{}
			assetEventList, errorList := validator.ValidateAssets(context.Background(), test.assetList, "6")
			assert.Equal(t, test.expectedDomainAssetEventList, assetEventList)
			assert.Equal(t, test.expectedErrorList, errorList)
		})
	}
}
