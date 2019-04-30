package v1

import (
	"context"
	"io/ioutil"
	"testing"

	"github.com/asecurityteam/logevent"
	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain"
	"github.com/asecurityteam/runhttp"
	"github.com/golang/mock/gomock"
)

func TestNexposeVulnNotificationHandler(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	assetFetcher := NewMockAssetFetcher(mockCtrl)

	assetChan := make(chan domain.AssetEvent)
	errChan := make(chan error)

	asset := domain.AssetEvent{
		ID: 12345,
	}

	go func() {
		assetChan <- asset
		close(assetChan)
		close(errChan)
	}()

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345").Return(assetChan, errChan)

	handler := NexposeVulnNotificationHandler{
		AssetFetcher: assetFetcher,
		LogFn:        runhttp.LoggerFromContext,
		StatFn:       runhttp.StatFromContext,
	}

	ctx := logevent.NewContext(context.Background(), logevent.New(logevent.Config{Output: ioutil.Discard}))
	scanInfo := ScanInfo{
		SiteID: "12345",
	}
	handler.Handle(ctx, scanInfo)

}
