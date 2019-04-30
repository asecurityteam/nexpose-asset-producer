package v1

import (
	"context"
	"io/ioutil"
	"testing"

	"github.com/asecurityteam/logevent"
	"github.com/asecurityteam/runhttp"
	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/assetfetcher"
)

func TestNexposeVulnNotificationHandler(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	assetFetcher := NewMockAssetFetcher(mockCtrl)
	producer := NewMockProducer(mockCtrl)

	assetChan := make(chan assetfetcher.Asset, 1)
	errChan := make(chan error, 1)

	asset := assetfetcher.Asset{
		ID: 12345,
	}

	assetChan <- asset
	close(assetChan)
	close(errChan)

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345").Return(assetChan, errChan)
	producer.EXPECT().Produce(gomock.Any(), gomock.Any()).Return(nil)

	handler := NexposeVulnNotificationHandler{
		Producer:     producer,
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

func TestNexposeVulnNotificationHandlerMultipleAssets(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	assetFetcher := NewMockAssetFetcher(mockCtrl)
	producer := NewMockProducer(mockCtrl)

	assetChan := make(chan assetfetcher.Asset, 2)
	errChan := make(chan error, 1)

	asset := assetfetcher.Asset{ID: 12345}
	asset2 := assetfetcher.Asset{ID: 56789}

	assetChan <- asset
	assetChan <- asset2
	close(assetChan)
	close(errChan)

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345").Return(assetChan, errChan)
	producer.EXPECT().Produce(gomock.Any(), gomock.Any()).Return(nil).Times(2)

	handler := NexposeVulnNotificationHandler{
		Producer:     producer,
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

func TestNexposeVulnNotificationHandlerError(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	assetFetcher := NewMockAssetFetcher(mockCtrl)
	producer := NewMockProducer(mockCtrl)

	assetChan := make(chan assetfetcher.Asset, 1)
	errChan := make(chan error, 1)

	errChan <- errors.New("myError")
	close(assetChan)
	close(errChan)

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345").Return(assetChan, errChan)
	producer.EXPECT().Produce(gomock.Any(), gomock.Any()).Return(nil).Times(0)

	handler := NexposeVulnNotificationHandler{
		Producer:     producer,
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

func TestNexposeVulnNotificationHandlerWithAssetsAndErrors(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	assetFetcher := NewMockAssetFetcher(mockCtrl)
	producer := NewMockProducer(mockCtrl)

	assetChan := make(chan assetfetcher.Asset, 2)
	errChan := make(chan error, 1)

	asset := assetfetcher.Asset{ID: 12345}
	asset2 := assetfetcher.Asset{ID: 56789}
	err := errors.New("myError")

	assetChan <- asset
	assetChan <- asset2
	errChan <- err
	close(assetChan)
	close(errChan)

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345").Return(assetChan, errChan)
	producer.EXPECT().Produce(gomock.Any(), gomock.Any()).Return(nil).Times(2)

	handler := NexposeVulnNotificationHandler{
		Producer:     producer,
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
