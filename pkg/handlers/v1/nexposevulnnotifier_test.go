package v1

import (
	"context"
	"io/ioutil"
	"testing"

	"github.com/asecurityteam/logevent"
	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain"
	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
)

func TestNexposeVulnNotificationHandler(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	assetFetcher := NewMockAssetFetcher(mockCtrl)
	producer := NewMockProducer(mockCtrl)

	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)

	asset := domain.AssetEvent{
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
		LogFn:        func(ctx context.Context) domain.Logger { return NewMockLogger(mockCtrl) },
		StatFn:       MockStatFn,
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

	assetChan := make(chan domain.AssetEvent, 2)
	errChan := make(chan error, 1)

	asset := domain.AssetEvent{ID: 12345}
	asset2 := domain.AssetEvent{ID: 56789}

	assetChan <- asset
	assetChan <- asset2
	close(assetChan)
	close(errChan)

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345").Return(assetChan, errChan)
	producer.EXPECT().Produce(gomock.Any(), gomock.Any()).Return(nil).Times(2)

	handler := NexposeVulnNotificationHandler{
		Producer:     producer,
		AssetFetcher: assetFetcher,
		LogFn:        func(ctx context.Context) domain.Logger { return NewMockLogger(mockCtrl) },
		StatFn:       MockStatFn,
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
	mockLogger := NewMockLogger(mockCtrl)

	assetFetcher := NewMockAssetFetcher(mockCtrl)
	producer := NewMockProducer(mockCtrl)

	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)

	errChan <- errors.New("myError")
	close(assetChan)
	close(errChan)

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345").Return(assetChan, errChan)
	producer.EXPECT().Produce(gomock.Any(), gomock.Any()).Return(nil).Times(0)
	mockLogger.EXPECT().Error(gomock.Any())

	handler := NexposeVulnNotificationHandler{
		Producer:     producer,
		AssetFetcher: assetFetcher,
		LogFn:        func(ctx context.Context) domain.Logger { return mockLogger },
		StatFn:       MockStatFn,
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
	mockLogger := NewMockLogger(mockCtrl)

	assetFetcher := NewMockAssetFetcher(mockCtrl)
	producer := NewMockProducer(mockCtrl)

	assetChan := make(chan domain.AssetEvent, 2)
	errChan := make(chan error, 1)

	asset := domain.AssetEvent{ID: 12345}
	asset2 := domain.AssetEvent{ID: 56789}
	err := errors.New("myError")

	assetChan <- asset
	assetChan <- asset2
	errChan <- err
	close(assetChan)
	close(errChan)

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345").Return(assetChan, errChan)
	producer.EXPECT().Produce(gomock.Any(), gomock.Any()).Return(nil).Times(2)
	mockLogger.EXPECT().Error(gomock.Any())

	handler := NexposeVulnNotificationHandler{
		Producer:     producer,
		AssetFetcher: assetFetcher,
		LogFn:        func(ctx context.Context) domain.Logger { return mockLogger },
		StatFn:       MockStatFn,
	}

	ctx := logevent.NewContext(context.Background(), logevent.New(logevent.Config{Output: ioutil.Discard}))
	scanInfo := ScanInfo{
		SiteID: "12345",
	}
	handler.Handle(ctx, scanInfo)
}

func TestNexposeVulnNotificationHandlerProducerError(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockLogger := NewMockLogger(mockCtrl)

	assetFetcher := NewMockAssetFetcher(mockCtrl)
	producer := NewMockProducer(mockCtrl)

	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)

	asset := domain.AssetEvent{
		ID: 12345,
	}

	assetChan <- asset
	close(assetChan)
	close(errChan)

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345").Return(assetChan, errChan)
	producer.EXPECT().Produce(gomock.Any(), gomock.Any()).Return(errors.New("HTTPError"))
	mockLogger.EXPECT().Error(gomock.Any())

	handler := NexposeVulnNotificationHandler{
		Producer:     producer,
		AssetFetcher: assetFetcher,
		LogFn:        func(ctx context.Context) domain.Logger { return mockLogger },
		StatFn:       MockStatFn,
	}

	ctx := logevent.NewContext(context.Background(), logevent.New(logevent.Config{Output: ioutil.Discard}))
	scanInfo := ScanInfo{
		SiteID: "12345",
	}
	handler.Handle(ctx, scanInfo)
}
