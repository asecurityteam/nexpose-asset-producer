package v1

import (
	"context"
	"testing"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/assetfetcher"
	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	"github.com/asecurityteam/nexpose-asset-producer/pkg/logs"
	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
)

func TestNexposeAssetProducerHandler(t *testing.T) {
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

	handler := NexposeScannedAssetProducer{
		Producer:     producer,
		AssetFetcher: assetFetcher,
		LogFn:        func(ctx context.Context) domain.Logger { return NewMockLogger(mockCtrl) },
		StatFn:       MockStatFn,
	}

	scanInfo := ScanInfo{
		SiteID: "12345",
	}
	handler.Handle(context.Background(), scanInfo)
}

func TestNexposeEmptyAssetDoesNotProduce(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockLogger := NewMockLogger(mockCtrl)

	assetFetcher := NewMockAssetFetcher(mockCtrl)
	producer := NewMockProducer(mockCtrl)

	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)

	asset := domain.AssetEvent{}
	err := &assetfetcher.ErrorConvertingAssetPayload{
		AssetID: 0,
		Inner:   &assetfetcher.MissingRequiredFields{},
	}

	assetChan <- asset
	errChan <- err
	close(assetChan)
	close(errChan)

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345").Return(assetChan, errChan)
	producer.EXPECT().Produce(gomock.Any(), gomock.Any()).Times(0)
	mockLogger.EXPECT().Error(logs.AssetFetchFail{Reason: err.Error()})

	handler := NexposeScannedAssetProducer{
		Producer:     producer,
		AssetFetcher: assetFetcher,
		LogFn:        func(ctx context.Context) domain.Logger { return mockLogger },
		StatFn:       MockStatFn,
	}

	scanInfo := ScanInfo{
		SiteID: "12345",
	}
	handler.Handle(context.Background(), scanInfo)
}

func TestNexposeAssetProducerHandlerMultipleAssets(t *testing.T) {
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

	handler := NexposeScannedAssetProducer{
		Producer:     producer,
		AssetFetcher: assetFetcher,
		LogFn:        func(ctx context.Context) domain.Logger { return NewMockLogger(mockCtrl) },
		StatFn:       MockStatFn,
	}

	scanInfo := ScanInfo{
		SiteID: "12345",
	}
	handler.Handle(context.Background(), scanInfo)
}

func TestNexposeAssetProducerHandlerError(t *testing.T) {
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

	handler := NexposeScannedAssetProducer{
		Producer:     producer,
		AssetFetcher: assetFetcher,
		LogFn:        func(ctx context.Context) domain.Logger { return mockLogger },
		StatFn:       MockStatFn,
	}

	scanInfo := ScanInfo{
		SiteID: "12345",
	}
	handler.Handle(context.Background(), scanInfo)
}

func TestNexposeAssetProducerHandlerWithAssetsAndErrors(t *testing.T) {
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

	handler := NexposeScannedAssetProducer{
		Producer:     producer,
		AssetFetcher: assetFetcher,
		LogFn:        func(ctx context.Context) domain.Logger { return mockLogger },
		StatFn:       MockStatFn,
	}

	scanInfo := ScanInfo{
		SiteID: "12345",
	}
	handler.Handle(context.Background(), scanInfo)
}

func TestNexposeAssetProducerHandlerProducerError(t *testing.T) {
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

	handler := NexposeScannedAssetProducer{
		Producer:     producer,
		AssetFetcher: assetFetcher,
		LogFn:        func(ctx context.Context) domain.Logger { return mockLogger },
		StatFn:       MockStatFn,
	}

	scanInfo := ScanInfo{
		SiteID: "12345",
	}
	handler.Handle(context.Background(), scanInfo)
}
