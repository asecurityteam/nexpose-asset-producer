package v1

import (
	"context"
	"fmt"
	"testing"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
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

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345", int64(1)).Return(assetChan, errChan)
	producer.EXPECT().Produce(gomock.Any(), gomock.Any()).Return(nil)

	handler := NexposeScannedAssetProducer{
		Producer:     producer,
		AssetFetcher: assetFetcher,
		LogFn:        func(ctx context.Context) domain.Logger { return NewMockLogger(mockCtrl) },
		StatFn:       MockStatFn,
	}

	scanInfo := ScanInfo{
		SiteID: "12345",
		ScanID: 1,
	}
	handler.Handle(context.Background(), scanInfo)
}

// This test not only handles testing multiple incoming assets, but also
// tests whether we have race conditions. The race conditions are related to
// the metric we want to keep track of and emit at the end of the Handle function
func TestNexposeAssetProducerHandlerMultipleAssets(t *testing.T) {
	const numberOfGoRoutines = 100
	const siteID string = "12345"
	const scanID int64 = 1

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	assetFetcher := NewMockAssetFetcher(mockCtrl)
	producer := NewMockProducer(mockCtrl)
	mockStatFn := NewMockStat(mockCtrl)

	assetChan := make(chan domain.AssetEvent, numberOfGoRoutines)
	errChan := make(chan error, 1)

	for i := 0; i < numberOfGoRoutines; i++ {
		assetChan <- domain.AssetEvent{ID: int64(i)}
	}

	close(assetChan)
	close(errChan)

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), siteID, scanID).Return(assetChan, errChan)
	producer.EXPECT().Produce(gomock.Any(), gomock.Any()).Return(nil).Times(numberOfGoRoutines)
	mockStatFn.EXPECT().Count("totalassetsproduced", float64(numberOfGoRoutines), fmt.Sprintf("site:%s", siteID)).Times(1)
	handler := NexposeScannedAssetProducer{
		Producer:     producer,
		AssetFetcher: assetFetcher,
		LogFn:        func(ctx context.Context) domain.Logger { return NewMockLogger(mockCtrl) },
		StatFn:       func(ctx context.Context) domain.Stat { return mockStatFn },
	}

	scanInfo := ScanInfo{
		SiteID: siteID,
		ScanID: 1,
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

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345", int64(1)).Return(assetChan, errChan)
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
		ScanID: 1,
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

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345", int64(1)).Return(assetChan, errChan)
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
		ScanID: 1,
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

	assetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345", int64(1)).Return(assetChan, errChan)
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
		ScanID: 1,
	}
	handler.Handle(context.Background(), scanInfo)
}
