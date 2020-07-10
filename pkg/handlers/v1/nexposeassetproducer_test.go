package v1

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestNexposeAssetProducerHandler(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAssetFetcher := NewMockAssetFetcher(mockCtrl)
	mockAssetValidator := NewMockAssetValidator(mockCtrl)
	mockProducer := NewMockProducer(mockCtrl)

	asset := domain.Asset{
		ID: 12345,
	}

	assetEvent := domain.AssetEvent{ID: 12345}

	assetList := []domain.Asset{asset}
	validAssetList := []domain.AssetEvent{assetEvent}
	scanInfo := domain.ScanInfo{
		SiteID: "12345",
		ScanID: "1",
	}
	mockAssetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345").Return(assetList, nil)
	mockAssetValidator.EXPECT().ValidateAssets(gomock.Any(), assetList, scanInfo).Return(validAssetList, []error{})
	mockProducer.EXPECT().Produce(gomock.Any(), gomock.Any()).Return(nil)

	handler := NexposeScannedAssetProducer{
		Producer:       mockProducer,
		AssetFetcher:   mockAssetFetcher,
		AssetValidator: mockAssetValidator,
		LogFn:          func(ctx context.Context) domain.Logger { return NewMockLogger(mockCtrl) },
		StatFn:         MockStatFn,
	}

	err := handler.Handle(context.Background(), scanInfo)
	assert.Nil(t, err)
}

func TestNexposeAssetProducerHandlerMultipleAssets(t *testing.T) {
	const numberOFAssets = 100
	const siteID string = "12345"
	const scanID string = "1"

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAssetFetcher := NewMockAssetFetcher(mockCtrl)
	mockAssetValidator := NewMockAssetValidator(mockCtrl)
	mockProducer := NewMockProducer(mockCtrl)
	mockStatFn := NewMockStat(mockCtrl)

	assetList := []domain.Asset{}
	validAssetList := []domain.AssetEvent{}

	for i := 0; i < numberOFAssets; i++ {
		assetList = append(assetList, domain.Asset{ID: int64(i)})
		validAssetList = append(validAssetList, domain.AssetEvent{ID: int64(i)})

	}
	scanInfo := domain.ScanInfo{
		SiteID: siteID,
		ScanID: "1",
	}

	mockAssetFetcher.EXPECT().FetchAssets(gomock.Any(), siteID).Return(assetList, nil)
	mockAssetValidator.EXPECT().ValidateAssets(gomock.Any(), assetList, scanInfo).Return(validAssetList, []error{})
	mockProducer.EXPECT().Produce(gomock.Any(), gomock.Any()).Return(nil).Times(numberOFAssets)
	mockStatFn.EXPECT().Count("totalassets", float64(numberOFAssets), fmt.Sprintf("site:%s", siteID)).Times(1)
	mockStatFn.EXPECT().Count("totalassetsproduced", float64(numberOFAssets), fmt.Sprintf("site:%s", siteID)).Times(1)

	handler := NexposeScannedAssetProducer{
		Producer:       mockProducer,
		AssetFetcher:   mockAssetFetcher,
		AssetValidator: mockAssetValidator,
		LogFn:          func(ctx context.Context) domain.Logger { return NewMockLogger(mockCtrl) },
		StatFn:         func(ctx context.Context) domain.Stat { return mockStatFn },
	}

	err := handler.Handle(context.Background(), scanInfo)
	assert.Nil(t, err)
}

func TestNexposeAssetProducerHandlerError(t *testing.T) {
	const scanID string = "1"

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockLogger := NewMockLogger(mockCtrl)

	mockAssetFetcher := NewMockAssetFetcher(mockCtrl)
	mockAssetValidator := NewMockAssetValidator(mockCtrl)
	mockProducer := NewMockProducer(mockCtrl)
	asset := domain.Asset{
		ID: 12345,
	}

	assetEvent := domain.AssetEvent{ID: 12345}

	assetList := []domain.Asset{asset}
	validAssetList := []domain.AssetEvent{assetEvent}
	scanInfo := domain.ScanInfo{
		SiteID: "12345",
		ScanID: "1",
	}

	mockAssetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345").Return(assetList, nil)
	mockAssetValidator.EXPECT().ValidateAssets(gomock.Any(), assetList, scanInfo).Return(validAssetList, []error{})
	mockProducer.EXPECT().Produce(gomock.Any(), gomock.Any()).Return(errors.New("i am error"))
	mockLogger.EXPECT().Error(gomock.Any())

	handler := NexposeScannedAssetProducer{
		Producer:       mockProducer,
		AssetFetcher:   mockAssetFetcher,
		AssetValidator: mockAssetValidator,
		LogFn:          func(ctx context.Context) domain.Logger { return mockLogger },
		StatFn:         MockStatFn,
	}

	err := handler.Handle(context.Background(), scanInfo)
	assert.Nil(t, err)
}

func TestNexposeAssetProducerHandlerFetchFailure(t *testing.T) {

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockLogger := NewMockLogger(mockCtrl)

	mockAssetFetcher := NewMockAssetFetcher(mockCtrl)
	mockAssetValidator := NewMockAssetValidator(mockCtrl)
	mockProducer := NewMockProducer(mockCtrl)

	asset := domain.Asset{
		ID: 12345,
	}
	assetList := []domain.Asset{asset}

	mockAssetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345").Return(assetList, &domain.ErrorFetchingAssets{Inner: errors.New("i am error")})
	mockLogger.EXPECT().Error(gomock.Any())

	handler := NexposeScannedAssetProducer{
		Producer:       mockProducer,
		AssetFetcher:   mockAssetFetcher,
		AssetValidator: mockAssetValidator,
		LogFn:          func(ctx context.Context) domain.Logger { return mockLogger },
		StatFn:         MockStatFn,
	}

	scanInfo := domain.ScanInfo{
		SiteID: "12345",
		ScanID: "1",
	}
	err := handler.Handle(context.Background(), scanInfo)
	assert.NotNil(t, err)
}

func TestNexposeAssetProducerHandlerMultipleErrors(t *testing.T) {
	const scanID string = "1"

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockLogger := NewMockLogger(mockCtrl)

	mockAssetFetcher := NewMockAssetFetcher(mockCtrl)
	mockAssetValidator := NewMockAssetValidator(mockCtrl)
	mockProducer := NewMockProducer(mockCtrl)
	asset := domain.Asset{
		ID: 12345,
	}

	assetList := []domain.Asset{asset}
	validAssetList := []domain.AssetEvent{}
	scanInfo := domain.ScanInfo{
		SiteID: "12345",
		ScanID: "1",
	}
	errorList := []error{&domain.ScanIDForLastScanNotInAssetHistory{}, &domain.InvalidScanTime{}, &domain.MissingRequiredInformation{}, errors.New("unknown")}

	mockAssetFetcher.EXPECT().FetchAssets(gomock.Any(), "12345").Return(assetList, nil)
	mockAssetValidator.EXPECT().ValidateAssets(gomock.Any(), assetList, scanInfo).Return(validAssetList, errorList)

	handler := NexposeScannedAssetProducer{
		Producer:       mockProducer,
		AssetFetcher:   mockAssetFetcher,
		AssetValidator: mockAssetValidator,
		LogFn:          func(ctx context.Context) domain.Logger { return mockLogger },
		StatFn:         MockStatFn,
	}

	err := handler.Handle(context.Background(), scanInfo)
	assert.Nil(t, err)
}
