package v1

import (
	"context"
	"fmt"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	"github.com/asecurityteam/nexpose-asset-producer/pkg/logs"
)

// NexposeScannedAssetProducer is a lambda handler that fetches Nexpose Assets and sends them to an event stream
type NexposeScannedAssetProducer struct {
	Producer       domain.Producer
	AssetFetcher   domain.AssetFetcher
	AssetValidator domain.AssetValidator
	LogFn          domain.LogFn
	StatFn         domain.StatFn
}

// Handle is an AWS Lambda handler that takes in a SiteID for a Nexpose scan that has completed,
// get all the assets in the site that was scanned and produces each asset to a stream
func (h *NexposeScannedAssetProducer) Handle(ctx context.Context, in domain.ScanInfo) error {
	logger := h.LogFn(ctx)
	stater := h.StatFn(ctx)
	totalAssets, fetchError := h.AssetFetcher.FetchAssets(ctx, in.SiteID)
	if fetchError != nil {
		switch fetchError.(type) {
		case *domain.ErrorFetchingAssets:
			fetchError := fetchError.(*domain.ErrorFetchingAssets)
			logger.Error(logs.AssetFetchFail{Message: fetchError.Error(), Reason: fetchError.Inner.Error(), Page: fetchError.Page, SiteID: in.SiteID})
		default:
			logger.Error(logs.AssetFetchFail{Reason: fetchError.Error(), SiteID: in.SiteID})
		}
		return fetchError
	}
	stater.Count("totalassets", float64(len(totalAssets)), fmt.Sprintf("site:%s", in.SiteID))

	var totalAssetsProduced float64
	validAssets, _ := h.AssetValidator.ValidateAssets(ctx, totalAssets, in)
	for _, validAsset := range validAssets {
		err := h.Producer.Produce(ctx, validAsset)
		if err != nil {
			stater.Count("producerfailure", 1, fmt.Sprintf("site:%s", in.SiteID))
			logger.Error(logs.ProducerFailure{
				Reason:  err.Error(),
				SiteID:  in.SiteID,
				AssetID: validAsset.ID,
			})
			continue
		}
		totalAssetsProduced++

	}
	stater.Count("totalassetsproduced", totalAssetsProduced, fmt.Sprintf("site:%s", in.SiteID))

	return nil
}
