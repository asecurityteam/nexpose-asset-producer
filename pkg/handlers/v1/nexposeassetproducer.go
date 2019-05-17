package v1

import (
	"context"

	"sync"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	"github.com/asecurityteam/nexpose-asset-producer/pkg/logs"
)

// ScanInfo represents the fields we want from the incoming payload
type ScanInfo struct {
	// SiteID is the ID of the site that just got scanned
	SiteID string `json:"site_id"`
}

// NexposeScannedAssetProducer is a lambda handler that fetches Nexpose Assets and sends them to an event stream
type NexposeScannedAssetProducer struct {
	Producer     domain.Producer
	AssetFetcher domain.AssetFetcher
	LogFn        domain.LogFn
	StatFn       domain.StatFn
}

// Handle is an AWS Lambda handler that takes in a SiteID for a Nexpose scan that has completed,
// get all the assets in the site that was scanned and produces each asset to a stream
func (h *NexposeScannedAssetProducer) Handle(ctx context.Context, in ScanInfo) {
	logger := h.LogFn(ctx)
	stater := h.StatFn(ctx)

	assetChan, errChan := h.AssetFetcher.FetchAssets(ctx, in.SiteID)

	wg := sync.WaitGroup{}
	for {
		select {
		case asset, ok := <-assetChan:
			if !ok {
				assetChan = nil
			} else {
				stater.Count("assetreceived.success", 1)
				wg.Add(1)
				go func(ctx context.Context, asset domain.AssetEvent) {
					defer wg.Done()
					err := h.Producer.Produce(ctx, asset)
					if err != nil {
						logger.Error(logs.ProducerFailure{
							Reason: err.Error(),
						})
					}
				}(ctx, asset)
			}
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
			} else {
				stater.Count("assetfetch.error", 1)
				logger.Error(logs.AssetFetchFail{
					Reason: err.Error(),
				})
			}
		}
		if assetChan == nil && errChan == nil {
			break
		}
	}
	wg.Wait()
}