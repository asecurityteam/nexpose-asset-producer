package v1

import (
	"context"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain"
)

// ScanInfo represents the incoming payload
type ScanInfo struct {
	// ScanID is the ID of the completed scan whose vulnerabilities we'll process
	ScanID string `json:"scan_id"`
	// SiteID is the ID of the site that just got scanned
	SiteID string `json:"site_id"`
}

// NexposeVulnNotificationHandler is a lambda handler that fetches Nexpose Assets and sends them to an event stream
type NexposeVulnNotificationHandler struct {
	AssetFetcher domain.AssetFetcher
	LogFn        domain.LogFn
	StatFn       domain.StatFn
}

// Handle is an AWS Lambda handler that takes in a ScanID and SiteID for a Nexpose scan that has completed,
// get all the Assets in the site that was scanned, hydrates the asset with the vulnerabilities that were found
// on that asset and publishes the asset to a stream
func (h *NexposeVulnNotificationHandler) Handle(ctx context.Context, in ScanInfo) {
	logger := h.LogFn(ctx)

	assetChan, errChan := h.AssetFetcher.FetchAssets(ctx, in.SiteID)

	// this loop currently logs when it receives an asset or error from their respective channels
	// The future issues will take these assets and use them to call Nexpose again to get heir vulnerabilities
	for {
		select {
		case _, ok := <-assetChan:
			if !ok {
				assetChan = nil
			} else {
				logger.Info("Got an asset off the channel")
			}
		case _, ok := <-errChan:
			if !ok {
				errChan = nil
			} else {
				logger.Info("Got an error off the channel")
			}
		}
		if assetChan == nil && errChan == nil {
			break
		}
	}

	// TODO: SECD-441
	// for each asset:
	//   get the list of vulnerabilities for that asset /api/3/assets/{id}/vulnerabilities and
	//   for each vulnerability on the asset:
	//     get the complete vulnerability information /api/3/vulnerabilities/{id}

	// TODO: SECD-442
	// once the asset is hydrated with the vulnerability details, publish it to the queue

}
