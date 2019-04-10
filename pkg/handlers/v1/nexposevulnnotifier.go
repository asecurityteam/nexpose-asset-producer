package v1

import (
	"context"
	"fmt"
	"net/http"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain"
	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/assetFetcher"
)

// ScanInfo represents the incoming payload
type ScanInfo struct {
	// ScanID is the ID of the completed scan whose vulnerabilities we'll process
	ScanID string `json:"scan_id"`
	// SiteID is the ID of the site that just got scanned
	SiteID string `json:"site_id"`
}

// Processor is a lambda handler that fetches Nexpose Vulns and sends them off to an event stream
type NexposeVulnNotificationHandler struct {
	NexposeHTTPClient *http.Client
	NexposeHost string
	NexposeAssetPageSize int
	LogFn  domain.LogFn
	StatFn domain.StatFn
}


// Handle is an AWS Lambda handler that takes in a ScanID and SiteID for a Nexpose scan that has completed.
//TODO more comment here
func (h *NexposeVulnNotificationHandler) Handle(ctx context.Context, in ScanInfo) {

	fetcher := assetFetcher.NexposeAssetFetcher{
		Client: h.NexposeHTTPClient,
		Host: h.NexposeHost,
		PageSize: h.NexposeAssetPageSize,
	}
	assetChan, errChan := fetcher.FetchAssets(ctx, in.SiteID)

	for {
		select {
		case asset := <- assetChan:
			fmt.Printf("Got an asset off the channel, here's the ID: %v", asset.ID)

		case err := <- errChan:
			fmt.Printf("Got an error off the channel, here's the error: %s", err)
			// do some error handling here
		}
		if assetChan == nil && errChan == nil {
			break
		}
	}

	// for each asset, hydrate it with vulnerability information:
	// get the list of vulnerability instances for that asset
	// by calling /api/3/assets/{id}/vulnerabilities
	// and put the result in here

	// for each vuln instance, get the Vuln info
	// https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getVulnerability

	// then publish it to the queue

}
