package assetfetcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"sync"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
)

// This const block helps format our request to the Nexpose sites asset endpoint:
// GET /api/3/sites/{id}/assets (doc: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteAssets)
const (
	basePath       = "/api/3"
	nexposeSite    = "/sites"
	nexposeAssets  = "/assets"
	pageQueryParam = "page" // The index of the page (zero-based) to retrieve.
	sizeQueryParam = "size" // The number of records per page to retrieve.
)

// SiteAssetsResponse is the structure of the Nexpose site assets response
type SiteAssetsResponse struct {
	// The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.
	Page Page
	// The page of resources returned (resources = assets)
	Resources []Asset
}

// Page represents the JSON object Nexpose provides to help paginate through all the Assets
type Page struct {
	// The index (zero-based) of the current page returned.
	Number int
	// The maximum size of the page returned.
	Size int
	// The total number of pages available.
	TotalPages int
	// The total number of resources available across all pages.
	TotalResources int
}

// NexposeAssetFetcher is used to create a new
type NexposeAssetFetcher struct {
	// The Nexpose HTTP Cient
	HTTPClient *http.Client
	// The scheme and host of a Nexpose instance
	Host *url.URL
	// The number of assets that should be returned at one time
	PageSize int
	// Stat Function to report custom statistics
	StatFn domain.StatFn
}

// FetchAssets gets all the assets for a given site ID from Nexpose by calling `/api/3/sites/{id}/assets`.
// This function is asynchronous, which means you can start listening to the AssetEvent and error channels immediately.
// Assets will be added to the AssetEvent channel as they're returned from Nexpose
// and errors will be added to the error channel if there's an error fetching
// or reading the asset. It's the responsibility of the caller to check if a channel is closed before reading from it.
func (c *NexposeAssetFetcher) FetchAssets(ctx context.Context, siteID string, scanID string) (<-chan domain.AssetEvent, <-chan error) {
	errChan := make(chan error, 1)
	defer close(errChan)

	stater := c.StatFn(ctx)
	allAssetsInSite, err := c.fetchAllNexposeSiteAssets(ctx, siteID)
	if err != nil {
		errChan <- err
		return nil, errChan
	}

	numTotalAssets := len(allAssetsInSite)
	stater.Count("totalassets", float64(numTotalAssets), fmt.Sprintf("site:%s", siteID))
	pagedAssetChan := make(chan domain.AssetEvent, numTotalAssets)
	pagedErrChan := make(chan error, numTotalAssets)
	var wg sync.WaitGroup

	for _, asset := range allAssetsInSite {
		wg.Add(1)
		go func(singleAsset Asset) {
			defer wg.Done()
			scanTime, err := singleAsset.GetScanTime(scanID)
			if err != nil {
				pagedErrChan <- err
				return
			}
			assetEvent, err := singleAsset.AssetPayloadToAssetEvent(scanTime)
			if err != nil {
				pagedErrChan <- err
				return
			}
			pagedAssetChan <- assetEvent

		}(asset)

	}

	go func() {
		defer close(pagedErrChan)
		defer close(pagedAssetChan)
		wg.Wait()
	}()

	return pagedAssetChan, pagedErrChan
}

// newNexposeSiteAssetsRequest builds URL we'll use to make the request to Nexpose's site assets endpoint
func (c *NexposeAssetFetcher) newNexposeSiteAssetsRequest(siteID string, page int) *http.Request {
	u, _ := url.Parse(c.Host.String())
	u.Path = path.Join(u.Path, basePath, nexposeSite, siteID, nexposeAssets)
	q := u.Query()
	q.Set(pageQueryParam, fmt.Sprint(page))
	q.Set(sizeQueryParam, fmt.Sprint(c.PageSize))
	u.RawQuery = q.Encode()
	// the only time http.NewRequest returns an error is if there's a parsing error,
	// which we already checked for earlier, so no need to check it again
	req, _ := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	return req
}

// fetchNexposeSiteAssetsPage makes a call to Nexpose to retrieve and return a page of assets in the form of SiteAssetsResponse
func (c *NexposeAssetFetcher) fetchAllNexposeSiteAssets(ctx context.Context, siteID string) ([]Asset, error) {
	// have to page through to get all the assets, start with page 0
	// make the first call to Nexpose to get the total number of pages we'll
	var currentPage = 0
	firstPageOfAssets, initialErr := c.fetchNexposeSiteAssetsPage(ctx, currentPage, siteID)
	if initialErr != nil {
		return []Asset{}, errors.New("failed initial!")
	}

	totalPages := firstPageOfAssets.Page.TotalPages
	totalAssets := firstPageOfAssets.Resources

	pageAssetChan := make(chan SiteAssetsResponse, totalPages-1)
	pageErrChan := make(chan error, totalPages-1)
	for currentPage := 1; currentPage < totalPages; currentPage++ {
		// go c.makeRequest(ctx, &wg, siteID, scanID, currentPage, pagedAssetChan, pagedErrChan)
		go func(ctx context.Context, page int, site string) {
			pageOfAssets, err := c.fetchNexposeSiteAssetsPage(ctx, page, site)
			if err != nil {
				pageErrChan <- err
				return
			}
			pageAssetChan <- pageOfAssets
		}(ctx, currentPage, siteID)
	}

	for currentPage := 1; currentPage < totalPages; currentPage++ {
		select {
		case pageOfAssets := <-pageAssetChan:
			totalAssets = append(totalAssets, pageOfAssets.Resources...)
		case err := <-pageErrChan:
			return []Asset{}, err
		}
	}

	return totalAssets, nil
}

// fetchNexposeSiteAssetsPage makes a call to Nexpose to retrieve and return a particular page of assets in the form of SiteAssetsResponse
func (c *NexposeAssetFetcher) fetchNexposeSiteAssetsPage(ctx context.Context, page int, siteID string) (SiteAssetsResponse, error) {
	req := c.newNexposeSiteAssetsRequest(siteID, page)

	res, err := c.HTTPClient.Do(req.WithContext(ctx))
	if err != nil {
		return SiteAssetsResponse{}, errors.New("http failure!")
	}
	defer res.Body.Close()
	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return SiteAssetsResponse{}, errors.New("http failure!")

	}

	if res.StatusCode != http.StatusOK {
		return SiteAssetsResponse{}, errors.New("http failure!")

	}

	var siteAssetResp SiteAssetsResponse
	if err := json.Unmarshal(respBody, &siteAssetResp); err != nil {
		return SiteAssetsResponse{}, errors.New("http failure!")

	}

	return SiteAssetsResponse{}, nil
}

// CheckDependencies makes a call to the nexpose endppoint "/api/3".
// Because asset producer endpoints vary user to user, we want to hit an endpoint
// that is consistent for any Nexpose user
func (c *NexposeAssetFetcher) CheckDependencies(ctx context.Context) error {
	u, _ := url.Parse(c.Host.String() + "/api/3")
	req, _ := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("Nexpose unexpectedly returned non-200 response code: %d attempting to GET: %s", res.StatusCode, u.String())
	}
	return nil
}
