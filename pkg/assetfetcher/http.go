package assetfetcher

import (
	"context"
	"encoding/json"
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
	// The username used to login to the Nexpose instance at the given host
	Username string
	// The password for the corresponding username
	Password string
	// The number of assets that should be returned at one time
	PageSize int
}

// FetchAssets gets all the assets for a given site ID from Nexpose. This function is asynchronous, which means
// you can start listening to the AssetEvent and error channels immediately. Assets will be added to the AssetEvent
// channel as they're returned from Nexpose and errors will be added to the error channel if there's an error fetching
// or reading the asset. It's the responsibility of the caller to check if a channel is closed before reading from it.
func (c *NexposeAssetFetcher) FetchAssets(ctx context.Context, siteID string) (<-chan domain.AssetEvent, <-chan error) {
	errChan := make(chan error, 1)
	defer close(errChan)

	// have to page through to get all the assets, start with page 0
	// make the first call to Nexpose to get the total number of pages we'll
	var currentPage = 0
	req := c.newNexposeSiteAssetsRequest(siteID, currentPage)

	res, err := c.HTTPClient.Do(req.WithContext(ctx))
	if err != nil {
		errChan <- &NexposeHTTPRequestError{err, req.URL.String()}
		return nil, errChan
	}
	defer res.Body.Close()
	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		errChan <- &ErrorReadingNexposeResponse{err, req.URL.String()}
		return nil, errChan
	}

	var siteAssetResp SiteAssetsResponse
	if err := json.Unmarshal(respBody, &siteAssetResp); err != nil {
		errChan <- &ErrorParsingJSONResponse{err, req.URL.String()}
		return nil, errChan
	}

	pagedAssetChan := make(chan domain.AssetEvent, siteAssetResp.Page.TotalResources)
	pagedErrChan := make(chan error, siteAssetResp.Page.TotalResources)

	for _, asset := range siteAssetResp.Resources {
		assetEvent, err := asset.AssetPayloadToAssetEvent()
		if err != nil {
			pagedErrChan <- &ErrorConvertingAssetPayload{asset.ID, err}
		} else {
			pagedAssetChan <- assetEvent
		}
	}

	// We've gotten the first page (page 0) and added the assets to the channel,
	// so here we'll get the TotalPages of assets that Nexpose has, then paginate
	// through from page 1 to TotalPages to get all the assets
	totalPages := siteAssetResp.Page.TotalPages
	var wg sync.WaitGroup
	for currentPage := 1; currentPage < totalPages; currentPage++ {
		wg.Add(1)
		go c.makeRequest(ctx, &wg, siteID, currentPage, pagedAssetChan, pagedErrChan)
	}

	go func() {
		defer close(pagedErrChan)
		defer close(pagedAssetChan)
		wg.Wait()
	}()

	return pagedAssetChan, pagedErrChan
}

func (c *NexposeAssetFetcher) makeRequest(ctx context.Context, wg *sync.WaitGroup, siteID string, page int, assetChan chan domain.AssetEvent, errChan chan error) {
	defer wg.Done()
	req := c.newNexposeSiteAssetsRequest(siteID, page)

	res, err := c.HTTPClient.Do(req.WithContext(ctx))
	if err != nil {
		errChan <- &NexposeHTTPRequestError{err, req.URL.String()}
		return
	}
	defer res.Body.Close()
	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		errChan <- &ErrorReadingNexposeResponse{err, req.URL.String()}
		return
	}
	var siteAssetResp SiteAssetsResponse
	if err := json.Unmarshal(respBody, &siteAssetResp); err != nil {
		errChan <- &ErrorParsingJSONResponse{err, req.URL.String()}
		return
	}
	for _, asset := range siteAssetResp.Resources {
		assetEvent, err := asset.AssetPayloadToAssetEvent()
		if err != nil {
			errChan <- &ErrorConvertingAssetPayload{asset.ID, err}
		} else {
			assetChan <- assetEvent
		}
	}
}

// newNexposeSiteAssetsRequest builds URL we'll use to make the request to Nexpose's site assets endpoint
func (c *NexposeAssetFetcher) newNexposeSiteAssetsRequest(siteID string, page int) *http.Request {
	u, _ := url.Parse(c.Host.String())
	u.Path = path.Join(u.Path, basePath, nexposeSite, siteID, nexposeAssets)
	q := u.Query()
	q.Set(pageQueryParam, fmt.Sprint(page))
	q.Set(sizeQueryParam, fmt.Sprint(c.PageSize))
	u.RawQuery = q.Encode()
	req, _ := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	// the only time http.NewRequest returns an error is if there's a parsing error,
	// which we already checked for earlier, so no need to check it again
	req.SetBasicAuth(c.Username, c.Password)
	return req
}
