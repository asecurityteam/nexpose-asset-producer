package assetfetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"sync"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain"
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
	// Hypermedia links to corresponding or related resources
	Links domain.Link
	// The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.
	Page Page
	// The page of resources returned (resources = assets)
	Resources []domain.Asset
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
	// The Nexpose host that points to your instance
	Host string
	// The number of assets that should be returned at one time
	PageSize int
}

// FetchAssets gets all the assets for a given site ID from Nexpose, with pagination.
// It returns a channel of assets and a channel of errors that can by asynchronously listened to.
func (c *NexposeAssetFetcher) FetchAssets(ctx context.Context, siteID string) (<-chan domain.Asset, <-chan error) {
	errChan := make(chan error, 1)
	assetChan := make(chan domain.Asset, 1)
	defer close(errChan)
	defer close(assetChan)

	// have to page through to get all the assets, start with page 0
	// make the first call to Nexpose to get the total number of pages we'll
	var currentPage = 0
	req, err := newNexposeSiteAssetsRequest(c.Host, siteID, currentPage, c.PageSize)
	if err != nil {
		errChan <- err
		return assetChan, errChan
	}

	res, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		errChan <- &NexposeHTTPRequestError{err, req.URL.String()}
		return assetChan, errChan
	}
	defer res.Body.Close()
	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		errChan <- &ErrorReadingNexposeResponse{err, req.URL.String()}
		return assetChan, errChan
	}

	var siteAssetResp SiteAssetsResponse
	if err := json.Unmarshal(respBody, &siteAssetResp); err != nil {
		errChan <- &ErrorParsingJSONResponse{err, req.URL.String()}
		return assetChan, errChan
	}

	pagedAssetChan := make(chan domain.Asset, siteAssetResp.Page.TotalResources)
	pagedErrChan := make(chan error, siteAssetResp.Page.TotalResources)

	for _, asset := range siteAssetResp.Resources {
		pagedAssetChan <- asset
	}

	// We've gotten the first page (page 0) and added the assets to the channel,
	// so here we'll increment the currentPage to start on page 1 and use TotalPages, which is
	// the total number of pages of assets that Nexpose has, to paginate through to get all the assets
	currentPage++
	totalPages := siteAssetResp.Page.TotalPages
	var wg sync.WaitGroup
	for currentPage < totalPages {
		wg.Add(1)
		go c.makeRequest(ctx, &wg, siteID, currentPage, pagedAssetChan, pagedErrChan)
		currentPage++
	}

	go func() {
		defer close(pagedErrChan)
		defer close(pagedAssetChan)
		wg.Wait()
	}()

	return pagedAssetChan, pagedErrChan
}

func (c *NexposeAssetFetcher) makeRequest(ctx context.Context, wg *sync.WaitGroup, siteID string, page int, assetChan chan domain.Asset, errChan chan error) {
	defer wg.Done()
	req, err := newNexposeSiteAssetsRequest(c.Host, siteID, page, c.PageSize)
	if err != nil {
		errChan <- err
		return
	}
	res, err := http.DefaultClient.Do(req.WithContext(ctx))
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
		assetChan <- asset
	}
}

// newNexposeSiteAssetsRequest builds URL we'll use to make the request to Nexpose's site assets endpoint
func newNexposeSiteAssetsRequest(host string, siteID string, page int, size int) (*http.Request, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, &URLParsingError{err, host}
	}
	u.Path = path.Join(u.Path, basePath, nexposeSite, siteID, nexposeAssets)
	q := u.Query()
	q.Set(pageQueryParam, fmt.Sprint(page))
	q.Set(sizeQueryParam, fmt.Sprint(size))
	u.RawQuery = q.Encode()
	req, _ := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	// the only time http.NewRequest returns an error is if there's a parsing error,
	// which we already checked for earlier, so no need to check it again
	req.SetBasicAuth(os.Getenv("NEXPOSE_USERNAME"), os.Getenv("NEXPOSE_PASSWORD"))
	return req, nil
}
