package assetFetcher

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain/nexpose"
	"encoding/json"
	"io/ioutil"
	"sync"
)

const (
    // GET /api/3/sites/{id}/assets (https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteAssets)
	nexposeSite = "/api/3/sites/"
	nexposeAssets = "/assets"
	pageQueryParam = "page" //The index of the page (zero-based) to retrieve.
	sizeQueryParam = "size" // The number of records per page to retrieve.

)

// SiteAssetsResponse is the structure of the api/3/sites/{id}/assets response
type SiteAssetsResponse struct {
	// Hypermedia links to corresponding or related resources
	Links 	  nexpose.Link
	// The details of pagination indicating which page was returned, and how the remaining pages can be retrieved.
	Page 	  Page
	// The page of resources returned (resources = assets)
	Resources []nexpose.Asset
}

//
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
	Client	 *http.Client
	Host	 string
	PageSize int
}

//
func (c *NexposeAssetFetcher) FetchAssets(ctx context.Context, siteID string) (<- chan nexpose.Asset, <- chan error) {
	var errChan = make(chan error)
	var assetChan= make(chan nexpose.Asset)

	go func() {
		var wg sync.WaitGroup
		defer close(assetChan)
		defer close(errChan)
		// make the first call to Nexpose to get the total number of pages we'll have to page through to get all the assets,
		// start with page 0
		var currentPage = 0
		req, err := newNexposeSiteAssetsRequest(c.Host, siteID, currentPage, c.PageSize)
		if err != nil {
			errChan <- err
		}

		res, err := c.Client.Do(req.WithContext(ctx))
		if err != nil {
			errChan <- err
		}
		defer res.Body.Close()
		respBody, err := ioutil.ReadAll(res.Body)

		var siteAssetResp SiteAssetsResponse
		if err := json.Unmarshal(respBody, &siteAssetResp); err != nil {
			errChan <- err
		}

		for _, asset := range siteAssetResp.Resources {
			assetChan <- asset
		}
		// add note about currentPage
		currentPage++
		totalPages := siteAssetResp.Page.TotalPages
		for currentPage < totalPages {
			wg.Add(1)
			go c.makeRequest(ctx, &wg, siteID, currentPage, assetChan, errChan)
			currentPage++
		}
		wg.Wait()
	} ()

	return assetChan, errChan
}

func (c *NexposeAssetFetcher) makeRequest(ctx context.Context, wg *sync.WaitGroup, siteID string, page int, assetChan chan nexpose.Asset, errChan chan error) {
	defer wg.Done()
	fmt.Println("inside makeRequest")
	req, err := newNexposeSiteAssetsRequest(c.Host, siteID, page, c.PageSize)
	if err != nil {
		errChan <- err
	}
	fmt.Println("about to make request")
	res, err := c.Client.Do(req.WithContext(ctx))
	fmt.Println("finished making request")
	if err != nil {
		errChan <- err
	}
	defer res.Body.Close()
	fmt.Println("reading in body")
	respBody, err := ioutil.ReadAll(res.Body)

	var siteAssetResp SiteAssetsResponse
	fmt.Println("unmarshalling body")
	if err := json.Unmarshal(respBody, &siteAssetResp); err != nil {
		fmt.Printf("here is the err chan: %v", errChanl)
		errChan <- err
		return
	}
	fmt.Println("marshalled body")
	for _, asset := range siteAssetResp.Resources {
		assetChan <- asset
	}
	fmt.Println("at the end of makeRequest")
}

func newNexposeSiteAssetsRequest(baseURL string, siteID string, page int, size int) (*http.Request, error) {
	u, _ := url.Parse(baseURL)
	u.Path = path.Join(u.Path, nexposeSite, siteID, nexposeAssets)
	q := u.Query()
	q.Set(pageQueryParam, fmt.Sprint(page))
	q.Set(sizeQueryParam, fmt.Sprint(size))
	u.RawQuery = q.Encode()
	fmt.Printf("forming request: %s", u.String())
	return http.NewRequest(http.MethodGet, u.String(), nil)
}