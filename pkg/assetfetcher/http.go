package assetfetcher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
)

// This const block helps format our request to the Nexpose asset search endpoint:
// POST /api/3/assets/search (doc: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/findAssets)
const (
	allMatch           = "all"
	basePath           = "/api/3"
	isOnOrAferOperator = "is-on-or-after"
	inOperator         = "in"
	nexposeAssets      = "/assets"
	nexposeSearch      = "/search"
	pageQueryParam     = "page" // The index of the page (zero-based) to retrieve.
	sizeQueryParam     = "size" // The number of records per page to retrieve.
	scanDateField      = "last-scan-date"
	siteIDField        = "site-id"
)

// SiteAssetsResponse is the structure of the Nexpose site assets response
type SiteAssetsResponse struct {
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
	// The Nexpose HTTP Cient
	HTTPClient *http.Client
	// The scheme and host of a Nexpose instance
	Host *url.URL
	// The number of assets that should be returned at one time
	PageSize int
	// Stat Function to report custom statistics
	StatFn domain.StatFn
}

// NexposeAssetSearchRequestBody represents the request body required to make an asset
// search request against the Nexpose API
type NexposeAssetSearchRequestBody struct {
	Filters []SearchCriteria `json:"filters"`
	Match   string           `json:"match"`
}

// SearchCriteria represents a 'Search Criteria' as defined by the Nexpose API. It is used
// as criteria to filter down the results returned from the asset search API
type SearchCriteria struct {
	Field    string   `json:"field"`
	Operator string   `json:"operator"`
	Value    string   `json:"value,omitempty"`
	Values   []string `json:"values,omitempty"`
}

// FetchAssets gets all the assets for a given site ID from Nexpose by calling `/api/3/sites/{id}/assets`
func (c *NexposeAssetFetcher) FetchAssets(ctx context.Context, siteID string) ([]domain.Asset, error) {
	// have to page through to get all the assets, start with page 0
	// make the first call to Nexpose to get the total number of pages we'll
	var currentPage = 0
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	firstPageOfAssets, initialErr := c.fetchNexposeSiteAssetsPage(ctx, currentPage, siteID)
	if initialErr != nil {
		return []domain.Asset{}, &domain.ErrorFetchingAssets{Inner: initialErr, Page: 0, SiteID: siteID}
	}

	totalPages := firstPageOfAssets.Page.TotalPages
	totalAssets := firstPageOfAssets.Resources

	pageAssetChan := make(chan SiteAssetsResponse, totalPages)
	pageErrChan := make(chan error, totalPages)
	for currentPage := 1; currentPage < totalPages; currentPage++ {
		go func(ctx context.Context, page int, site string) {
			pageOfAssets, err := c.fetchNexposeSiteAssetsPage(ctx, page, site)
			if err != nil {
				pageErrChan <- &domain.ErrorFetchingAssets{Inner: err, Page: int64(page), SiteID: siteID}
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
			return []domain.Asset{}, err
		}
	}

	return totalAssets, nil
}

// fetchNexposeSiteAssetsPage makes a call to Nexpose to retrieve and return a particular page of assets in the form of SiteAssetsResponse
func (c *NexposeAssetFetcher) fetchNexposeSiteAssetsPage(ctx context.Context, page int, siteID string) (SiteAssetsResponse, error) {
	req, err := c.newNexposeAssetsSearchRequest(siteID, page)
	if err != nil {
		return SiteAssetsResponse{}, err
	}

	res, err := c.HTTPClient.Do(req.WithContext(ctx))
	if err != nil {
		return SiteAssetsResponse{}, &domain.NexposeHTTPRequestError{NexposeURL: req.URL.String(), Inner: err}
	}
	defer res.Body.Close()
	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return SiteAssetsResponse{}, &domain.ErrorReadingNexposeResponse{NexposeURL: req.URL.String(), Inner: err}
	}

	if res.StatusCode != http.StatusOK {
		return SiteAssetsResponse{}, &domain.NexposeHTTPRequestError{NexposeURL: req.URL.String(), Inner: fmt.Errorf("bad response code: %v", res.StatusCode)}
	}

	var siteAssetResp SiteAssetsResponse
	if err := json.Unmarshal(respBody, &siteAssetResp); err != nil {
		return SiteAssetsResponse{}, &domain.ErrorParsingJSONResponse{NexposeURL: req.URL.String(), Inner: err}
	}

	return siteAssetResp, nil
}

// newNexposeAssetsSearchRequest builds the request for the Nexpose Assets API and using the passed in siteID
// for a Search Criteria and page for pagination purposes. It passes in the current date minus one day as a
// search criteria to lessen the amount of assets returned from Nexpose
func (c *NexposeAssetFetcher) newNexposeAssetsSearchRequest(siteID string, page int) (*http.Request, error) {
	u, _ := url.Parse(c.Host.String())
	u.Path = path.Join(u.Path, basePath, nexposeAssets, nexposeSearch)
	q := u.Query()
	q.Set(pageQueryParam, fmt.Sprint(page))
	q.Set(sizeQueryParam, fmt.Sprint(c.PageSize))
	u.RawQuery = q.Encode()

	// Golang seems to not require YYYY-MM-DD for date formatting
	// Yes, that is Golangs actual syntax for date formatting
	currentDate := time.Now()
	adjustedDate := currentDate.AddDate(0, 0, -1)
	formattedDate := adjustedDate.Format("2006-01-02")

	filters := []SearchCriteria{
		SearchCriteria{
			Field:    scanDateField,
			Operator: isOnOrAferOperator,
			Value:    formattedDate,
		},
		SearchCriteria{
			Field:    siteIDField,
			Operator: inOperator,
			Values: []string{
				siteID,
			},
		},
	}
	payload := NexposeAssetSearchRequestBody{
		Filters: filters,
		Match:   allMatch,
	}

	requestBody, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, &domain.URLParsingError{Inner: err, NexposeURL: u.String()}
	}
	return req, nil
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
