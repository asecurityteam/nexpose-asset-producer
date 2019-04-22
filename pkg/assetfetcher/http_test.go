package assetfetcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain"
	"github.com/stretchr/testify/assert"
)

func TestFetchAssetsSuccess(t *testing.T) {
	expectedAsset := domain.Asset{
		IP: "127.0.0.1",
		ID: 123456,
	}
	resp := SiteAssetsResponse{
		Resources: []domain.Asset{expectedAsset},
		Page: Page{
			TotalPages:     1,
			TotalResources: 1,
		},
		Links: domain.Link{},
	}
	respJSON, _ := json.Marshal(resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(respJSON)
		if err != nil {
			t.Fatalf("Unexpected error occurred %v ", err)
		}
	}))
	defer ts.Close()

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       ts.URL,
		PageSize:   100,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	var actualAsset domain.Asset
	for {
		select {
		case respAsset, ok := <-assetChan:
			if !ok {
				assetChan = nil
			} else {
				actualAsset = respAsset
			}
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
			} else {
				t.Fatalf("Unexpected error occurred %v ", err)
			}
		}
		if assetChan == nil && errChan == nil {
			break
		}
	}
	assert.Equal(t, expectedAsset, actualAsset)
}

func TestFetchAssetsSuccessWithOneMakeRequestCall(t *testing.T) {
	expectedAsset1 := domain.Asset{
		IP: "127.0.0.1",
		ID: 123,
	}
	expectedAsset2 := domain.Asset{
		IP: "127.0.0.2",
		ID: 456,
	}
	resp1 := SiteAssetsResponse{
		Resources: []domain.Asset{expectedAsset1},
		Page: Page{
			TotalPages:     2,
			TotalResources: 2,
		},
		Links: domain.Link{},
	}
	resp2 := SiteAssetsResponse{
		Resources: []domain.Asset{expectedAsset2},
		Page: Page{
			TotalPages:     2,
			TotalResources: 2,
		},
		Links: domain.Link{},
	}
	respJSON1, _ := json.Marshal(resp1)
	respJSON2, _ := json.Marshal(resp2)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if page == "0" {
			_, err := w.Write(respJSON1)
			if err != nil {
				t.Fatalf("Unexpected error occurred %v ", err)
			}
		}
		if page == "1" {
			_, err := w.Write(respJSON2)
			if err != nil {
				t.Fatalf("Unexpected error occurred %v ", err)
			}
		}
	}))
	defer ts.Close()

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       ts.URL,
		PageSize:   1,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	var assets []domain.Asset
	for {
		select {
		case respAsset, ok := <-assetChan:
			if !ok {
				assetChan = nil
			} else {
				assets = append(assets, respAsset)
			}
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
			} else {
				t.Fatalf("Unexpected error occurred %v ", err)
			}
		}

		if assetChan == nil && errChan == nil {
			break
		}
	}
	assert.Equal(t, []domain.Asset{expectedAsset1, expectedAsset2}, assets)
}

func TestFetchAssetsSuccessWithMultipleMakeRequestsCalled(t *testing.T) {
	expectedAsset1 := domain.Asset{
		IP: "127.0.0.1",
		ID: 123,
	}
	expectedAsset2 := domain.Asset{
		IP: "127.0.0.2",
		ID: 234,
	}
	expectedAsset3 := domain.Asset{
		IP: "127.0.0.3",
		ID: 345,
	}
	expectedAsset4 := domain.Asset{
		IP: "127.0.0.4",
		ID: 456,
	}
	expectedAsset5 := domain.Asset{
		IP: "127.0.0.5",
		ID: 567,
	}
	page := Page{
		TotalPages:     3,
		TotalResources: 5,
	}
	page1Resp := SiteAssetsResponse{
		Resources: []domain.Asset{expectedAsset1, expectedAsset2},
		Page:      page,
	}
	page2Resp := SiteAssetsResponse{
		Resources: []domain.Asset{expectedAsset3, expectedAsset4},
		Page:      page,
	}
	page3Resp := SiteAssetsResponse{
		Resources: []domain.Asset{expectedAsset5},
		Page:      page,
	}
	respJSON1, _ := json.Marshal(page1Resp)
	respJSON2, _ := json.Marshal(page2Resp)
	respJSON3, _ := json.Marshal(page3Resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageParam := r.URL.Query().Get("page")
		switch pageParam {
		case "0":
			_, err := w.Write(respJSON1)
			if err != nil {
				t.Fatalf("Unexpected error occurred %v ", err)
			}
		case "1":
			_, err := w.Write(respJSON2)
			if err != nil {
				t.Fatalf("Unexpected error occurred %v ", err)
			}
		case "2":
			_, err := w.Write(respJSON3)
			if err != nil {
				t.Fatalf("Unexpected error occurred %v ", err)
			}
		}
	}))
	defer ts.Close()

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       ts.URL,
		PageSize:   2, // with a page size of 2: 2 assets will be returned for pages 1 and 2, and 1 will be returned on page 3
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	var assets []domain.Asset
	for {
		select {
		case respAsset, ok := <-assetChan:
			if !ok {
				assetChan = nil
			} else {
				assets = append(assets, respAsset)
			}
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
			} else {
				t.Fatalf("Unexpected error occurred %v ", err)
			}
		}

		if assetChan == nil && errChan == nil {
			break
		}
	}
	assert.Len(t, assets, 5)
	assert.Contains(t, assets, expectedAsset1)
	assert.Contains(t, assets, expectedAsset2)
	assert.Contains(t, assets, expectedAsset3)
	assert.Contains(t, assets, expectedAsset4)
	assert.Contains(t, assets, expectedAsset5)
}

func TestFetchAssetsSuccessWithMultipleMakeRequestsCalledWithError(t *testing.T) {
	expectedAsset1 := domain.Asset{
		IP: "127.0.0.1",
		ID: 123,
	}
	expectedAsset2 := domain.Asset{
		IP: "127.0.0.2",
		ID: 234,
	}

	expectedAsset3 := domain.Asset{
		IP: "127.0.0.3",
		ID: 345,
	}
	page := Page{
		TotalPages:     3,
		TotalResources: 5,
	}
	page1Resp := SiteAssetsResponse{
		Resources: []domain.Asset{expectedAsset1, expectedAsset2},
		Page:      page,
	}
	page3Resp := SiteAssetsResponse{
		Resources: []domain.Asset{expectedAsset3},
		Page:      page,
	}
	respJSON1, _ := json.Marshal(page1Resp)
	respJSON3, _ := json.Marshal(page3Resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageParam := r.URL.Query().Get("page")
		switch pageParam {
		case "0":
			_, err := w.Write(respJSON1)
			if err != nil {
				t.Fatalf("Unexpected error occurred %v ", err)
			}
		case "1":
			_, err := w.Write([]byte("fail")) // the response form this call will
			if err != nil {
				t.Fatalf("Unexpected error occurred %v ", err)
			}
		case "2":
			_, err := w.Write(respJSON3)
			if err != nil {
				t.Fatalf("Unexpected error occurred %v ", err)
			}
		}
	}))
	defer ts.Close()

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       ts.URL,
		PageSize:   2,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	var assets []domain.Asset
	var retErrors []error
	for {
		select {
		case asset, ok := <-assetChan:
			if !ok {
				assetChan = nil
			} else {
				assets = append(assets, asset)
			}
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
			} else {
				retErrors = append(retErrors, err)
			}
		}

		if assetChan == nil && errChan == nil {
			break
		}
	}
	assert.Len(t, assets, 3)
	assert.Contains(t, assets, expectedAsset1)
	assert.Contains(t, assets, expectedAsset2)
	assert.Contains(t, assets, expectedAsset3)
	assert.Len(t, retErrors, 1)
	assert.IsType(t, &ErrorParsingJSONResponse{}, retErrors[0])
}

func TestFetchAssetsSuccessNoResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       ts.URL,
	}

	_, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	assert.IsType(t, &ErrorParsingJSONResponse{}, <-errChan) // Error will be returned from json.Unmarshal and added to errChan
}

func TestFetchAssetsSuccessWithNoAssetReturned(t *testing.T) {
	resp := SiteAssetsResponse{
		Resources: []domain.Asset{},
		Page: Page{
			TotalPages:     1,
			TotalResources: 1,
		},
		Links: domain.Link{},
	}
	respJSON, _ := json.Marshal(resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(respJSON)
		if err != nil {
			t.Fatalf("Unexpected error occurred %v ", err)
		}
	}))
	defer ts.Close()

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       ts.URL,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	assert.Equal(t, domain.Asset{}, <-assetChan) // An empty asset will be added to assetChan if there's a response with no asset
	assert.Nil(t, <-errChan)
}

func TestFetchAssetsBadResponseError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1")
	}))
	defer ts.Close()

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       ts.URL,
		PageSize:   100,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	var actualError error

	for {
		select {
		case respAsset, ok := <-assetChan:
			if !ok {
				assetChan = nil
			} else {
				t.Fatalf("Unexpected error occurred %v ", respAsset)
			}
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
			} else {
				actualError = err
			}
		}
		if assetChan == nil && errChan == nil {
			break
		}
	}
	assert.IsType(t, &ErrorReadingNexposeResponse{}, actualError)
}

func TestFetchAssetsBadJSONInResponseError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("fail"))
		if err != nil {
			t.Fatalf("Unexpected error occurred %v ", err)
		}
	}))
	defer ts.Close()

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       ts.URL,
		PageSize:   100,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	var actualError error

	for {
		select {
		case respAsset, ok := <-assetChan:
			if !ok {
				assetChan = nil
			} else {
				t.Fatalf("Unexpected error occurred %v ", respAsset)
			}
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
			} else {
				actualError = err
			}
		}
		if assetChan == nil && errChan == nil {
			break
		}
	}
	assert.IsType(t, &ErrorParsingJSONResponse{}, actualError)
}

func TestFetchAssetsHTTPError(t *testing.T) {
	expectedAsset := domain.Asset{
		IP: "127.0.0.1",
		ID: 123456,
	}
	resp := SiteAssetsResponse{
		Resources: []domain.Asset{expectedAsset},
		Page:      Page{},
		Links:     domain.Link{},
	}
	respJSON, _ := json.Marshal(resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(respJSON)
		if err != nil {
			t.Fatalf("Unexpected error occurred %v ", err)
		}
	}))
	defer ts.Close()

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       "fail://",
		PageSize:   100,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	var actualError error

	for {
		select {
		case respAsset, ok := <-assetChan:
			if !ok {
				assetChan = nil
			} else {
				t.Fatalf("Unexpected error occurred %v ", respAsset)
			}
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
			} else {
				actualError = err
			}
		}
		if assetChan == nil && errChan == nil {
			break
		}
	}
	assert.IsType(t, &NexposeHTTPRequestError{}, actualError)
}

func TestFetchAssetsWithInvalidHost(t *testing.T) {
	asset := domain.Asset{
		IP: "127.0.0.1",
		ID: 123456,
	}
	resp := SiteAssetsResponse{
		Resources: []domain.Asset{asset},
		Page:      Page{},
		Links:     domain.Link{},
	}
	respJSON, _ := json.Marshal(resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(respJSON)
		if err != nil {
			t.Fatalf("Unexpected error occurred %v ", err)
		}
	}))
	defer ts.Close()

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       "~!@#$%^&*()_+:?><!@#$%^&*())_:",
		PageSize:   100,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	var actualError error

	for {
		select {
		case respAsset, ok := <-assetChan:
			if !ok {
				assetChan = nil
			} else {
				t.Fatalf("Unexpected error occurred %v ", respAsset)
			}
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
			} else {
				actualError = err
			}
		}
		if assetChan == nil && errChan == nil {
			break
		}
	}
	assert.IsType(t, &URLParsingError{}, actualError)
}

func TestMakeRequestSuccess(t *testing.T) {
	asset := domain.Asset{
		IP: "127.0.0.1",
		ID: 123456,
	}
	resp := SiteAssetsResponse{
		Resources: []domain.Asset{asset},
		Page:      Page{},
		Links:     domain.Link{},
	}

	respJSON, _ := json.Marshal(resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(respJSON)
		if err != nil {
			t.Fatalf("Unexpected error occurred %v ", err)
		}
	}))
	defer ts.Close()

	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       ts.URL,
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.Asset, 1)
	errChan := make(chan error, 1)
	defer close(assetChan)
	defer close(errChan)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)

	assert.NotNil(t, <-assetChan)
}

func TestMakeRequestWithBadResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1")
	}))
	defer ts.Close()
	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       ts.URL,
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.Asset, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	wg.Wait()

	close(assetChan)
	close(errChan)

	assert.IsType(t, &ErrorReadingNexposeResponse{}, <-errChan)
}

func TestMakeRequestWithInvalidHost(t *testing.T) {
	resp := SiteAssetsResponse{
		Resources: []domain.Asset{},
		Page:      Page{},
		Links:     domain.Link{},
	}
	respJSON, _ := json.Marshal(resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(respJSON)
		if err != nil {
			t.Fatalf("Unexpected error occurred %v ", err)
		}
	}))
	defer ts.Close()
	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       "~!@#$%^&*()_+:?><!@#$%^&*())_:",
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.Asset, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	wg.Wait()

	close(assetChan)
	close(errChan)

	assert.IsType(t, &URLParsingError{}, <-errChan)
}

func TestMakeRequestHTTPError(t *testing.T) {
	resp := SiteAssetsResponse{
		Resources: []domain.Asset{},
		Page:      Page{},
		Links:     domain.Link{},
	}
	respJSON, _ := json.Marshal(resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(respJSON)
		if err != nil {
			t.Fatalf("Unexpected error occurred %v ", err)
		}
	}))
	defer ts.Close()
	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       "http://fail",
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.Asset, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	wg.Wait()

	close(assetChan)
	close(errChan)

	err := <-errChan
	assert.IsType(t, &NexposeHTTPRequestError{}, err)
	assert.Contains(t, err.Error(), "Error making an HTTP request to Nexpose with URL http://fail/api/3/sites/siteID/assets?page=100&size=100:")
}

func TestMakeRequestWithNoAssetsReturned(t *testing.T) {
	resp := SiteAssetsResponse{
		Resources: []domain.Asset{},
		Page:      Page{},
		Links:     domain.Link{},
	}
	respJSON, _ := json.Marshal(resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(respJSON)
		if err != nil {
			t.Fatalf("Unexpected error occurred %v ", err)
		}
	}))
	defer ts.Close()
	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       ts.URL,
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.Asset, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	wg.Wait()

	close(assetChan)
	close(errChan)

	assert.Equal(t, domain.Asset{}, <-assetChan) // An empty asset will be added to assetChan if there's a response with no asset
	assert.Nil(t, <-errChan)
}

func TestMakeRequestWithNoResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: ts.Client(),
		Host:       ts.URL,
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.Asset, 1)
	errChan := make(chan error, 1)
	defer close(assetChan)
	defer close(errChan)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)

	assert.IsType(t, &ErrorParsingJSONResponse{}, <-errChan) // Error will be returned from json.Unmarshal and added to errChan
}

func TestNewNexposeSiteAssetsRequestSuccess(t *testing.T) {
	req, err := newNexposeSiteAssetsRequest("http://nexpose-instance.com", "siteID", 1, 100)

	assert.Nil(t, err)
	assert.Equal(t, "http://nexpose-instance.com/api/3/sites/siteID/assets?page=1&size=100", req.URL.String())
}

func TestNewNexposeSiteAssetsRequestWithExtraSlashes(t *testing.T) {
	req, err := newNexposeSiteAssetsRequest("http://nexpose-instance.com/", "/siteID/", 1, 100)

	assert.NoError(t, err)
	assert.Equal(t, "http://nexpose-instance.com/api/3/sites/siteID/assets?page=1&size=100", req.URL.String())
}

func TestNewNexposeSiteAssetsRequestWithInvalidHost(t *testing.T) {
	_, err := newNexposeSiteAssetsRequest("http://nexpose!@#$%^&*().com", "siteID", 1, 100)

	assert.IsType(t, &URLParsingError{}, err) // Error will be returned from url.Parse
}
