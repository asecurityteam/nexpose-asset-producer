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
		Host:     ts.URL,
		PageSize: 100,
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

func TestFetchAssetsBadResponseError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1")
	}))
	defer ts.Close()

	nexposeAssetFetcher := &NexposeAssetFetcher{
		Host:     ts.URL,
		PageSize: 100,
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
		Host:     ts.URL,
		PageSize: 100,
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
		Host:     "fail://",
		PageSize: 100,
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
		Host:     "~!@#$%^&*()_+:?><!@#$%^&*())_:",
		PageSize: 100,
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
		Host:     ts.URL,
		PageSize: 100,
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
		Host:     ts.URL,
		PageSize: 100,
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
		Host:     "~!@#$%^&*()_+:?><!@#$%^&*())_:",
		PageSize: 100,
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
		Host:     "http://fail",
		PageSize: 100,
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
		Host:     ts.URL,
		PageSize: 100,
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
		Host:     ts.URL,
		PageSize: 100,
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
