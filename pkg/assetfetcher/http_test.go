package assetfetcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain/nexpose"
	"github.com/stretchr/testify/assert"
)

func TestFetchAssetsSuccess(t *testing.T) {
	expectedAsset := nexpose.Asset{
		IP: "127.0.0.1",
		ID: 123456,
	}
	resp := SiteAssetsResponse{
		Resources: []nexpose.Asset{expectedAsset},
		Page:      Page{},
		Links:     nexpose.Link{},
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

	var actualAsset nexpose.Asset
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
	expectedAsset := nexpose.Asset{
		IP: "127.0.0.1",
		ID: 123456,
	}
	resp := SiteAssetsResponse{
		Resources: []nexpose.Asset{expectedAsset},
		Page:      Page{},
		Links:     nexpose.Link{},
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
	asset := nexpose.Asset{
		IP: "127.0.0.1",
		ID: 123456,
	}
	resp := SiteAssetsResponse{
		Resources: []nexpose.Asset{asset},
		Page:      Page{},
		Links:     nexpose.Link{},
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

	asset := nexpose.Asset{
		IP: "127.0.0.1",
		ID: 123456,
	}
	resp := SiteAssetsResponse{
		Resources: []nexpose.Asset{asset},
		Page:      Page{},
		Links:     nexpose.Link{},
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
	assetChan := make(chan nexpose.Asset, 1)
	errChan := make(chan error, 1)
	defer close(assetChan)
	defer close(errChan)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)

	assert.NotNil(t, <-assetChan)
}

func TestMakeRequestWithInvalidHost(t *testing.T) {
	resp := SiteAssetsResponse{
		Resources: []nexpose.Asset{},
		Page:      Page{},
		Links:     nexpose.Link{},
	}
	respJSON, _ := json.Marshal(resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(respJSON)
		if err != nil {
			t.Fatalf("Unexpected error occurred %v ", err)
		}
	}))
	defer ts.Close()
	c := ts.Client()
	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: c,
		Host:       "~!@#$%^&*()_+:?><!@#$%^&*())_:",
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan nexpose.Asset, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	wg.Wait()

	close(assetChan)
	close(errChan)

	assert.IsType(t, &URLParsingError{}, <-errChan)
}

func TestMakeRequestWithNoAssetsReturned(t *testing.T) {
	resp := SiteAssetsResponse{
		Resources: []nexpose.Asset{},
		Page:      Page{},
		Links:     nexpose.Link{},
	}
	respJSON, _ := json.Marshal(resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(respJSON)
		if err != nil {
			t.Fatalf("Unexpected error occurred %v ", err)
		}
	}))
	defer ts.Close()
	c := ts.Client()
	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: c,
		Host:       ts.URL,
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan nexpose.Asset, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	wg.Wait()

	close(assetChan)
	close(errChan)

	assert.Equal(t, nexpose.Asset{}, <-assetChan) // An empty asset will be added to assetChan if there's a response with no asset
	assert.Nil(t, <-errChan)
}

func TestMakeRequestWithNoResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	c := ts.Client()
	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: c,
		Host:       ts.URL,
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan nexpose.Asset, 1)
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
