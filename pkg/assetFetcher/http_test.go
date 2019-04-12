package assetFetcher

import (

	"context"
	"net/http/httptest"
	"net/http"
	"sync"
	"testing"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain/nexpose"
	"github.com/stretchr/testify/assert"
	"encoding/json"
)


func TestFetchAssets(t *testing.T) {
	asset := nexpose.Asset{
			IP: "127.0.0.1",
			ID: 123456,
		}
	resp := SiteAssetsResponse{
		Resources: []nexpose.Asset{asset},
		Page: Page{},
		Links:nexpose.Link{},
	}
	respJSON,_ := json.Marshal(resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(respJSON)
	}))
	defer ts.Close()

	nexposeAssetFetcher := &NexposeAssetFetcher{
		Client: ts.Client(),
		Host: "http://nexpose-instance.com",
		PageSize: 100,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	//respAsset := <- assetChan
	//assert.Nil(t, <-errChan)
	for {
		select {
		case respAsset, ok := <-assetChan:
			if !ok {
				assetChan = nil
			}
			assert.Equal(t, respAsset, asset)
		case err, ok := <-errChan:
			if !ok {
				errChan = nil
			}
			t.Fatal(err)
		}
		if assetChan == nil && errChan == nil {
			break
		}
	}
}

func TestMakeRequest(t *testing.T) {

	resp := SiteAssetsResponse{
		 Resources: []nexpose.Asset{
			 nexpose.Asset{
				 IP: "127.0.0.1",
				 ID: 123456,
			 },
		 },
		 Page: Page{},
		 Links:nexpose.Link{},
	}
	respJSON,_ := json.Marshal(resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(respJSON)
	}))
	defer ts.Close()
	c := ts.Client()
	assetFetcher := &NexposeAssetFetcher{
		Client:   c,
		Host:     ts.URL,
		PageSize: 100,
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

func TestMakeRequestWithNoAssetsReturned(t *testing.T) {
	resp := SiteAssetsResponse{
		Resources: []nexpose.Asset{},
		Page: Page{},
		Links:nexpose.Link{},
	}
	respJSON,_ := json.Marshal(resp)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(respJSON)
	}))
	defer ts.Close()
	c := ts.Client()
	assetFetcher := &NexposeAssetFetcher{
		Client:   c,
		Host:     ts.URL,
		PageSize: 100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan nexpose.Asset, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	wg.Wait()

	close(assetChan)
	close(errChan)

	assert.Equal(t, nexpose.Asset{}, <-assetChan)
	assert.Nil(t, <-errChan)
}

func TestMakeRequestNoResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	c := ts.Client()
	assetFetcher := &NexposeAssetFetcher{
		Client:   c,
		Host:     ts.URL,
		PageSize: 100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan nexpose.Asset, 1)
	errChan := make(chan error, 1)
	defer close(assetChan)
	defer close(errChan)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)

	assert.NotNil(t, <-errChan)
}


func TestNewNexposeSiteAssetsRequest(t *testing.T) {
	req, err := newNexposeSiteAssetsRequest("http://nexpose-instance.com", "siteID", 1, 100)

	assert.Nil(t, err)
	assert.Equal(t, "http://nexpose-instance.com/api/3/sites/siteID/assets?page=1&size=100", req.URL.String())
}

func TestNewNexposeSiteAssetsRequestExtraSlashes(t *testing.T) {
	req, err := newNexposeSiteAssetsRequest("http://nexpose-instance.com/", "/siteID/", 1, 100)

	assert.NoError(t, err)
	assert.Equal(t, "http://nexpose-instance.com/api/3/sites/siteID/assets?page=1&size=100", req.URL.String())
}