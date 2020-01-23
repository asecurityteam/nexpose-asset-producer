package assetfetcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestFetchAssetsSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	asset := Asset{
		IP:      "127.0.0.1",
		ID:      123456,
		History: assetHistoryEvents{AssetHistory{ScanID: 1, Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}},
	}
	expectedAsset, err := asset.AssetPayloadToAssetEvent(time.Date(2019, 05, 14, 15, 03, 47, 0, time.UTC))
	assert.NoError(t, err)
	resp := SiteAssetsResponse{
		Resources: []Asset{asset},
		Page: Page{
			TotalPages:     1,
			TotalResources: 1,
		},
	}
	respJSON, _ := json.Marshal(resp)
	respReader := bytes.NewReader(respJSON)
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(respReader),
		StatusCode: http.StatusOK,
	}, nil)

	host, _ := url.Parse("http://localhost")
	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       host,
		PageSize:   100,
		StatFn:     MockStatFn,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67", "1")

	var actualAsset domain.AssetEvent
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

func TestFetchAssetsSuccessNoScans(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	asset := Asset{
		IP: "127.0.0.1",
		ID: 123456,
		// this asset has never been scanned, so no SCAN Type exists in the assetHistoryEvents array
		History: assetHistoryEvents{AssetHistory{Type: "CREATE", Date: "2019-05-14T15:03:47.000Z"}},
	}

	resp := SiteAssetsResponse{
		Resources: []Asset{asset},
		Page: Page{
			TotalPages:     1,
			TotalResources: 1,
		},
	}
	respJSON, _ := json.Marshal(resp)
	respReader := bytes.NewReader(respJSON)
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(respReader),
		StatusCode: http.StatusOK,
	}, nil)

	host, _ := url.Parse("http://localhost")
	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       host,
		PageSize:   100,
		StatFn:     MockStatFn,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67", "1")

	for {
		select {
		case _, ok := <-assetChan:
			if !ok {
				assetChan = nil
			} else {
				t.Fatal("Nothing should have been produced into the assetChan channel")
			}
		case assetError, ok := <-errChan:
			if !ok {
				errChan = nil
			} else {
				assert.Error(t, assetError)
			}
		}
		if assetChan == nil && errChan == nil {
			break
		}
	}
}

func TestFetchAssetsSuccessWithOneMakeRequestCall(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	asset1 := Asset{
		IP:      "127.0.0.1",
		ID:      123456,
		History: assetHistoryEvents{AssetHistory{ScanID: 1, Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}},
	}
	expectedAsset1, _ := asset1.AssetPayloadToAssetEvent(time.Date(2019, 05, 14, 15, 03, 47, 0, time.UTC))
	asset2 := Asset{
		IP:      "127.0.0.1",
		ID:      123456,
		History: assetHistoryEvents{AssetHistory{ScanID: 1, Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}},
	}
	expectedAsset2, _ := asset2.AssetPayloadToAssetEvent(time.Date(2019, 05, 14, 15, 03, 47, 0, time.UTC))
	page := Page{
		TotalPages:     2,
		TotalResources: 2,
	}
	resp1 := SiteAssetsResponse{
		Resources: []Asset{asset1},
		Page:      page,
	}
	resp2 := SiteAssetsResponse{
		Resources: []Asset{asset2},
		Page:      page,
	}
	respJSON1, _ := json.Marshal(resp1)
	respJSON2, _ := json.Marshal(resp2)

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(respJSON1)),
		StatusCode: http.StatusOK,
	}, nil)
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(respJSON2)),
		StatusCode: http.StatusOK,
	}, nil)

	host, _ := url.Parse("http://localhost")
	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       host,
		PageSize:   1,
		StatFn:     MockStatFn,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67", "1")

	var assets []domain.AssetEvent
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
	assert.Equal(t, []domain.AssetEvent{expectedAsset1, expectedAsset2}, assets)
}

func TestFetchAssetsFirstResponseError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader([]byte("fail"))),
		StatusCode: http.StatusBadRequest,
	}, nil)

	host, _ := url.Parse("http://localhost")
	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       host,
		StatFn:     MockStatFn,
	}

	_, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67", "1")

	assert.IsType(t, &ErrorFetchingAssets{}, <-errChan) // Error will be returned from json.Unmarshal and added to errChan
}

type errReader struct {
	Error error
}

func (r *errReader) Read(_ []byte) (int, error) {
	return 0, r.Error
}

func TestFetchAssetsWithErrorReadingResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	rd := &errReader{Error: errors.New("ioutil.ReadAll error")}

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body: ioutil.NopCloser(rd),
	}, nil)

	host, _ := url.Parse("http://localhost")
	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       host,
		PageSize:   100,
		StatFn:     MockStatFn,
	}

	_, err := nexposeAssetFetcher.fetchNexposeSiteAssetsPage(context.Background(), 0, "site67")

	assert.IsType(t, &ErrorReadingNexposeResponse{}, err)
}

func TestFetchAssetsSuccessWithNoAssetReturned(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	resp := SiteAssetsResponse{
		Resources: []Asset{},
		Page: Page{
			TotalPages:     1,
			TotalResources: 1,
		},
	}
	respJSON, _ := json.Marshal(resp)

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(respJSON)),
		StatusCode: http.StatusOK,
	}, nil)

	host, _ := url.Parse("http://localhost")
	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       host,
		StatFn:     MockStatFn,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67", "1")

	// An empty Asset will be returned on the channel because we're reading from a closed channel here - this is expected
	assert.Equal(t, domain.AssetEvent{}, <-assetChan)
	assert.Nil(t, <-errChan)
}

func TestFetchAssetsHTTPError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(nil, errors.New("HTTPError"))

	host, _ := url.Parse("http://localhost")
	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       host,
		PageSize:   100,
		StatFn:     MockStatFn,
	}

	_, err := nexposeAssetFetcher.fetchNexposeSiteAssetsPage(context.Background(), 0, "site67")

	assert.IsType(t, &NexposeHTTPRequestError{}, err)
}

func TestFetchAssetsAssetPayloadToAssetEventError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	resp := SiteAssetsResponse{
		Resources: []Asset{{History: assetHistoryEvents{AssetHistory{ScanID: 1, Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}}}},
		Page: Page{
			TotalPages:     1,
			TotalResources: 1,
		},
	}
	respJSON, _ := json.Marshal(resp)
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(respJSON)),
		StatusCode: http.StatusOK,
	}, nil)

	host, _ := url.Parse("http://localhost")
	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       host,
		PageSize:   1,
		StatFn:     MockStatFn,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67", "1")

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
	assert.IsType(t, &MissingRequiredInformation{}, actualError)
}

func TestNewNexposeSiteAssetsRequestSuccess(t *testing.T) {
	host, _ := url.Parse("http://localhost")
	assetFetcher := &NexposeAssetFetcher{
		Host:     host,
		PageSize: 100,
		StatFn:   MockStatFn,
	}
	req, err := assetFetcher.newNexposeSiteAssetsRequest("siteID", 1)
	assert.Nil(t, err)
	assert.Equal(t, "http://localhost/api/3/sites/siteID/assets?page=1&size=100", req.URL.String())
}

func TestNewNexposeSiteAssetsRequestWithExtraSlashes(t *testing.T) {
	host, _ := url.Parse("http://localhost")
	assetFetcher := &NexposeAssetFetcher{
		Host:     host,
		PageSize: 100,
		StatFn:   MockStatFn,
	}
	req, err := assetFetcher.newNexposeSiteAssetsRequest("/siteID/", 1)
	assert.Nil(t, err)
	assert.Equal(t, "http://localhost/api/3/sites/siteID/assets?page=1&size=100", req.URL.String())
}

func TestCheckDependenciesSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockRT := NewMockRoundTripper(ctrl)

	host, _ := url.Parse("http://localhost")
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader([]byte("🦀"))),
		StatusCode: http.StatusOK,
	}, nil)
	assetFetcher := &NexposeAssetFetcher{
		Host:       host,
		HTTPClient: &http.Client{Transport: mockRT},
	}
	req := assetFetcher.CheckDependencies(context.Background())

	assert.Equal(t, req, nil)
}

func TestCheckDependenciesFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockRT := NewMockRoundTripper(ctrl)

	host, _ := url.Parse("http://localhost")
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader([]byte("🐖"))),
		StatusCode: http.StatusTeapot,
	}, nil)
	assetFetcher := &NexposeAssetFetcher{
		Host:       host,
		HTTPClient: &http.Client{Transport: mockRT},
	}
	req := assetFetcher.CheckDependencies(context.Background())

	assert.NotNil(t, req)
}
