package assetfetcher

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestFetchAssetsSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	asset := Asset{
		IP:      "127.0.0.1",
		ID:      123456,
		History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}},
	}
	expectedAsset, err := asset.AssetPayloadToAssetEvent()
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
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

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

func TestFetchAssetsSuccessWithOneMakeRequestCall(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	asset1 := Asset{
		IP:      "127.0.0.1",
		ID:      123456,
		History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}},
	}
	expectedAsset1, _ := asset1.AssetPayloadToAssetEvent()
	asset2 := Asset{
		IP:      "127.0.0.1",
		ID:      123456,
		History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}},
	}
	expectedAsset2, _ := asset2.AssetPayloadToAssetEvent()
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
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

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

func TestFetchAssetsSuccessWithMultipleMakeRequestsCalled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	asset1 := Asset{IP: "127.0.0.1", ID: 1, History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}}}
	expectedAsset1, _ := asset1.AssetPayloadToAssetEvent()
	asset2 := Asset{IP: "127.0.0.2", ID: 2, History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}}}
	expectedAsset2, _ := asset1.AssetPayloadToAssetEvent()
	asset3 := Asset{IP: "127.0.0.3", ID: 3, History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}}}
	expectedAsset3, _ := asset1.AssetPayloadToAssetEvent()
	asset4 := Asset{IP: "127.0.0.4", ID: 4, History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}}}
	expectedAsset4, _ := asset1.AssetPayloadToAssetEvent()
	asset5 := Asset{IP: "127.0.0.5", ID: 5, History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}}}
	expectedAsset5, _ := asset1.AssetPayloadToAssetEvent()
	page := Page{
		TotalPages:     3,
		TotalResources: 5,
	}
	page1Resp := SiteAssetsResponse{
		Resources: []Asset{asset1, asset2},
		Page:      page,
	}
	page2Resp := SiteAssetsResponse{
		Resources: []Asset{asset3, asset4},
		Page:      page,
	}
	page3Resp := SiteAssetsResponse{
		Resources: []Asset{asset5},
		Page:      page,
	}
	respJSON1, _ := json.Marshal(page1Resp)
	respJSON2, _ := json.Marshal(page2Resp)
	respJSON3, _ := json.Marshal(page3Resp)

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(respJSON1)),
		StatusCode: http.StatusOK,
	}, nil)
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(respJSON2)),
		StatusCode: http.StatusOK,
	}, nil)
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(respJSON3)),
		StatusCode: http.StatusOK,
	}, nil)

	host, _ := url.Parse("http://localhost")
	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       host,
		PageSize:   2, // with a page size of 2: 2 assets will be returned for pages 1 and 2, and 1 will be returned on page 3
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

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
	assert.Len(t, assets, 5)
	assert.Contains(t, assets, expectedAsset1)
	assert.Contains(t, assets, expectedAsset2)
	assert.Contains(t, assets, expectedAsset3)
	assert.Contains(t, assets, expectedAsset4)
	assert.Contains(t, assets, expectedAsset5)
}

func TestFetchAssetsSuccessWithMultipleMakeRequestsCalledWithError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	asset1 := Asset{IP: "127.0.0.1", ID: 1, History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}}}
	expectedAsset1, _ := asset1.AssetPayloadToAssetEvent()
	asset2 := Asset{IP: "127.0.0.2", ID: 2, History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}}}
	expectedAsset2, _ := asset1.AssetPayloadToAssetEvent()
	asset3 := Asset{IP: "127.0.0.3", ID: 3, History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}}}
	expectedAsset3, _ := asset1.AssetPayloadToAssetEvent()
	page := Page{
		TotalPages:     3,
		TotalResources: 5,
	}
	page1Resp := SiteAssetsResponse{
		Resources: []Asset{asset1, asset2},
		Page:      page,
	}
	page3Resp := SiteAssetsResponse{
		Resources: []Asset{asset3},
		Page:      page,
	}
	respJSON1, _ := json.Marshal(page1Resp)
	respJSON3, _ := json.Marshal(page3Resp)
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(respJSON1)),
		StatusCode: http.StatusOK,
	}, nil)
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader([]byte("fail"))),
		StatusCode: http.StatusOK,
	}, nil)
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(respJSON3)),
		StatusCode: http.StatusOK,
	}, nil)

	host, _ := url.Parse("http://localhost")
	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       host,
		PageSize:   2,
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	var assets []domain.AssetEvent
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

func TestFetchAssetsBadJSONInResponseError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body: ioutil.NopCloser(bytes.NewReader([]byte("fail"))),
	}, nil)

	host, _ := url.Parse("http://localhost")
	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       host,
	}

	_, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	assert.IsType(t, &ErrorParsingJSONResponse{}, <-errChan) // Error will be returned from json.Unmarshal and added to errChan
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
		Links: Link{},
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
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	// An empty Asset will be returned on the channel because we're reading from a close channel here - this is expected
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

func TestFetchAssetsAssetPayloadToAssetEventError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	resp := SiteAssetsResponse{
		Resources: []Asset{{History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "not a time"}}}},
		Page: Page{
			TotalPages:     1,
			TotalResources: 1,
		},
		Links: Link{},
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
	assert.IsType(t, &ErrorConvertingAssetPayload{}, actualError)
}

func TestMakeRequestSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	asset := Asset{
		IP:      "127.0.0.1",
		ID:      1,
		History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}}}
	resp := SiteAssetsResponse{
		Resources: []Asset{asset},
		Page:      Page{},
		Links:     Link{},
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
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)
	defer close(assetChan)
	defer close(errChan)

	wg.Add(1)
	nexposeAssetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)

	assert.NotNil(t, <-assetChan)
}

func TestMakeRequestWithErrorReadingResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	rd := &errReader{Error: errors.New("ioutil.ReadAll error")}

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(rd),
		StatusCode: http.StatusOK,
	}, nil)

	host, _ := url.Parse("http://localhost")
	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       host,
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	nexposeAssetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	wg.Wait()

	close(assetChan)
	close(errChan)

	assert.IsType(t, &ErrorReadingNexposeResponse{}, <-errChan)
}

func TestMakeRequestHTTPError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(nil, errors.New("HTTPError"))

	host, _ := url.Parse("http://localhost")
	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       host,
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	nexposeAssetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	wg.Wait()

	close(assetChan)
	close(errChan)

	err := <-errChan
	assert.IsType(t, &NexposeHTTPRequestError{}, err)
	assert.Contains(t, err.Error(), "Error making an HTTP request to Nexpose with URL http://localhost/api/3/sites/siteID/assets?page=100&size=100:")
}

func TestMakeRequestWithAssetPayloadToAssetEventError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	resp := SiteAssetsResponse{
		Resources: []Asset{{History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "not a time"}}}},
		Page:      Page{},
		Links:     Link{},
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
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	nexposeAssetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	wg.Wait()

	close(assetChan)
	close(errChan)

	assert.IsType(t, &ErrorConvertingAssetPayload{}, <-errChan)
}

func TestMakeRequestWithNoAssetsReturned(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	resp := SiteAssetsResponse{
		Resources: []Asset{},
		Page:      Page{},
		Links:     Link{},
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
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	nexposeAssetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	wg.Wait()

	close(assetChan)
	close(errChan)

	// An empty Asset will be returned on the channel because we're reading from a close channel here - this is expected
	assert.Equal(t, domain.AssetEvent{}, <-assetChan)
	assert.Nil(t, <-errChan)
}

func TestMakeRequestWithNoResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body: ioutil.NopCloser(bytes.NewReader([]byte("fail"))),
	}, nil)

	host, _ := url.Parse("http://localhost")
	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       host,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)
	defer close(assetChan)
	defer close(errChan)

	wg.Add(1)
	nexposeAssetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)

	assert.IsType(t, &ErrorParsingJSONResponse{}, <-errChan) // Error will be returned from json.Unmarshal and added to errChan
}

func TestNewNexposeSiteAssetsRequestSuccess(t *testing.T) {
	host, _ := url.Parse("http://localhost")
	assetFetcher := &NexposeAssetFetcher{
		Host:     host,
		Username: "username",
		Password: "password",
		PageSize: 100,
	}
	req := assetFetcher.newNexposeSiteAssetsRequest("siteID", 1)

	assert.Equal(t, "http://localhost/api/3/sites/siteID/assets?page=1&size=100", req.URL.String())
}

func TestNewNexposeSiteAssetsRequestWithExtraSlashes(t *testing.T) {
	host, _ := url.Parse("http://localhost")
	assetFetcher := &NexposeAssetFetcher{
		Host:     host,
		Username: "username",
		Password: "password",
		PageSize: 100,
	}
	req := assetFetcher.newNexposeSiteAssetsRequest("/siteID/", 1)

	assert.Equal(t, "http://localhost/api/3/sites/siteID/assets?page=1&size=100", req.URL.String())
}
