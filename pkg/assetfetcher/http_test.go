package assetfetcher

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"sync"
	"testing"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain"
	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestFetchAssetsSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	expectedAsset := domain.AssetEvent{
		IP: "127.0.0.1",
		ID: 123456,
	}
	resp := SiteAssetsResponse{
		Resources: []Asset{Asset{IP: "127.0.0.1", ID: 123456}},
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

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
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

	expectedAsset1 := domain.AssetEvent{
		IP: "127.0.0.1",
		ID: 123,
	}
	expectedAsset2 := domain.AssetEvent{
		IP: "127.0.0.2",
		ID: 456,
	}
	page := Page{
		TotalPages:     2,
		TotalResources: 2,
	}
	resp1 := SiteAssetsResponse{
		Resources: []Asset{Asset{IP: "127.0.0.1", ID: 123}},
		Page:      page,
	}
	resp2 := SiteAssetsResponse{
		Resources: []Asset{Asset{IP: "127.0.0.2", ID: 456}},
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

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
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

	expectedAsset1 := domain.AssetEvent{ID: 1}
	expectedAsset2 := domain.AssetEvent{ID: 2}
	expectedAsset3 := domain.AssetEvent{ID: 3}
	expectedAsset4 := domain.AssetEvent{ID: 4}
	expectedAsset5 := domain.AssetEvent{ID: 5}
	page := Page{
		TotalPages:     3,
		TotalResources: 5,
	}
	page1Resp := SiteAssetsResponse{
		Resources: []Asset{Asset{ID: 1}, Asset{ID: 2}},
		Page:      page,
	}
	page2Resp := SiteAssetsResponse{
		Resources: []Asset{Asset{ID: 3}, Asset{ID: 4}},
		Page:      page,
	}
	page3Resp := SiteAssetsResponse{
		Resources: []Asset{Asset{ID: 5}},
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

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
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

	expectedAsset1 := domain.AssetEvent{ID: 1}
	expectedAsset2 := domain.AssetEvent{ID: 2}
	expectedAsset3 := domain.AssetEvent{ID: 3}
	page := Page{
		TotalPages:     3,
		TotalResources: 5,
	}
	page1Resp := SiteAssetsResponse{
		Resources: []Asset{Asset{ID: 1}, Asset{ID: 2}},
		Page:      page,
	}
	page3Resp := SiteAssetsResponse{
		Resources: []Asset{Asset{ID: 3}},
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

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
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

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
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

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
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

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
	}

	assetChan, errChan := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	assert.Equal(t, domain.AssetEvent{}, <-assetChan) // An empty asset will be added to assetChan if there's a response with no asset
	assert.Nil(t, <-errChan)
}

func TestFetchAssetsHTTPError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(nil, errors.New("HTTPError"))

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
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
		Resources: []Asset{Asset{History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "not a time"}}}},
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

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
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

func TestFetchAssetsWithInvalidHost(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	asset := Asset{
		IP: "127.0.0.1",
		ID: 123456,
	}
	resp := SiteAssetsResponse{
		Resources: []Asset{asset},
		Page:      Page{},
		Links:     Link{},
	}
	respJSON, _ := json.Marshal(resp)
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(respJSON)),
		StatusCode: http.StatusOK,
	}, nil).Times(0)

	nexposeAssetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	asset := Asset{
		IP: "127.0.0.1",
		ID: 123456,
	}
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

	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)
	defer close(assetChan)
	defer close(errChan)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)

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

	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	wg.Wait()

	close(assetChan)
	close(errChan)

	assert.IsType(t, &ErrorReadingNexposeResponse{}, <-errChan)
}

func TestMakeRequestWithInvalidHost(t *testing.T) {
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
	}, nil).Times(0)

	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "~!@#$%^&*()_+:?><!@#$%^&*())_:",
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	wg.Wait()

	close(assetChan)
	close(errChan)

	assert.IsType(t, &URLParsingError{}, <-errChan)
}

func TestMakeRequestHTTPError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(nil, errors.New("HTTPError"))

	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
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
		Resources: []Asset{Asset{History: assetHistoryEvents{AssetHistory{Type: "SCAN", Date: "not a time"}}}},
		Page:      Page{},
		Links:     Link{},
	}
	respJSON, _ := json.Marshal(resp)
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(respJSON)),
		StatusCode: http.StatusOK,
	}, nil)

	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
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
	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
		PageSize:   100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.AssetEvent, 1)
	errChan := make(chan error, 1)

	wg.Add(1)
	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	wg.Wait()

	close(assetChan)
	close(errChan)

	assert.Equal(t, domain.AssetEvent{}, <-assetChan) // An empty asset will be added to assetChan if there's a response with no asset
	assert.Nil(t, <-errChan)
}

func TestMakeRequestWithNoResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body: ioutil.NopCloser(bytes.NewReader([]byte("fail"))),
	}, nil)

	assetFetcher := &NexposeAssetFetcher{
		HTTPClient: &http.Client{Transport: mockRT},
		Host:       "http://localhost",
	}

	var wg sync.WaitGroup
	assetChan := make(chan domain.AssetEvent, 1)
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
