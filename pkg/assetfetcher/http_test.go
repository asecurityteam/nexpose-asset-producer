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

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestFetchAssetsSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	expectedAsset := domain.Asset{
		IP:      "127.0.0.1",
		ID:      123456,
		History: domain.AssetHistoryEvents{domain.AssetHistory{ScanID: 1, Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}},
	}
	resp := SiteAssetsResponse{
		Resources: []domain.Asset{expectedAsset},
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

	assetList, err := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	assert.Equal(t, []domain.Asset{expectedAsset}, assetList)
	assert.Nil(t, err)
}

func TestFetchAssetsSuccessWithOneMakeRequestCall(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	expectedAsset1 := domain.Asset{
		IP:      "127.0.0.1",
		ID:      123456,
		History: domain.AssetHistoryEvents{domain.AssetHistory{ScanID: 1, Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}},
	}
	expectedAsset2 := domain.Asset{
		IP:      "127.0.0.1",
		ID:      123456,
		History: domain.AssetHistoryEvents{domain.AssetHistory{ScanID: 1, Type: "SCAN", Date: "2019-05-14T15:03:47.000Z"}},
	}
	page := Page{
		TotalPages:     2,
		TotalResources: 2,
	}
	resp1 := SiteAssetsResponse{
		Resources: []domain.Asset{expectedAsset1},
		Page:      page,
	}
	resp2 := SiteAssetsResponse{
		Resources: []domain.Asset{expectedAsset2},
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

	assetList, err := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	assert.Equal(t, []domain.Asset{expectedAsset1, expectedAsset2}, assetList)
	assert.Nil(t, err)
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

	_, err := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	assert.IsType(t, &domain.ErrorFetchingAssets{}, err) // Error will be returned from json.Unmarshal and added to errChan
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

	assert.IsType(t, &domain.ErrorReadingNexposeResponse{}, err)
}

func TestFetchAssetsSuccessWithNoAssetReturned(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	resp := SiteAssetsResponse{
		Resources: []domain.Asset{},
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

	assetList, err := nexposeAssetFetcher.FetchAssets(context.Background(), "site67")

	// An empty Asset will be returned on the channel because we're reading from a closed channel here - this is expected
	assert.Equal(t, 0, len(assetList))
	assert.Nil(t, err)
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

	assert.IsType(t, &domain.NexposeHTTPRequestError{}, err)
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

func TestNewNexposeAssetsSearchRequestSuccess(t *testing.T) {
	host, _ := url.Parse("http://localhost")
	assetFetcher := &NexposeAssetFetcher{
		Host:     host,
		PageSize: 100,
		StatFn:   MockStatFn,
	}
	req, err := assetFetcher.newNexposeAssetsSearchRequest("siteID", 1)
	assert.Nil(t, err)
	assert.Equal(t, "http://localhost/api/3/assets/search?page=1&size=100", req.URL.String())
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
