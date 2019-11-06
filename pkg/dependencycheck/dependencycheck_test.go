package dependencycheck

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"

	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestDepCheckSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	nexposeURL, _ := url.Parse("http://nexpose.com/api/3/vulnerabilities/vulnID/solutions")

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(nil)),
		StatusCode: http.StatusOK,
	}, nil)
	depCheck := DependencyCheck{
		HTTPClient:      &http.Client{Transport: mockRT},
		NexposeEndpoint: nexposeURL,
	}
	err := depCheck.CheckDependencies(context.Background())
	assert.Equal(t, err, nil)
}

func TestDepCheckNexposeFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)
	nexposeURL, _ := url.Parse("http://nexpose.com/api/3/vulnerabilities/vulnID/solutions")

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader(nil)),
		StatusCode: http.StatusTeapot,
	}, nil)
	depCheck := DependencyCheck{
		HTTPClient:      &http.Client{Transport: mockRT},
		NexposeEndpoint: nexposeURL,
	}
	err := depCheck.CheckDependencies(context.Background())
	assert.NotNil(t, err, nil)
}
