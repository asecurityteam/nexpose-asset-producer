package producer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestProduceSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	asset := domain.AssetEvent{
		IP: "127.0.0.1",
		ID: 123456,
	}

	respJSON, _ := json.Marshal(asset)
	respReader := bytes.NewReader(respJSON)
	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{
		Body:       ioutil.NopCloser(respReader),
		StatusCode: http.StatusOK,
	}, nil)

	producer := &AssetProducer{
		HTTPClient: &http.Client{Transport: mockRT},
		Endpoint:   "http://localhost",
	}
	err := producer.Produce(context.Background(), asset)
	assert.Nil(t, err)
}

func TestProduceError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRT := NewMockRoundTripper(ctrl)

	mockRT.EXPECT().RoundTrip(gomock.Any()).Return(nil, errors.New("HTTPError"))

	asset := domain.AssetEvent{
		IP: "127.0.0.1",
		ID: 123456,
	}
	producer := &AssetProducer{
		HTTPClient: &http.Client{Transport: mockRT},
		Endpoint:   "http://localhost",
	}
	err := producer.Produce(context.Background(), asset)
	assert.NotNil(t, err)
}
