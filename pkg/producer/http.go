package producer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
)

// AssetProducer holds streaming appliance configuration
type AssetProducer struct {
	HTTPClient *http.Client
	Endpoint   *url.URL
}

type assetEventPayload struct {
	ScanTime time.Time `json:"scanTime,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
	ID       int64     `json:"id,omitempty"`
	IP       string    `json:"ip,omitempty"`
	ScanType string    `json:"scanType, omitempty"`
}

// Produce publishes sends the asset event to the streaming appliance
func (p *AssetProducer) Produce(ctx context.Context, asset domain.AssetEvent) error {
	payload := assetEventPayload{
		ScanTime: asset.ScanTime,
		Hostname: asset.Hostname,
		ID:       asset.ID,
		IP:       asset.IP,
		ScanType: asset.ScanType,
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, p.Endpoint.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := p.HTTPClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response from http producer: %d %s",
			res.StatusCode, string(resBody))
	}
	return nil
}
