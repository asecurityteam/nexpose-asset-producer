package producer

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"time"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain"
)

// AssetProducer holds streaming appliance configuration
type AssetProducer struct {
	HTTPClient *http.Client
	Endpoint   string
}

type assetEventPayload struct {
	LastScanned time.Time `json:"lastScanned,omitempty"`
	Hostname    string    `json:"hostName,omitempty"`
	ID          int64     `json:"id,omitempty"`
	IP          string    `json:"ip,omitempty"`
}

// Produce publishes sends the asset event to the streaming appliance
func (p *AssetProducer) Produce(ctx context.Context, asset domain.AssetEvent) error {
	payload := assetEventPayload{
		LastScanned: asset.LastScanned,
		Hostname:    asset.Hostname,
		ID:          asset.ID,
		IP:          asset.IP,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, p.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := p.HTTPClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return nil
}
