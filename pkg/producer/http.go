package producer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain"
)

// AssetProducer holds streaming appliance configuration
type AssetProducer struct {
	HTTPClient *http.Client
	Endpoint   string
}

// Produce publishes sends the asset event to the streaming appliance
func (p *AssetProducer) Produce(ctx context.Context, asset domain.Asset) error {
	body, _ := json.Marshal(asset)
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
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response from streaming appliance: %d", res.StatusCode)
	}
	return nil
}
