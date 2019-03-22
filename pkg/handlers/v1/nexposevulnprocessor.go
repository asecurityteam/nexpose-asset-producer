package v1

import (
	"context"
	"time"
	"net/http"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain"
)


// Processor is a lambda handler that fetches Nexpose Vulns and sends them off to an event stream
type Processor struct {
	Duration time.Duration
	NexposeHTTPClient *http.Client
	LogFn  domain.LogFn
	StatFn domain.StatFn
}


// Handle
func (p *Processor) Handle(ctx context.Context) (Output, error) {

	// call /api/3/assets/search with last-scan-date is-on-or-after (yyyy-MM-dd)
	NexposeFetchAssets(duration)
	// parse response

	// figure out which assets were scanned in the last hour (or set duration)
	// p.Duration

	// for each asset, get the list of vulnerability instances for that asset
	// by calling /api/3/assets/{id}/vulnerabilities
	// and put the result in here

	// for each vuln

}

