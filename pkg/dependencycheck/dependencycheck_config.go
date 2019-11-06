package dependencycheck

import (
	"context"
	"net/http"
	"net/url"

	httpclient "github.com/asecurityteam/component-httpclient"
)

// DependencyCheckConfig holds configuration to connect to Nexpose
// and make a call to the fetch assets API
type DependencyCheckConfig struct {
	HTTPClient      *httpclient.Config `description:"The HTTP client config from github.com/asecurityteam/component-httpclient."`
	NexposeEndpoint string             `description:"The scheme and host of a Nexpose instance, including endpoint."`
}

// Name is used by the settings library and will add a "DEPENDENCYCHECK_"
// prefix to NexposeEndPoint environment variable
func (c *DependencyCheckConfig) Name() string {
	return "DependencyCheck"
}

// DependencyCheckComponent satisfies the settings library Component
// API, and may be used by the settings.NewComponent function.
type DependencyCheckComponent struct {
	HTTP *httpclient.Component
}

// NewDependencyCheckComponent generates a NewDependencyCheckComponent.
func NewDependencyCheckComponent() *DependencyCheckComponent {
	return &DependencyCheckComponent{
		HTTP: httpclient.NewComponent(),
	}
}

// Settings can be used to populate default values if there are any
func (c *DependencyCheckComponent) Settings() *DependencyCheckConfig {
	return &DependencyCheckConfig{
		HTTPClient: c.HTTP.Settings(),
	}
}

// New constructs a DependencyCheck from a config.
func (c *DependencyCheckComponent) New(ctx context.Context, config *DependencyCheckConfig) (*DependencyCheck, error) {
	rt, e := c.HTTP.New(ctx, config.HTTPClient)
	if e != nil {
		return nil, e
	}
	nexposeEndpoint, err := url.Parse(config.NexposeEndpoint)
	if err != nil {
		return nil, err
	}
	return &DependencyCheck{
		HTTPClient:      &http.Client{Transport: rt},
		NexposeEndpoint: nexposeEndpoint,
	}, nil
}
