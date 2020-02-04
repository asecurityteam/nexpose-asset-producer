package assetvalidator

import (
	"context"
)

// AssetValidatorConfig holds configuration that validates
// assets from Nexpose
type AssetValidatorConfig struct {
}

// Name is used by the settings library and will add a "NEXPOSEVALIDATOR_"
// prefix to AssetValidatorConfig environment variables
func (c *AssetValidatorConfig) Name() string {
	return "NexposeValidator"
}

// AssetValidatorComponent satisfies the settings library Component
// API, and may be used by the settings.NewComponent function.
type AssetValidatorComponent struct{}

// Settings can be used to populate default values if there are any
func (*AssetValidatorComponent) Settings() *AssetValidatorConfig {
	return &AssetValidatorConfig{}
}

// New constructs a NexposeAssetValidator from a config.
func (*AssetValidatorComponent) New(_ context.Context, c *AssetValidatorConfig) (*NexposeAssetValidator, error) {

	return &NexposeAssetValidator{}, nil
}
