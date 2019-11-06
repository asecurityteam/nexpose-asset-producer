package dependencycheck

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDepCheckName(t *testing.T) {
	dependencyCheckConfig := DependencyCheckConfig{}
	assert.Equal(t, "DependencyCheck", dependencyCheckConfig.Name())
}

func TestDepCheckSettings(t *testing.T) {
	dependencyCheckComponent := NewDependencyCheckComponent()
	dependencyCheckConfig := dependencyCheckComponent.Settings()
	assert.IsType(t, dependencyCheckConfig, &DependencyCheckConfig{})
	assert.NotNil(t, dependencyCheckConfig.HTTPClient)
}

func TestDepCheckNew(t *testing.T) {
	dependencyCheckComponent := NewDependencyCheckComponent()
	dependencyCheckConfig := dependencyCheckComponent.Settings()
	dependencyCheck, _ := dependencyCheckComponent.New(context.Background(), dependencyCheckConfig)
	assert.IsType(t, dependencyCheck, &DependencyCheck{})
	assert.NotNil(t, dependencyCheckConfig.HTTPClient)
}
