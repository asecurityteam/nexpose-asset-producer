package producer

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProducerConfig_Name(t *testing.T) {
	producerComponent := &ProducerConfigComponent{}
	producerConfig := producerComponent.Settings()
	require.Equal(t, "HTTPProducer", producerConfig.Name())
}

func TestProducerComponent_New(t *testing.T) {
	config := &ProducerConfig{Endpoint: "http://localhost"}
	producerComponent := &ProducerConfigComponent{}
	_, e := producerComponent.New(context.Background(), config)
	require.Nil(t, e)
}

func TestProducerComponent_New_InvalidEndpoint(t *testing.T) {
	config := &ProducerConfig{Endpoint: "~!@#$%^&*()_+:?><!@#$%^&*())_:"}
	producerComponent := &ProducerConfigComponent{}
	_, e := producerComponent.New(context.Background(), config)
	require.NotNil(t, e)
}
