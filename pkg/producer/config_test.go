package producer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestName(t *testing.T) {
	producerConfig := ProducerConfig{}
	assert.Equal(t, "HTTPProducer", producerConfig.Name())
}
