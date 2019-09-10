package main

import (
	"context"
	"net/http"
	"os"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/assetfetcher"
	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	nexposeassetproducer "github.com/asecurityteam/nexpose-asset-producer/pkg/handlers/v1"
	"github.com/asecurityteam/nexpose-asset-producer/pkg/producer"
	"github.com/asecurityteam/serverfull"
	"github.com/asecurityteam/settings"
)

func main() {
	ctx := context.Background()

	source, err := settings.NewEnvSource(os.Environ())
	if err != nil {
		panic(err.Error())
	}
	assetFetcherComponent := &assetfetcher.AssetFetcherConfigComponent{}
	assetFetcher := new(assetfetcher.NexposeAssetFetcher)
	if err = settings.NewComponent(context.Background(), source, assetFetcherComponent, assetFetcher); err != nil {
		panic(err.Error())
	}
	assetFetcher.HTTPClient = http.DefaultClient

	producerComponent := &producer.ProducerConfigComponent{}
	assetProducer := new(producer.AssetProducer)
	if err = settings.NewComponent(context.Background(), source, producerComponent, assetProducer); err != nil {
		panic(err.Error())
	}
	assetProducer.HTTPClient = http.DefaultClient

	notifier := &nexposeassetproducer.NexposeScannedAssetProducer{
		Producer:     assetProducer,
		AssetFetcher: assetFetcher,
		LogFn:        domain.LoggerFromContext,
		StatFn:       domain.StatFromContext,
	}

	lambdaHandlers := map[string]serverfull.Function{
		"notification": serverfull.NewFunction(notifier.Handle),
	}

	fetcher := &serverfull.StaticFetcher{Functions: lambdaHandlers}
	if err := serverfull.Start(ctx, source, fetcher); err != nil {
		panic(err.Error())
	}
}
