package main

import (
	"context"
	"net/http"
	"os"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/assetfetcher"
	nexposevulnnotiifier "github.com/asecurityteam/nexpose-vuln-notifier/pkg/handlers/v1"
	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/producer"
	"github.com/asecurityteam/runhttp"
	"github.com/asecurityteam/serverfull/pkg"
	serverfulldomain "github.com/asecurityteam/serverfull/pkg/domain"
	"github.com/asecurityteam/settings"
	"github.com/aws/aws-lambda-go/lambda"
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

	notifier := &nexposevulnnotiifier.NexposeVulnNotificationHandler{
		Producer:     assetProducer,
		AssetFetcher: assetFetcher,
		LogFn:        runhttp.LoggerFromContext,
		StatFn:       runhttp.StatFromContext,
	}

	lambdaHandlers := map[string]serverfulldomain.Handler{
		"notification": lambda.NewHandler(notifier.Handle),
	}

	rt, err := serverfull.NewStatic(ctx, source, lambdaHandlers)
	if err != nil {
		panic(err.Error())
	}
	if err := rt.Run(); err != nil {
		panic(err.Error())
	}
}
