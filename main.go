package main

import (
	"context"
	"net/http"
	"os"
	"strconv"

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

	pageSize, _ := strconv.Atoi(os.Getenv("NEXPOSE_SITE_ASSET_PAGE_SIZE"))

	notifier := &nexposevulnnotiifier.NexposeVulnNotificationHandler{
		Producer: &producer.AssetProducer{
			HTTPClient: http.DefaultClient,
			Endpoint:   os.Getenv("STREAMING_APPLIANCE_ENDPOINT"),
		},
		AssetFetcher: &assetfetcher.NexposeAssetFetcher{
			HTTPClient: http.DefaultClient,
			Host:       os.Getenv("NEXPOSE_HOST"),
			PageSize:   pageSize,
		},
		LogFn:  runhttp.LoggerFromContext,
		StatFn: runhttp.StatFromContext,
	}

	lambdaHandlers := map[string]serverfulldomain.Handler{
		"notification": lambda.NewHandler(notifier.Handle),
	}

	source, err := settings.NewEnvSource(os.Environ())
	if err != nil {
		panic(err.Error())
	}

	rt, err := serverfull.NewStatic(ctx, source, lambdaHandlers)
	if err != nil {
		panic(err.Error())
	}
	if err := rt.Run(); err != nil {
		panic(err.Error())
	}
}
