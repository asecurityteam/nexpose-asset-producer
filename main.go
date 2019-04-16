package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"time"
	"strconv"

	"github.com/asecurityteam/runhttp"
	serverfull "github.com/asecurityteam/serverfull/pkg"
	serverfulldomain "github.com/asecurityteam/serverfull/pkg/domain"
	"github.com/asecurityteam/settings"
	"github.com/aws/aws-lambda-go/lambda"
	nexposevulnnotiifier "github.com/asecurityteam/nexpose-vuln-notifier/pkg/handlers/v1"
	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/assetFetcher"
	"github.com/asecurityteam/transport"
)

func main() {
	ctx := context.Background()

	nexposeHTTPClient, err := nexposeHTTPClient()
	if err != nil {
 	//handle error
	}
	pageSize, _ := strconv.Atoi(os.Getenv("NEXPOSE_SITE_ASSET_RESPONSE_SIZE"))

	notifier := &nexposevulnnotiifier.NexposeVulnNotificationHandler{
		AssetFetcher: &assetFetcher.NexposeAssetFetcher{
			HTTPClient: nexposeHTTPClient,
			Host: os.Getenv("NEXPOSE_HOST"),
			PageSize: pageSize,
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

// nexpose http client
func nexposeHTTPClient() (*http.Client, error) {
	nexposeTimeout, err := strconv.Atoi(os.Getenv("NEXPOSE_REQUEST_TIMEOUT_MS"))
	if err != nil {
		return nil, err
	}
	var retryDecorator = transport.NewRetrier(
		transport.NewPercentJitteredBackoffPolicy(transport.NewFixedBackoffPolicy(50*time.Millisecond), .25),
		transport.NewLimitedRetryPolicy(3,
			transport.NewStatusCodeRetryPolicy(http.StatusInternalServerError, http.StatusBadGateway, http.StatusGatewayTimeout),
			transport.NewTimeoutRetryPolicy(time.Duration(nexposeTimeout)*time.Millisecond)),
	)

	var headerDecorator = transport.NewHeader(
		func(*http.Request) (string, string) {
			return "Authorization",  basicAuth(os.Getenv("NEXPOSE_USERNAME"), os.Getenv("NEXPOSE_PASSWORD"))
		})

	var chain = transport.Chain{
		retryDecorator,
		headerDecorator,
	}
	var t = transport.New(
		transport.OptionDefaultTransport,
		transport.OptionMaxResponseHeaderBytes(4096),
		transport.OptionDisableCompression(true),
	)
	var client = &http.Client{
		Transport: chain.Apply(t),
	}
	return client, nil
}

func basicAuth(username, password string) string {
	auth := "Basic " + username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}