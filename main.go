package main

import (
	"context"
	"os"

	"github.com/asecurityteam/runhttp"
	serverfull "github.com/asecurityteam/serverfull/pkg"
	serverfulldomain "github.com/asecurityteam/serverfull/pkg/domain"
	"github.com/asecurityteam/settings"
	"github.com/aws/aws-lambda-go/lambda"
	nexposevulnprocessor "github.com/asecurityteam/nexpose-vuln-notifier/pkg/handlers/v1"
	"time"
	"net/http"
	"strconv"
	"github.com/asecurityteam/transport"
	"encoding/base64"
)

func main() {
	ctx := context.Background()

	// get Nexpose URL from ENVAR
	timeSinceLastScan, err := time.ParseDuration(os.Getenv("TIME_SINCE_LAST_NEXPOSE_SCAN"))
	if err != nil {
		//do error - string can't be parsed into Duration
	}

	nexposeHTTPClient, err := nexposeHTTPClient()
	if err != nil {
 //handle error
	}

	processor := &nexposevulnprocessor.Processor{
		Duration: timeSinceLastScan,
		NexposeHTTPClient: nexposeHTTPClient,
		LogFn:  runhttp.LoggerFromContext,
		StatFn: runhttp.StatFromContext,
	}

	lambdaHandlers := map[string]serverfulldomain.Handler{
		"processVulnsHandler": lambda.NewHandler(processor.Handle),
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

//make nexpose http client
func nexposeHTTPClient() (*http.Client, error) {
	nexposeTimeout, err := strconv.Atoi(os.Getenv("DIGEST_REQUEST_TIMEOUT_MS"))
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