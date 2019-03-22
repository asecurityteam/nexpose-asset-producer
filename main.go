package main

import (
	"context"
	"os"

	serverfull "github.com/asecurityteam/serverfull/pkg"
	serverfulldomain "github.com/asecurityteam/serverfull/pkg/domain"
	"github.com/asecurityteam/settings"
	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	ctx := context.Background()
	var _ lambda.Handler = nil // Placeholder to keep lambda imported. Delete after adding to the map.
	handlers := map[string]serverfulldomain.Handler{
		// TODO: Register lambda functions here in the form of
		// "name_or_arn": lambda.NewHandler(myHandler.Handle)
	}

	source, err := settings.NewEnvSource(os.Environ())
	if err != nil {
		panic(err.Error())
	}
	rt, err := serverfull.NewStatic(ctx, source, handlers)
	if err != nil {
		panic(err.Error())
	}
	if err := rt.Run(); err != nil {
		panic(err.Error())
	}
}
