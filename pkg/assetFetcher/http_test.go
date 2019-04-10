package assetFetcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"net/http"
	"context"
	"sync"

	"github.com/asecurityteam/nexpose-vuln-notifier/pkg/domain/nexpose"
	"fmt"
)


func TestMakeRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("inside request handler")
		fmt.Fprintln(w, "ok")
	}))
	defer ts.Close()
	c := ts.Client()
	fmt.Println("made the test http server")
	assetFetcher := &NexposeAssetFetcher{
		Client: c,
		Host: ts.URL,
		PageSize: 100,
	}

	var wg sync.WaitGroup
	assetChan := make(chan nexpose.Asset)
	errChan := make(chan error)
	defer close(assetChan)
	defer close(errChan)

	wg.Add(1)
	fmt.Println("about to call makeRequest")

	assetFetcher.makeRequest(context.Background(), &wg, "siteID", 100, assetChan, errChan)
	fmt.Print("after makeRequest")


	go func () {
		for {
			fmt.Print("inside forloop1")
			select {
			case _, ok := <-assetChan:
				if !ok {
					t.Fatal("assetChan was closed")
				}
			case err, ok := <-errChan:
				if !ok {
					t.Fatal("errChan was closed")
				} else {
					t.Fatalf("Got error making request: %s", err.Error())
				}
			}
			fmt.Print("inside forloop2")
		}
	}()
	wg.Wait()
	fmt.Print("done with forloop")
}

func TestNewNexposeSiteAssetsRequest(t *testing.T) {
	fmt.Print("starting test")
	req, err := newNexposeSiteAssetsRequest("http://nexpose.com", "siteID", 1, 100)

	assert.Nil(t, err)
	assert.Equal(t, "http://nexpose.com/api/3/sites/siteID/assets?page=1&size=100", req.URL.String())
}
