package assetfetcher

import (
	"fmt"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type errorTest struct {
	name     string
	input    error
	expected string
}

func TestAssetFetcherErrors(t *testing.T) {
	nexposeTestURL := "http://nexpose-instance.com"
	customError := errors.New("myCustomError")
	tc := []errorTest{
		{
			"URLParsingError",
			&URLParsingError{customError, nexposeTestURL},
			fmt.Sprintf("Error parsing Nexpose URL (%v): %v", nexposeTestURL, customError),
		},
		{
			"ErrorParsingJSONResponse",
			&ErrorParsingJSONResponse{customError, nexposeTestURL},
			fmt.Sprintf("Error parsing Nexpose response from %v: %v", nexposeTestURL, customError),
		},
		{
			"ErrorReadingNexposeResponse",
			&ErrorReadingNexposeResponse{customError, nexposeTestURL},
			fmt.Sprintf("Error reading Nexpose response from %v: %v", nexposeTestURL, customError),
		},
		{
			"NexposeHTTPRequestError",
			&NexposeHTTPRequestError{customError, nexposeTestURL},
			fmt.Sprintf("Error making an HTTP request to Nexpose with URL %v: %v", nexposeTestURL, customError),
		},
		{
			"ErrorFetchingAssets",
			&ErrorFetchingAssets{customError},
			fmt.Sprintf("Error fetching assets from Nexpose %v", customError),
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			actual := (tt.input).Error()
			require.Equal(t, tt.expected, actual)
		})
	}
}

type errorNilTest struct {
	name  string
	input error
}

// Test that calling Error() on our Errors.Inner errors won't cause an error when they're empty
func TestAssetFetcherErrorsCanBeNil(t *testing.T) {
	tc := []errorNilTest{
		{
			"URLParsingErrorEmpty",
			&URLParsingError{},
		},
		{
			"ErrorParsingJSONResponse",
			&ErrorParsingJSONResponse{},
		},
		{
			"ErrorReadingNexposeResponse",
			&ErrorReadingNexposeResponse{},
		},
		{
			"NexposeHTTPRequestError",
			&NexposeHTTPRequestError{},
		},
		{
			"ErrorFetchingAssets",
			&ErrorFetchingAssets{},
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {

			actual := (tt.input).Error()
			assert.NotNil(t, actual)
		})
	}
}
