package assetfetcher

import (
	"fmt"
	"time"
)

// URLParsingError when trying to parse the given host or URL
type URLParsingError struct {
	Inner      error
	NexposeURL string
}

// Error returns a URLParsingError
func (e *URLParsingError) Error() string {
	return fmt.Sprintf("Error parsing Nexpose URL (%v): %v", e.NexposeURL, e.Inner)
}

// ErrorParsingJSONResponse when trying to parse a Nexpose response
type ErrorParsingJSONResponse struct {
	Inner      error
	NexposeURL string
}

// Error returns an ErrorParsingJSONResponse
func (e *ErrorParsingJSONResponse) Error() string {
	return fmt.Sprintf("Error parsing Nexpose response from %v: %v", e.NexposeURL, e.Inner)
}

// ErrorReadingNexposeResponse represents an error returned when the response from Nexpose can't be read
type ErrorReadingNexposeResponse struct {
	Inner      error
	NexposeURL string
}

// Error returns a ErrorReadingNexposeResponse
func (e *ErrorReadingNexposeResponse) Error() string {
	return fmt.Sprintf("Error reading Nexpose response from %v: %v", e.NexposeURL, e.Inner)
}

// NexposeHTTPRequestError represents an error we get when trying to make a request to Nexpose
type NexposeHTTPRequestError struct {
	Inner      error
	NexposeURL string
}

// Error returns a NexposeHTTPRequestError
func (e *NexposeHTTPRequestError) Error() string {
	return fmt.Sprintf("Error making an HTTP request to Nexpose with URL %v: %v", e.NexposeURL, e.Inner)
}

// ErrorFetchingAssets represents an error we get when trying to fetch assets
type ErrorFetchingAssets struct {
	Inner error
}

// Error returns an ErrorFetchingAssets
func (e *ErrorFetchingAssets) Error() string {
	return fmt.Sprintf("Error fetching assets from Nexpose %v", e.Inner)
}

// ErrorConvertingAssetPayload represents an error we get when trying to convert a Nexpose Asset
// payload to AssetEvent
type ErrorConvertingAssetPayload struct {
	AssetID int64
	Inner   error
}

// Error returns an ErrorConvertingAssetPayload
func (e *ErrorConvertingAssetPayload) Error() string {
	return fmt.Sprintf("Error converting asset %v payload to event %v", e.AssetID, e.Inner)
}

// MissingRequiredFields represents an error we get if the ID, IP, or lastScanned date is empty
type MissingRequiredFields struct {
	AssetID          int64
	AssetIP          string
	AssetLastScanned time.Time
}

// Error returns an MissingRequiredFields
func (e *MissingRequiredFields) Error() string {
	return fmt.Sprintf("Required fields are missing. ID: %v, IP: %s, LastScanned: %v", e.AssetID, e.AssetIP, e.AssetLastScanned)
}

// AssetNotScanned represents an error when the asset being checked has never been scanned
type AssetNotScanned struct {
	AssetID int64
	AssetIP string
}

// Error prints a useful message indicating why an asset scan report will not be produced
func (e *AssetNotScanned) Error() string {
	return fmt.Sprintf("This Nexpose asset has never been scanned, so no scan report can be produced. ID: %v, IP: %s", e.AssetID, e.AssetIP)
}
