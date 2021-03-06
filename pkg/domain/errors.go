package domain

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
	return fmt.Sprintf("error parsing Nexpose URL (%v): %v", e.NexposeURL, e.Inner)
}

// ErrorParsingJSONResponse when trying to parse a Nexpose response
type ErrorParsingJSONResponse struct {
	Inner      error
	NexposeURL string
}

// Error returns an ErrorParsingJSONResponse
func (e *ErrorParsingJSONResponse) Error() string {
	return fmt.Sprintf("error parsing Nexpose response from %v: %v", e.NexposeURL, e.Inner)
}

// ErrorReadingNexposeResponse represents an error returned when the response from Nexpose can't be read
type ErrorReadingNexposeResponse struct {
	Inner      error
	NexposeURL string
}

// Error returns a ErrorReadingNexposeResponse
func (e *ErrorReadingNexposeResponse) Error() string {
	return fmt.Sprintf("error reading Nexpose response from %v: %v", e.NexposeURL, e.Inner)
}

// NexposeHTTPRequestError represents an error we get when trying to make a request to Nexpose
type NexposeHTTPRequestError struct {
	Inner      error
	NexposeURL string
}

// Error returns a NexposeHTTPRequestError
func (e *NexposeHTTPRequestError) Error() string {
	return fmt.Sprintf("error making an HTTP request to Nexpose with URL %v: %v", e.NexposeURL, e.Inner)
}

// ErrorFetchingAssets represents an error we get when trying to fetch assets
type ErrorFetchingAssets struct {
	Inner  error
	Page   int64
	SiteID string
}

// Error returns an ErrorFetchingAssets
func (e *ErrorFetchingAssets) Error() string {
	return "error fetching a particular page of assets from Nexpose"
}

// ScanIDForLastScanNotInAssetHistory represents an error that occurs when an asset's history doesn't contain
// the ScanID for the notification for a completed scan. This means that the asset is in the site that was scanned,
// but the asset itself was not scanned.
type ScanIDForLastScanNotInAssetHistory struct {
	ScanID        string
	AssetID       int64
	AssetIP       string
	AssetHostname string
}

// Error returns an ScanIdForLastScanNotInAssetHistory
func (e *ScanIDForLastScanNotInAssetHistory) Error() string {
	return "Asset was not scanned during the scan"
}

// MissingRequiredInformation represents an error we get if the ID, or IP and Hostname
type MissingRequiredInformation struct {
	AssetID       int64
	AssetIP       string
	AssetHostname string
}

// Error returns an MissingRequiredFields
func (e *MissingRequiredInformation) Error() string {
	return "required fields are missing"
}

// InvalidScanTime represents an error that occurs when an asset's scan time invalid
type InvalidScanTime struct {
	ScanID        string
	ScanTime      time.Time
	AssetID       int64
	AssetIP       string
	AssetHostname string
	Inner         error
}

// Error returns an InvalidScanTime
func (e *InvalidScanTime) Error() string {
	return fmt.Sprintf("Invalid scan time: %v", e.ScanTime)
}
