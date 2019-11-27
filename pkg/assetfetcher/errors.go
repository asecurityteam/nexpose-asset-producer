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
	Inner error
}

// Error returns an ErrorFetchingAssets
func (e *ErrorFetchingAssets) Error() string {
	return fmt.Sprintf("error fetching assets from Nexpose %v", e.Inner)
}

// MissingRequiredInformation represents an error we get if the ID, or IP and Hostname
type MissingRequiredInformation struct {
	AssetID       int64
	AssetIP       string
	AssetHostname string
	AssetScanTime time.Time
}

// Error returns an MissingRequiredFields
func (e *MissingRequiredInformation) Error() string {
	return fmt.Sprintf("required fields are missing. ID: %v, IP: %s, Hostname: %s, ScanTime: %v", e.AssetID, e.AssetIP, e.AssetHostname, e.AssetScanTime)
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
	return fmt.Sprintf("Invalid scan time. ScanID: %v, ScanTime: %v, AssetID: %v, IP: %s, Hostname: %s, Error: %s", e.ScanID, e.ScanTime, e.AssetID, e.AssetIP, e.AssetHostname, e.Inner.Error())
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
	return fmt.Sprintf("Asset was not scanned during the scan with ScanID: %v, AssetID: %v, IP: %s, Hostname: %s", e.ScanID, e.AssetID, e.AssetIP, e.AssetHostname)
}
