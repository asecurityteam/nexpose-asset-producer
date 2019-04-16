package assetfetcher

import "fmt"

// URLParsingError when trying to parse the given host or URL
type URLParsingError struct {
	Inner      error
	NexposeURL string
}

// Error returns a URLParsingError
func (e *URLParsingError) Error() string {
	return fmt.Sprintf("Error parsing Nexpose URL (%v): %v", e.NexposeURL, e.Inner.Error())
}

// ErrorParsingJSONResponse when trying to parse a Nexpose response
type ErrorParsingJSONResponse struct {
	Inner      error
	NexposeURL string
}

// Error returns an ErrorParsingJSONResponse
func (e *ErrorParsingJSONResponse) Error() string {
	return fmt.Sprintf("Error parsing Nexpose response from %v: %v", e.NexposeURL, e.Inner.Error())
}

// ErrorReadingNexposeResponse represents an error returned when the response from Nexpose can't be read
type ErrorReadingNexposeResponse struct {
	Inner      error
	NexposeURL string
}

// Error returns a ErrorReadingNexposeResponse
func (e *ErrorReadingNexposeResponse) Error() string {
	return fmt.Sprintf("Error reading Nexpose response from %v: %v", e.NexposeURL, e.Inner.Error())
}

// NexposeHTTPRequestError represents an error we get when trying make a request to Nexpose
type NexposeHTTPRequestError struct {
	Inner      error
	NexposeURL string
}

// Error returns a NexposeHTTPRequestError
func (e *NexposeHTTPRequestError) Error() string {
	return fmt.Sprintf("Error making an HTTP request to Nexpose with URL %v: %v", e.NexposeURL, e.Inner.Error())
}
