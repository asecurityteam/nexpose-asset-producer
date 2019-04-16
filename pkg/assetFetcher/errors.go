package assetFetcher

import "fmt"

// URLParsingError when trying to parse the given host or URL
type URLParsingError struct {
	Inner error
	NexposeURL string
}

// Error returns a URLParsingError
func (e *URLParsingError) Error() string {
	return fmt.Sprintf("Error parsing Nexpose URL (%v): %v", e.NexposeURL, e.Inner.Error())
}


// ResponseParsingError when trying to parse a Nexpose response
type ResponseParsingError struct {
	Inner error
	NexposeURL string
}

// Error returns a ResponseParsingError
func (e *ResponseParsingError) Error() string {
	return fmt.Sprintf("Error parsing Nexpose response from %v: %v", e.NexposeURL, e.Inner.Error())
}

// ErrorReadingNexposeResponse represents an error returned when the response from Nexpose can't be read
type ErrorReadingNexposeResponse struct {
	Inner error
	NexposeURL string
}

// Error returns a ErrorReadingNexposeResponse
func (e *ErrorReadingNexposeResponse) Error() string {
	return fmt.Sprintf("Error reading Nexpose response from %v: %v", e.NexposeURL, e.Inner.Error())
}

// NexposeRequestError
type NexposeHTTPRequestError struct {
	Inner error
	NexposeURL string
}

func (e *NexposeHTTPRequestError) Error() string {
	return fmt.Sprintf("Error making an HTTP request to Nexpose with URL %v: %v", e.NexposeURL, e.Inner.Error())
}
