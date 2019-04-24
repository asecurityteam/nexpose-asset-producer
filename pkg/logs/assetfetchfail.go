package logs

// AssetFetchFail is logged when the attempt to fetch assets from Nexpose fails
type AssetFetchFail struct {
	Message string `logevent:"message,default=asset-fetch-fail"`
	Reason  string `logevent:"reason"`
}
