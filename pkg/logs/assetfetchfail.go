package logs

// AssetFetchFail is logged when the attempt to fetch assets from Nexpose fails
type AssetFetchFail struct {
	Message string `logevent:"message,default=asset-fetch-fail"`
	Reason  string `logevent:"reason,default=unknown"`
	Page    int64  `logevent:"page,default=unknown"`
	SiteID  string `logevent:"siteid,default=unknown"`
}
