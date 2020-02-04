package logs

// AssetValidateFail is logged when the attempt to validate assets from Nexpose fails
type AssetValidateFail struct {
	Message       string `logevent:"message,default=asset-validate-fail"`
	Reason        string `logevent:"reason,default=unknown"`
	SiteID        string `logevent:"siteid,default=unknown"`
	AssetID       int64  `logevent:"assetid,default=unknown"`
	AssetIP       string `logevent:"assetip,default=unknown"`
	AssetHostname string `logevent:"assethostname,default=unknown"`
}
