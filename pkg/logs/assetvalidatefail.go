package logs

// AssetValidateFail is logged when the attempt to validate assets from Nexpose fails
type AssetValidateFail struct {
	Message string `logevent:"message,default=asset-validate-fail"`
	Reason  string `logevent:"reason,default=unknown"`
	AssetID int64  `logevent:"assetID,default=unknown"`
	SiteID  string `logevent:"siteid,default=unknown"`
}
