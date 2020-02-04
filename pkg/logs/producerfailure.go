package logs

// ProducerFailure is logged when the producer fails to put as asset on the queue
type ProducerFailure struct {
	Message string `logevent:"message,default=producer-failure"`
	Reason  string `logevent:"reason"`
	SiteID  string `logevent:"siteid,default=unknown"`
	AssetID int64  `logevent:"assetid"`
}
