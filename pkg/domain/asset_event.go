package domain

import "time"

// AssetEvent contains all pertinent Nexpose Asset information for downstream services
type AssetEvent struct {
	// LastScanned will get removed as a part of PSD-306
	LastScanned time.Time
	// The time the asset was scanned.
	ScanTime time.Time
	// The primary host name (local or FQDN) of the asset.
	Hostname string
	// The identifier of the asset.
	ID int64
	// The primary IPv4 or IPv6 address of the asset.
	IP string
}
