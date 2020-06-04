package assetvalidator

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	"github.com/asecurityteam/nexpose-asset-producer/pkg/logs"
)

// NexposeAssetValidator is used to validate a list of retrieved Assets
type NexposeAssetValidator struct {
	AgentSite string
}

// ValidateAssets takes in a list of assets from Nexpose, and returns a list of valid Asset events, and a list of errors based
// on defined validation rules
func (v *NexposeAssetValidator) ValidateAssets(ctx context.Context, assets []domain.Asset, scanID string, siteID string, logger domain.Logger) ([]domain.AssetEvent, []error) {
	assetEventListList := []domain.AssetEvent{}
	errorList := []error{}
	for _, asset := range assets {
		scanTime, err := v.getScanTime(asset, scanID, siteID, logger)
		if err != nil {
			errorList = append(errorList, err)
			continue
		}
		assetEvent, err := v.assetPayloadToAssetEvent(asset, scanTime)
		if err != nil {
			errorList = append(errorList, err)
			continue
		}
		assetEventListList = append(assetEventListList, assetEvent)
	}
	return assetEventListList, errorList
}

// getScanTime searches through the asset's event history for a scan event with the ScanID
// that matches the ScanID of the scan completion event that triggered the pipeline.
func (v *NexposeAssetValidator) getScanTime(asset domain.Asset, scanID string, siteID string, logger domain.Logger) (time.Time, error) {
	for _, evt := range asset.History {
		if evt.Type == "SCAN" {
			if strconv.FormatInt(evt.ScanID, 10) == scanID || siteID == "2" {
				scanTime, err := time.Parse(time.RFC3339, evt.Date)
				if err != nil {
					return time.Time{}, &domain.InvalidScanTime{ScanID: scanID, ScanTime: scanTime, AssetID: asset.ID, AssetIP: asset.IP, AssetHostname: asset.HostName, Inner: err}
				}
				if scanTime.IsZero() {
					return time.Time{}, &domain.InvalidScanTime{ScanID: scanID, ScanTime: scanTime, AssetID: asset.ID, AssetIP: asset.IP, AssetHostname: asset.HostName, Inner: errors.New("scan time is zero")}
				}
				// if siteID == v.AgentSite && time.Since(scanTime).Hours() > 24 { // agent scans often lack scanIDs, so we validate them based on recency instead.
				// 	return time.Time{}, &domain.InvalidScanTime{ScanID: scanID, ScanTime: scanTime, AssetID: asset.ID, AssetIP: asset.IP, AssetHostname: asset.HostName, Inner: errors.New("agent scan is more than one day old")}
				// }
				return scanTime, nil
			}
			logger.Warn(logs.AssetValidateFail{
				Message: "invalid-scan-event",
				Reason:  fmt.Sprintf("Invalid SCAN event: Site ID: %s, ScanTime: %s, ScanID: %d | Desired ScanID: %s", siteID, evt.Date, evt.ScanID, scanID),
				AssetID: evt.ScanID,
			})
		}
		logger.Warn(logs.AssetValidateFail{
			Message: "not-scan-event",
			Reason:  fmt.Sprintf("Not a SCAN Event: Site ID: %s, ScanTime: %s, ScanID: %d | Desired ScanID: %s", siteID, evt.Date, evt.ScanID, scanID),
			AssetID: evt.ScanID,
		})
	}
	logger.Warn(logs.AssetValidateFail{
		Message: "No valid events",
		Reason:  fmt.Sprintf("No scan events found: Site ID: %s, Total Events: %d | Desired ScanID: %s", siteID, len(asset.History), scanID),
	})
	return time.Time{}, &domain.ScanIDForLastScanNotInAssetHistory{ScanID: scanID, AssetID: asset.ID, AssetIP: asset.IP, AssetHostname: asset.HostName}
}

// assetPayloadToAssetEvent translates a Nexpose Asset API response payload
// into an AssetEvent for downstream services.
func (v *NexposeAssetValidator) assetPayloadToAssetEvent(asset domain.Asset, scanTime time.Time) (domain.AssetEvent, error) {
	if asset.ID == 0 || (asset.IP == "" && asset.HostName == "") {
		return domain.AssetEvent{}, &domain.MissingRequiredInformation{AssetID: asset.ID, AssetIP: asset.IP, AssetHostname: asset.HostName}
	}
	return domain.AssetEvent{
		ID:       asset.ID,
		Hostname: asset.HostName,
		IP:       asset.IP,
		ScanTime: scanTime,
	}, nil
}
