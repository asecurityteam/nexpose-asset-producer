package assetvalidator

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
)

// NexposeScanType is a type alias to signify type of scan according to Nexpose
type NexposeScanType string

const (
	automated NexposeScanType = "Automated"
	manual    NexposeScanType = "Manual"
	scheduled NexposeScanType = "Scheduled"
	agent     NexposeScanType = "Agent"
)

// ScanType is a type alias to signify type generify scan, local or remote
// The purpose is to not expose Nexpose specifics further down the pipeline
type ScanType string

const (
	local   ScanType = "local"
	remote  ScanType = "remote"
	unknown ScanType = "unknown"
)

// NexposeAssetValidator is used to validate a list of retrieved Assets
type NexposeAssetValidator struct {
}

// ValidateAssets takes in a list of assets from Nexpose, and returns a list of valid Asset events, and a list of errors based
// on defined validation rules
func (v *NexposeAssetValidator) ValidateAssets(ctx context.Context, assets []domain.Asset, scanInfo domain.ScanInfo) ([]domain.AssetEvent, []error) {
	assetEventListList := []domain.AssetEvent{}
	errorList := []error{}
	for _, asset := range assets {
		scanTime, scanType, err := v.getScanTimeAndScanType(asset, scanInfo)
		if err != nil {
			errorList = append(errorList, err)
			continue
		}
		assetEvent, err := v.assetPayloadToAssetEvent(asset, scanTime, string(scanType))
		if err != nil {
			errorList = append(errorList, err)
			continue
		}
		assetEventListList = append(assetEventListList, assetEvent)
	}
	return assetEventListList, errorList
}

// getScanTimeAndScanType searches through the asset's event history for a scan event with the ScanID
// that matches the ScanID of the scan completion event that triggered the pipeline, and also returns the type of scan.
func (v *NexposeAssetValidator) getScanTimeAndScanType(asset domain.Asset, scanInfo domain.ScanInfo) (time.Time, ScanType, error) {
	for _, evt := range asset.History {
		scanTime, err := time.Parse(time.RFC3339, evt.Date)
		if evt.Type == "SCAN" && (scanInfo.ScanType == string(automated) || scanInfo.ScanType == string(manual) || scanInfo.ScanType == string(scheduled)) {
			if strconv.FormatInt(evt.ScanID, 10) == scanInfo.ScanID {
				if err != nil {
					return time.Time{}, remote, &domain.InvalidScanTime{ScanID: scanInfo.ScanID, ScanTime: scanTime, AssetID: asset.ID, AssetIP: asset.IP, AssetHostname: asset.HostName, Inner: err}
				}
				if scanTime.IsZero() {
					return time.Time{}, remote, &domain.InvalidScanTime{ScanID: scanInfo.ScanID, ScanTime: scanTime, AssetID: asset.ID, AssetIP: asset.IP, AssetHostname: asset.HostName, Inner: errors.New("scan time is zero")}
				}
				return scanTime, remote, nil
			}
		}
		if evt.Type == "AGENT-IMPORT" && scanInfo.ScanType == string(agent) {
			startScanTime, startErr := time.Parse(time.RFC3339, scanInfo.StartTime)
			endScanTime, endErr := time.Parse(time.RFC3339, scanInfo.EndTime)
			if err != nil || startErr != nil || endErr != nil {
				return time.Time{}, remote, &domain.InvalidScanTime{ScanID: scanInfo.ScanID, ScanTime: scanTime, AssetID: asset.ID, AssetIP: asset.IP, AssetHostname: asset.HostName, Inner: err}
			}

			if scanTime.After(startScanTime) && scanTime.Before(endScanTime) {
				return scanTime, local, nil
			}
		}
	}
	return time.Time{}, unknown, &domain.ScanIDForLastScanNotInAssetHistory{ScanID: scanInfo.ScanID, AssetID: asset.ID, AssetIP: asset.IP, AssetHostname: asset.HostName}
}

// assetPayloadToAssetEvent translates a Nexpose Asset API response payload
// into an AssetEvent for downstream services.
func (v *NexposeAssetValidator) assetPayloadToAssetEvent(asset domain.Asset, scanTime time.Time, scanType string) (domain.AssetEvent, error) {
	if asset.ID == 0 || (asset.IP == "" && asset.HostName == "") {
		return domain.AssetEvent{}, &domain.MissingRequiredInformation{AssetID: asset.ID, AssetIP: asset.IP, AssetHostname: asset.HostName}
	}
	return domain.AssetEvent{
		ID:       asset.ID,
		Hostname: asset.HostName,
		IP:       asset.IP,
		ScanTime: scanTime,
		ScanType: scanType,
	}, nil
}
