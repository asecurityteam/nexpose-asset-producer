package assetvalidator

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
)

// ScanType is a type alias to signify type of scan, local or remote
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
func (v *NexposeAssetValidator) ValidateAssets(ctx context.Context, assets []domain.Asset, scanID string) ([]domain.AssetEvent, []error) {
	assetEventListList := []domain.AssetEvent{}
	errorList := []error{}
	for _, asset := range assets {
		scanTime, scanType, err := v.getScanTimeAndScanType(asset, scanID)
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
func (v *NexposeAssetValidator) getScanTimeAndScanType(asset domain.Asset, scanID string) (time.Time, ScanType, error) {
	for _, evt := range asset.History {
		scanTime, err := time.Parse(time.RFC3339, evt.Date)
		switch evt.Type {
		case "SCAN":
			if strconv.FormatInt(evt.ScanID, 10) == scanID {
				if err != nil {
					return time.Time{}, remote, &domain.InvalidScanTime{ScanID: scanID, ScanTime: scanTime, AssetID: asset.ID, AssetIP: asset.IP, AssetHostname: asset.HostName, Inner: err}
				}
				if scanTime.IsZero() {
					return time.Time{}, remote, &domain.InvalidScanTime{ScanID: scanID, ScanTime: scanTime, AssetID: asset.ID, AssetIP: asset.IP, AssetHostname: asset.HostName, Inner: errors.New("scan time is zero")}
				}
				return scanTime, remote, nil
			}
		case "AGENT-IMPORT":
			if time.Since(scanTime).Hours() < 24 {
				return scanTime, local, nil
			}
		}
	}
	return time.Time{}, unknown, &domain.ScanIDForLastScanNotInAssetHistory{ScanID: scanID, AssetID: asset.ID, AssetIP: asset.IP, AssetHostname: asset.HostName}
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
