package assetvalidator

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
)

// NexposeAssetValidator is used to validate a list of retrieved Assets
type NexposeAssetValidator struct {
}

func (v *NexposeAssetValidator) ValidateAssets(ctx context.Context, assets []domain.Asset, scanID string) ([]domain.AssetEvent, []error) {
	assetEventListList := []domain.AssetEvent{}
	errorList := []error{}
	for _, asset := range assets {
		scanTime, err := v.getScanTime(asset, scanID)
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

// GetScanTime searches through the asset's event history for a scan event with the ScanID
// that matches the ScanID of the scan completion event that triggered the pipeline.
func (v *NexposeAssetValidator) getScanTime(asset domain.Asset, scanID string) (time.Time, error) {
	for _, evt := range asset.History {
		if evt.Type == "SCAN" {
			if strconv.FormatInt(evt.ScanID, 10) == scanID {
				scanTime, err := time.Parse(time.RFC3339, evt.Date)
				if err != nil {
					return time.Time{}, &domain.InvalidScanTime{scanID, scanTime, asset.ID, asset.IP, asset.HostName, err}
				}
				if scanTime.IsZero() {
					return time.Time{}, &domain.InvalidScanTime{scanID, scanTime, asset.ID, asset.IP, asset.HostName, errors.New("scan time is zero")}
				}
				return scanTime, nil
			}
		}
	}
	return time.Time{}, &domain.ScanIDForLastScanNotInAssetHistory{scanID, asset.ID, asset.IP, asset.HostName}
}

// AssetPayloadToAssetEvent translates a Nexpose Asset API response payload
// into an AssetEvent for downstream services.
func (v *NexposeAssetValidator) assetPayloadToAssetEvent(asset domain.Asset, scanTime time.Time) (domain.AssetEvent, error) {
	if asset.ID == 0 || (asset.IP == "" && asset.HostName == "") {
		return domain.AssetEvent{}, &domain.MissingRequiredInformation{asset.ID, asset.IP, asset.HostName, scanTime}
	}
	return domain.AssetEvent{
		ID:       asset.ID,
		Hostname: asset.HostName,
		IP:       asset.IP,
		ScanTime: scanTime,
	}, nil
}
