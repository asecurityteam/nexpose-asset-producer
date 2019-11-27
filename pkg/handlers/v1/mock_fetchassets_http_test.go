// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/domain/assetFetcher.go

// Package v1 is a generated GoMock package.
package v1

import (
	context "context"
	domain "github.com/asecurityteam/nexpose-asset-producer/pkg/domain"
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// MockAssetFetcher is a mock of AssetFetcher interface
type MockAssetFetcher struct {
	ctrl     *gomock.Controller
	recorder *MockAssetFetcherMockRecorder
}

// MockAssetFetcherMockRecorder is the mock recorder for MockAssetFetcher
type MockAssetFetcherMockRecorder struct {
	mock *MockAssetFetcher
}

// NewMockAssetFetcher creates a new mock instance
func NewMockAssetFetcher(ctrl *gomock.Controller) *MockAssetFetcher {
	mock := &MockAssetFetcher{ctrl: ctrl}
	mock.recorder = &MockAssetFetcherMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockAssetFetcher) EXPECT() *MockAssetFetcherMockRecorder {
	return m.recorder
}

// FetchAssets mocks base method
func (m *MockAssetFetcher) FetchAssets(ctx context.Context, siteID string, scanID string) (<-chan domain.AssetEvent, <-chan error) {
	ret := m.ctrl.Call(m, "FetchAssets", ctx, siteID, scanID)
	ret0, _ := ret[0].(<-chan domain.AssetEvent)
	ret1, _ := ret[1].(<-chan error)
	return ret0, ret1
}

// FetchAssets indicates an expected call of FetchAssets
func (mr *MockAssetFetcherMockRecorder) FetchAssets(ctx, siteID, scanID interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FetchAssets", reflect.TypeOf((*MockAssetFetcher)(nil).FetchAssets), ctx, siteID, scanID)
}