package v1

import (
	"context"
	"fmt"
	"testing"

	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestDepCheckHandleSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	MockDependencyChecker := NewMockDependencyChecker(ctrl)
	MockDependencyChecker.EXPECT().CheckDependencies(context.Background()).Return(nil)
	handler := &DependencyCheckHandler{
		DependencyChecker: MockDependencyChecker,
	}
	err := handler.Handle(context.Background())

	assert.Nil(t, err)
}

func TestDepCheckHandleError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	MockDependencyChecker := NewMockDependencyChecker(ctrl)
	MockDependencyChecker.EXPECT().CheckDependencies(context.Background()).Return(fmt.Errorf("error"))
	handler := &DependencyCheckHandler{
		DependencyChecker: MockDependencyChecker,
	}
	err := handler.Handle(context.Background())

	assert.NotNil(t, err)
}
