package frameworkmock

import (
	"io"
	"log"
	"testing"

	libGoMock "github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"go.uber.org/mock/gomock"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
)

var MockOrgID = uuid.MustParse("c8dbe227-1968-5654-a467-58d73f8f0311")

func NewMockInvocationContext(
	t *testing.T,
) *mocks.MockInvocationContext {
	t.Helper()
	libCtrl := libGoMock.NewController(t)

	mockConfig := configuration.New()
	mockConfig.Set(configuration.AUTHENTICATION_TOKEN, "<MOCK_API_TOKEN>")
	mockConfig.Set(configuration.ORGANIZATION, MockOrgID.String())
	mockConfig.Set("name", "mock-project")
	mockConfig.Set("version", "0.0.0")

	mockRuntimeInfo := runtimeinfo.New(
		runtimeinfo.WithName("test-app"),
		runtimeinfo.WithVersion("1.2.3"))

	enhancedLogger := zerolog.New(io.Discard)
	ui := mocks.NewMockUserInterface(libCtrl)
	bar := mocks.NewMockProgressBar(libCtrl)
	bar.EXPECT().SetTitle(gomock.Any()).AnyTimes()
	bar.EXPECT().UpdateProgress(gomock.Any()).AnyTimes()
	bar.EXPECT().Clear().AnyTimes()
	ui.EXPECT().NewProgressBar().Return(bar).AnyTimes()

	ictx := mocks.NewMockInvocationContext(libCtrl)
	ictx.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	ictx.EXPECT().GetEngine().Return(nil).AnyTimes()
	ictx.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(mockConfig)).AnyTimes()
	ictx.EXPECT().GetLogger().Return(log.New(io.Discard, "", 0)).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(&enhancedLogger).AnyTimes()
	ictx.EXPECT().GetRuntimeInfo().Return(mockRuntimeInfo).AnyTimes()
	ictx.EXPECT().GetUserInterface().Return(ui).AnyTimes()
	return ictx
}
