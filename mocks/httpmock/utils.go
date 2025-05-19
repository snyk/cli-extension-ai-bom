package httpmock

import (
	"fmt"
	"net/http"

	"go.uber.org/mock/gomock"
)

type RequestMatcher struct {
	ExpectedPath   string
	ExpectedMethod string
}

var _ gomock.Matcher = (*RequestMatcher)(nil)

func (rm RequestMatcher) Matches(x interface{}) bool {
	req, ok := x.(*http.Request)
	if !ok {
		return false
	}
	return req.URL.Path == rm.ExpectedPath && req.Method == rm.ExpectedMethod
}

func (rm RequestMatcher) String() string {
	return fmt.Sprintf("matches request with method %s and path %s", rm.ExpectedMethod, rm.ExpectedPath)
}

func ForRequest(method, path string) RequestMatcher {
	return RequestMatcher{ExpectedMethod: method, ExpectedPath: path}
}
