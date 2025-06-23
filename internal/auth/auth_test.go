package auth

import (
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetAPIKey(t *testing.T) {
	testCases := map[string]struct {
		header string
		token  string
		expect string
	}{
		"Correct Header": {header: "Authorization",
			token:  "ApiKey 123456789",
			expect: "123456 789"},
		"No Header": {header: "",
			token:  "",
			expect: ErrNoAuthHeaderIncluded.Error()},
		"Wrong leading Auth": {header: "Authorization",
			token:  "Bearer 123456789",
			expect: "malformed authorization header"},
		"Wrong len split": {header: "Authorization",
			token:  "ApiKey123456789",
			expect: "malformed authorization header"},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			testReq := httptest.NewRequest("GET", "/", nil)
			testReq.Header.Set(test.header, test.token)
			got, err := GetAPIKey(testReq.Header)
			if err != nil {
				diff := cmp.Diff(err.Error(), test.expect)
				if diff != "" {
					t.Fatalf("Wrong error had %v wanted %v",
						err.Error(), test.expect)
				}
			} else {
				diff := cmp.Diff(got, test.expect)
				if diff != "" {
					t.Fatalf("Wrong auth token had: %v wanted: %v",
						got,
						test.expect)
				}
			}
		})
	}
}
