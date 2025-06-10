package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/owncloud/ocis/v2/ocis-pkg/log"
	"github.com/owncloud/ocis/v2/ocis-pkg/oidc"
	"github.com/owncloud/ocis/v2/services/proxy/pkg/config"
	"github.com/stretchr/testify/assert"
)

// TestSelectorCookie tests the core functionality of the selector cookie middleware.
func TestSelectorCookie(t *testing.T) {
	tests := []struct {
		name           string
		hasOIDCContext bool
		config         config.PolicySelector
		checkCookie    func(*testing.T, []*http.Cookie)
	}{
		{
			name:           "successful cookie set with claims selector",
			hasOIDCContext: true,
			config: config.PolicySelector{
				Claims: &config.ClaimsSelectorConf{
					SelectorCookieName: "test-selector",
					DefaultPolicy:      "test-value",
				},
			},
			checkCookie: func(t *testing.T, cookies []*http.Cookie) {
				assert.Len(t, cookies, 1)
				cookie := cookies[0]
				assert.Equal(t, "test-selector", cookie.Name)
				assert.Equal(t, "test-value", cookie.Value)
				assert.Equal(t, "/", cookie.Path)
				assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite, "SameSite=Strict prevents CSRF attacks by blocking cross-site cookie manipulation (OWASP: https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet.html#samesite-attribute)")
				assert.True(t, cookie.Secure, "Secure flag prevents MITM attacks by ensuring cookie only sent over HTTPS (OWASP: https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet.html#secure-attribute)")
				assert.True(t, cookie.HttpOnly, "HttpOnly prevents XSS attacks by blocking JavaScript access to cookie (OWASP: https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet.html#httponly-attribute)")
			},
		},
		{
			name:           "no cookie set without OIDC context",
			hasOIDCContext: false,
			config: config.PolicySelector{
				Claims: &config.ClaimsSelectorConf{
					SelectorCookieName: "test-selector",
					DefaultPolicy:      "test-value",
				},
			},
			checkCookie: func(t *testing.T, cookies []*http.Cookie) {
				assert.Empty(t, cookies)
			},
		},
		{
			name:           "no cookie set without selector config",
			hasOIDCContext: true,
			config:         config.PolicySelector{},
			checkCookie: func(t *testing.T, cookies []*http.Cookie) {
				assert.Empty(t, cookies)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := log.NewLogger()
			options := []Option{
				Logger(logger),
				PolicySelectorConfig(tt.config),
			}

			handler := SelectorCookie(options...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

			req := httptest.NewRequest("GET", "https://example.com", nil)
			if tt.hasOIDCContext {
				req = req.WithContext(oidc.NewContext(req.Context(), map[string]interface{}{
					oidc.OcisRoutingPolicy: "test-value",
				}))
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			tt.checkCookie(t, w.Result().Cookies())
		})
	}
}

// TestSelectorCookieOverwrite verifies the behavior when updating existing cookies.
func TestSelectorCookieOverwrite(t *testing.T) {
	// Note: SameSite=Strict enforcement is a browser responsibility and cannot be fully tested in unit tests alone.
	// In a real browser:
	// 1. SameSite=Strict prevents the cookie from being sent with cross-site requests
	// 2. This test only verifies that the cookie is set with correct security attributes
	//
	// Cookie Overwrite Attack Scenario:
	// 1. Attacker attempts to overwrite a valid cookie with malicious value
	// 2. Attack vectors:
	//   - Cross-site request forgery (CSRF) to overwrite cookie
	//   - XSS to inject malicious cookie via JavaScript
	//   - Man-in-the-middle to intercept and modify cookie
	//
	// 3. Protection mechanisms:
	//   - SameSite=Strict prevents cross-site cookie manipulation
	//   - Secure flag ensures cookie only sent over HTTPS
	//   - HttpOnly prevents JavaScript access to cookie
	//   - Domain/path restrictions limit cookie scope
	//
	// Reference: https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet.html#samesite-attribute

	logger := log.NewLogger()
	options := []Option{
		Logger(logger),
		PolicySelectorConfig(config.PolicySelector{
			Claims: &config.ClaimsSelectorConf{
				SelectorCookieName: "test-selector",
				DefaultPolicy:      "first-value",
			},
		}),
	}

	handler := SelectorCookie(options...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	// First request - sets initial cookie
	req1 := httptest.NewRequest("GET", "https://example.com", nil)
	req1 = req1.WithContext(oidc.NewContext(req1.Context(), map[string]interface{}{
		oidc.OcisRoutingPolicy: "first-value",
	}))
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	// Verify initial cookie security attributes
	cookies1 := w1.Result().Cookies()
	assert.Len(t, cookies1, 1)
	cookie1 := cookies1[0]
	assert.Equal(t, "first-value", cookie1.Value)
	assert.Equal(t, http.SameSiteStrictMode, cookie1.SameSite, "SameSite=Strict prevents CSRF attacks by blocking cross-site cookie manipulation (OWASP: https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet.html#samesite-attribute)")
	assert.True(t, cookie1.Secure, "Secure flag prevents MITM attacks by ensuring cookie only sent over HTTPS (OWASP: https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet.html#secure-attribute)")
	assert.True(t, cookie1.HttpOnly, "HttpOnly prevents XSS attacks by blocking JavaScript access to cookie (OWASP: https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet.html#httponly-attribute)")

	// Second request - legitimate update
	req2 := httptest.NewRequest("GET", "https://example.com", nil)
	req2 = req2.WithContext(oidc.NewContext(req2.Context(), map[string]interface{}{
		oidc.OcisRoutingPolicy: "second-value",
	}))
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	// Verify updated cookie maintains security attributes
	cookies2 := w2.Result().Cookies()
	assert.Len(t, cookies2, 1)
	cookie2 := cookies2[0]
	assert.Equal(t, "second-value", cookie2.Value)
	assert.Equal(t, http.SameSiteStrictMode, cookie2.SameSite)
	assert.True(t, cookie2.Secure)
	assert.True(t, cookie2.HttpOnly)

	// Test cross-site request handling
	req4 := httptest.NewRequest("GET", "https://example.com", nil)
	req4.Header.Set("Origin", "https://malicious.com")
	req4.Header.Set("Referer", "https://malicious.com")
	// Set the cookie from previous request
	req4.AddCookie(&http.Cookie{
		Name:     "test-selector",
		Value:    "second-value",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	req4 = req4.WithContext(oidc.NewContext(req4.Context(), map[string]interface{}{
		oidc.OcisRoutingPolicy: "malicious-value",
	}))
	w4 := httptest.NewRecorder()
	handler.ServeHTTP(w4, req4)

	// Verify cookie value is preserved for cross-site request
	cookies4 := w4.Result().Cookies()
	assert.Len(t, cookies4, 1)
	cookie4 := cookies4[0]
	assert.Equal(t, "second-value", cookie4.Value, "Cookie value should be preserved for cross-site requests")
	assert.Equal(t, http.SameSiteStrictMode, cookie4.SameSite)
	assert.True(t, cookie4.Secure)
	assert.True(t, cookie4.HttpOnly)
}
