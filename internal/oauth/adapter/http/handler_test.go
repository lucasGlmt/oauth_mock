package http

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"oauthmock/internal/oauth/adapter/db"
	"oauthmock/internal/oauth/domain"
	"oauthmock/internal/oauth/jwt"
	"oauthmock/internal/oauth/usecase"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

type testClientsFile struct {
	Clients []domain.Client `yaml:"clients"`
}

func newTestRepo(t *testing.T, clients []domain.Client) *db.Repository {
	t.Helper()

	data, err := yaml.Marshal(testClientsFile{Clients: clients})
	if err != nil {
		t.Fatalf("marshal clients: %v", err)
	}

	tmp, err := os.CreateTemp(t.TempDir(), "clients-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		t.Fatalf("write temp file: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}

	repo, err := db.NewRepositoryFromYAML(tmp.Name())
	if err != nil {
		t.Fatalf("load repo: %v", err)
	}
	return repo
}

func newTestServer(t *testing.T) (*gin.Engine, *handlerImpl) {
	t.Helper()

	gin.SetMode(gin.TestMode)
	repo := newTestRepo(t, []domain.Client{
		{
			ID:            "client-1",
			Name:          "demo",
			RedirectUris:  []string{"http://localhost:3000/callback"},
			AllowedScopes: []string{"openid", "email"},
		},
	})
	uc := usecase.NewValidateClientUsecase(repo)
	signer, err := jwt.NewSigner()
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	h := NewOAUTHRouter(nil, uc, signer, "http://localhost:8080").(*handlerImpl)

	r := gin.New()
	r.POST("/token", h.Token)
	return r, h
}

func postForm(t *testing.T, r *gin.Engine, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()

	body := strings.NewReader(form.Encode())
	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestToken_Success(t *testing.T) {
	r, h := newTestServer(t)

	h.codes.Put("code-1", authCode{
		ClientID:    "client-1",
		RedirectURI: "http://localhost:3000/callback",
		Scopes:      []string{"openid", "email"},
	})

	w := postForm(t, r, "/token", url.Values{
		"grant_type":   []string{"authorization_code"},
		"code":         []string{"code-1"},
		"client_id":    []string{"client-1"},
		"redirect_uri": []string{"http://localhost:3000/callback"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode json: %v", err)
	}

	if resp["token_type"] != "Bearer" {
		t.Fatalf("expected token_type Bearer, got %v", resp["token_type"])
	}
	if _, ok := resp["access_token"].(string); !ok {
		t.Fatalf("expected access_token string, got %T", resp["access_token"])
	}
	if _, ok := resp["refresh_token"].(string); !ok {
		t.Fatalf("expected refresh_token string, got %T", resp["refresh_token"])
	}
	if _, ok := resp["expires_in"].(float64); !ok {
		t.Fatalf("expected expires_in number, got %T", resp["expires_in"])
	}
	if resp["scope"] != "openid email" {
		t.Fatalf("expected scope 'openid email', got %v", resp["scope"])
	}
}

func TestToken_InvalidGrant(t *testing.T) {
	r, _ := newTestServer(t)

	w := postForm(t, r, "/token", url.Values{
		"grant_type":   []string{"authorization_code"},
		"code":         []string{"missing"},
		"client_id":    []string{"client-1"},
		"redirect_uri": []string{"http://localhost:3000/callback"},
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid_grant") {
		t.Fatalf("expected invalid_grant, got %s", w.Body.String())
	}
}

func TestToken_CodeReuse(t *testing.T) {
	r, h := newTestServer(t)

	h.codes.Put("code-2", authCode{
		ClientID:    "client-1",
		RedirectURI: "http://localhost:3000/callback",
	})

	w1 := postForm(t, r, "/token", url.Values{
		"grant_type":   []string{"authorization_code"},
		"code":         []string{"code-2"},
		"client_id":    []string{"client-1"},
		"redirect_uri": []string{"http://localhost:3000/callback"},
	})
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w1.Code, w1.Body.String())
	}

	w2 := postForm(t, r, "/token", url.Values{
		"grant_type":   []string{"authorization_code"},
		"code":         []string{"code-2"},
		"client_id":    []string{"client-1"},
		"redirect_uri": []string{"http://localhost:3000/callback"},
	})
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), "invalid_grant") {
		t.Fatalf("expected invalid_grant, got %s", w2.Body.String())
	}
}

func TestToken_RedirectUriMismatch(t *testing.T) {
	r, h := newTestServer(t)

	h.codes.Put("code-3", authCode{
		ClientID:    "client-1",
		RedirectURI: "http://localhost:3000/callback",
	})

	w := postForm(t, r, "/token", url.Values{
		"grant_type":   []string{"authorization_code"},
		"code":         []string{"code-3"},
		"client_id":    []string{"client-1"},
		"redirect_uri": []string{"http://localhost:3000/other"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid_grant") {
		t.Fatalf("expected invalid_grant, got %s", w.Body.String())
	}
}

func newTestServerWithUserinfo(t *testing.T) (*gin.Engine, *handlerImpl) {
	t.Helper()

	gin.SetMode(gin.TestMode)
	repo := newTestRepo(t, []domain.Client{
		{
			ID:            "client-1",
			Name:          "demo",
			RedirectUris:  []string{"http://localhost:3000/callback"},
			AllowedScopes: []string{"openid", "email", "profile"},
		},
	})
	uc := usecase.NewValidateClientUsecase(repo)
	signer, err := jwt.NewSigner()
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	h := NewOAUTHRouter(nil, uc, signer, "http://localhost:8080").(*handlerImpl)

	r := gin.New()
	r.POST("/token", h.Token)
	r.GET("/userinfo", h.Userinfo)
	return r, h
}

func TestUserinfo_ReturnsEmailAndSub(t *testing.T) {
	r, h := newTestServerWithUserinfo(t)

	// Simulate auth code with email
	h.codes.Put("code-with-email", authCode{
		ClientID:    "client-1",
		RedirectURI: "http://localhost:3000/callback",
		Scopes:      []string{"openid", "email"},
		Email:       "test@example.com",
	})

	// Exchange code for tokens
	tokenResp := postForm(t, r, "/token", url.Values{
		"grant_type":   []string{"authorization_code"},
		"code":         []string{"code-with-email"},
		"client_id":    []string{"client-1"},
		"redirect_uri": []string{"http://localhost:3000/callback"},
	})

	if tokenResp.Code != http.StatusOK {
		t.Fatalf("token exchange failed: %d: %s", tokenResp.Code, tokenResp.Body.String())
	}

	var tokenData map[string]any
	if err := json.Unmarshal(tokenResp.Body.Bytes(), &tokenData); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	accessToken := tokenData["access_token"].(string)

	// Call userinfo
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("userinfo failed: %d: %s", w.Code, w.Body.String())
	}

	var userinfo map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &userinfo); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}

	if userinfo["sub"] != "test@example.com" {
		t.Errorf("expected sub=test@example.com, got %v", userinfo["sub"])
	}
	if userinfo["email"] != "test@example.com" {
		t.Errorf("expected email=test@example.com, got %v", userinfo["email"])
	}
}

func TestToken_ReturnsIDToken(t *testing.T) {
	r, h := newTestServerWithUserinfo(t)

	h.codes.Put("code-idtoken", authCode{
		ClientID:    "client-1",
		RedirectURI: "http://localhost:3000/callback",
		Scopes:      []string{"openid", "email"},
		Email:       "idtoken@example.com",
	})

	w := postForm(t, r, "/token", url.Values{
		"grant_type":   []string{"authorization_code"},
		"code":         []string{"code-idtoken"},
		"client_id":    []string{"client-1"},
		"redirect_uri": []string{"http://localhost:3000/callback"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode json: %v", err)
	}

	idToken, ok := resp["id_token"].(string)
	if !ok || idToken == "" {
		t.Fatalf("expected id_token in response, got %v", resp["id_token"])
	}

	// Verify it's a valid JWT (has 3 parts)
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT with 3 parts, got %d", len(parts))
	}
}

func TestRefreshToken_PreservesEmail(t *testing.T) {
	r, h := newTestServerWithUserinfo(t)

	// Simulate auth code with email
	h.codes.Put("code-refresh", authCode{
		ClientID:    "client-1",
		RedirectURI: "http://localhost:3000/callback",
		Scopes:      []string{"openid", "email"},
		Email:       "refresh@example.com",
	})

	// Exchange code for tokens
	tokenResp := postForm(t, r, "/token", url.Values{
		"grant_type":   []string{"authorization_code"},
		"code":         []string{"code-refresh"},
		"client_id":    []string{"client-1"},
		"redirect_uri": []string{"http://localhost:3000/callback"},
	})

	var tokenData map[string]any
	if err := json.Unmarshal(tokenResp.Body.Bytes(), &tokenData); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	refreshToken := tokenData["refresh_token"].(string)

	// Use refresh token
	refreshResp := postForm(t, r, "/token", url.Values{
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{refreshToken},
		"client_id":     []string{"client-1"},
	})

	if refreshResp.Code != http.StatusOK {
		t.Fatalf("refresh failed: %d: %s", refreshResp.Code, refreshResp.Body.String())
	}

	var newTokenData map[string]any
	if err := json.Unmarshal(refreshResp.Body.Bytes(), &newTokenData); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}

	newAccessToken := newTokenData["access_token"].(string)

	// Call userinfo with new token
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+newAccessToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("userinfo failed: %d: %s", w.Code, w.Body.String())
	}

	var userinfo map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &userinfo); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}

	if userinfo["sub"] != "refresh@example.com" {
		t.Errorf("expected sub=refresh@example.com, got %v", userinfo["sub"])
	}
	if userinfo["email"] != "refresh@example.com" {
		t.Errorf("expected email=refresh@example.com, got %v", userinfo["email"])
	}
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func TestPKCE_S256_Success(t *testing.T) {
	r, h := newTestServer(t)

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := generateCodeChallenge(codeVerifier)

	h.codes.Put("code-pkce", authCode{
		ClientID:            "client-1",
		RedirectURI:         "http://localhost:3000/callback",
		Scopes:              []string{"openid"},
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	})

	w := postForm(t, r, "/token", url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{"code-pkce"},
		"client_id":     []string{"client-1"},
		"redirect_uri":  []string{"http://localhost:3000/callback"},
		"code_verifier": []string{codeVerifier},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPKCE_S256_InvalidVerifier(t *testing.T) {
	r, h := newTestServer(t)

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := generateCodeChallenge(codeVerifier)

	h.codes.Put("code-pkce-invalid", authCode{
		ClientID:            "client-1",
		RedirectURI:         "http://localhost:3000/callback",
		Scopes:              []string{"openid"},
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	})

	w := postForm(t, r, "/token", url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{"code-pkce-invalid"},
		"client_id":     []string{"client-1"},
		"redirect_uri":  []string{"http://localhost:3000/callback"},
		"code_verifier": []string{"wrong-verifier"},
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid_grant") {
		t.Fatalf("expected invalid_grant error, got %s", w.Body.String())
	}
}

func TestPKCE_MissingVerifier(t *testing.T) {
	r, h := newTestServer(t)

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := generateCodeChallenge(codeVerifier)

	h.codes.Put("code-pkce-missing", authCode{
		ClientID:            "client-1",
		RedirectURI:         "http://localhost:3000/callback",
		Scopes:              []string{"openid"},
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	})

	w := postForm(t, r, "/token", url.Values{
		"grant_type":   []string{"authorization_code"},
		"code":         []string{"code-pkce-missing"},
		"client_id":    []string{"client-1"},
		"redirect_uri": []string{"http://localhost:3000/callback"},
		// No code_verifier
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "code_verifier is required") {
		t.Fatalf("expected code_verifier required error, got %s", w.Body.String())
	}
}

func TestPKCE_Plain_Success(t *testing.T) {
	r, h := newTestServer(t)

	codeVerifier := "plain-verifier-value"

	h.codes.Put("code-pkce-plain", authCode{
		ClientID:            "client-1",
		RedirectURI:         "http://localhost:3000/callback",
		Scopes:              []string{"openid"},
		CodeChallenge:       codeVerifier, // plain: challenge == verifier
		CodeChallengeMethod: "plain",
	})

	w := postForm(t, r, "/token", url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{"code-pkce-plain"},
		"client_id":     []string{"client-1"},
		"redirect_uri":  []string{"http://localhost:3000/callback"},
		"code_verifier": []string{codeVerifier},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
