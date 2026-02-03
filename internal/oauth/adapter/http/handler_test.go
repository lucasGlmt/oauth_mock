package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"oauthmock/internal/oauth/adapter/db"
	"oauthmock/internal/oauth/domain"
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
	h := NewOAUTHRouter(nil, uc).(*handlerImpl)

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
