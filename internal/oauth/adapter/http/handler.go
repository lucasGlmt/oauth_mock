package http

import (
	"errors"
	"net/http"
	"net/url"
	"oauthmock/internal/config"
	"oauthmock/internal/oauth/domain"
	"oauthmock/internal/oauth/usecase"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type Handler interface {
	Authorize(ctx *gin.Context)
	AuthorizeLogin(ctx *gin.Context)
	AuthorizeConsent(ctx *gin.Context)
	Token(ctx *gin.Context)
}

type handlerImpl struct {
	cfg              *config.Config
	validateClientUc usecase.ValidateClientUsecase
	codes            *authCodeStore
}

func NewOAUTHRouter(cfg *config.Config, validateClientUc usecase.ValidateClientUsecase) Handler {
	return &handlerImpl{
		validateClientUc: validateClientUc,
		cfg:              cfg,
		codes:            newAuthCodeStore(5 * time.Minute),
	}
}

// Authorize godoc
// @Summary Start authorization flow
// @Tags oauth
// @Produce html
// @Param response_type query string true "Response type" Enums(code)
// @Param client_id query string true "Client ID"
// @Param redirect_uri query string true "Redirect URI"
// @Param scope query string false "Scopes (space-delimited)"
// @Param state query string false "State"
// @Success 200 {string} string "Login page"
// @Failure 400 {object} ErrorResponse
// @Router /authorize [get]
func (h *handlerImpl) Authorize(ctx *gin.Context) {
	params := authorizeParamsFromQuery(ctx)
	requestedScopes := strings.Fields(params.Scope)

	client, ok := h.validateAuthorizeParams(ctx, params, requestedScopes)
	if !ok {
		return
	}

	if !h.validateResponseType(ctx, params.ResponseType, params.RedirectURI, params.State) {
		return
	}

	ctx.HTML(http.StatusOK, "login.tmpl", loginViewData{
		ClientName:   client.Name,
		ClientID:     params.ClientID,
		RedirectURI:  params.RedirectURI,
		ResponseType: params.ResponseType,
		Scope:        params.Scope,
		State:        params.State,
	})
}

// AuthorizeLogin godoc
// @Summary Submit login form
// @Tags oauth
// @Accept application/x-www-form-urlencoded
// @Produce html
// @Param client_id formData string true "Client ID"
// @Param redirect_uri formData string true "Redirect URI"
// @Param response_type formData string true "Response type" Enums(code)
// @Param scope formData string false "Scopes (space-delimited)"
// @Param state formData string false "State"
// @Param email formData string true "Email"
// @Param password formData string true "Password"
// @Success 200 {string} string "Consent page"
// @Failure 401 {string} string "Invalid credentials"
// @Failure 400 {object} ErrorResponse
// @Router /authorize/login [post]
func (h *handlerImpl) AuthorizeLogin(ctx *gin.Context) {
	params := authorizeParamsFromForm(ctx)
	email := strings.TrimSpace(ctx.PostForm("email"))
	password := ctx.PostForm("password")
	requestedScopes := strings.Fields(params.Scope)

	client, ok := h.validateAuthorizeParams(ctx, params, requestedScopes)
	if !ok {
		return
	}

	if !h.validateResponseType(ctx, params.ResponseType, params.RedirectURI, params.State) {
		return
	}

	if !clientHasUser(client, email, password) {
		ctx.HTML(http.StatusUnauthorized, "login.tmpl", loginViewData{
			ClientName:   client.Name,
			ClientID:     params.ClientID,
			RedirectURI:  params.RedirectURI,
			ResponseType: params.ResponseType,
			Scope:        params.Scope,
			State:        params.State,
			Email:        email,
			Error:        "Identifiants invalides",
		})
		return
	}

	scopesToDisplay := requestedScopes
	if len(scopesToDisplay) == 0 {
		scopesToDisplay = client.AllowedScopes
	}
	selectedScopes := requestedScopes
	if len(selectedScopes) == 0 {
		selectedScopes = scopesToDisplay
	}

	ctx.HTML(http.StatusOK, "consent.tmpl", consentViewData{
		ClientName:     client.Name,
		ClientID:       params.ClientID,
		RedirectURI:    params.RedirectURI,
		ResponseType:   params.ResponseType,
		State:          params.State,
		Scopes:         scopesToDisplay,
		SelectedScopes: selectedScopes,
	})
}

// AuthorizeConsent godoc
// @Summary Submit consent
// @Tags oauth
// @Accept application/x-www-form-urlencoded
// @Produce html
// @Param client_id formData string true "Client ID"
// @Param redirect_uri formData string true "Redirect URI"
// @Param response_type formData string true "Response type" Enums(code)
// @Param state formData string false "State"
// @Param scopes formData []string false "Scopes"
// @Success 302 {string} string "Redirect with code"
// @Failure 400 {object} ErrorResponse
// @Router /authorize/consent [post]
func (h *handlerImpl) AuthorizeConsent(ctx *gin.Context) {
	params := authorizeParamsFromForm(ctx)
	selectedScopes := ctx.PostFormArray("scopes")

	_, ok := h.validateAuthorizeParams(ctx, params, selectedScopes)
	if !ok {
		return
	}

	if !h.validateResponseType(ctx, params.ResponseType, params.RedirectURI, params.State) {
		return
	}

	code := "mock-" + time.Now().UTC().Format("20060102150405.000000000")
	h.codes.Put(code, authCode{
		ClientID:    params.ClientID,
		RedirectURI: params.RedirectURI,
		Scopes:      selectedScopes,
	})
	redirectTo, err := buildRedirectURL(params.RedirectURI, url.Values{
		"code":  []string{code},
		"state": optionalState(params.State),
	})
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri", "error_description": "redirect_uri is invalid"})
		return
	}

	ctx.Redirect(http.StatusFound, redirectTo)
}

// Token godoc
// @Summary Exchange authorization code for token
// @Tags oauth
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param grant_type formData string true "Grant type" Enums(authorization_code)
// @Param code formData string true "Authorization code"
// @Param client_id formData string true "Client ID"
// @Param redirect_uri formData string true "Redirect URI"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} ErrorResponse
// @Router /token [post]
func (h *handlerImpl) Token(ctx *gin.Context) {
	grantType := ctx.PostForm("grant_type")
	if grantType == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "grant_type is required"})
		return
	}
	if grantType != "authorization_code" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type", "error_description": "grant_type must be authorization_code"})
		return
	}

	code := ctx.PostForm("code")
	if code == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "code is required"})
		return
	}

	clientID := ctx.PostForm("client_id")
	if basicUser, _, ok := ctx.Request.BasicAuth(); ok && clientID == "" {
		clientID = basicUser
	}
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client", "error_description": "client_id is required"})
		return
	}

	redirectURI := ctx.PostForm("redirect_uri")
	if redirectURI == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "redirect_uri is required"})
		return
	}

	codeData, ok := h.codes.Consume(code)
	if !ok {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "code is invalid or expired"})
		return
	}
	if codeData.ClientID != clientID {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "client_id does not match code"})
		return
	}
	if codeData.RedirectURI != redirectURI {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "redirect_uri does not match code"})
		return
	}

	_, err := h.validateClientUc.Execute(ctx.Request.Context(), usecase.ValidateClientInput{
		ClientId:    clientID,
		RedirectUri: redirectURI,
		Scopes:      codeData.Scopes,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrClientNotFound):
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client", "error_description": "client not found"})
			return
		case errors.Is(err, domain.ErrInvalidRedirectURI):
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "redirect_uri not authorized"})
			return
		case errors.Is(err, domain.ErrInvalidScope):
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope", "error_description": "scope not allowed"})
			return
		case errors.Is(err, domain.ErrUnauthorized):
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client", "error_description": "client not authorized"})
			return
		default:
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "internal error"})
			return
		}
	}

	issuedAt := time.Now().UTC()
	accessToken := "access-" + issuedAt.Format("20060102150405.000000000")
	refreshToken := "refresh-" + issuedAt.Format("20060102150405.000000000")

	resp := gin.H{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
	}
	if len(codeData.Scopes) > 0 {
		resp["scope"] = strings.Join(codeData.Scopes, " ")
	}
	ctx.JSON(http.StatusOK, resp)
}

func (h *handlerImpl) redirectWithError(ctx *gin.Context, redirectUri, code, description, state string) {
	params := url.Values{
		"error":             []string{code},
		"error_description": []string{description},
		"state":             optionalState(state),
	}
	redirectTo, err := buildRedirectURL(redirectUri, params)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri", "error_description": "redirect_uri is invalid"})
		return
	}

	ctx.Redirect(http.StatusFound, redirectTo)
}

type authorizeParams struct {
	ResponseType string
	ClientID     string
	RedirectURI  string
	Scope        string
	State        string
}

type loginViewData struct {
	ClientName   string
	ClientID     string
	RedirectURI  string
	ResponseType string
	Scope        string
	State        string
	Email        string
	Error        string
}

type consentViewData struct {
	ClientName     string
	ClientID       string
	RedirectURI    string
	ResponseType   string
	State          string
	Scopes         []string
	SelectedScopes []string
	Error          string
}

func authorizeParamsFromQuery(ctx *gin.Context) authorizeParams {
	return authorizeParams{
		ResponseType: ctx.Query("response_type"),
		ClientID:     ctx.Query("client_id"),
		RedirectURI:  ctx.Query("redirect_uri"),
		Scope:        ctx.Query("scope"),
		State:        ctx.Query("state"),
	}
}

func authorizeParamsFromForm(ctx *gin.Context) authorizeParams {
	return authorizeParams{
		ResponseType: ctx.PostForm("response_type"),
		ClientID:     ctx.PostForm("client_id"),
		RedirectURI:  ctx.PostForm("redirect_uri"),
		Scope:        ctx.PostForm("scope"),
		State:        ctx.PostForm("state"),
	}
}

func (h *handlerImpl) validateAuthorizeParams(ctx *gin.Context, params authorizeParams, scopes []string) (domain.Client, bool) {
	mandatoryState := h.cfg != nil && h.cfg.Authorize.MandatoryState

	if params.ClientID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "client_id is required"})
		return domain.Client{}, false
	}

	if params.RedirectURI == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "redirect_uri is required"})
		return domain.Client{}, false
	}

	if mandatoryState && params.State == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "state is required"})
		return domain.Client{}, false
	}

	out, err := h.validateClientUc.Execute(ctx.Request.Context(), usecase.ValidateClientInput{
		ClientId:    params.ClientID,
		RedirectUri: params.RedirectURI,
		Scopes:      scopes,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrClientNotFound):
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client", "error_description": "client not found"})
			return domain.Client{}, false
		case errors.Is(err, domain.ErrInvalidRedirectURI):
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri", "error_description": "redirect_uri not authorized"})
			return domain.Client{}, false
		case errors.Is(err, domain.ErrInvalidScope):
			h.redirectWithError(ctx, params.RedirectURI, "invalid_scope", "scope not allowed", params.State)
			return domain.Client{}, false
		case errors.Is(err, domain.ErrUnauthorized):
			h.redirectWithError(ctx, params.RedirectURI, "unauthorized_client", "client not authorized", params.State)
			return domain.Client{}, false
		default:
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "internal error"})
			return domain.Client{}, false
		}
	}

	return out.Client, true
}

func (h *handlerImpl) validateResponseType(ctx *gin.Context, responseType, redirectURI, state string) bool {
	if responseType == "" {
		h.redirectWithError(ctx, redirectURI, "invalid_request", "response_type is required", state)
		return false
	}

	if responseType != "code" {
		h.redirectWithError(ctx, redirectURI, "unsupported_response_type", "response_type must be code", state)
		return false
	}

	return true
}

func clientHasUser(client domain.Client, email, password string) bool {
	for _, user := range client.Users {
		if user.Email == email && user.Password == password {
			return true
		}
	}
	return false
}

func buildRedirectURL(base string, params url.Values) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("invalid redirect uri")
	}

	q := u.Query()
	for key, values := range params {
		if len(values) == 0 {
			continue
		}
		if len(values) == 1 && values[0] == "" {
			continue
		}
		for _, v := range values {
			if v == "" {
				continue
			}
			q.Set(key, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func optionalState(state string) []string {
	if state == "" {
		return nil
	}
	return []string{state}
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type authCode struct {
	ClientID    string
	RedirectURI string
	Scopes      []string
	ExpiresAt   time.Time
}

type authCodeStore struct {
	mu    sync.Mutex
	ttl   time.Duration
	codes map[string]authCode
}

func newAuthCodeStore(ttl time.Duration) *authCodeStore {
	return &authCodeStore{
		ttl:   ttl,
		codes: make(map[string]authCode),
	}
}

func (s *authCodeStore) Put(code string, data authCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data.ExpiresAt = time.Now().UTC().Add(s.ttl)
	s.codes[code] = data
}

func (s *authCodeStore) Consume(code string) (authCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.codes[code]
	if !ok {
		return authCode{}, false
	}
	delete(s.codes, code)
	if time.Now().UTC().After(data.ExpiresAt) {
		return authCode{}, false
	}
	return data, true
}
