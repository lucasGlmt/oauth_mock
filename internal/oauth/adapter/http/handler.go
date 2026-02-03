package http

import (
	"errors"
	"net/http"
	"net/url"
	"oauthmock/internal/config"
	"oauthmock/internal/oauth/domain"
	"oauthmock/internal/oauth/usecase"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type Handler interface {
	Authorize(ctx *gin.Context)
	AuthorizeLogin(ctx *gin.Context)
	AuthorizeConsent(ctx *gin.Context)
}

type handlerImpl struct {
	cfg              *config.Config
	validateClientUc usecase.ValidateClientUsecase
}

func NewOAUTHRouter(cfg *config.Config, validateClientUc usecase.ValidateClientUsecase) Handler {
	return &handlerImpl{
		validateClientUc: validateClientUc,
		cfg:              cfg,
	}
}

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
