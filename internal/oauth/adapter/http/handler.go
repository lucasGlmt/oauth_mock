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
	responseType := ctx.Query("response_type")
	clientId := ctx.Query("client_id")
	redirectUri := ctx.Query("redirect_uri")
	scope := ctx.Query("scope")
	state := ctx.Query("state")
	mandatoryState := h.cfg != nil && h.cfg.Authorize.MandatoryState

	if clientId == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "client_id is required"})
		return
	}

	if redirectUri == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "redirect_uri is required"})
		return
	}

	if mandatoryState && state == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "state is required"})
		return
	}

	_, err := h.validateClientUc.Execute(ctx.Request.Context(), usecase.ValidateClientInput{
		ClientId:    clientId,
		RedirectUri: redirectUri,
		Scopes:      strings.Fields(scope),
	})

	if err != nil {
		switch {
		case errors.Is(err, domain.ErrClientNotFound):
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client", "error_description": "client not found"})
			return
		case errors.Is(err, domain.ErrInvalidRedirectURI):
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri", "error_description": "redirect_uri not authorized"})
			return
		case errors.Is(err, domain.ErrInvalidScope):
			h.redirectWithError(ctx, redirectUri, "invalid_scope", "scope not allowed", state)
			return
		case errors.Is(err, domain.ErrUnauthorized):
			h.redirectWithError(ctx, redirectUri, "unauthorized_client", "client not authorized", state)
			return
		default:
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "internal error"})
			return
		}
	}

	if responseType == "" {
		h.redirectWithError(ctx, redirectUri, "invalid_request", "response_type is required", state)
		return
	}

	if responseType != "code" {
		h.redirectWithError(ctx, redirectUri, "unsupported_response_type", "response_type must be code", state)
		return
	}

	code := "mock-" + time.Now().UTC().Format("20060102150405.000000000")
	redirectTo, err := buildRedirectURL(redirectUri, url.Values{
		"code":  []string{code},
		"state": optionalState(state),
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
