package usecase

import (
	"context"
	"fmt"
	"oauthmock/internal/oauth/adapter/db"
	"oauthmock/internal/oauth/domain"
)

type ValidateClientInput struct {
	ClientId    string
	RedirectUri string
	Scopes      []string
}
type ValidateClientOutput struct{}
type ValidateClientUsecase interface {
	Execute(ctx context.Context, input ValidateClientInput) (ValidateClientOutput, error)
}
type validateClientImpl struct {
	repo *db.Repository
}

func NewValidateClientUsecase(repo *db.Repository) ValidateClientUsecase {
	return &validateClientImpl{
		repo: repo,
	}
}

func (u *validateClientImpl) Execute(ctx context.Context, input ValidateClientInput) (ValidateClientOutput, error) {
	if err := ctx.Err(); err != nil {
		return ValidateClientOutput{}, err
	}

	client, found := u.repo.ClientByID(input.ClientId)
	if !found {
		return ValidateClientOutput{}, fmt.Errorf("client %v not found: %w", input.ClientId, domain.ErrClientNotFound)
	}

	// Validate redirect URIs
	redirectionUriValid := false
	for _, uri := range client.RedirectUris {
		if uri == input.RedirectUri {
			redirectionUriValid = true
			break
		}
	}

	if !redirectionUriValid {
		return ValidateClientOutput{}, fmt.Errorf("redirect uri %s is not authorized: %w", input.RedirectUri, domain.ErrInvalidRedirectURI)
	}

	// Check scopes
	if len(input.Scopes) > 0 {
		allowed := make(map[string]struct{}, len(client.AllowedScopes))
		for _, s := range client.AllowedScopes {
			if s != "" {
				allowed[s] = struct{}{}
			}
		}
		for _, requested := range input.Scopes {
			if requested == "" {
				continue
			}
			if _, ok := allowed[requested]; !ok {
				return ValidateClientOutput{}, fmt.Errorf("scope %s is not allowed: %w", requested, domain.ErrInvalidScope)
			}
		}
	}

	return ValidateClientOutput{}, nil
}
