package usecase

import (
	"context"
	"errors"
	"os"
	"testing"

	"oauthmock/internal/oauth/adapter/db"
	"oauthmock/internal/oauth/domain"

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

func TestValidateClientUsecase(t *testing.T) {
	repo := newTestRepo(t, []domain.Client{
		{
			ID:            "client-1",
			Name:          "demo",
			RedirectUris:  []string{"http://localhost:3000/callback"},
			AllowedScopes: []string{"openid", "profile", "email"},
		},
	})
	uc := NewValidateClientUsecase(repo)

	t.Run("client not found", func(t *testing.T) {
		_, err := uc.Execute(context.Background(), ValidateClientInput{
			ClientId:    "missing",
			RedirectUri: "http://localhost:3000/callback",
		})
		if !errors.Is(err, domain.ErrClientNotFound) {
			t.Fatalf("expected ErrClientNotFound, got %v", err)
		}
	})

	t.Run("invalid redirect uri", func(t *testing.T) {
		_, err := uc.Execute(context.Background(), ValidateClientInput{
			ClientId:    "client-1",
			RedirectUri: "http://localhost:3000/other",
		})
		if !errors.Is(err, domain.ErrInvalidRedirectURI) {
			t.Fatalf("expected ErrInvalidRedirectURI, got %v", err)
		}
	})

	t.Run("invalid scope", func(t *testing.T) {
		_, err := uc.Execute(context.Background(), ValidateClientInput{
			ClientId:    "client-1",
			RedirectUri: "http://localhost:3000/callback",
			Scopes:      []string{"openid", "admin"},
		})
		if !errors.Is(err, domain.ErrInvalidScope) {
			t.Fatalf("expected ErrInvalidScope, got %v", err)
		}
	})

	t.Run("valid scopes", func(t *testing.T) {
		_, err := uc.Execute(context.Background(), ValidateClientInput{
			ClientId:    "client-1",
			RedirectUri: "http://localhost:3000/callback",
			Scopes:      []string{"openid", "email"},
		})
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("empty scopes allowed", func(t *testing.T) {
		_, err := uc.Execute(context.Background(), ValidateClientInput{
			ClientId:    "client-1",
			RedirectUri: "http://localhost:3000/callback",
			Scopes:      nil,
		})
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})
}

func TestValidateClientUsecase_ContextCanceled(t *testing.T) {
	repo := newTestRepo(t, []domain.Client{
		{
			ID:            "client-1",
			RedirectUris:  []string{"http://localhost:3000/callback"},
			AllowedScopes: []string{"openid"},
		},
	})
	uc := NewValidateClientUsecase(repo)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := uc.Execute(ctx, ValidateClientInput{
		ClientId:    "client-1",
		RedirectUri: "http://localhost:3000/callback",
		Scopes:      []string{"openid"},
	})
	if err == nil {
		t.Fatalf("expected context error, got nil")
	}
}
