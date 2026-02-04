# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OAuth Mock is a Go application that simulates an OAuth2/OpenID Connect authorization server for testing and development purposes. It implements the authorization code flow with login and consent screens, OIDC discovery, and JWT ID tokens.

## Commands

```bash
# Run the server
go run cmd/api/main.go

# Run all tests
go test ./...

# Run a single test
go test ./internal/oauth/usecase -run TestValidateClientUsecase

# Regenerate Swagger docs (after editing annotations)
swag init -g cmd/api/main.go -o docs

# Docker build and run
docker build -t oauth_mock .
docker run -p 8080:8080 oauth_mock
```

## Architecture

The project follows a layered architecture with clean separation of concerns:

```
cmd/api/main.go          → Entrypoint, HTTP server setup with graceful shutdown
internal/
  api/                   → Router setup, wires dependencies together
  config/                → Environment (.env) and YAML config loading
  oauth/
    domain/              → Core entities (Client, User) and domain errors
    usecase/             → Business logic (ValidateClientUsecase)
    jwt/                 → JWT signing and JWKS generation
    adapter/
      db/                → YAML-based client repository
      http/              → Gin HTTP handlers for OAuth endpoints
```

**Data Flow**: HTTP Handler → Usecase → Repository (YAML file)

## Configuration

- **`.env`**: Server port (`PORT`), environment (`APP_ENV`), and issuer URL (`ISSUER`)
- **`config.yaml`**: OAuth behavior settings (e.g., `authorize.mandatory_state`)
- **`clients.yaml`**: Client definitions including IDs, redirect URIs, allowed scopes, and test users with credentials

## API Endpoints

### OIDC Discovery (root level)
- `GET /.well-known/openid-configuration` - OIDC discovery document
- `GET /.well-known/jwks.json` - JSON Web Key Set for token validation

### OAuth2 Flow (under `/api/v1`)
- `GET /authorize` - Start authorization flow (renders login page)
- `POST /authorize/login` - Submit credentials (renders consent page)
- `POST /authorize/consent` - Grant consent (redirects with auth code)
- `POST /token` - Exchange auth code or refresh token for tokens
- `GET /userinfo` - Get user information (requires Bearer token)
- `GET /ping` - Health check

Swagger UI available at `/swagger/index.html`

## Key Implementation Details

- Authorization codes are stored in-memory with 5-minute TTL and single-use enforcement
- Access tokens are stored in-memory with 1-hour TTL
- Refresh tokens are stored in-memory with 24-hour TTL and single-use (rotation)
- Tokens are mock timestamps prefixed with `access-` or `refresh-`
- ID tokens are JWTs signed with RS256 (key generated at startup)
- PKCE: supports S256 (default) and plain methods; code_challenge stored with auth code
- Client validation checks: client exists, redirect URI whitelisted, scopes allowed
- HTML templates in `templates/` directory for login and consent pages
- User email is passed through the flow: login → consent form (hidden field) → auth code → tokens
