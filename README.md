# OAUTH MOCK

OAUTH MOCK is a small application written in Go that allows you to simulate an OAuth2/OpenID Connect service, mainly for testing and development purposes.

## Disclaimer

This project is intended **for development and testing purposes only**.

It is **NOT designed to be used in production** and should not be deployed in a production environment.

## Features

- OAuth2 Authorization Code Flow
- **PKCE support** (S256 and plain)
- OpenID Connect (OIDC) support
- ID Token (JWT signed with RS256)
- Refresh Token support
- OIDC Discovery endpoint
- JWKS endpoint for token validation
- Userinfo endpoint
- Configurable clients via YAML

## Prerequisites

- Go **1.23+**
- (optional) Docker

## Getting Started

### Build from source

```bash
go run cmd/api/main.go
```

The API will start on the port defined in the `.env` file (default: 8080).

### Using Docker

```bash
docker build -t oauth_mock .
docker run -p 8080:8080 oauth_mock
```

## Configuration

### Environment Variables (`.env`)

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8080` |
| `APP_ENV` | Environment (`development`/`production`) | `development` |
| `ISSUER` | OIDC Issuer URL | `http://localhost:{PORT}` |

### Clients (`clients.yaml`)

```yaml
clients:
  - id: my-client-id
    name: My App
    redirect_uris:
      - http://localhost:3000/callback
    allowed_scopes:
      - openid
      - profile
      - email
    users:
      - email: user@example.com
        password: secret
```

### OAuth Behavior (`config.yaml`)

```yaml
authorize:
  mandatory_state: true  # Require state parameter
```

## API Endpoints

### OIDC Discovery

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/.well-known/openid-configuration` | OIDC Discovery document |
| GET | `/.well-known/jwks.json` | JSON Web Key Set |

### OAuth2 Flow

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/authorize` | Start authorization (login page) |
| POST | `/api/v1/authorize/login` | Submit credentials |
| POST | `/api/v1/authorize/consent` | Grant consent |
| POST | `/api/v1/token` | Exchange code/refresh token for tokens |
| GET | `/api/v1/userinfo` | Get user information |

### Other

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/ping` | Health check |
| GET | `/swagger/index.html` | Swagger UI |

## Usage Example

### 1. Start Authorization Flow

```
GET http://localhost:8080/api/v1/authorize
    ?response_type=code
    &client_id=1
    &redirect_uri=http://localhost:3000/callback
    &scope=openid%20email%20profile
    &state=random-state
```

### 2. Exchange Code for Tokens

```bash
curl -X POST http://localhost:8080/api/v1/token \
  -d "grant_type=authorization_code" \
  -d "code=mock-20260204..." \
  -d "client_id=1" \
  -d "redirect_uri=http://localhost:3000/callback"
```

Response:
```json
{
  "access_token": "access-20260204...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh-20260204...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "scope": "openid email profile"
}
```

### 3. Refresh Token

```bash
curl -X POST http://localhost:8080/api/v1/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=refresh-20260204..." \
  -d "client_id=1"
```

### 4. Get User Info

```bash
curl -H "Authorization: Bearer access-20260204..." \
  http://localhost:8080/api/v1/userinfo
```

Response:
```json
{
  "sub": "user@example.com",
  "email": "user@example.com",
  "name": "user"
}
```

## ID Token

When the `openid` scope is requested, the token response includes a signed JWT (`id_token`) with the following claims:

| Claim | Description |
|-------|-------------|
| `iss` | Issuer URL |
| `sub` | Subject (user email) |
| `aud` | Audience (client ID) |
| `exp` | Expiration time |
| `iat` | Issued at |
| `email` | User email |
| `name` | User name |

The JWT is signed with RS256. Public keys are available at `/.well-known/jwks.json`.

## PKCE (Proof Key for Code Exchange)

PKCE is supported for public clients (SPAs, mobile apps). It prevents authorization code interception attacks.

### Methods Supported

| Method | Description |
|--------|-------------|
| `S256` | SHA-256 hash (recommended) |
| `plain` | Plain text (not recommended) |

### Usage with PKCE

1. Generate a `code_verifier` (43-128 characters, URL-safe)
2. Create `code_challenge` = BASE64URL(SHA256(code_verifier))
3. Include in authorization request:

```
GET /api/v1/authorize
    ?response_type=code
    &client_id=1
    &redirect_uri=http://localhost:3000/callback
    &scope=openid
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    &code_challenge_method=S256
```

4. Include `code_verifier` in token request:

```bash
curl -X POST http://localhost:8080/api/v1/token \
  -d "grant_type=authorization_code" \
  -d "code=mock-..." \
  -d "client_id=1" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

## Development

### Run Tests

```bash
go test ./...
```

### Regenerate Swagger Docs

```bash
swag init -g cmd/api/main.go -o docs
```

## License

MIT
