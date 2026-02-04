package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Signer struct {
	privateKey *rsa.PrivateKey
	keyID      string
}

func NewSigner() (*Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Generate a stable key ID from the public key
	pubKeyBytes := privateKey.PublicKey.N.Bytes()
	hash := sha256.Sum256(pubKeyBytes)
	keyID := base64.RawURLEncoding.EncodeToString(hash[:8])

	return &Signer{
		privateKey: privateKey,
		keyID:      keyID,
	}, nil
}

type IDTokenClaims struct {
	jwt.RegisteredClaims
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

func (s *Signer) CreateIDToken(issuer, subject, audience, email, name, nonce string, expiry time.Duration) (string, error) {
	now := time.Now()

	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Email: email,
		Name:  name,
		Nonce: nonce,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID

	return token.SignedString(s.privateKey)
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func (s *Signer) JWKS() JWKS {
	return JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: s.keyID,
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(s.privateKey.PublicKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.privateKey.PublicKey.E)).Bytes()),
			},
		},
	}
}

func (s *Signer) JWKSBytes() ([]byte, error) {
	return json.Marshal(s.JWKS())
}

func (s *Signer) KeyID() string {
	return s.keyID
}
