package domain

import "errors"

var (
	ErrClientNotFound     = errors.New("client not found")
	ErrUnauthorized       = errors.New("client not authorized")
	ErrInvalidScope       = errors.New("invalid scope")
	ErrInvalidRedirectURI = errors.New("invalid redirect uri")
)
