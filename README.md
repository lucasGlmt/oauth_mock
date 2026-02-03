# OAUTH MOCK

OAUTH MOCK is a small application written in Go that allows you to simulate a connection to an OAuth2 service, mainly for testing and development purposes.

## ⚠️ Disclaimer ⚠️ 

This project is intended **for development and testing purposes only**.

It is **NOT designed to be used in production** and should not be deployed
in a production environment.

## Prerequisites
- Go **1.25.3**
- (optional) Docker

## Getting Started

### Build from source
- The entrypoint is located in `cmd/api/main.go`
- Configuration is handled via a `.env` file

To start the mock API:

```bash
go run cmd/api/main.go
```
The API will start on the port defined in the `.env` file.

### Using Docker
```bash
docker build -t oauth_mock .
docker run -p 8080:8080 oauth_mock
```
(adjust the port if needed according to your .env file)

## Project Goal
The purpose of this project is to provide a mocked OAuth2 server
to test authentication flows without relying on a real external provider.

## API Docs (Swagger)
Swagger UI is available at:
- `http://localhost:8080/swagger/index.html`

To regenerate the documentation after edits to annotations:
```bash
swag init -g cmd/api/main.go -o docs
```
