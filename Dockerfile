# syntax=docker/dockerfile:1.6

FROM --platform=$BUILDPLATFORM golang:1.25.3-alpine AS builder
WORKDIR /src

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG SWAGGER_GEN=true

RUN if [ "$SWAGGER_GEN" = "true" ]; then \
	go install github.com/swaggo/swag/cmd/swag@v1.16.4 && \
	swag init -g cmd/api/main.go -o docs; \
	fi

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
	go build -trimpath -ldflags="-s -w" -o /out/oauthmock ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app

ENV PORT=8080
ENV APP_ENV=production

COPY --from=builder /out/oauthmock /app/oauthmock
COPY config.yaml clients.yaml /app/
COPY templates /app/templates
COPY docs /app/docs

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/app/oauthmock"]
