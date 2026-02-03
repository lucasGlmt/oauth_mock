package api

import (
	"net/http"

	"oauthmock/internal/config"
	"oauthmock/internal/oauth/adapter/db"
	"oauthmock/internal/oauth/usecase"

	oauthHandler "oauthmock/internal/oauth/adapter/http"

	"github.com/gin-gonic/gin"
)

type HealthResponse struct {
	Status string `json:"status"`
	Time   string `json:"time"`
}

func NewRouter(conf config.ApiConfig) *gin.Engine {
	if conf.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	cfg, err := config.LoadConfig("config.yaml")

	// Inst

	repoClients, err := db.NewRepositoryFromYAML("clients.yaml")
	if err != nil {
		panic(err)
	}

	validateClientUC := usecase.NewValidateClientUsecase(repoClients)
	oauthRouter := oauthHandler.NewOAUTHRouter(cfg, validateClientUC)

	api := r.Group("/api/v1")
	api.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})

	api.GET("/authorize", oauthRouter.Authorize)

	return r
}
