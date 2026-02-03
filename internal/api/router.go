package api

import (
	"html/template"

	"oauthmock/internal/config"
	"oauthmock/internal/oauth/adapter/db"
	"oauthmock/internal/oauth/usecase"

	oauthHandler "oauthmock/internal/oauth/adapter/http"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func NewRouter(conf config.ApiConfig) *gin.Engine {
	if conf.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.SetFuncMap(template.FuncMap{
		"contains": func(list []string, value string) bool {
			for _, v := range list {
				if v == value {
					return true
				}
			}
			return false
		},
	})
	r.LoadHTMLGlob("templates/*.tmpl")
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		panic(err)
	}

	// Inst

	repoClients, err := db.NewRepositoryFromYAML("clients.yaml")
	if err != nil {
		panic(err)
	}

	validateClientUC := usecase.NewValidateClientUsecase(repoClients)
	oauthRouter := oauthHandler.NewOAUTHRouter(cfg, validateClientUC)

	api := r.Group("/api/v1")
	api.GET("/ping", Ping)

	api.GET("/authorize", oauthRouter.Authorize)
	api.POST("/authorize/login", oauthRouter.AuthorizeLogin)
	api.POST("/authorize/consent", oauthRouter.AuthorizeConsent)
	api.POST("/token", oauthRouter.Token)

	return r
}
