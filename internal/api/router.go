package api

import (
	"html/template"

	"oauthmock/internal/config"
	"oauthmock/internal/oauth/adapter/db"
	oauthHandler "oauthmock/internal/oauth/adapter/http"
	"oauthmock/internal/oauth/jwt"
	"oauthmock/internal/oauth/usecase"

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

	repoClients, err := db.NewRepositoryFromYAML("clients.yaml")
	if err != nil {
		panic(err)
	}

	jwtSigner, err := jwt.NewSigner()
	if err != nil {
		panic(err)
	}

	validateClientUC := usecase.NewValidateClientUsecase(repoClients)
	oauthRouter := oauthHandler.NewOAUTHRouter(cfg, validateClientUC, jwtSigner, conf.Issuer)

	// OIDC Discovery endpoints (at root level)
	r.GET("/.well-known/openid-configuration", oauthRouter.Discovery)
	r.GET("/.well-known/jwks.json", oauthRouter.JWKS)

	// Pages
	r.GET("/", Index)
	r.GET("/docs", Docs)

	api := r.Group("/api/v1")
	api.GET("/ping", Ping)

	api.GET("/authorize", oauthRouter.Authorize)
	api.POST("/authorize/login", oauthRouter.AuthorizeLogin)
	api.POST("/authorize/consent", oauthRouter.AuthorizeConsent)
	api.POST("/token", oauthRouter.Token)
	api.GET("/userinfo", oauthRouter.Userinfo)

	return r
}
