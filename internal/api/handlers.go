package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Ping godoc
// @Summary Health check
// @Tags health
// @Produce json
// @Success 200 {object} PingResponse
// @Router /ping [get]
func Ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "pong"})
}

type PingResponse struct {
	Message string `json:"message"`
}
