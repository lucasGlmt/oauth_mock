package api

import (
	"bytes"
	"html/template"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
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

// Index serves the home page
func Index(c *gin.Context) {
	c.HTML(http.StatusOK, "index.tmpl", nil)
}

// Docs serves the README as HTML
func Docs(c *gin.Context) {
	content, err := os.ReadFile("README.md")
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to read documentation")
		return
	}

	md := goldmark.New(
		goldmark.WithExtensions(extension.GFM),
	)

	var buf bytes.Buffer
	if err := md.Convert(content, &buf); err != nil {
		c.String(http.StatusInternalServerError, "Failed to render documentation")
		return
	}

	c.HTML(http.StatusOK, "docs.tmpl", gin.H{
		"Content": template.HTML(buf.String()),
	})
}
