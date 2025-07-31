package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/eyoba-bisru/go_auth/config"
	"github.com/eyoba-bisru/go_auth/handlers"
	"github.com/eyoba-bisru/go_auth/middlewares"
	"github.com/gin-gonic/gin"
)

func main() {

	config.Init()

	PORT := os.Getenv("PORT")
	if PORT == "" {
		PORT = "8080"
	}

	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome to the Go Auth API")
	})

	r.POST("/auth/signup", handlers.SignupHandler)

	r.POST("/auth/signin", handlers.SigninHandler)

	protectedGroup := r.Group("/protected")
	protectedGroup.Use(middlewares.Auth())
	{
		protectedGroup.GET("/", func(c *gin.Context) {
			c.String(http.StatusOK, "Protected Route")
		})
	}

	log.Printf("Server running on port :%s", PORT)
	r.Run(fmt.Sprintf(":%s", PORT))
}
