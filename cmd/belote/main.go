package main

import (
	"fmt"
	"net/http"

	"github.com/delyan-kirov/belote/internal/database"
	"github.com/gin-gonic/gin"
)

func main() {
	// Test DB
	database.Test()

	// server

	// Initialize Gin
	fmt.Println("Starting gin")
	router := gin.Default()

	// Define a routeroute
	router.GET("/", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "index.html", nil)
	})

	router.Static("static", "./static")
	router.LoadHTMLGlob("templates/*html")

	// register page
	router.POST("/register", func(ctx *gin.Context) {
		username := ctx.PostForm("username")
		password := ctx.PostForm("password")
		ctx.String(
			http.StatusOK,
			"Registered successfully! Username: %s, Password: %s",
			username,
			password,
		)
	})

	// run the server
	router.Run(":8080")
}
