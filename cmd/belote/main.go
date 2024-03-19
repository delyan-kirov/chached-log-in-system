package main

import (
	"fmt"
	"net/http"

	"github.com/delyan-kirov/belote/internal/database"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Test DB
	database.Connect()

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
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			fmt.Println("Could not hask useer password")
			ctx.String(http.StatusInternalServerError, "Failed to register user")
			return
		}
		new_user := database.User{
			Name:     username,
			Password: hashedPassword,
		}
		err = database.AddUser(new_user)
		if err != nil {
			ctx.String(http.StatusInternalServerError, "Failed to add user to database")
			return
		}

		ctx.String(
			http.StatusOK,
			"Registered successfully! Username: %s, Password: %s",
			username,
			password,
		)
	})

	router.POST("/signin", func(ctx *gin.Context) {
		username := ctx.PostForm("username")
		password := ctx.PostForm("password")

		user, err := database.AuthUser(username)
		if err != nil {
			fmt.Printf("Invalid username: %s", err)
			ctx.String(http.StatusUnauthorized, "Invalid username")
			return
		}

		if err := bcrypt.CompareHashAndPassword(user.Password, []byte(password)); err != nil {
			ctx.String(http.StatusUnauthorized, "Invalid password")
			fmt.Println("Invalid password")
			return
		}

		ctx.String(http.StatusOK, "User %s successfully logged in", user.Name)
	})

	// run the server
	router.Run(":8080")
}

// TODO: Return the error
