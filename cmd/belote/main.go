package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/delyan-kirov/belote/internal/database"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func generateSessionKey() (string, error) {
	// Generate random bytes
	randomBytes := make([]byte, 10*6)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("[ERROR] Could not generate random key")
	}

	// Encode random bytes to a hexadecimal string
	sessionKey := hex.EncodeToString(randomBytes)

	return sessionKey, nil
}

func main() {
	// Test DB
	fmt.Println("Starting database")
	database.Connect()

	// server

	// Initialize Gin
	fmt.Println("Starting gin")
	router := gin.Default()

	// generate session key
	session_key := make([]byte, 32)
	_, err := rand.Read(session_key)
	if err != nil {
		fmt.Println("Could not generate random key")
		fmt.Printf("[ERROR] %s\n", err)
	}

	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("mysession", store))

	// Define a routeroute
	router.GET("/", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "index.html", nil)
	})

	router.Static("static", "./static")
	router.LoadHTMLGlob("templates/*html")

	// register page
	router.POST("/register", func(ctx *gin.Context) {
		// TODO: Check user password length
		username := ctx.PostForm("username")
		password := ctx.PostForm("password")
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			fmt.Println("Could not hash user password")
			fmt.Printf("[ERROR] %s\n", err)
			ctx.String(http.StatusInternalServerError, "Failed to register user")
			return
		}
		new_user := database.User{
			Name:     username,
			Password: hashedPassword,
		}
		err = database.AddUser(new_user)
		if err != nil {
			fmt.Printf("[ERROR] %s\n", err)
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

	// signin page
	router.POST("/signin", func(ctx *gin.Context) {
		// TODO: Add CSRF Protection
		// TODO: Add Rate limiting
		// TODO: When authentication is unsuccessful, redirect elsewhere
		// TODO: Time out the session
		username := ctx.PostForm("username")
		password := ctx.PostForm("password")

		user, err := database.AuthUser(username)
		if err != nil {
			fmt.Printf("[ERROR] Invalid username %s\n", err)
			ctx.String(http.StatusUnauthorized, "Invalid username")
			return
		}

		if err := bcrypt.CompareHashAndPassword(user.Password, []byte(password)); err != nil {
			ctx.String(http.StatusUnauthorized, "Invalid password")
			fmt.Printf("[ERROR] Invalid password %s\n", err)
			return
		}

		// session
		user_key, err := generateSessionKey()
		if err != nil {
			// think how errors print potentially twice
			fmt.Println("[ERROR] Could not generate session key")
			return
		}
		user_session := sessions.Default(ctx)
		// Set session expiration time to 30 minutes
		store.Options(sessions.Options{MaxAge: 1800, Path: "/", HttpOnly: true})
		user_session.Set("user_key", user_key)
		user_session.Set("user_id", user.Name) // TODO: Dont use name, use id
		user_session.Save()

		fmt.Printf("[SUCCESS] The user: %s was successfully authorized.", user.Name)
		ctx.Redirect(http.StatusSeeOther, "/profile")
	})

	// user page
	router.GET("/profile", func(ctx *gin.Context) {
		user_session := sessions.Default(ctx)
		user_key := user_session.Get("user_key")

		if user_key == nil {
			ctx.String(http.StatusUnauthorized, "Unauthorized")
		}

		user_name := user_session.Get("user_id").(string)
		ctx.String(
			http.StatusOK,
			fmt.Sprintf("User: %s", user_name),
		)
	})

	// run the server in https
	router.RunTLS(":8080", "./tests/server.crt", "tests/server.key")
}

// TODO: Add sessions
// TODO: Make site https
// TODO: What is a middleware
// TODO: Add redis for the middleware
// TODO: Properly hash the user key
// TODO: Make documentation
// TODO: How do we maintain a user session
// TODO: Learn more about session cookies and other web stuff
// TODO: Leanr a bit about security
// TODO: Create a user session
// TODO: Does the user session need to be async?
// TODO: Template bootstrapping
