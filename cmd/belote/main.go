package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"

	"github.com/delyan-kirov/belote/internal/database"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func genSession(store cookie.Store, user database.User, ctx *gin.Context) error {
	// Generate random bytes
	randomBytes := make([]byte, 10*6)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return err
	}

	// Encode random bytes to a hexadecimal string
	user_key := hex.EncodeToString(randomBytes)
	// session
	user_session := sessions.Default(ctx)
	// Set session expiration time to 30 minutes
	store.Options(sessions.Options{MaxAge: 1800, Path: "/", HttpOnly: true})
	// Set session
	user_session.Set("user_key", user_key)
	user_session.Set("user_id", user.Name) // TODO: Dont use name, use id
	user_session.Save()
	return nil
}

func main() {
	// Open a file to log stdout and stderr
	logFile, err := os.Create("./tests/gin_logs.txt")
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		return
	}
	defer logFile.Close()

	// Redirect stdout and stderr to the log file
	os.Stdout = logFile
	os.Stderr = logFile

	// Test DB
	fmt.Println("Starting database")
	database.Connect()

	// server

	// Initialize Gin
	fmt.Println("Starting gin")
	router := gin.Default()
	router.Use(cors.Default())

	// generate session key
	session_key := make([]byte, 32)
	_, err = rand.Read(session_key)
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
	router.GET("./register", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "register.html", nil)
	})
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
		// Clear session if exists
		err = genSession(store, new_user, ctx)
		if err != nil {
			ctx.String(http.StatusUnauthorized, "Could not generate session")
			fmt.Printf("[ERROR] Could not generate session %s\n", err)
			return
		}
		ctx.Redirect(http.StatusSeeOther, "/profile")
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
		err = genSession(store, user, ctx)
		if err != nil {
			ctx.String(http.StatusUnauthorized, "Could not generate session")
			fmt.Printf("[ERROR] Could not generate session %s\n", err)
			return
		}
		fmt.Printf("[SUCCESS] The user: %s was successfully authorized\n", user.Name)
		ctx.Redirect(http.StatusSeeOther, "/profile")
	})

	// user page
	router.GET("/profile", func(ctx *gin.Context) {
		user_session := sessions.Default(ctx)
		user_key := user_session.Get("user_key")

		if user_key == nil {
			fmt.Println("[ERROR] Session ended or unauthorized")
			ctx.String(http.StatusUnauthorized, "Unauthorized")
		}

		user_name := user_session.Get("user_id").(string)
		fmt.Printf("[SUCCESS] User %s redirected to profile\n", user_name)
		ctx.HTML(http.StatusOK, "profile.html", nil)
	})

	// run the server in https
	// router.RunTLS(":8080", "./tests/server.crt", "tests/server.key")
	router.Run(":8080")
}

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
// TODO: Desing game
// TODO: Implement CORS
// TODO: [https://chenyitian.gitbooks.io/gin-tutorials/content/tdd/21.html]
