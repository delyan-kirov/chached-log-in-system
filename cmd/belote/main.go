package main

import (
	"crypto/rand"
	"fmt"
	"net/http"

	"github.com/delyan-kirov/belote/internal/database"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func SessionMiddleware(store sessions.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, _ := store.Get(c.Request, "session-name")
		c.Set("session", session)
		c.Next()
	}
}

func main() {
	// Test DB
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

	router.POST("/signin", func(ctx *gin.Context) {
		// TODO: Add CSRF Protection
		// TODO: Add Rate limiting
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

		user_key := 0000 // TODO: make secure random key
		user_session := sessions.Default(ctx)
		user_session.Set("user_space", user_key)
		user_session.Save()

		ctx.String(
			http.StatusOK,
			"User %s successfully logged in!\nSession is: %b",
			user.Name,
			user_key,
		)
	})

	// run the server
	router.Run(":8080")
}

// TODO: Return the error

// TODO: Add sessions
// - [x] What is a user sessions?
// - [ ] How do we maintain a user session
// - [ ] Learn more about session cookies and other web stuff
// - [ ] Leanr a bit about security
// - [ ] Create a user session
// - [ ] Does the user session need to be async?
// - [ ] Template bootstrapping
