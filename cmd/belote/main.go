package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/delyan-kirov/belote/internal/database"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-contrib/sessions/redis"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func enterGameQueue(ctx *gin.Context, keyHolder string, gameKey string) gin.H {
	userSession := sessions.DefaultMany(ctx, "userSession")
	gameSession := sessions.DefaultMany(ctx, "gameSession")
	userName, ok := userSession.Get("user_id").(string)

	if !ok {
		fmt.Println("[GIN] User session is over")
		return gin.H{
			"status":  http.StatusGatewayTimeout,
			"message": "User session over",
		}
	}

	// Check the key exists
	gameType, gameExists := gameKeys[keyHolder]
	playerNames := gameType.playerNames
	userCanPlay := slices.Contains(playerNames, userName)

	// Check if the game key is invalid or the user is unauthorized
	if !gameExists || gameType.key != gameKey || !userCanPlay {
		fmt.Println("[ERROR] Game key is invalid")
		return gin.H{
			"status":    http.StatusNotFound,
			"message":   "Game key is invalid or user unauthorized",
			"key":       gameKey,
			"keyHolder": keyHolder,
			"user":      userName,
			"players":   playerNames,
		}
	}

	fmt.Printf("[SUCCESS] Key Holder: %s, Game Key: %s\n", keyHolder, gameKey)

	// Add the user to the game session
	gameSession.Set(userName, true)

	return gin.H{
		"status":      http.StatusOK,
		"message":     "Entering game queue",
		"user":        userName,
		"keyHolder":   keyHolder,
		"gameKey":     gameKey,
		"playerCount": gameType.playerCount,
		"players":     playerNames,
	}
}

type GameType struct {
	key         string
	playerCount int
	playerNames []string
}

type GameKeys map[string]GameType // TODO: redo in redis

// Initialize gameKeys map
var gameKeys = make(GameKeys)

func genUserSession(store cookie.Store, user database.User, ctx *gin.Context) error {
	// Generate random bytes
	randomBytes := make([]byte, 10*6)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return err
	}

	// Encode random bytes to a hexadecimal string
	userKey := hex.EncodeToString(randomBytes)
	userSession := sessions.DefaultMany(ctx, "userSession")
	// Set session expiration time to 30 minutes
	store.Options(sessions.Options{MaxAge: 1800, Path: "/", HttpOnly: true})
	// Set session
	userSession.Set("user_key", userKey)
	userSession.Set("user_id", user.Name) // TODO: Dont use name, use id
	userSession.Save()
	return nil
}

func genGameSession(store cookie.Store, user database.User, ctx *gin.Context) error {
	// Generate random bytes
	randomBytes := make([]byte, 10*6)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return err
	}

	gameSession := sessions.DefaultMany(ctx, "gameSession")
	// Set session expiration time to 30 minutes
	store.Options(sessions.Options{MaxAge: 1800, Path: "/", HttpOnly: true})
	// Set session
	gameSession.Set(user.Name, true)
	gameSession.Save()
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
	fmt.Println("[DATA] Starting database")
	database.Connect()

	// server

	// Initialize Gin
	fmt.Println("[GIN] Starting gin")
	router := gin.Default()
	router.Use(cors.Default())

	// TODO generate session key
	session_key := make([]byte, 32)
	_, err = rand.Read(session_key)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err)
	}

	// Initialize Redis client
	store, err := redis.NewStore(10, "tcp", "localhost:6379", "", []byte("secret"))
	if err != nil {
		panic(err)
	}

	sessionNames := []string{"userSession", "gameSession"}

	// Use Redis store for session management
	router.Use(sessions.SessionsMany(sessionNames, store))

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
		err = genUserSession(store, new_user, ctx)
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
		err = genUserSession(store, user, ctx)
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
		userSession := sessions.DefaultMany(ctx, "userSession")
		userKey := userSession.Get("user_key")

		if userKey == nil {
			fmt.Println("[ERROR] Session ended or unauthorized")
			ctx.String(http.StatusUnauthorized, "Unauthorized")
		}

		user_name, ok := userSession.Get("user_id").(string)

		if !ok {
			fmt.Println("[GIN] User session is over")
			ctx.JSON(http.StatusGatewayTimeout, gin.H{
				"message": "User session over",
			})
		}

		fmt.Printf("[SUCCESS] User %s redirected to profile\n", user_name)
		ctx.HTML(http.StatusOK, "profile.html", nil)
	})

	router.POST("/profile/genGameKey", func(ctx *gin.Context) {
		userSession := sessions.DefaultMany(ctx, "userSession")
		userKey := userSession.Get("user_key")

		if userKey == nil {
			fmt.Println("[ERROR] Session ended or unauthorized")
			ctx.String(http.StatusUnauthorized, "Unauthorized")
			return
		}

		// Generate game key
		userName := userSession.Get("user_id").(string)

		// Generate random bytes
		randomBytes := make([]byte, 32)
		_, err := rand.Read(randomBytes)
		if err != nil {
			fmt.Println("[ERROR] Failed to generate random bytes:", err)
			ctx.String(http.StatusInternalServerError, "Failed to generate game key")
			return
		}

		// Get player count
		playerCount, err := strconv.Atoi(ctx.PostForm("playerCount"))
		if err != nil {
			fmt.Println("[ERROR] Invalid player count:", err)
			ctx.String(http.StatusBadRequest, "Invalid player count")
			return
		}

		// Parse player names
		var playerNames []string
		for i := 1; i <= playerCount; i++ {
			playerName := ctx.PostForm(fmt.Sprintf("name%d", i))
			if playerName == "" {
				fmt.Println("[ERROR] Player name is empty")
				ctx.String(http.StatusBadRequest, "Player name is empty")
				return
			}
			playerNames = append(playerNames, playerName)
		}

		// Encode random bytes to base32 string
		gameKey := base64.RawURLEncoding.EncodeToString(randomBytes)

		// Store game key
		gameKeys[userName] = GameType{
			key:         gameKey,
			playerCount: playerCount,
			playerNames: playerNames,
		}

		fmt.Printf("[SUCCESS] The key for user %s has been generated: %s\n", userName, gameKey)

		// Return a success response
		ctx.JSON(http.StatusOK, gin.H{
			"message":     "Game key generated successfully",
			"user":        userName,
			"gameKey":     gameKey,
			"playerCount": playerCount,
			"playerNames": playerNames,
		})
	})

	router.POST("/profile/enterGameQueue", func(ctx *gin.Context) {
		// Retrieve the key holder and game key from the form data
		keyHolder := ctx.PostForm("keyHolder")
		gameKey := ctx.PostForm("gameKey")
		gameQueueData := enterGameQueue(ctx, keyHolder, gameKey)
		ctx.JSON(
			gameQueueData["status"].(int),
			gameQueueData,
		)
	})

	// TODO: Replace redis session with another map, probably inmemory go hasmap
	router.GET("/profile/enterGameQueue", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "Hello")
	})

	router.GET("/profile/enterGame", func(ctx *gin.Context) {
		keyHolder := ctx.Query("keyHolder")
		gameKey := ctx.Query("gameKey")
		gameQueueData := enterGameQueue(ctx, keyHolder, gameKey)
		isInQueue := gameQueueData["status"].(int) == http.StatusOK

		gameSession := sessions.DefaultMany(ctx, "gameSession")

		// Check the key exists
		gameType, _ := gameKeys[keyHolder]
		playerNames := gameType.playerNames

		fmt.Println("Players: ", strings.Join(playerNames, ", "))

		canEnterGame := true
		for _, player := range playerNames {
			playerInQueue, _ := gameSession.Get(player).(bool)
			fmt.Printf("[DEBUG] Player:  %s is %t\n", player, playerInQueue)
			canEnterGame = canEnterGame && playerInQueue
		}
		if canEnterGame && len(playerNames) > 0 && isInQueue {
			ctx.String(http.StatusAccepted, "The game can begin")
		} else {
			ctx.String(http.StatusAccepted, "Not all players are ready %s", gameQueueData)
		}
	})

	// run the server in https
	// router.RunTLS(":8080", "./tests/server.crt", "tests/server.key")
	router.Run(":8080")
}

// TODO: What is a middleware
// TODO: Refactor main
// TODO: Add redis for the middleware
// TODO: Properly hash the user key
// TODO: Make documentation
// TODO: Template bootstrapping
// TODO: Desing game
// TODO: Implement CORS
// TODO: [https://chenyitian.gitbooks.io/gin-tutorials/content/tdd/21.html]
