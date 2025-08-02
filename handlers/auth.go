package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/eyoba-bisru/go_auth/config"
	"github.com/eyoba-bisru/go_auth/db"
	"github.com/eyoba-bisru/go_auth/helpers"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

type Body struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

func SignupHandler(c *gin.Context) {
	database := db.GetDB()
	var parsedBody Body

	if err := c.ShouldBindJSON(&parsedBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	var user db.User
	if err := database.First(&user, "email = ?", parsedBody.Email).Error; err == nil {

		c.JSON(http.StatusBadRequest, gin.H{"error": "User with this email already exists"})
		return
	} else if err.Error() != "record not found" {

		log.Printf("Database error checking user existence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check user existence"})
		return
	}

	hashedPassword, err := helpers.HashPassword(parsedBody.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		log.Println("SECRET_KEY environment variable not set")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server configuration error"})
		return
	}

	accessTokenString, err := helpers.AccessTokenGenerate(parsedBody.Email, secretKey)
	if err != nil {
		log.Printf("Error generating access token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	refreshTokenString, err := helpers.RefreshTokenGenerate(parsedBody.Email, secretKey)
	if err != nil {
		log.Printf("Error generating refresh token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	c.SetCookie("access", accessTokenString, 3600, "/", "localhost", false, true)
	c.SetCookie("refresh", refreshTokenString, 24*30*3600, "/", "localhost", false, true)

	newUser := db.User{Email: parsedBody.Email, Password: hashedPassword}
	if err := database.Create(&newUser).Error; err != nil {
		log.Printf("Error saving new user to database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "User registered successfully"})
}

func SigninHandler(c *gin.Context) {
	database := db.GetDB()
	var parsedBody Body

	if err := c.ShouldBindJSON(&parsedBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		log.Println("SECRET_KEY environment variable not set")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server configuration error"})
		return
	}

	var user db.User
	if err := database.First(&user, "email = ?", parsedBody.Email).Error; err != nil {
		if err.Error() == "record not found" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "User with this email does not exist"})
		} else {
			log.Printf("Database error checking user existence: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check user existence"})
		}
		return
	}

	isVerified := helpers.VerifyPassword(parsedBody.Password, user.Password)
	if !isVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email or password"})
		return
	}

	accessTokenString, err := helpers.AccessTokenGenerate(parsedBody.Email, secretKey)
	if err != nil {
		log.Printf("Error generating access token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	refreshTokenString, err := helpers.RefreshTokenGenerate(parsedBody.Email, secretKey)
	if err != nil {
		log.Printf("Error generating refresh token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	c.SetCookie("access", accessTokenString, 3600, "/", "localhost", false, true)
	c.SetCookie("refresh", refreshTokenString, 24*30*3600, "/", "localhost", false, true)

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "User logged in successfully"})
}

func OAuthLoginHandler(c *gin.Context) {
	provider := c.Param("provider")
	if provider != "google" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported provider"})
		return
	}
	config := config.GoogleConfig()
	url := config.AuthCodeURL("state", oauth2.AccessTypeOffline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func OAuthCallbackHandler(c *gin.Context) {
	provider := c.Param("provider")
	if provider != "google" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported provider"})
		return
	}

	config := config.GoogleConfig()
	code := c.Query("code")
	token, err := config.Exchange(c, code)
	if err != nil {
		log.Printf("Error exchanging code for token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange code for token"})
		return
	}

	if token == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve token"})
		return
	}

	c.SetCookie("access", token.AccessToken, 3600, "/", "localhost", false, true)

	client := config.Client(c, token)
	userInfoResp, err := client.Get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json")
	if err != nil {
		log.Printf("Error fetching user info: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user info"})
		return
	}
	defer userInfoResp.Body.Close()

	var userInfo map[string]interface{}
	if err := json.NewDecoder(userInfoResp.Body).Decode(&userInfo); err != nil {
		log.Printf("Error decoding user info response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode user info response"})
		return
	}

	email := userInfo["email"].(string)
	log.Printf("User authenticated with email: %s", email)

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "User authenticated successfully", "email": email})
}
