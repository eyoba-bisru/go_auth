package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/mail"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type Body struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func main() {
	err := godotenv.Load()

	if err != nil {
		log.Fatal("Error loading .env file")
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World"))
	})

	authRoute := chi.NewRouter()
	authRoute.Post("/signup", func(w http.ResponseWriter, r *http.Request) {
		var parsedBody Body
		err := json.NewDecoder(r.Body).Decode(&parsedBody)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}

		// Validate
		if parsedBody.Email == "" || parsedBody.Password == "" {
			http.Error(w, "email or password missing", http.StatusBadRequest)
			return
		}

		validatedEmail, err := mail.ParseAddress(parsedBody.Email)
		if err != nil {
			http.Error(w, "invalid email", http.StatusBadRequest)
			return
		}

		// hash password
		hashedPassword, err := HashPassword(parsedBody.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"exp":   time.Now().Add(time.Hour).Unix(),
			"email": validatedEmail,
			"hash":  hashedPassword,
		})

		secret_key := os.Getenv("SECRET_KEY")

		accessTokenString, err := accessToken.SignedString([]byte(secret_key))
		if err != nil {
			http.Error(w, "Access Error", http.StatusInternalServerError)
		}

		refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"exp":   time.Now().Add(time.Hour * 8760).Unix(),
			"email": validatedEmail.Address,
		})

		refreshTokenString, err := refreshToken.SignedString([]byte(secret_key))
		if err != nil {
			http.Error(w, "Refresh Error", http.StatusInternalServerError)
		}

		http.SetCookie(w, &http.Cookie{
			Name:  "access",
			Value: accessTokenString,
		})

		http.SetCookie(w, &http.Cookie{
			Name:  "refresh",
			Value: refreshTokenString,
		})

		// Save to DB

		var response = map[string]bool{
			"success": true,
		}

		res, err := json.Marshal(&response)

		if err != nil {
			http.Error(w, "Marshal Error", http.StatusInternalServerError)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(res)
	})

	r.Mount("/auth", authRoute)

	http.ListenAndServe(":8080", r)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
