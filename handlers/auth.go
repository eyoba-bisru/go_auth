package handlers

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"os"

	"github.com/eyoba-bisru/go_auth/db"
	"github.com/eyoba-bisru/go_auth/helpers"
)

type Body struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var database = db.GetDB()

var user db.User

func SignupHandler(w http.ResponseWriter, r *http.Request) {
	var parsedBody Body
	err := json.NewDecoder(r.Body).Decode(&parsedBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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

	database.First(&user, "email = ?", parsedBody.Email)
	if user.Email != "" {
		http.Error(w, "user already exit", http.StatusBadRequest)
		return
	}

	// hash password
	hashedPassword, err := helpers.HashPassword(parsedBody.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	secretKey := os.Getenv("SECRET_KEY")

	accessTokenString, err := helpers.AccessTokenGenerate(validatedEmail, secretKey)

	if err != nil {
		http.Error(w, "Access Error", http.StatusInternalServerError)
		return
	}

	refreshTokenString, err := helpers.RefreshTokenGenerate(validatedEmail, secretKey)

	if err != nil {
		http.Error(w, "Refresh Error", http.StatusInternalServerError)
		return
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

	database.Create(&db.User{Email: parsedBody.Email, Password: hashedPassword})

	var response = map[string]bool{
		"success": true,
	}

	res, err := json.Marshal(&response)

	if err != nil {
		http.Error(w, "Marshal Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(res)
}

func SigninHandler(w http.ResponseWriter, r *http.Request) {
	var parsedBody Body

	secretKey := os.Getenv("SECRET_KEY")

	err := json.NewDecoder(r.Body).Decode(&parsedBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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

	database.First(&user, "email = ?", parsedBody.Email)
	if user.Email == "" {
		http.Error(w, "user doen't exit", http.StatusBadRequest)
		return
	}

	isVerified := helpers.VerifyPassword(parsedBody.Password, user.Password)
	if !isVerified {
		http.Error(w, "wrong email or password", http.StatusBadRequest)
		return
	}

	accessTokenString, err := helpers.AccessTokenGenerate(validatedEmail, secretKey)
	if err != nil {
		http.Error(w, "Access Error", http.StatusInternalServerError)
		return
	}

	refreshTokenString, err := helpers.RefreshTokenGenerate(validatedEmail, secretKey)
	if err != nil {
		http.Error(w, "Refresh Error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "access",
		Value: accessTokenString,
	})
	http.SetCookie(w, &http.Cookie{
		Name:  "refresh",
		Value: refreshTokenString,
	})

	var response = map[string]bool{
		"success": true,
	}

	res, err := json.Marshal(&response)

	if err != nil {
		http.Error(w, "Marshal Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(res)
}
