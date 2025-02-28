package auth

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"os"
	"time"

	"github.com/eyoba-bisru/go_auth/db"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Body struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func Auth() *chi.Mux {

	database := db.Connect()

	var user db.User

	authRoute := chi.NewRouter()
	authRoute.Post("/signup", func(w http.ResponseWriter, r *http.Request) {
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
		hashedPassword, err := HashPassword(parsedBody.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		secretKey := os.Getenv("SECRET_KEY")

		accessTokenString, err := CreateJWT(jwt.MapClaims{
			"exp":   time.Now().Add(time.Hour).Unix(),
			"email": validatedEmail.Address,
		}, secretKey, true, w)

		if err != nil {
			http.Error(w, "Access Error", http.StatusInternalServerError)
			return
		}

		refreshTokenString, err := CreateJWT(jwt.MapClaims{
			"exp":   time.Now().Add(time.Hour * 8760).Unix(),
			"email": validatedEmail.Address,
		}, secretKey, false, w)

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
	})

	authRoute.Post("/signin", func(w http.ResponseWriter, r *http.Request) {
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

		database.First(&user, "Email = ?", parsedBody.Email)
		if user.Email == "" {
			http.Error(w, "user doen't exit", http.StatusBadRequest)
			return
		}

		isVerified := VerifyPassword(parsedBody.Password, user.Password)
		if !isVerified {
			http.Error(w, "wrong email or password", http.StatusBadRequest)
			return
		}

		accessTokenString, err := CreateJWT(jwt.MapClaims{
			"exp":   time.Now().Add(time.Hour).Unix(),
			"email": validatedEmail.Address,
		}, secretKey, true, w)
		if err != nil {
			http.Error(w, "Access Error", http.StatusInternalServerError)
			return
		}

		refreshTokenString, err := CreateJWT(jwt.MapClaims{
			"exp":   time.Now().Add(time.Hour * 8760).Unix(),
			"email": validatedEmail.Address,
		}, secretKey, false, w)
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

	})

	return authRoute
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func CreateJWT(claims jwt.MapClaims, secretKey string, isAccess bool, w http.ResponseWriter) (string, error) {

	if isAccess {
		accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		accessTokenString, err := accessToken.SignedString([]byte(secretKey))

		return accessTokenString, err
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	refreshTokenString, err := refreshToken.SignedString([]byte(secretKey))

	return refreshTokenString, err

}
