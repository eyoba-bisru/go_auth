package middlewares

import (
	"net/http"
	"net/mail"
	"os"

	"github.com/eyoba-bisru/go_auth/helpers"
	"github.com/golang-jwt/jwt/v5"
)

func Auth(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		secretKey := os.Getenv("SECRET_KEY")

		accessCookie, err := r.Cookie("access")
		if err != nil {
			http.Error(w, "Unauthorised", http.StatusUnauthorized)
			return
		}

		accessTokenString := accessCookie.Value
		accessToken, err := jwt.Parse(accessTokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, http.ErrAbortHandler
			}
			return []byte(secretKey), nil
		})
		if err != nil {
			http.Error(w, "Unauthorised", http.StatusUnauthorized)
			return
		}

		if accessToken.Valid {
			next.ServeHTTP(w, r)
			return
		}

		refreshCookie, err := r.Cookie("refresh")
		if err != nil {
			http.Error(w, "Unauthorised", http.StatusUnauthorized)
			return
		}

		refreshTokenString := refreshCookie.Value
		refreshToken, err := jwt.Parse(refreshTokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, http.ErrAbortHandler
			}
			return []byte(secretKey), nil
		})
		if err != nil || !refreshToken.Valid {
			http.Error(w, "Unauthorised", http.StatusUnauthorized)
			return
		}

		if claims, ok := refreshToken.Claims.(jwt.MapClaims); ok {
			email := claims["email"].(string)
			parsedEmail, err := mail.ParseAddress(email)
			if err != nil {
				http.Error(w, "Unauthorised", http.StatusUnauthorized)
				return
			}

			newAccessTokenString, err := helpers.AccessTokenGenerate(parsedEmail, secretKey)
			if err != nil {
				http.Error(w, "Unauthorised", http.StatusUnauthorized)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:  "access",
				Value: newAccessTokenString,
			})
			http.SetCookie(w, &http.Cookie{
				Name:  "refresh",
				Value: refreshTokenString,
			})
		} else {
			http.Error(w, "Unauthorised", http.StatusUnauthorized)
		}

		next.ServeHTTP(w, r)
	})
}
