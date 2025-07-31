package middlewares

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/eyoba-bisru/go_auth/helpers"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		secretKey := os.Getenv("SECRET_KEY")
		if secretKey == "" {

			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		accessCookie, err := c.Cookie("access")
		if err == nil {
			accessToken, err := jwt.Parse(accessCookie, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(secretKey), nil
			})

			if err == nil && accessToken.Valid {

				c.Next()
				return
			}

		}

		refreshCookie, refreshErr := c.Cookie("refresh")

		if refreshErr != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		refreshToken, err := jwt.Parse(refreshCookie, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secretKey), nil
		})

		if err != nil || !refreshToken.Valid {

			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if claims, ok := refreshToken.Claims.(jwt.MapClaims); ok {
			email, ok := claims["email"].(string)
			if !ok {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			newAccessTokenString, err := helpers.AccessTokenGenerate(email, secretKey)
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			c.SetCookie("access", newAccessTokenString, int(time.Hour.Seconds()), "/", c.Request.Host, false, true)

			c.Next()
			return

		} else {

			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	}
}
