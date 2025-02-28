package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/eyoba-bisru/go_auth/auth"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	PORT := os.Getenv("PORT")

	if err != nil {
		log.Fatal("Error loading .env file")
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World"))
	})

	authRoute := auth.Auth()

	r.Mount("/auth", authRoute)

	log.Printf("Server running on port :%s", PORT)
	http.ListenAndServe(fmt.Sprintf(":%s", PORT), r)
}
