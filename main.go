package main

import (
	"log"
	"net/http"

	"github.com/eyoba-bisru/go_auth/auth"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

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

	authRoute := auth.Auth()

	r.Mount("/auth", authRoute)

	log.Println("Server running on port :8080")
	http.ListenAndServe(":8000", r)
}
