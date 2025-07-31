package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/eyoba-bisru/go_auth/config"
	"github.com/eyoba-bisru/go_auth/handlers"
	"github.com/eyoba-bisru/go_auth/middlewares"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {

	config.Init()

	PORT := os.Getenv("PORT")
	if PORT == "" {
		PORT = "8080"
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World"))
	})

	r.Post("/signup", handlers.SignupHandler)

	r.Post("/signin", handlers.SigninHandler)

	r.Route("/protected", func(r chi.Router) {
		r.Use(middlewares.Auth)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Protected Route"))
		})
	})

	log.Printf("Server running on port :%s", PORT)
	http.ListenAndServe(fmt.Sprintf(":%s", PORT), r)
}
