package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World"))
	})

	authRoute := chi.NewRouter()
	authRoute.Get("/signup", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Man"))
	})

	r.Mount("/auth", authRoute)

	http.ListenAndServe(":8080", r)
}
