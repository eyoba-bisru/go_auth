package config

import (
	"log"

	"github.com/eyoba-bisru/go_auth/db"
	"github.com/joho/godotenv"
)

func Init() {
	// Initialize the database connection
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	db.Connect()
}
