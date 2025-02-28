package db

import (
	"log"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email    string
	Password string
}

func Connect() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})

	if err != nil {
		log.Fatal("Failed to connect to db")
	}

	db.AutoMigrate(&User{})

	return db
}
