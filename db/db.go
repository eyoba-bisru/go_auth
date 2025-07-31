package db

import (
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email    string `gorm:"unique"`
	Password string
}

var db *gorm.DB

func Connect() {
	dsn := os.Getenv("DATABASE_URL")
	DB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to DB")
	}
	log.Println("Connected successfully to PostgreSQL")

	db = DB

	DB.AutoMigrate(&User{})

}

func GetDB() *gorm.DB {
	return db
}
