package main

import (
	"log"
	"shade-server/database"
	"shade-server/server"
)

func main() {
	// Initialize database
	db, err := database.NewSQLiteDB("./shade.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	server := server.NewServer(db)
	server.Start(":8080")
}
