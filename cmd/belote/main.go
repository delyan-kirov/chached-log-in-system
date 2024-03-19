package main

import (
	"github.com/delyan-kirov/belote/internal/database"
	_ "github.com/lib/pq"
)

func main() {
	// Test DB
	database.Test()
}
